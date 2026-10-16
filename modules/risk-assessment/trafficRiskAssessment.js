"use strict";

const { createHmac, createHash, randomBytes, timingSafeEqual } = require("node:crypto");
const createIpIntelligenceCache = require("./ipIntelligenceCache.js");
const createFreeIpIntelligenceProvider = require("./freeIpIntelligenceProvider.js");
const createCampaignRiskStore = require("./campaignRiskStore.js");

const TOTAL_FIELDS = ["observedRequests", "headlessMarkers", "headerAnomalies", "networkKnown", "networkUnknown", "hostingIndicators", "proxyIndicators", "vpnIndicators", "residentialProxyIndicators", "challengePassed", "challengeFailed"];
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const EVENT_RE = /^[A-Za-z0-9_.:-]{1,128}$/;

function createTrafficRiskAssessment({
  env = {}, hashSecret = "", getRequestIdentity = () => ({}),
  headlessSuspicion = () => ({}), createRedisClient = () => null,
  provider: suppliedProvider, cache: suppliedCache, store: suppliedStore,
  persistence = null, onRiskObservation = () => {},
  fetch: fetchImpl = globalThis.fetch, now = Date.now
} = {}) {
  const enabled = !["0", "false", "off", "no"].includes(String(env.RISK_REPORTING_ENABLED || "1").trim().toLowerCase());
  const requestedProvider = String(env.RISK_IP_PROVIDER || "ipapi.is").trim().toLowerCase() || "ipapi.is";
  const validProvider = ["ipapi.is", "ipquery"].includes(requestedProvider);
  const providerName = validProvider ? requestedProvider : "unsupported";
  const externalEnabled = enabled && validProvider && ["1", "true", "on", "yes"].includes(String(env.RISK_IP_INTELLIGENCE_ENABLED || "0").trim().toLowerCase());
  const configErrors = [];
  if (!validProvider) configErrors.push("RISK_IP_PROVIDER");
  const number = (name, fallback, min, max) => {
    const raw = env[name];
    if (raw == null || raw === "") return fallback;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < min || value > max) { configErrors.push(name); return fallback; }
    return value;
  };
  let campaignIds = [...new Set(String(env.RISK_CAMPAIGN_IDS || "").split(",").map(id => id.trim()).filter(Boolean))];
  if (campaignIds.length > 32 || campaignIds.some(id => !ID_RE.test(id) || id === "__unattributed__")) {
    configErrors.push("RISK_CAMPAIGN_IDS"); campaignIds = [];
  }
  const allowed = new Set(campaignIds);
  let namespace = String(env.RISK_NAMESPACE || env.TRAFFIC_METRICS_NAMESPACE || "oldserver222");
  const namespaceValid = /^[A-Za-z0-9:_-]{1,80}$/.test(namespace);
  if (!namespaceValid) { configErrors.push("RISK_NAMESPACE"); namespace = "oldserver222"; }
  const key = String(env.RISK_HASH_SECRET || hashSecret || "") || randomBytes(32).toString("hex");
  const totals = Object.fromEntries(TOTAL_FIELDS.map(field => [field, 0]));
  const startedAt = new Date(now()).toISOString();
  const challengeEvidence = new WeakMap();
  let observerErrors = 0;
  let closed = false;
  let redisClient = null;
  let redisSetupFailed = false;
  if (enabled && namespaceValid && !suppliedStore && !persistence) {
    try { redisClient = createRedisClient(); }
    catch (_) { redisSetupFailed = true; configErrors.push("risk_storage_unavailable"); }
  }
  const provider = suppliedProvider || createFreeIpIntelligenceProvider({ enabled: externalEnabled, provider: providerName, fetch: fetchImpl,
    dailyBudget: number("RISK_IP_DAILY_BUDGET", 900, 0, 1000) });
  const cache = suppliedCache || createIpIntelligenceCache({ enabled: externalEnabled, lookup: provider.lookup,
    maxEntries: number("RISK_IP_CACHE_MAX_ENTRIES", 2048, 1, 10000),
    maxQueue: number("RISK_IP_QUEUE_MAX", 64, 1, 128), concurrency: 2,
    timeoutMs: number("RISK_IP_TIMEOUT_MS", 800, 100, 2000),
    ttlMs: number("RISK_IP_CACHE_TTL_MS", 3600000, 60000, 86400000),
    negativeTtlMs: number("RISK_IP_NEGATIVE_TTL_MS", 60000, 1000, 3600000), now });
  // Failed configured storage must not silently authorize local conversions.
  const store = suppliedStore || createCampaignRiskStore({ client: redisSetupFailed ? { status: "end" } : redisClient, namespace, campaignIds,
    ...(persistence && namespaceValid ? { onDirty: persistence.onDirty, commit: persistence.commit, persistenceReady: persistence.isReady } : {}),
    windowSec: number("RISK_WINDOW_SECONDS", 300, 10, 3600), now });
  const minRequests = number("RISK_BURST_MIN_REQUESTS", 200, 10, 100000);
  const minSources = number("RISK_BURST_MIN_SOURCES", 20, 2, 10000);
  const conversionToken = String(env.RISK_CONVERSION_TOKEN || "");
  const validConversionToken = /^[\x21-\x7e]{32,256}$/.test(conversionToken);
  const conversionEnabled = enabled && namespaceValid && validConversionToken && campaignIds.length > 0;
  if (conversionToken && !validConversionToken) configErrors.push("RISK_CONVERSION_TOKEN");
  const conversionTokenHash = createHash("sha256").update(conversionToken).digest();

  function hash(purpose, value) { return createHmac("sha256", key).update(`${namespace}:${purpose}:`).update(value).digest("hex"); }
  function increment(field) { totals[field] = Math.min(Number.MAX_SAFE_INTEGER, totals[field] + 1); }
  function campaignFor(req) {
    const query = req && req.query;
    if (query && typeof query.campaign_id === "string" && allowed.has(query.campaign_id)) return query.campaign_id;
    return null;
  }
  function recordChallengeOutcome(event, req) {
    if (!enabled || closed || !req || typeof req !== "object" || !["passed", "failed"].includes(event)) return;
    const evidence = challengeEvidence.get(req) || { passed: false, failed: false };
    evidence[event] = true;
    challengeEvidence.set(req, evidence);
  }
  function observe(req, { kind } = {}) {
    const evidence = req && typeof req === "object" ? challengeEvidence.get(req) : null;
    if (req && typeof req === "object") challengeEvidence.delete(req);
    if (!enabled || closed || kind === "operational") return;
    try {
      const identity = getRequestIdentity(req);
      // Never use displayIp/rateLimitKey: those can include untrusted forwarded headers.
      const ip = typeof identity.keyIp === "string" ? identity.keyIp : "";
      const browser = headlessSuspicion(req) || {};
      const headless = Number(browser.hardCount) > 0;
      const anomalous = Number(browser.softCount) >= 2;
      const network = cache.observe(ip);
      increment("observedRequests");
      if (headless) increment("headlessMarkers");
      if (anomalous) increment("headerAnomalies");
      const known = ["hosting", "proxy", "vpn", "residentialProxy"].some(name => typeof network[name] === "boolean");
      increment(known ? "networkKnown" : "networkUnknown");
      for (const name of ["hosting", "proxy", "vpn", "residentialProxy"]) if (network[name] === true) increment(`${name}Indicators`);
      if (evidence?.passed) increment("challengePassed");
      if (evidence?.failed) increment("challengeFailed");
      store.recordRequest({ campaignId: campaignFor(req), sourceHash: ip && ip !== "unknown" ? hash("source", ip) : "",
        headless: headless || anomalous, hosting: network.hosting === true, proxy: network.proxy === true,
        vpn: network.vpn === true, residentialProxy: network.residentialProxy === true,
        challengePassed: evidence?.passed === true, challengeFailed: evidence?.failed === true });
      onRiskObservation({ headlessMarkers: headless, headerAnomalies: anomalous, networkKnown: known, networkUnknown: !known,
        hostingIndicators: network.hosting === true, proxyIndicators: network.proxy === true, vpnIndicators: network.vpn === true,
        residentialProxyIndicators: network.residentialProxy === true, challengePassed: evidence?.passed === true, challengeFailed: evidence?.failed === true });
    } catch (_) { observerErrors = Math.min(Number.MAX_SAFE_INTEGER, observerErrors + 1); }
  }
  async function recordConversion(body) {
    if (!conversionEnabled || closed) return { accepted: false, reason: "unavailable" };
    if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).some(field => !["campaignId", "eventId"].includes(field)) ||
      typeof body.campaignId !== "string" || !allowed.has(body.campaignId) || typeof body.eventId !== "string" || !EVENT_RE.test(body.eventId)) {
      return { accepted: false, reason: "invalid_event" };
    }
    try { return await store.recordConversion({ campaignId: body.campaignId, eventIdHash: hash("conversion", body.eventId) }); }
    catch (_) { return { accepted: false, reason: "unavailable" }; }
  }
  function conversionAuthorized(authorization) {
    if (!conversionEnabled || typeof authorization !== "string") return false;
    const match = /^Bearer ([\x21-\x7e]{1,256})$/.exec(authorization);
    return Boolean(match && timingSafeEqual(createHash("sha256").update(match[1]).digest(), conversionTokenHash));
  }
  async function getSnapshot() {
    let campaignWindow;
    try { campaignWindow = await store.getSnapshot(); }
    catch (_) { campaignWindow = { scope: "unavailable", campaigns: [], storage: { ready: false, lastError: "unavailable" } }; }
    campaignWindow = { ...campaignWindow, campaigns: (campaignWindow.campaigns || []).slice(0, 33).map(row => ({ ...row,
      unusualActivity: !row.distinctSourcesSaturated && row.requests >= minRequests && row.distinctSourcesEstimate >= minSources && row.headless >= row.requests / 2 })) };
    return { mode: enabled ? "report_only" : "disabled", scope: "current_process", startedAt, totals: { ...totals }, observerErrors,
      intelligence: { enabled: externalEnabled, provider: providerName,
        capabilities: { hosting: validProvider, proxy: validProvider, vpn: validProvider, residentialProxy: false },
        providerStatus: provider.getStatus(), cache: cache.getStatus() },
      campaignWindow, conversions: { enabled: conversionEnabled, dedupeHours: 24 },
      configErrors: [...configErrors], classification: "indicators_only" };
  }
  async function close() {
    if (closed) return;
    closed = true;
    cache.close();
    try { await store.close(); } finally { redisClient?.disconnect?.(); }
  }
  return { observe, recordChallengeOutcome, recordConversion, conversionAuthorized, getSnapshot, close, enabled, conversionEnabled,
    exportPersistentState: () => store.exportState(), restorePersistentState: state => store.restoreState(state) };
}

module.exports = createTrafficRiskAssessment;
