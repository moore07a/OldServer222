"use strict";

const assert = require("node:assert/strict");
const { createHmac } = require("node:crypto");
const { EventEmitter } = require("node:events");
const test = require("node:test");
const createTrafficRiskAssessment = require("../modules/risk-assessment/trafficRiskAssessment.js");
const createTrafficMetrics = require("../modules/runtime-utils/trafficMetrics.js");

const TOKEN = "dedicated-conversion-token-123456789";
const HASH_SECRET = "unit-hash-secret-abcdefghijklmnopqrstuvwxyz";
const unknown = (state = "unknown") => ({ state, hosting: null, vpn: null, proxy: null, residentialProxy: null, source: null });
const TOTAL_FIELDS = ["observedRequests", "headlessMarkers", "headerAnomalies", "networkKnown", "networkUnknown", "hostingIndicators", "proxyIndicators", "vpnIndicators", "residentialProxyIndicators", "challengePassed", "challengeFailed"];

test("redirect policy cache access shares one lookup without recording visits or trusting display IPs", async t => {
  const urls = [];
  const risk = createTrafficRiskAssessment({ env: { RISK_IP_PROVIDER: "ipquery", RISK_IP_INTELLIGENCE_ENABLED: "1" },
    hashSecret: HASH_SECRET, getRequestIdentity: () => ({ keyIp: "8.8.8.8", displayIp: "1.1.1.1", ip: "9.9.9.9" }),
    fetch: async url => { urls.push(url); return new Response(JSON.stringify({ risk: { is_datacenter: false, is_proxy: false, is_vpn: true } })); } });
  t.after(() => risk.close());
  const req = { query: { ip: "4.4.4.4", vpn: false }, headers: { "x-forwarded-for": "4.4.4.4" } };
  assert.equal(risk.intelligenceEnabled, true);
  assert.equal(risk.observeNetwork(req).vpn, null);
  assert.equal(risk.observeNetwork(req).vpn, null);
  assert.equal(urls.length, 0, "cache access never waits for or directly calls the provider");
  await new Promise(resolve => setImmediate(resolve));
  assert.equal((await risk.getSnapshot()).totals.observedRequests, 0);
  assert.equal(risk.observeNetwork(req).vpn, true);
  risk.observe(req, { kind: "get" });
  const report = await risk.getSnapshot();
  assert.deepEqual(urls, ["https://api.ipquery.io/8.8.8.8"]);
  assert.equal(report.intelligence.providerStatus.used, 1);
  assert.equal(report.totals.observedRequests, 1);
  assert.equal(report.totals.networkKnown, 1);
  assert.equal(report.totals.vpnIndicators, 1);
  await risk.close();
  assert.equal(risk.observeNetwork(req).state, "disabled");
  assert.equal(urls.length, 1, "closed cache access cannot start another lookup");
});

test("disabled intelligence does not consult request identities through policy cache access", async t => {
  const risk = createTrafficRiskAssessment({ env: { RISK_IP_PROVIDER: "ipquery" },
    getRequestIdentity() { assert.fail("disabled intelligence must not read request identity"); },
    fetch() { assert.fail("disabled intelligence must not fetch"); } });
  t.after(() => risk.close());
  assert.equal(risk.intelligenceEnabled, false);
  assert.equal(risk.observeNetwork({}).state, "disabled");
});

test("explicit IPQuery selection uses the real bounded cache and reports cached network indicators", async t => {
  const calls = [];
  const risk = createTrafficRiskAssessment({
    env: { RISK_IP_PROVIDER: " IPQUERY ", RISK_IP_INTELLIGENCE_ENABLED: "1" }, hashSecret: HASH_SECRET,
    getRequestIdentity: () => ({ keyIp: "8.8.8.8" }),
    fetch: async (url, options) => {
      calls.push({ url, options });
      return new Response(JSON.stringify({ ip: "8.8.8.8", risk: { is_datacenter: true, is_proxy: true, is_vpn: true },
        location: { city: "private-provider-location" } }));
    }
  });
  t.after(() => risk.close());
  risk.observe({ query: {} }, { kind: "get" });
  assert.equal(calls.length, 0, "visitor observation does not wait for or directly call the provider");
  await new Promise(resolve => setImmediate(resolve));
  const cached = await risk.getSnapshot();
  assert.equal(cached.intelligence.cache.active, 0);
  assert.equal(cached.intelligence.cache.cacheEntries, 1);
  risk.observe({ query: {} }, { kind: "get" });
  const report = await risk.getSnapshot();
  assert.equal(calls.length, 1, "a repeat visitor request reuses the cached response");
  assert.equal(calls[0].url, "https://api.ipquery.io/8.8.8.8");
  assert.equal(calls[0].options.credentials, "omit");
  assert.equal(calls[0].options.redirect, "error");
  assert.equal(report.intelligence.provider, "ipquery");
  assert.equal(report.intelligence.providerStatus.provider, "ipquery");
  assert.equal(report.intelligence.providerStatus.used, 1);
  assert.equal(report.intelligence.providerStatus.lastResult, "known");
  assert.equal(report.intelligence.providerStatus.lastHttpStatus, 200);
  assert.equal(report.totals.observedRequests, 2);
  assert.equal(report.totals.networkUnknown, 1, "the first cache miss is not retroactively reclassified");
  assert.equal(report.totals.networkKnown, 1);
  for (const field of ["hostingIndicators", "proxyIndicators", "vpnIndicators"]) assert.equal(report.totals[field], 1);
  assert.equal(report.intelligence.capabilities.residentialProxy, false);
  assert.equal(report.observerErrors, 0);
  assert.doesNotMatch(JSON.stringify(report), /8\.8\.8\.8|api\.ipquery\.io|private-provider-location/);
});

test("provider selection alone is not lookup authorization and the legacy provider remains the default", async t => {
  for (const env of [{}, { RISK_IP_PROVIDER: "ipquery" }, { RISK_IP_PROVIDER: "ipquery", RISK_REPORTING_ENABLED: "0", RISK_IP_INTELLIGENCE_ENABLED: "1" }]) {
    const risk = createTrafficRiskAssessment({ env, getRequestIdentity: () => ({ keyIp: "8.8.8.8" }),
      fetch() { assert.fail("selecting a provider must not silently enable lookups"); } });
    t.after(() => risk.close());
    risk.observe({}, { kind: "get" });
    await new Promise(resolve => setImmediate(resolve));
    const report = await risk.getSnapshot();
    assert.equal(report.intelligence.enabled, false);
    assert.equal(report.intelligence.provider, env.RISK_IP_PROVIDER || "ipapi.is");
    assert.equal(report.intelligence.providerStatus.provider, env.RISK_IP_PROVIDER || "ipapi.is");
    assert.equal(report.intelligence.providerStatus.used, 0);
    assert.equal(report.intelligence.cache.lookups, 0);
  }
});

test("unsupported provider configuration disables requests without reflecting its value", async t => {
  const risk = createTrafficRiskAssessment({ env: { RISK_IP_INTELLIGENCE_ENABLED: "1", RISK_IP_PROVIDER: "https://private-provider.invalid/secret-value" },
    getRequestIdentity: () => ({ keyIp: "8.8.8.8" }), fetch() { assert.fail("unsupported endpoints cannot receive visitor IPs"); } });
  t.after(() => risk.close());
  risk.observe({}, { kind: "get" });
  await new Promise(resolve => setImmediate(resolve));
  const report = await risk.getSnapshot();
  assert.equal(report.mode, "report_only");
  assert.equal(report.intelligence.enabled, false);
  assert.equal(report.intelligence.provider, "unsupported");
  assert.equal(report.intelligence.providerStatus.configured, false);
  assert.equal(report.intelligence.cache.lookups, 0);
  assert.deepEqual(report.configErrors, ["RISK_IP_PROVIDER"]);
  assert.deepEqual(report.intelligence.capabilities, { hosting: false, proxy: false, vpn: false, residentialProxy: false });
  assert.equal(report.totals.observedRequests, 1);
  assert.equal(report.totals.networkUnknown, 1);
  assert.doesNotMatch(JSON.stringify(report), /private-provider|secret-value|https:/);
});

function harness(options = {}) {
  const seenIps = [];
  const requests = [];
  const conversions = [];
  const saved = new Set();
  let network = unknown();
  let rows = [];
  let cacheCloses = 0;
  let storeCloses = 0;
  let providerLookups = 0;
  const cache = {
    observe(ip) { seenIps.push(ip); return options.cacheObserve ? options.cacheObserve(ip) : network; },
    getStatus: () => ({ active: 0, queued: 0, cacheEntries: 0 }),
    close() { cacheCloses += 1; }
  };
  const provider = {
    lookup() { providerLookups += 1; throw new Error("The injected cache owns lookup scheduling"); },
    getStatus: () => ({ provider: "ipapi.is", used: 0, remaining: 900 })
  };
  const store = {
    recordRequest(value) { requests.push(value); return options.recordRequest ? options.recordRequest(value) : true; },
    async recordConversion(value) {
      conversions.push(value);
      if (options.recordConversion) return options.recordConversion(value);
      const key = `${value.campaignId}:${value.eventIdHash}`;
      const duplicate = saved.has(key);
      saved.add(key);
      return { accepted: true, duplicate, scope: "current_process" };
    },
    async getSnapshot() {
      if (options.getStoreSnapshot) return options.getStoreSnapshot();
      return { scope: "current_process", campaigns: rows, storage: { ready: false, lastError: null } };
    },
    async close() { storeCloses += 1; }
  };
  const risk = createTrafficRiskAssessment({
    env: { RISK_CAMPAIGN_IDS: "alpha,beta", RISK_CONVERSION_TOKEN: TOKEN, ...options.env },
    hashSecret: HASH_SECRET, now: () => 1800000000000,
    getRequestIdentity: options.getRequestIdentity || (() => ({ keyIp: "8.8.8.8", ip: "9.9.9.9", displayIp: "9.9.9.9", rateLimitKey: "1.1.1.1" })),
    headlessSuspicion: options.headlessSuspicion || (req => req.markers || {}),
    cache, provider, store,
    createRedisClient() { assert.fail("Injected storage must not create a Redis client"); }
  });
  return {
    risk, seenIps, requests, conversions,
    setNetwork(value) { network = value; }, setRows(value) { rows = value; },
    get cacheCloses() { return cacheCloses; }, get storeCloses() { return storeCloses; },
    get providerLookups() { return providerLookups; }
  };
}

test("observation synchronously uses only the trusted key IP and never awaits work or calls the provider", async t => {
  const h = harness({ recordRequest() { return { get then() { assert.fail("Observation must not await storage"); } }; } });
  t.after(() => h.risk.close());
  assert.equal(h.risk.observe({ query: {} }, { kind: "get" }), undefined);
  assert.deepEqual(h.seenIps, ["8.8.8.8"]);
  assert.equal(h.requests.length, 1);
  assert.equal(h.requests[0].sourceHash, createHmac("sha256", HASH_SECRET).update("oldserver222:source:").update("8.8.8.8").digest("hex"));
  assert.equal(h.providerLookups, 0);
  const withoutTrustedIp = harness({ getRequestIdentity: () => ({ displayIp: "9.9.9.9", rateLimitKey: "1.1.1.1", ip: "4.2.2.2" }) });
  t.after(() => withoutTrustedIp.risk.close());
  withoutTrustedIp.risk.observe({}, { kind: "get" });
  assert.deepEqual(withoutTrustedIp.seenIps, [""]);
  assert.equal(withoutTrustedIp.requests[0].sourceHash, "", "untrusted identity aliases cannot supply distinct-source evidence");
});

test("operational, disabled and closed observations do not assess traffic or retain challenge evidence", async () => {
  const h = harness();
  const req = {};
  h.risk.recordChallengeOutcome("passed", req);
  h.risk.observe(req, { kind: "operational" });
  assert.equal(h.seenIps.length, 0);
  assert.equal(h.requests.length, 0);
  h.risk.observe(req, { kind: "get" });
  assert.equal((await h.risk.getSnapshot()).totals.challengePassed, 0);
  await h.risk.close(); await h.risk.close();
  h.risk.observe({}, { kind: "get" });
  assert.equal(h.requests.length, 1);
  assert.equal(h.cacheCloses, 1);
  assert.equal(h.storeCloses, 1);

  const disabled = harness({ env: { RISK_REPORTING_ENABLED: "0", RISK_IP_INTELLIGENCE_ENABLED: "1" } });
  disabled.risk.recordChallengeOutcome("failed", req);
  disabled.risk.observe(req, { kind: "get" });
  const snapshot = await disabled.risk.getSnapshot();
  assert.equal(snapshot.mode, "disabled");
  assert.equal(snapshot.intelligence.enabled, false);
  assert.ok(Object.values(snapshot.totals).every(value => value === 0));
  assert.equal(disabled.seenIps.length, 0);
  assert.equal(disabled.risk.conversionEnabled, false);
  await disabled.risk.close();
});

test("fixed totals preserve unknown network intelligence and report unsupported residential capability", async t => {
  const h = harness({ env: { RISK_IP_INTELLIGENCE_ENABLED: "1" } });
  t.after(() => h.risk.close());
  for (const state of ["unknown", "pending", "disabled"]) {
    h.setNetwork(unknown(state));
    h.risk.observe({ markers: {} }, { kind: "get" });
  }
  h.setNetwork({ state: "known", hosting: false, proxy: false, vpn: false, residentialProxy: null, source: "ipapi.is" });
  h.risk.observe({ markers: { hardCount: 0, softCount: 1 } }, { kind: "head" });
  h.setNetwork({ state: "known", hosting: true, proxy: true, vpn: true, residentialProxy: null, source: "ipapi.is" });
  h.risk.observe({ markers: { hardCount: 1, softCount: 2 } }, { kind: "other" });
  const snapshot = await h.risk.getSnapshot();
  assert.deepEqual(Object.keys(snapshot.totals).sort(), [...TOTAL_FIELDS].sort());
  assert.deepEqual(snapshot.totals, {
    observedRequests: 5, headlessMarkers: 1, headerAnomalies: 1,
    networkKnown: 2, networkUnknown: 3, hostingIndicators: 1, proxyIndicators: 1,
    vpnIndicators: 1, residentialProxyIndicators: 0, challengePassed: 0, challengeFailed: 0
  });
  assert.deepEqual(snapshot.intelligence.capabilities, { hosting: true, proxy: true, vpn: true, residentialProxy: false });
  assert.equal(snapshot.classification, "indicators_only");
  assert.equal(snapshot.mode, "report_only");
  assert.equal(h.requests.at(-1).residentialProxy, false, "ISP or other network flags cannot infer residential-proxy evidence");
  snapshot.totals.observedRequests = 999;
  assert.equal((await h.risk.getSnapshot()).totals.observedRequests, 5);
});

test("verified challenge evidence is attached privately and counted once by real request completion hooks", async t => {
  const h = harness();
  t.after(() => h.risk.close());
  const collector = createTrafficMetrics({ onRequest: (observation, req) => h.risk.observe(req, observation) });
  const req = Object.assign(new EventEmitter(), {
    method: "GET", path: "/landing", query: { challengePassed: "true", challengeFailed: "true" },
    headers: {}, markers: {}, challengePassed: true
  });
  const res = Object.assign(new EventEmitter(), { statusCode: 200 });
  let nextCalls = 0;
  collector.middleware(req, res, () => { nextCalls++; });
  const keysBeforeEvidence = Object.keys(req);
  h.risk.recordChallengeOutcome("passed", req); h.risk.recordChallengeOutcome("passed", req);
  h.risk.recordChallengeOutcome("failed", req); h.risk.recordChallengeOutcome("failed", req);
  h.risk.recordChallengeOutcome("expired", req);
  assert.deepEqual(Object.keys(req), keysBeforeEvidence, "verified evidence must not become request properties");
  assert.equal((await h.risk.getSnapshot()).totals.observedRequests, 0, "an unfinished request is not observed yet");
  res.emit("finish"); res.emit("close"); req.emit("aborted");
  const snapshot = await h.risk.getSnapshot();
  assert.equal(nextCalls, 1);
  assert.equal(snapshot.totals.observedRequests, 1);
  assert.equal(snapshot.totals.challengePassed, 1);
  assert.equal(snapshot.totals.challengeFailed, 1);
  assert.equal(h.requests[0].challengePassed, true);
  assert.equal(h.requests[0].challengeFailed, true);
  h.risk.observe(req, { kind: "get" });
  assert.equal(h.requests[1].challengePassed, false, "completion consumes the private evidence");
  assert.equal(h.requests[1].challengeFailed, false);
  assert.equal((await h.risk.getSnapshot()).totals.challengePassed, 1);
});

test("campaign attribution accepts only exact allowlisted string IDs and snapshots contain no request data or source hashes", async t => {
  const h = harness();
  t.after(() => h.risk.close());
  const marker = "private-request-token-marker";
  const base = { url: `/SensitivePath?token=${marker}`, headers: { authorization: `Bearer ${marker}` }, body: { email: "private@example.test" } };
  for (const campaign_id of ["alpha", "beta", "Alpha", "unknown-campaign", ["alpha"], { alpha: true }, undefined]) {
    h.risk.observe({ ...base, query: { campaign_id, token: marker } }, { kind: "get" });
  }
  assert.deepEqual(h.requests.map(row => row.campaignId), ["alpha", "beta", null, null, null, null, null]);
  const serialized = JSON.stringify(await h.risk.getSnapshot());
  for (const forbidden of [marker, "SensitivePath", "private@example.test", "8.8.8.8", "9.9.9.9", "1.1.1.1", HASH_SECRET, h.requests[0].sourceHash]) {
    assert.equal(serialized.includes(forbidden), false, "aggregate snapshots must not expose identifying request data");
  }
  assert.deepEqual(Object.keys(h.requests[0]).sort(), ["campaignId", "sourceHash", "headless", "hosting", "proxy", "vpn", "residentialProxy", "challengePassed", "challengeFailed"].sort());
});

test("invalid namespace avoids Redis creation and configuration limits fall back without exposing values", async t => {
  let redisCalls = 0;
  const risk = createTrafficRiskAssessment({
    env: {
      RISK_NAMESPACE: "https://private-config.example/key", RISK_CAMPAIGN_IDS: "alpha,beta,alpha", RISK_CONVERSION_TOKEN: TOKEN,
      RISK_IP_DAILY_BUDGET: "1001", RISK_IP_CACHE_MAX_ENTRIES: "10001", RISK_IP_QUEUE_MAX: "0",
      RISK_IP_TIMEOUT_MS: "99", RISK_IP_CACHE_TTL_MS: "1", RISK_IP_NEGATIVE_TTL_MS: "3600001",
      RISK_WINDOW_SECONDS: "3601", RISK_BURST_MIN_REQUESTS: "9", RISK_BURST_MIN_SOURCES: "1"
    },
    hashSecret: HASH_SECRET,
    createRedisClient() { redisCalls++; assert.fail("An invalid namespace cannot access Redis"); },
    fetch() { assert.fail("Disabled intelligence cannot call a provider"); }
  });
  t.after(() => risk.close());
  const snapshot = await risk.getSnapshot();
  assert.equal(redisCalls, 0);
  assert.equal(risk.conversionEnabled, false, "invalid namespaces cannot silently accept conversions using local dedupe");
  assert.equal(risk.conversionAuthorized(`Bearer ${TOKEN}`), false);
  assert.deepEqual(await risk.recordConversion({ campaignId: "alpha", eventId: "order-1" }), { accepted: false, reason: "unavailable" });
  assert.equal(snapshot.intelligence.enabled, false, "external lookup is opt-in");
  assert.deepEqual(snapshot.intelligence.cache.limits, { maxEntries: 2048, ttlMs: 3600000, negativeTtlMs: 60000, maxQueue: 64, concurrency: 2, timeoutMs: 800 });
  assert.equal(snapshot.intelligence.providerStatus.dailyBudget, 900);
  assert.equal(snapshot.campaignWindow.windowSeconds, 300);
  assert.deepEqual(snapshot.campaignWindow.campaigns.map(row => row.id), ["alpha", "beta", "__unattributed__"]);
  assert.ok(snapshot.configErrors.includes("RISK_NAMESPACE"));
  for (const name of ["RISK_IP_DAILY_BUDGET", "RISK_IP_CACHE_MAX_ENTRIES", "RISK_IP_QUEUE_MAX", "RISK_IP_TIMEOUT_MS", "RISK_IP_CACHE_TTL_MS", "RISK_IP_NEGATIVE_TTL_MS", "RISK_WINDOW_SECONDS", "RISK_BURST_MIN_REQUESTS", "RISK_BURST_MIN_SOURCES"]) {
    assert.ok(snapshot.configErrors.includes(name), `${name} must report invalid configuration`);
  }
  assert.doesNotMatch(JSON.stringify(snapshot), /private-config\.example|https:/);
});

test("a Redis client construction failure keeps conversions unavailable instead of accepting local writes", async t => {
  let factoryCalls = 0;
  const risk = createTrafficRiskAssessment({
    env: { RISK_CAMPAIGN_IDS: "alpha", RISK_CONVERSION_TOKEN: TOKEN },
    hashSecret: HASH_SECRET,
    getRequestIdentity: () => ({ keyIp: "8.8.8.8" }),
    createRedisClient() {
      factoryCalls += 1;
      throw new Error("private-redis://credentials@storage.example/0");
    },
    fetch() { assert.fail("Disabled intelligence cannot make an external request"); }
  });
  t.after(() => risk.close());
  assert.equal(factoryCalls, 1);
  assert.equal(risk.conversionEnabled, true, "configured backend credentials preserve the unavailable-storage response");
  assert.equal(risk.conversionAuthorized(`Bearer ${TOKEN}`), true);
  risk.observe({ query: { campaign_id: "alpha" } }, { kind: "get" });
  assert.deepEqual(await risk.recordConversion({ campaignId: "alpha", eventId: "order-1" }), { accepted: false, reason: "unavailable" });
  const snapshot = await risk.getSnapshot();
  assert.deepEqual(snapshot.configErrors, ["risk_storage_unavailable"]);
  assert.equal(snapshot.campaignWindow.scope, "unavailable");
  assert.equal(snapshot.campaignWindow.storage.configured, true);
  assert.equal(snapshot.campaignWindow.storage.ready, false);
  assert.equal(snapshot.campaignWindow.storage.fallbackScope, "current_process");
  const localRow = snapshot.campaignWindow.campaigns.find(row => row.id === "alpha");
  assert.equal(localRow.requests, 1, "local request observations remain available as an explicit fallback");
  assert.equal(localRow.conversions, 0, "the rejected conversion cannot increment local totals");
  assert.doesNotMatch(JSON.stringify(snapshot), /private-redis|credentials|storage\.example/);
});

test("invalid or over-cap campaign allowlists disable conversions rather than creating arbitrary buckets", async () => {
  for (const ids of ["alpha,unsafe/id", "__unattributed__", Array.from({ length: 33 }, (_, index) => `campaign_${index}`).join(",")]) {
    const h = harness({ env: { RISK_CAMPAIGN_IDS: ids } });
    h.risk.observe({ query: { campaign_id: "alpha" } }, { kind: "get" });
    const snapshot = await h.risk.getSnapshot();
    assert.ok(snapshot.configErrors.includes("RISK_CAMPAIGN_IDS"));
    assert.equal(h.requests[0].campaignId, null);
    assert.equal(h.risk.conversionEnabled, false);
    assert.deepEqual(await h.risk.recordConversion({ campaignId: "alpha", eventId: "event-1" }), { accepted: false, reason: "unavailable" });
    await h.risk.close();
  }
});

test("conversion authorization requires its dedicated 32–256 printable-character token", async () => {
  for (const length of [31, 32, 256, 257]) {
    const token = "x".repeat(length);
    const h = harness({ env: { RISK_CONVERSION_TOKEN: token } });
    assert.equal(h.risk.conversionEnabled, length >= 32 && length <= 256);
    assert.equal(h.risk.conversionAuthorized(`Bearer ${token}`), length >= 32 && length <= 256);
    await h.risk.close();
  }
  for (const token of ["", `${TOKEN} `, `${TOKEN}\n`, `${TOKEN}é`]) {
    const h = harness({ env: { RISK_CONVERSION_TOKEN: token } });
    assert.equal(h.risk.conversionEnabled, false);
    await h.risk.close();
  }
  const h = harness();
  assert.equal(h.risk.conversionAuthorized(`Bearer ${TOKEN}`), true);
  for (const authorization of [null, "", `Bearer ${HASH_SECRET}`, `bearer ${TOKEN}`, ` Bearer ${TOKEN}`, `Bearer  ${TOKEN}`, `Bearer ${TOKEN} `, `Bearer ${TOKEN}\n`]) {
    assert.equal(h.risk.conversionAuthorized(authorization), false);
  }
  await h.risk.close();
});

test("conversion events use a strict schema and delegate hashed IDs unchanged for idempotent storage", async t => {
  const h = harness();
  t.after(() => h.risk.close());
  for (const body of [null, [], {}, { campaignId: "unknown", eventId: "one" }, { campaignId: "alpha", eventId: 1 },
    { campaignId: "alpha", eventId: "" }, { campaignId: "alpha", eventId: "x".repeat(129) }, { campaignId: "alpha", eventId: "has spaces" },
    { campaignId: "alpha", eventId: "line\nbreak" }, { campaignId: "alpha", eventId: "one", ip: "8.8.8.8" }]) {
    assert.deepEqual(await h.risk.recordConversion(body), { accepted: false, reason: "invalid_event" });
  }
  assert.equal(h.conversions.length, 0);
  const event = { campaignId: "alpha", eventId: "purchase:MiXeD_123.1" };
  const first = await h.risk.recordConversion(event);
  const repeated = await h.risk.recordConversion(event);
  assert.equal(first.duplicate, false);
  assert.equal(repeated.duplicate, true);
  const expectedHash = createHmac("sha256", HASH_SECRET).update("oldserver222:conversion:").update(event.eventId).digest("hex");
  assert.deepEqual(h.conversions, [{ campaignId: "alpha", eventIdHash: expectedHash }, { campaignId: "alpha", eventIdHash: expectedHash }]);
  assert.equal((await h.risk.recordConversion({ ...event, campaignId: "beta" })).duplicate, false);
  assert.equal((await h.risk.recordConversion({ campaignId: "alpha", eventId: "x".repeat(128) })).accepted, true);
  const snapshot = JSON.stringify(await h.risk.getSnapshot());
  assert.equal(snapshot.includes(event.eventId), false);
  assert.equal(snapshot.includes(expectedHash), false);
  assert.equal(snapshot.includes(TOKEN), false);
});

test("observer and storage failures stay report-only and expose no raw exception messages", async t => {
  const h = harness({ cacheObserve() { throw new Error("private IP and provider URL"); },
    recordConversion() { throw new Error("private conversion event details"); },
    getStoreSnapshot() { throw new Error("private Redis connection string"); } });
  t.after(() => h.risk.close());
  assert.doesNotThrow(() => h.risk.observe({}, { kind: "get" }));
  const snapshot = await h.risk.getSnapshot();
  assert.equal(snapshot.observerErrors, 1);
  assert.equal(snapshot.campaignWindow.scope, "unavailable");
  assert.equal(snapshot.campaignWindow.storage.lastError, "unavailable");
  assert.doesNotMatch(JSON.stringify(snapshot), /private|connection string|event details|provider URL/);
  assert.deepEqual(await h.risk.recordConversion({ campaignId: "alpha", eventId: "one" }), { accepted: false, reason: "unavailable" });
});

test("unusual activity requires request volume, distinct sources and browser evidence, and refuses saturated estimates", async t => {
  const h = harness();
  t.after(() => h.risk.close());
  h.setRows([
    { id: "many-signals", requests: 200, distinctSourcesEstimate: 20, headless: 100, distinctSourcesSaturated: false },
    { id: "low-volume", requests: 199, distinctSourcesEstimate: 100, headless: 199, distinctSourcesSaturated: false },
    { id: "one-source", requests: 200, distinctSourcesEstimate: 19, headless: 200, distinctSourcesSaturated: false },
    { id: "few-markers", requests: 200, distinctSourcesEstimate: 20, headless: 99, distinctSourcesSaturated: false },
    { id: "saturated", requests: 10000, distinctSourcesEstimate: 10000, headless: 10000, distinctSourcesSaturated: true },
    { id: "network-only", requests: 200, distinctSourcesEstimate: 20, headless: 0, hosting: 200, proxy: 200, challengeFailed: 200, distinctSourcesSaturated: false }
  ]);
  assert.deepEqual((await h.risk.getSnapshot()).campaignWindow.campaigns.map(row => row.unusualActivity), [true, false, false, false, false, false]);
  const configured = harness({ env: { RISK_BURST_MIN_REQUESTS: "10", RISK_BURST_MIN_SOURCES: "2" } });
  t.after(() => configured.risk.close());
  configured.setRows([{ id: "alpha", requests: 10, distinctSourcesEstimate: 2, headless: 5, distinctSourcesSaturated: false }]);
  assert.equal((await configured.risk.getSnapshot()).campaignWindow.campaigns[0].unusualActivity, true);
});
