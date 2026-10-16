"use strict";

const createCheckpointStore = require("./analyticsCheckpointStore.js");

const KINDS = ["operational", "head", "prefetch", "get", "other"];
const STATUSES = ["1xx", "2xx", "3xx", "4xx", "5xx", "other"];
const EVENTS = ["shown", "passed", "failed", "expired", "expiredOrDuplicate", "providerError", "redirected", "payloadExpired"];
const RISK_FIELDS = ["observedRequests", "headlessMarkers", "headerAnomalies", "networkKnown", "networkUnknown", "hostingIndicators", "proxyIndicators", "vpnIndicators", "residentialProxyIndicators", "challengePassed", "challengeFailed"];
const MAX = Number.MAX_SAFE_INTEGER;
const validNumber = value => typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= MAX;
const validCount = value => validNumber(value) && Number.isInteger(value);
const exactKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const clone = value => JSON.parse(JSON.stringify(value));

function createDiskAnalytics({ directory = "", namespace = "oldserver222", checkpoint: suppliedCheckpoint,
  flushIntervalMs = 5000, now = Date.now } = {}) {
  const configured = Boolean(directory || suppliedCheckpoint);
  let checkpoint = null;
  if (configured) {
    try { checkpoint = suppliedCheckpoint || createCheckpointStore({ directory, namespace }); }
    catch (_) {
      checkpoint = { ready: Promise.resolve(false), getData: () => null, flush: async () => false, close: async () => false,
        getStatus: () => ({ ready: false, pending: 0, lastSaveAt: null, lastError: "analytics_invalid_configuration" }) };
    }
  }
  const emptyGroup = () => ({ requests: 0, completed: 0, aborted: 0,
    byStatusClass: Object.fromEntries(STATUSES.map(status => [status, 0])), durationSumMs: 0, durationMaxMs: 0 });
  let http = { startedAt: new Date(now()).toISOString(), total: emptyGroup(),
    byKind: Object.fromEntries(KINDS.map(kind => [kind, emptyGroup()])), challenges: Object.fromEntries(EVENTS.map(event => [event, 0])) };
  let risk = { startedAt: http.startedAt, totals: Object.fromEntries(RISK_FIELDS.map(field => [field, 0])) };
  let hooks = { exportState: () => null, restoreState: state => state === null };
  let initialized = false;
  let initialization = null;
  let validationError = null;
  let closing = false;
  let dirty = false;
  let revision = 0;
  let lastSavedRevision = -1;
  let savedSummary = null;
  let interval = null;
  let closePromise = null;

  function available() { return configured && initialized && !closing && !validationError && checkpoint.getStatus().ready; }
  function canWrite() {
    if (!configured || !initialized || closing || validationError) return false;
    const status = checkpoint.getStatus();
    // Recoverable write errors make conversions unhealthy while the locked
    // worker remains able to retry. Older injected stores expose only ready.
    return status.canWrite === undefined ? status.ready === true : status.canWrite === true;
  }
  function markDirty() { if (configured && initialized && !closing) { dirty = true; revision += 1; } }
  function count(object, key, amount = 1) { object[key] = Math.min(MAX, object[key] + amount); }
  function iso(value) { return typeof value === "string" && value.length <= 30 && Number.isFinite(Date.parse(value)); }
  function validGroup(group) {
    return exactKeys(group, ["requests", "completed", "aborted", "byStatusClass", "durationSumMs", "durationMaxMs"]) &&
      ["requests", "completed", "aborted"].every(field => validCount(group[field])) &&
      group.requests === group.completed + group.aborted && exactKeys(group.byStatusClass, STATUSES) &&
      STATUSES.every(status => validCount(group.byStatusClass[status])) &&
      STATUSES.reduce((sum, status) => sum + group.byStatusClass[status], 0) === group.completed &&
      validNumber(group.durationSumMs) && validNumber(group.durationMaxMs) && group.durationMaxMs <= group.durationSumMs &&
      (group.completed > 0 || (group.durationSumMs === 0 && group.durationMaxMs === 0));
  }
  function validData(data) {
    if (!exactKeys(data, ["version", "http", "risk", "campaigns"]) || data.version !== 1 ||
      !exactKeys(data.http, ["startedAt", "total", "byKind", "challenges"]) || !iso(data.http.startedAt) || !validGroup(data.http.total) ||
      !exactKeys(data.http.byKind, KINDS) || !KINDS.every(kind => validGroup(data.http.byKind[kind])) ||
      !exactKeys(data.http.challenges, EVENTS) || !EVENTS.every(event => validCount(data.http.challenges[event])) ||
      !exactKeys(data.risk, ["startedAt", "totals"]) || !iso(data.risk.startedAt) || !exactKeys(data.risk.totals, RISK_FIELDS) ||
      !RISK_FIELDS.every(field => validCount(data.risk.totals[field]))) return false;
    return ["requests", "completed", "aborted"].every(field =>
      KINDS.reduce((sum, kind) => sum + data.http.byKind[kind][field], 0) === data.http.total[field]) &&
      STATUSES.every(status => KINDS.reduce((sum, kind) => sum + data.http.byKind[kind].byStatusClass[status], 0) === data.http.total.byStatusClass[status]) &&
      data.risk.totals.networkKnown + data.risk.totals.networkUnknown === data.risk.totals.observedRequests &&
      RISK_FIELDS.slice(1).every(field => data.risk.totals[field] <= data.risk.totals.observedRequests);
  }
  function summarizeGroup(group) {
    return { requests: group.requests, completed: group.completed, aborted: group.aborted, byStatusClass: { ...group.byStatusClass },
      latencyMs: { mean: group.completed ? group.durationSumMs / group.completed : null, max: group.completed ? group.durationMaxMs : null } };
  }
  function summarize(data) {
    return { scope: "disk", namespace, startedAt: data.http.startedAt, total: summarizeGroup(data.http.total),
      byKind: Object.fromEntries(KINDS.map(kind => [kind, summarizeGroup(data.http.byKind[kind])])), challenges: { ...data.http.challenges },
      risk: { scope: "disk", startedAt: data.risk.startedAt, totals: { ...data.risk.totals } } };
  }
  function initialize(stateHooks) {
    if (initialization) return initialization;
    if (stateHooks) hooks = stateHooks;
    initialization = (async () => {
      if (!configured) return false;
      if (!await checkpoint.ready) return false;
      const data = checkpoint.getData();
      if (data !== null) {
        if (!validData(data) || !hooks.restoreState(data.campaigns)) { validationError = "analytics_invalid_state"; return false; }
        http = clone(data.http);
        risk = clone(data.risk);
        savedSummary = summarize(data);
      }
      initialized = true;
      // Fixed aggregate snapshots are created outside request callbacks. Each
      // urgent save waits for durable acknowledgement; the writer coalesces work.
      interval = setInterval(() => { if (dirty) void flush(); }, Math.min(60000, Math.max(100, Number(flushIntervalMs) || 5000)));
      interval.unref?.();
      if (data === null) { markDirty(); return flush(); }
      return true;
    })().catch(() => { validationError = "analytics_initialization_failed"; return false; });
    return initialization;
  }
  function recordRequest({ kind, completed, statusClass, durationMs } = {}) {
    if (!configured || !initialized || closing || !KINDS.includes(kind) || typeof completed !== "boolean") return false;
    if (http.total.requests >= MAX || http.byKind[kind].requests >= MAX) return false;
    const status = STATUSES.includes(statusClass) ? statusClass : "other";
    const duration = validNumber(durationMs) ? durationMs : 0;
    for (const group of [http.total, http.byKind[kind]]) {
      count(group, "requests"); count(group, completed ? "completed" : "aborted");
      if (completed) {
        count(group.byStatusClass, status);
        count(group, "durationSumMs", duration);
        group.durationMaxMs = Math.max(group.durationMaxMs, duration);
      }
    }
    markDirty();
    return true;
  }
  function recordChallengeEvent(event) {
    if (!configured || !initialized || closing || !EVENTS.includes(event)) return false;
    count(http.challenges, event); markDirty(); return true;
  }
  function recordRisk(observation = {}) {
    if (!configured || !initialized || closing) return false;
    count(risk.totals, "observedRequests");
    count(risk.totals, observation.networkKnown === true ? "networkKnown" : "networkUnknown");
    for (const field of RISK_FIELDS.slice(1)) if (!["networkKnown", "networkUnknown"].includes(field) && observation[field] === true) count(risk.totals, field);
    markDirty(); return true;
  }
  async function flush() {
    if (!canWrite()) return false;
    if (!dirty) return checkpoint.flush();
    const capturedRevision = revision;
    let data;
    try { data = { version: 1, http: clone(http), risk: clone(risk), campaigns: hooks.exportState() }; }
    catch (_) { validationError = "analytics_export_failed"; return false; }
    const ok = await checkpoint.save(data, { urgent: true });
    if (ok) {
      if (capturedRevision >= lastSavedRevision) { savedSummary = summarize(data); lastSavedRevision = capturedRevision; }
      if (revision === capturedRevision) dirty = false;
    }
    return ok;
  }
  function getSnapshot() { return savedSummary ? clone(savedSummary) : null; }
  function getStatus() {
    if (!configured) return { backend: "disk", configured: false, ready: false, namespace, pending: 0, lastSaveAt: null, lastError: null };
    const status = checkpoint.getStatus();
    return { ...status, backend: "disk", configured: true, ready: available(),
      pending: Math.max(status.pending || 0, Number(dirty)), lastError: validationError || status.lastError || null };
  }
  function close() {
    if (closePromise) return closePromise;
    closePromise = (async () => {
      if (interval) clearInterval(interval);
      if (initialization) await initialization;
      const flushed = await flush();
      closing = true;
      if (checkpoint) await checkpoint.close();
      return flushed;
    })();
    return closePromise;
  }
  return { initialize, recordRequest, recordChallengeEvent, recordRisk, markDirty, flush, getSnapshot, getStatus, close, isReady: available, configured };
}

module.exports = createDiskAnalytics;
