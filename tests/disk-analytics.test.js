"use strict";

const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const createCheckpointStore = require("../modules/runtime-utils/analyticsCheckpointStore.js");
const createDiskAnalytics = require("../modules/runtime-utils/diskAnalytics.js");
const createTrafficMetrics = require("../modules/runtime-utils/trafficMetrics.js");

const clone = value => structuredClone(value);
const startedAt = 1700000000000;

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

class FakeCheckpoint {
  constructor({ data = null, ready = true, error = null, canWrite } = {}) {
    this.data = clone(data);
    this.ready = Promise.resolve(ready);
    this.statusReady = ready;
    this.canWrite = canWrite;
    this.lastError = error;
    this.lastSaveAt = null;
    this.savedSequence = 0;
    this.saves = [];
    this.reads = 0;
    this.flushes = 0;
    this.closes = 0;
    this.saveBehavior = null;
  }

  getData() { this.reads += 1; return clone(this.data); }
  getStatus() {
    return { configured: true, backend: "disk", namespace: "test", ready: this.statusReady,
      ...(this.canWrite === undefined ? {} : { canWrite: this.canWrite }),
      pending: 0, lastSaveAt: this.lastSaveAt, lastError: this.lastError };
  }
  async save(data, options) {
    const saved = clone(data);
    this.saves.push({ data: saved, options: { ...options } });
    const sequence = this.saves.length;
    const ok = this.saveBehavior ? await this.saveBehavior(saved, sequence) : true;
    if (ok) {
      if (sequence >= this.savedSequence) {
        this.data = saved;
        this.savedSequence = sequence;
        this.lastSaveAt = new Date(startedAt + sequence).toISOString();
      }
      this.lastError = null;
    } else this.lastError = "write_failed";
    return ok;
  }
  async flush() { this.flushes += 1; return this.statusReady; }
  async close() { this.closes += 1; return true; }
}

function harness(t, options = {}) {
  const checkpoint = options.checkpoint || new FakeCheckpoint();
  const analytics = createDiskAnalytics({ checkpoint, namespace: "test", flushIntervalMs: 60000,
    now: () => startedAt, ...options });
  t.after(() => analytics.close());
  return { checkpoint, analytics };
}

async function savedFixture(t) {
  const { checkpoint, analytics } = harness(t);
  assert.equal(await analytics.initialize(), true);
  analytics.recordRequest({ kind: "get", completed: true, statusClass: "2xx", durationMs: 12 });
  analytics.recordChallengeEvent("shown");
  analytics.recordRisk({ networkUnknown: true });
  assert.equal(await analytics.flush(), true);
  return clone(checkpoint.data);
}

test("disk metrics expose only durable settled HTTP, challenge, and risk observations", async t => {
  const { checkpoint, analytics } = harness(t);
  assert.equal(await analytics.initialize(), true);
  const initial = analytics.getSnapshot();
  assert.equal(initial.total.requests, 0);
  assert.equal(checkpoint.saves.length, 1, "startup establishes a writable durable empty checkpoint");
  let time = 0;
  const local = createTrafficMetrics({ now: () => time, onRequest: analytics.recordRequest,
    onChallengeEvent: analytics.recordChallengeEvent });
  const req = Object.assign(new EventEmitter(), { method: "GET", path: "/landing", headers: {} });
  const res = Object.assign(new EventEmitter(), { statusCode: 302 });
  local.middleware(req, res, () => {});
  assert.equal(local.getSnapshot().total.inFlight, 1);
  assert.deepEqual(analytics.getSnapshot(), initial);
  assert.equal(checkpoint.saves.length, 1);
  time = 20;
  res.emit("finish");
  res.emit("close");
  assert.equal(analytics.recordRequest({ kind: "head", completed: false, statusClass: "2xx", durationMs: 999 }), true);
  local.recordChallengeEvent("passed");
  local.recordChallengeEvent("redirected");
  analytics.recordRisk({ headlessMarkers: true, networkKnown: true, hostingIndicators: true,
    proxyIndicators: true, vpnIndicators: true, residentialProxyIndicators: true, challengePassed: true });
  analytics.recordRisk({ headerAnomalies: true, networkUnknown: true, challengeFailed: true });
  assert.equal(checkpoint.saves.length, 1, "visitor callbacks do not start checkpoint writes");
  assert.deepEqual(analytics.getSnapshot(), initial, "unacknowledged observations are not presented as durable");
  assert.equal(await analytics.flush(), true);
  assert.deepEqual(checkpoint.saves[0].options, { urgent: true });
  const snapshot = analytics.getSnapshot();
  assert.equal(snapshot.scope, "disk");
  assert.equal(snapshot.namespace, "test");
  assert.equal(snapshot.startedAt, new Date(startedAt).toISOString());
  assert.equal(snapshot.total.requests, 2);
  assert.equal(snapshot.total.completed, 1);
  assert.equal(snapshot.total.aborted, 1);
  assert.equal(snapshot.total.byStatusClass["3xx"], 1);
  assert.equal(snapshot.total.byStatusClass["2xx"], 0);
  assert.deepEqual(snapshot.total.latencyMs, { mean: 20, max: 20 });
  assert.deepEqual(snapshot.byKind.head.latencyMs, { mean: null, max: null });
  assert.equal(Object.hasOwn(snapshot.total, "inFlight"), false);
  assert.equal(Object.hasOwn(snapshot.total.latencyMs, "recent"), false);
  assert.equal(snapshot.challenges.passed, 1);
  assert.equal(snapshot.challenges.redirected, 1);
  assert.equal(snapshot.risk.scope, "disk");
  assert.deepEqual(snapshot.risk.totals, { observedRequests: 2, headlessMarkers: 1, headerAnomalies: 1,
    networkKnown: 1, networkUnknown: 1, hostingIndicators: 1, proxyIndicators: 1, vpnIndicators: 1,
    residentialProxyIndicators: 1, challengePassed: 1, challengeFailed: 1 });
  assert.equal(local.getSnapshot().scope, "current_process");
  assert.equal(local.getSnapshot().total.requests, 1);
  analytics.recordChallengeEvent("shown");
  assert.equal(analytics.getSnapshot().challenges.shown, 0, "the public disk snapshot remains the last durable version");
  assert.equal(analytics.getStatus().pending, 1);
});

test("restarting restores durable aggregates and delegates campaign restoration to caller hooks", async t => {
  let campaignState = { version: 7, counters: { welcome: 4 } };
  let exports = 0;
  const first = harness(t);
  await first.analytics.initialize({
    exportState() { exports += 1; return clone(campaignState); },
    restoreState() { assert.fail("a new checkpoint has no campaign state to restore"); }
  });
  first.analytics.recordRequest({ kind: "get", completed: true, statusClass: "2xx", durationMs: 10 });
  first.analytics.recordChallengeEvent("expiredOrDuplicate");
  first.analytics.recordRisk({ networkUnknown: true });
  assert.equal(exports, 1, "only initialization has exported a checkpoint");
  await first.analytics.flush();
  const durable = first.analytics.getSnapshot();
  assert.equal(exports, 2);
  assert.deepEqual(first.checkpoint.data.campaigns, campaignState);
  await first.analytics.close();

  const restarted = harness(t, { checkpoint: new FakeCheckpoint({ data: first.checkpoint.data }), now: () => startedAt + 60000 });
  let restored;
  const initialization = restarted.analytics.initialize({
    exportState: () => clone(campaignState),
    restoreState(state) { restored = clone(state); return state.version === 7; }
  });
  assert.equal(restarted.analytics.initialize(), initialization, "initialization is idempotent");
  assert.equal(await initialization, true);
  assert.deepEqual(restored, campaignState);
  assert.deepEqual(restarted.analytics.getSnapshot(), durable);
  const current = createTrafficMetrics();
  assert.equal(current.getSnapshot().total.requests, 0, "restoration does not populate process-local counters");
  campaignState.counters.welcome = 5;
  restarted.analytics.markDirty();
  restarted.analytics.recordRequest({ kind: "get", completed: true, statusClass: "3xx", durationMs: 30 });
  assert.equal(restarted.checkpoint.saves.length, 0);
  await restarted.analytics.flush();
  assert.equal(restarted.analytics.getSnapshot().total.requests, 2);
  assert.deepEqual(restarted.analytics.getSnapshot().total.latencyMs, { mean: 20, max: 30 });
  assert.equal(restarted.analytics.getSnapshot().challenges.expiredOrDuplicate, 1);
  assert.equal(restarted.checkpoint.data.campaigns.counters.welcome, 5);
});

test("invalid aggregate schemas fail closed and cannot overwrite the original checkpoint", async t => {
  const fixture = await savedFixture(t);
  const mutations = [
    data => { data.version = 2; },
    data => { data.unexpected = true; },
    data => { delete data.http.byKind.head; },
    data => { data.http.total.requests = 2; },
    data => { data.http.byKind.get.completed = 0.5; },
    data => { data.http.total.byStatusClass["2xx"] = 0; },
    data => { data.http.total.byStatusClass["2xx"] = 0; data.http.total.byStatusClass["3xx"] = 1; },
    data => { data.http.total.durationSumMs = Infinity; },
    data => { data.http.byKind.get.durationMaxMs = 13; },
    data => { data.http.startedAt = "not-a-date"; },
    data => { data.risk.totals.networkKnown = -1; },
    data => { data.risk.totals.userIp = "192.0.2.10"; },
    data => { data.risk.totals.networkUnknown = 0; },
    data => { data.risk.totals.networkKnown = 1; },
    ...Object.keys(fixture.risk.totals).filter(field => field !== "observedRequests")
      .map(field => data => { data.risk.totals[field] = 2; })
  ];
  for (const mutate of mutations) {
    const original = clone(fixture);
    mutate(original);
    const { checkpoint, analytics } = harness(t, { checkpoint: new FakeCheckpoint({ data: original }) });
    assert.equal(await analytics.initialize(), false);
    assert.equal(analytics.isReady(), false);
    assert.equal(analytics.getStatus().lastError, "analytics_invalid_state");
    assert.equal(analytics.getSnapshot(), null);
    assert.equal(analytics.recordRequest({ kind: "get", completed: true }), false);
    assert.equal(analytics.recordChallengeEvent("shown"), false);
    assert.equal(analytics.recordRisk({ headlessMarkers: true }), false);
    analytics.markDirty();
    assert.equal(await analytics.flush(), false);
    assert.equal(checkpoint.saves.length, 0);
    assert.deepEqual(checkpoint.data, original);
  }
});

test("campaign restoration rejection and hook failures preserve disk data with safe errors", async t => {
  const fixture = await savedFixture(t);
  fixture.campaigns = { incompatible: true };
  for (const restoreState of [() => false, () => { throw new Error("private disk path /private/token-secret"); }]) {
    const { checkpoint, analytics } = harness(t, { checkpoint: new FakeCheckpoint({ data: fixture }) });
    assert.equal(await analytics.initialize({ restoreState, exportState: () => null }), false);
    assert.equal(analytics.getStatus().ready, false);
    assert.match(analytics.getStatus().lastError, /^analytics_(invalid_state|initialization_failed)$/);
    assert.doesNotMatch(JSON.stringify(analytics.getStatus()), /private|token-secret/);
    assert.equal(await analytics.flush(), false);
    assert.equal(checkpoint.saves.length, 0);
    assert.deepEqual(checkpoint.data, fixture);
  }
  const { checkpoint, analytics } = harness(t);
  await analytics.initialize({ restoreState: () => true, exportState() { throw new Error("/private/secret"); } });
  analytics.recordChallengeEvent("shown");
  assert.equal(await analytics.flush(), false);
  assert.equal(analytics.getStatus().lastError, "analytics_export_failed");
  assert.equal(analytics.getStatus().ready, false);
  assert.equal(checkpoint.saves.length, 0);
});

test("every risk observation contributes exactly one known or unknown network outcome", async t => {
  const { analytics } = harness(t);
  await analytics.initialize();
  assert.equal(analytics.recordRisk(), true);
  await analytics.flush();
  let totals = analytics.getSnapshot().risk.totals;
  assert.equal(totals.observedRequests, 1);
  assert.equal(totals.networkKnown, 0);
  assert.equal(totals.networkUnknown, 1, "an omitted network result is unknown");
  analytics.recordRisk({ networkKnown: true, networkUnknown: true });
  analytics.recordRisk({ networkKnown: "true", networkUnknown: false });
  await analytics.flush();
  totals = analytics.getSnapshot().risk.totals;
  assert.equal(totals.observedRequests, 3);
  assert.equal(totals.networkKnown, 1);
  assert.equal(totals.networkUnknown, 2);
  assert.equal(totals.networkKnown + totals.networkUnknown, totals.observedRequests);
});

test("checkpoint readiness and envelope rejection prevent reads and writes before validation", async t => {
  const gate = deferred();
  const checkpoint = new FakeCheckpoint({ ready: false, error: "invalid_checkpoint" });
  checkpoint.ready = gate.promise;
  const { analytics } = harness(t, { checkpoint });
  const initialization = analytics.initialize();
  assert.equal(analytics.recordChallengeEvent("shown"), false);
  assert.equal(analytics.recordRequest({ kind: "get", completed: true }), false);
  assert.equal(await analytics.flush(), false);
  assert.equal(checkpoint.reads, 0);
  gate.resolve(false); // The checkpoint layer owns envelope and namespace validation.
  assert.equal(await initialization, false);
  assert.equal(analytics.getStatus().lastError, "invalid_checkpoint");
  assert.equal(analytics.getStatus().ready, false);
  assert.equal(analytics.getSnapshot(), null);
  assert.equal(checkpoint.reads, 0);
  assert.equal(checkpoint.saves.length, 0);
  assert.equal(checkpoint.flushes, 0);
});

test("failed saves retain the last durable snapshot and recover without losing observations", async t => {
  const { checkpoint, analytics } = harness(t);
  await analytics.initialize();
  analytics.recordChallengeEvent("shown");
  await analytics.flush();
  const before = analytics.getSnapshot();
  checkpoint.saveBehavior = () => false;
  analytics.recordChallengeEvent("passed");
  analytics.recordRisk({ networkKnown: true });
  assert.equal(await analytics.flush(), false);
  assert.deepEqual(analytics.getSnapshot(), before);
  assert.equal(analytics.getStatus().pending, 1);
  assert.equal(analytics.getStatus().lastError, "write_failed");
  checkpoint.statusReady = false;
  const saves = checkpoint.saves.length;
  assert.equal(await analytics.flush(), false);
  assert.equal(checkpoint.saves.length, saves, "unready storage cannot replace the durable state");
  checkpoint.statusReady = true;
  checkpoint.saveBehavior = () => true;
  assert.equal(await analytics.flush(), true);
  assert.equal(analytics.getSnapshot().challenges.shown, 1);
  assert.equal(analytics.getSnapshot().challenges.passed, 1);
  assert.equal(analytics.getSnapshot().risk.totals.networkKnown, 1);
  assert.equal(analytics.getStatus().pending, 0);
  assert.equal(analytics.getStatus().lastError, null);
});

test("an unhealthy checkpoint with retained write capability retries without declaring conversions ready", async t => {
  const { checkpoint, analytics } = harness(t, { checkpoint: new FakeCheckpoint({ canWrite: true }) });
  await analytics.initialize();
  const before = analytics.getSnapshot();
  analytics.recordChallengeEvent("shown");
  checkpoint.saveBehavior = () => false;
  assert.equal(await analytics.flush(), false);
  checkpoint.statusReady = false;
  assert.equal(analytics.isReady(), false);
  assert.equal(analytics.getStatus().lastError, "write_failed");
  assert.deepEqual(analytics.getSnapshot(), before);
  const gate = deferred();
  checkpoint.saveBehavior = async () => {
    await gate.promise;
    checkpoint.statusReady = true;
    return true;
  };
  const saves = checkpoint.saves.length;
  const retry = analytics.flush();
  assert.equal(checkpoint.saves.length, saves + 1, "manual flush retries despite unhealthy readiness");
  assert.equal(analytics.isReady(), false, "conversion readiness must await successful durable acknowledgment");
  gate.resolve();
  assert.equal(await retry, true);
  assert.equal(analytics.isReady(), true);
  assert.equal(analytics.getSnapshot().challenges.shown, 1);
  assert.equal(analytics.getStatus().lastError, null);

  analytics.recordChallengeEvent("passed");
  checkpoint.canWrite = false;
  const refusedAt = checkpoint.saves.length;
  assert.equal(await analytics.flush(), false, "an explicitly nonwritable checkpoint must not be retried");
  assert.equal(checkpoint.saves.length, refusedAt);
  checkpoint.canWrite = true;
  await analytics.close();
  assert.equal(await analytics.flush(), false, "closed adapters cannot write through an injected checkpoint");
});

test("manual adapter flush recovers a filesystem replacement failure before either interval runs", { timeout: 10000 }, async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "disk-analytics-retry-"));
  const checkpoint = createCheckpointStore({ directory, namespace: "test", flushIntervalMs: 60000 });
  const analytics = createDiskAnalytics({ checkpoint, namespace: "test", flushIntervalMs: 60000 });
  t.after(async () => {
    await analytics.close();
    await fs.rm(directory, { recursive: true, force: true });
  });
  assert.equal(await analytics.initialize(), true);
  const filename = path.join(directory, "test.json");
  const preserved = `${filename}.preserved`;
  const original = await fs.readFile(filename, "utf8");
  const durable = analytics.getSnapshot();
  await fs.rename(filename, preserved);
  await fs.mkdir(filename, { mode: 0o700 });
  analytics.recordChallengeEvent("shown");
  assert.equal(await analytics.flush(), false);
  assert.equal(checkpoint.getStatus().ready, false);
  assert.equal(checkpoint.getStatus().canWrite, true, "the worker still owns its lock after a recoverable write failure");
  assert.equal(analytics.isReady(), false);
  assert.equal(analytics.getStatus().lastError, "unsafe_file");
  assert.deepEqual(analytics.getSnapshot(), durable);
  assert.equal(await fs.readFile(preserved, "utf8"), original);
  await fs.rmdir(filename);
  await fs.rename(preserved, filename);
  assert.equal(await analytics.flush(), true, "an immediate manual retry requires no checkpoint timer");
  assert.equal(analytics.isReady(), true);
  assert.equal(checkpoint.getStatus().ready, true);
  assert.equal(analytics.getStatus().lastError, null);
  assert.equal(analytics.getSnapshot().challenges.shown, 1);
  assert.equal(JSON.parse(await fs.readFile(filename, "utf8")).data.http.challenges.shown, 1);
  assert.doesNotMatch(JSON.stringify(analytics.getStatus()), /disk-analytics-retry-|\.preserved|\/tmp/);
  await analytics.close();
  assert.equal(checkpoint.getStatus().canWrite, false);
});

test("observations arriving during an asynchronous save remain dirty until a later durable save", async t => {
  const { checkpoint, analytics } = harness(t);
  await analytics.initialize();
  analytics.recordRequest({ kind: "get", completed: true, statusClass: "2xx", durationMs: 10 });
  const initial = analytics.getSnapshot();
  const beforeSaves = checkpoint.saves.length;
  const gate = deferred();
  checkpoint.saveBehavior = (_data, index) => index === beforeSaves + 1 ? gate.promise : true;
  const first = analytics.flush();
  assert.equal(checkpoint.saves.length, beforeSaves + 1);
  analytics.recordRequest({ kind: "other", completed: false });
  analytics.recordChallengeEvent("failed");
  analytics.recordRisk({ challengeFailed: true });
  assert.equal(checkpoint.saves.length, beforeSaves + 1, "visitor observations do not await or start another write");
  assert.deepEqual(analytics.getSnapshot(), initial);
  gate.resolve(true);
  assert.equal(await first, true);
  assert.equal(analytics.getSnapshot().total.requests, 1);
  assert.equal(analytics.getSnapshot().challenges.failed, 0);
  assert.equal(analytics.getStatus().pending, 1);
  assert.equal(await analytics.flush(), true);
  assert.equal(checkpoint.saves.length, beforeSaves + 2);
  assert.equal(analytics.getSnapshot().total.requests, 2);
  assert.equal(analytics.getSnapshot().total.aborted, 1);
  assert.equal(analytics.getSnapshot().challenges.failed, 1);
  assert.equal(analytics.getSnapshot().risk.totals.challengeFailed, 1);
  assert.equal(analytics.getStatus().pending, 0);
});

test("late acknowledgments cannot move the durable summary backwards", async t => {
  const { checkpoint, analytics } = harness(t);
  await analytics.initialize();
  analytics.recordChallengeEvent("shown");
  const older = deferred();
  const beforeSaves = checkpoint.saves.length;
  checkpoint.saveBehavior = (_data, index) => index === beforeSaves + 1 ? older.promise : true;
  const first = analytics.flush();
  analytics.recordChallengeEvent("passed");
  assert.equal(await analytics.flush(), true);
  assert.equal(analytics.getSnapshot().challenges.passed, 1);
  older.resolve(true);
  assert.equal(await first, true);
  assert.equal(analytics.getSnapshot().challenges.passed, 1);
  assert.equal(analytics.getStatus().pending, 0);
});

test("nonfinite inputs and unknown labels cannot create nonfinite counters or retained visitor fields", async t => {
  const { checkpoint, analytics } = harness(t);
  await analytics.initialize({ restoreState: () => true, exportState: () => ({ sourceHash: "opaque-campaign-private-state" }) });
  for (const durationMs of [NaN, Infinity, -1, Number.MAX_VALUE]) {
    assert.equal(analytics.recordRequest({ kind: "get", completed: true, statusClass: "private-status", durationMs }), true);
  }
  assert.equal(analytics.recordRequest({ kind: "person@example.test", completed: true }), false);
  assert.equal(analytics.recordRequest({ kind: "get", completed: "yes" }), false);
  for (const event of ["__proto__", "constructor", "https://private.example/destination"]) {
    assert.equal(analytics.recordChallengeEvent(event), false);
  }
  await analytics.flush();
  const initial = analytics.getSnapshot();
  for (let index = 0; index < 1000; index += 1) {
    const privateFields = { url: `https://private.example/${index}`, ip: `192.0.2.${index}`,
      sourceHash: `private-source-${index}`, email: `person${index}@example.test` };
    analytics.recordRequest({ kind: "get", completed: true, statusClass: "2xx", durationMs: 1, ...privateFields });
    analytics.recordRisk({ networkUnknown: true, headerAnomalies: "true", proxyIndicators: 1, ...privateFields });
  }
  assert.equal(checkpoint.saves.length, 2);
  await analytics.flush();
  const snapshot = analytics.getSnapshot();
  assert.equal(snapshot.total.requests, 1004);
  assert.equal(snapshot.total.byStatusClass.other, 4);
  assert.equal(snapshot.total.latencyMs.mean, 1000 / 1004);
  assert.equal(snapshot.total.latencyMs.max, 1);
  assert.equal(snapshot.risk.totals.observedRequests, 1000);
  assert.equal(snapshot.risk.totals.networkUnknown, 1000);
  assert.equal(snapshot.risk.totals.headerAnomalies, 0);
  assert.equal(snapshot.risk.totals.proxyIndicators, 0);
  assert.deepEqual(Object.keys(snapshot), Object.keys(initial));
  assert.deepEqual(Object.keys(snapshot.byKind), Object.keys(initial.byKind));
  assert.deepEqual(Object.keys(snapshot.risk.totals), Object.keys(initial.risk.totals));
  assert.doesNotMatch(JSON.stringify(snapshot), /private|person\d|192\.0\.2|sourceHash|example\.test/);
  assert.ok(JSON.stringify(snapshot).length < 5000, "aggregate snapshots have a fixed bounded shape");
  snapshot.total.requests = -1;
  snapshot.total.byStatusClass.other = -1;
  snapshot.byKind.get.latencyMs.max = -1;
  snapshot.challenges.shown = -1;
  snapshot.risk.totals.networkUnknown = -1;
  const fresh = analytics.getSnapshot();
  assert.equal(fresh.total.requests, 1004);
  assert.equal(fresh.total.byStatusClass.other, 4);
  assert.equal(fresh.byKind.get.latencyMs.max, 1);
  assert.equal(fresh.challenges.shown, 0);
  assert.equal(fresh.risk.totals.networkUnknown, 1000);
});

test("disabled disk analytics perform no initialization hooks or writes", async () => {
  const analytics = createDiskAnalytics({ directory: "", namespace: "disabled", now: () => startedAt });
  assert.equal(analytics.configured, false);
  assert.equal(await analytics.initialize({ exportState() { assert.fail("disabled export"); }, restoreState() { assert.fail("disabled restore"); } }), false);
  assert.equal(analytics.recordRequest({ kind: "get", completed: true }), false);
  assert.equal(analytics.recordChallengeEvent("shown"), false);
  assert.equal(analytics.recordRisk({ networkKnown: true }), false);
  analytics.markDirty();
  assert.equal(await analytics.flush(), false);
  assert.equal(analytics.getSnapshot(), null);
  assert.deepEqual(analytics.getStatus(), { backend: "disk", configured: false, ready: false,
    namespace: "disabled", pending: 0, lastSaveAt: null, lastError: null });
  const closing = analytics.close();
  assert.equal(analytics.close(), closing);
  assert.equal(await closing, false);
});
