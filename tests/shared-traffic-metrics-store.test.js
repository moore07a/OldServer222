"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const createStore = require("../modules/runtime-utils/sharedTrafficMetricsStore.js");

const DAY = 24 * 60 * 60 * 1000;

// This double models Redis atomic script acknowledgments and lost replies. The
// production Lua is additionally exercised by the Redis integration tests.
class FakeRedis {
  constructor() {
    this.status = "ready";
    this.clock = 1700000000000;
    this.hashes = new Map();
    this.writers = new Map();
    this.calls = [];
    this.failAfterApply = false;
    this.failRead = false;
    this.beforeApply = null;
  }

  async eval(script, keyCount, aggregateKey, writerKey, sequence, ttl, ...values) {
    this.calls.push({ aggregateKey, writerKey, sequence, ttl, values });
    assert.equal(keyCount, 2);
    assert.equal(aggregateKey.match(/\{([^}]+)\}/)[1], writerKey.match(/\{([^}]+)\}/)[1]);
    if (this.beforeApply) await this.beforeApply();
    const previous = this.writers.get(writerKey);
    if (previous && previous.expiresAt > this.clock && previous.sequence >= Number(sequence)) return 0;
    const fieldLine = script.match(/local fields = \{([^\n]+)\}/)[1];
    const fields = JSON.parse(`[${fieldLine}]`);
    assert.equal(values.length, fields.length);
    const hash = this.hashes.get(aggregateKey) || {};
    for (let index = 0; index < fields.length; index += 1) {
      const field = fields[index];
      const incoming = Number(values[index]);
      const current = Number(hash[field] || 0);
      if (incoming) hash[field] = String(field.endsWith(":durationMaxMs") ? Math.max(current, incoming) : current + incoming);
    }
    hash.startedAtMs ||= String(this.clock);
    hash.updatedAtMs = String(this.clock);
    this.hashes.set(aggregateKey, hash);
    this.writers.set(writerKey, { sequence: Number(sequence), expiresAt: this.clock + Number(ttl) * 1000 });
    if (this.failAfterApply) {
      this.failAfterApply = false;
      throw new Error("redis://sensitive-user:sensitive-password@private-host timed out");
    }
    return 1;
  }

  async hgetall(key) {
    if (this.failRead) throw new Error("redis://sensitive-user:sensitive-password@private-host read failed");
    return { ...(this.hashes.get(key) || {}) };
  }
}

function harness(t, options = {}) {
  const client = options.client || new FakeRedis();
  const store = createStore({ client, flushIntervalMs: 60000, ...options });
  t.after(() => store.close());
  return { client, store };
}

test("shared metrics combine fixed counters across replicas and collector restarts", async (t) => {
  const { client, store: first } = harness(t);
  const { store: second } = harness(t, { client });
  first.recordRequest({ kind: "get", completed: true, statusClass: "2xx", durationMs: 10 });
  first.recordRequest({ kind: "head", completed: false, statusClass: "2xx", durationMs: 100 });
  first.recordChallengeEvent("shown");
  second.recordRequest({ kind: "get", completed: true, statusClass: "3xx", durationMs: 30 });
  second.recordChallengeEvent("passed");
  second.recordChallengeEvent("redirected");
  assert.equal(await first.flush(), true);
  const snapshot = await second.getSnapshot();
  assert.equal(snapshot.scope, "redis");
  assert.equal(snapshot.namespace, "oldserver222");
  assert.equal(snapshot.startedAt, new Date(client.clock).toISOString());
  assert.equal(snapshot.updatedAt, snapshot.startedAt);
  assert.equal(snapshot.total.requests, 3);
  assert.equal(snapshot.total.completed, 2);
  assert.equal(snapshot.total.aborted, 1);
  assert.equal(snapshot.total.byStatusClass["2xx"], 1);
  assert.equal(snapshot.total.byStatusClass["3xx"], 1);
  assert.deepEqual(snapshot.total.latencyMs, { mean: 20, max: 30 });
  assert.equal(snapshot.byKind.head.aborted, 1);
  assert.deepEqual(snapshot.byKind.head.latencyMs, { mean: null, max: null });
  assert.equal(snapshot.challenges.shown, 1);
  assert.equal(snapshot.challenges.passed, 1);
  assert.equal(snapshot.challenges.redirected, 1);
  assert.equal(Object.hasOwn(snapshot.total, "inFlight"), false);
  assert.equal(Object.hasOwn(snapshot.total.latencyMs, "recent"), false);
  const { store: restarted } = harness(t, { client });
  assert.deepEqual(await restarted.getSnapshot(), snapshot);
  restarted.recordChallengeEvent("expired");
  const afterRestart = await restarted.getSnapshot();
  assert.equal(afterRestart.challenges.expired, 1);
  assert.equal(afterRestart.challenges.shown, 1);
  const writerKeys = client.calls.map(({ writerKey }) => writerKey);
  assert.equal(new Set(writerKeys).size, 3);
});

test("lost replies retry the immutable batch without duplicating its applied counts", async (t) => {
  const { client, store } = harness(t);
  store.recordChallengeEvent("shown");
  client.failAfterApply = true;
  assert.equal(await store.flush(), false);
  assert.equal(store.getStatus().pendingObservations, 1);
  assert.equal(store.getStatus().uncertainBatches, 1);
  assert.equal(store.getStatus().uncertainObservations, 1);
  assert.equal(store.getStatus().lastError, "write_failed");
  store.recordChallengeEvent("passed");
  store.recordRequest({ kind: "get", completed: true, statusClass: "2xx", durationMs: 5 });
  assert.equal(await store.flush(), true);
  assert.equal(store.getStatus().pendingObservations, 2);
  assert.deepEqual(client.calls[0], client.calls[1], "retry sends exactly the same writer, sequence, and values");
  const snapshot = await store.getSnapshot();
  assert.equal(snapshot.challenges.shown, 1);
  assert.equal(snapshot.challenges.passed, 1);
  assert.equal(snapshot.total.requests, 1);
  assert.equal(store.getStatus().pendingObservations, 0);
  assert.equal(store.getStatus().uncertainBatches, 1);
  assert.doesNotMatch(JSON.stringify(store.getStatus()), /sensitive|password|private-host|redis:\/\//);
});

test("concurrent flushes share one operation and observations during a write wait for the next batch", async (t) => {
  const { client, store } = harness(t);
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  client.beforeApply = () => gate;
  store.recordChallengeEvent("shown");
  const first = store.flush();
  assert.equal(first, store.flush());
  store.recordChallengeEvent("failed");
  const reading = store.getSnapshot();
  assert.equal(client.calls.length, 1);
  assert.equal(store.getStatus().pendingObservations, 2);
  release();
  const snapshot = await reading;
  assert.equal(snapshot.challenges.shown, 1);
  assert.equal(snapshot.challenges.failed, 1);
  assert.equal(client.calls.length, 2);
  assert.deepEqual(client.calls.map(({ sequence }) => sequence), ["1", "2"]);
  assert.equal(store.getStatus().pendingObservations, 0);
});

test("disconnected Redis retains fixed pending aggregates without commands or blocking recording", async (t) => {
  const { client, store } = harness(t);
  client.status = "reconnecting";
  assert.equal(store.recordRequest({ kind: "other", completed: false }), true);
  assert.equal(store.recordChallengeEvent("providerError"), true);
  assert.equal(client.calls.length, 0);
  assert.equal(await store.flush(), false);
  assert.equal(await store.getSnapshot(), null);
  assert.equal(client.calls.length, 0);
  assert.equal(store.getStatus().pendingObservations, 2);
  assert.equal(store.getStatus().ready, false);
  assert.equal(store.getStatus().lastError, "unavailable");
  client.status = "ready";
  const snapshot = await store.getSnapshot();
  assert.equal(snapshot.total.aborted, 1);
  assert.equal(snapshot.challenges.providerError, 1);
  assert.equal(store.getStatus().pendingObservations, 0);
  assert.equal(store.getStatus().lastError, null);
});

test("read errors return no shared snapshot and safe status recovers after a successful read", async (t) => {
  const { client, store } = harness(t);
  client.failRead = true;
  assert.equal(await store.getSnapshot(), null);
  assert.equal(store.getStatus().lastError, "read_failed");
  assert.equal(store.getStatus().lastReadAt, null);
  assert.doesNotMatch(JSON.stringify(store.getStatus()), /sensitive|password|private-host|redis:\/\//);
  client.failRead = false;
  const snapshot = await store.getSnapshot();
  assert.equal(snapshot.total.requests, 0);
  assert.equal(snapshot.startedAt, null);
  assert.equal(store.getStatus().lastError, null);
  assert.ok(store.getStatus().lastReadAt);
});

test("expired uncertain batches are dropped explicitly before their deduplication watermark can expire", async (t) => {
  let clock = 1700000000000;
  const { client, store } = harness(t, { now: () => clock });
  store.recordChallengeEvent("shown");
  client.failAfterApply = true;
  assert.equal(await store.flush(), false);
  client.status = "reconnecting";
  clock += DAY;
  assert.equal(await store.flush(), false);
  assert.equal(store.getStatus().droppedBatches, 1);
  assert.equal(store.getStatus().droppedObservations, 1);
  assert.equal(store.getStatus().pendingObservations, 0);
  client.status = "ready";
  store.recordChallengeEvent("passed");
  const snapshot = await store.getSnapshot();
  assert.equal(snapshot.challenges.shown, 1, "an uncertain batch may already have reached Redis");
  assert.equal(snapshot.challenges.passed, 1);
  assert.deepEqual(client.calls.map(({ sequence }) => sequence), ["1", "2"]);
  assert.equal(Number(client.calls[0].ttl), 7 * DAY / 1000);
});

test("arbitrary labels and private input never create retained fields or Redis keys", async (t) => {
  const { client, store } = harness(t);
  for (let index = 0; index < 1000; index += 1) {
    assert.equal(store.recordChallengeEvent(`person${index}@example.test`), false);
    assert.equal(store.recordChallengeEvent("__proto__"), false);
    assert.equal(store.recordRequest({ kind: `192.0.2.${index}`, completed: true }), false);
    store.recordRequest({
      kind: "get", completed: true, statusClass: `private-status-${index}`, durationMs: 2,
      url: `/private-url-${index}`, ip: `192.0.2.${index}`, token: `secret-token-${index}`
    });
  }
  assert.equal(client.calls.length, 0, "recording performs no Redis operations");
  const snapshot = await store.getSnapshot();
  assert.equal(snapshot.total.requests, 1000);
  assert.equal(snapshot.total.byStatusClass.other, 1000);
  assert.equal(snapshot.total.latencyMs.mean, 2);
  assert.equal(client.hashes.size, 1);
  assert.equal(client.writers.size, 1);
  assert.equal(client.calls[0].values.length, 74, "flush payload has a fixed field count");
  assert.doesNotMatch(JSON.stringify([...client.hashes, ...client.writers]), /person\d|192\.0\.2|private-url|private-status|secret-token/);
  snapshot.byKind.get.requests = -1;
  snapshot.challenges.shown = -1;
  const fresh = await store.getSnapshot();
  assert.equal(fresh.byKind.get.requests, 1000);
  assert.equal(fresh.challenges.shown, 0);
});

test("all supported event names and request classes are persisted without accepting malformed observations", async (t) => {
  const { store } = harness(t);
  const events = ["shown", "passed", "failed", "expired", "expiredOrDuplicate", "providerError", "redirected", "payloadExpired"];
  for (const name of events) assert.equal(store.recordChallengeEvent(name), true);
  for (const [index, kind] of ["operational", "head", "prefetch", "get", "other"].entries()) {
    store.recordRequest({ kind, completed: true, statusClass: ["1xx", "2xx", "3xx", "4xx", "5xx"][index], durationMs: index });
  }
  store.recordRequest({ kind: "get", completed: true, statusClass: "other", durationMs: NaN });
  store.recordRequest({ kind: "get", completed: true, durationMs: -10 });
  assert.equal(store.recordRequest({ kind: "get", completed: "yes" }), false);
  const snapshot = await store.getSnapshot();
  assert.equal(snapshot.total.requests, 7);
  assert.equal(snapshot.total.completed, 7);
  assert.equal(snapshot.total.aborted, 0);
  assert.deepEqual(snapshot.challenges, Object.fromEntries(events.map((name) => [name, 1])));
  assert.equal(snapshot.total.latencyMs.max, 4);
});

test("unconfigured persistence stays optional and namespaces reject unsafe key components", async () => {
  const store = createStore();
  assert.equal(store.recordChallengeEvent("shown"), false);
  assert.equal(store.recordRequest({ kind: "get", completed: true }), false);
  assert.equal(await store.flush(), false);
  assert.equal(await store.getSnapshot(), null);
  assert.equal(store.getStatus().configured, false);
  assert.equal(store.getStatus().pendingObservations, 0);
  await store.close();
  for (const namespace of ["", "bad{tag}", "bad space", "x".repeat(81), null]) {
    assert.throws(() => createStore({ namespace }), TypeError);
  }
});

test("close waits for an active write, flushes final pending observations, and is idempotent", async (t) => {
  const { client, store } = harness(t);
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  client.beforeApply = () => gate;
  store.recordChallengeEvent("shown");
  const write = store.flush();
  store.recordChallengeEvent("passed");
  const closing = store.close();
  assert.equal(closing, store.close());
  assert.equal(store.recordChallengeEvent("failed"), false);
  release();
  await write;
  assert.equal(await closing, true);
  assert.equal(store.getStatus().pendingObservations, 0);
  const snapshot = await store.getSnapshot();
  assert.equal(snapshot.challenges.shown, 1);
  assert.equal(snapshot.challenges.passed, 1);
  assert.equal(snapshot.challenges.failed, 0);
});

test("close also drains pending observations after acknowledging an earlier lost reply", async (t) => {
  const { client, store } = harness(t);
  store.recordChallengeEvent("shown");
  client.failAfterApply = true;
  await store.flush();
  store.recordChallengeEvent("passed");
  assert.equal(await store.close(), true);
  assert.equal(store.getStatus().pendingObservations, 0);
  const snapshot = await store.getSnapshot();
  assert.equal(snapshot.challenges.shown, 1);
  assert.equal(snapshot.challenges.passed, 1);
});

test("close retries an active write whose reply is lost and then drains its final pending batch", async (t) => {
  const { client, store } = harness(t);
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  client.beforeApply = () => gate;
  client.failAfterApply = true;
  store.recordChallengeEvent("shown");
  const active = store.flush();
  store.recordChallengeEvent("passed");
  const closing = store.close();
  release();
  assert.equal(await active, false);
  assert.equal(await closing, true);
  assert.equal(store.getStatus().pendingObservations, 0);
  assert.deepEqual(client.calls.map(({ sequence }) => sequence), ["1", "1", "2"]);
  const snapshot = await store.getSnapshot();
  assert.equal(snapshot.challenges.shown, 1);
  assert.equal(snapshot.challenges.passed, 1);
});
