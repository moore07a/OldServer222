"use strict";

const assert = require("node:assert/strict");
const { createHash, randomUUID } = require("node:crypto");
const test = require("node:test");
const createStore = require("../modules/risk-assessment/campaignRiskStore");
const hash = value => createHash("sha256").update(String(value)).digest("hex");
const campaign = (report, id = "summer") => report.campaigns.find(row => row.id === id);
const immediate = () => new Promise(resolve => setImmediate(resolve));

class FakeRedis {
  status = "ready";
  rows = new Map();
  sources = new Map();
  dedupe = new Map();
  calls = 0;
  fail = false;
  async eval(script, count, ...args) {
    this.calls += 1;
    if (this.fail) throw new Error("internal redis://password@private-host must not escape");
    const keys = args.slice(0, count);
    const values = args.slice(count);
    if (script.includes("'PFADD'")) {
      const row = this.rows.get(keys[0]) || Array(9).fill(0);
      values.slice(2).forEach((flag, index) => { row[index] += Number(flag); });
      this.rows.set(keys[0], row);
      const sources = this.sources.get(keys[1]) || new Set();
      if (values[1]) sources.add(values[1]);
      this.sources.set(keys[1], sources);
      return 1;
    }
    if (script.includes("'HMGET'")) {
      return keys.flatMap((key, index) => index % 2 ? [] : [...(this.rows.get(key) || Array(9).fill(0)), (this.sources.get(keys[index + 1]) || new Set()).size]);
    }
    const [timestamp, event, cap] = values;
    const today = this.dedupe.get(keys[1]) || new Map();
    const yesterday = this.dedupe.get(keys[2]) || new Map();
    const prior = today.get(event) ?? yesterday.get(event);
    if (prior !== undefined && prior > Number(timestamp) - 86400000) return 0;
    if (today.size >= Number(cap)) return -1;
    const row = this.rows.get(keys[0]) || Array(9).fill(0);
    row[8] += 1;
    this.rows.set(keys[0], row);
    today.set(event, Number(timestamp));
    this.dedupe.set(keys[1], today);
    return 1;
  }
}

test("local risk counters are fixed-cardinality, copy primitives, and reset each window", async t => {
  let clock = 300000;
  const store = createStore({ campaignIds: ["summer"], now: () => clock, windowSec: 10 });
  t.after(() => store.close());
  const input = { campaignId: "summer", sourceHash: hash("same"), headless: true, proxy: true, hosting: false, challengePassed: true, url: "private" };
  assert.equal(store.recordRequest(input), true);
  input.campaignId = "unknown";
  input.headless = false;
  store.recordRequest({ campaignId: "summer", sourceHash: hash("same"), hosting: true, vpn: true, residentialProxy: true, challengeFailed: true });
  for (let i = 0; i < 200; i++) store.recordRequest({ campaignId: `unconfigured-${i}`, sourceHash: hash(i) });
  const report = await store.getSnapshot();
  assert.equal(report.scope, "current_process");
  assert.equal(report.attribution, "client_supplied");
  assert.equal(report.campaigns.length, 2);
  assert.deepEqual(campaign(report), { id: "summer", requests: 2, headless: 1, hosting: 1, proxy: 1, vpn: 1, residentialProxy: 1, challengePassed: 1, challengeFailed: 1, conversions: 0, distinctSourcesEstimate: 1, distinctSourcesSaturated: false });
  assert.equal(campaign(report, "__unattributed__").requests, 200);
  assert.doesNotMatch(JSON.stringify(report), /private|sourceHash|unconfigured-/);
  clock += 10000;
  const next = await store.getSnapshot();
  assert.equal(next.windowStartedAt, new Date(clock).toISOString());
  assert.ok(next.campaigns.every(row => row.requests === 0));
});

test("local source bitmap has bounded saturation and a useful approximate estimate", async t => {
  const store = createStore({ campaignIds: ["summer"], now: () => 300000 });
  t.after(() => store.close());
  for (let index = 0; index < 2000; index++) store.recordRequest({ campaignId: "summer", sourceHash: hash(index) });
  const row = campaign(await store.getSnapshot());
  assert.ok(row.distinctSourcesEstimate > 1750 && row.distinctSourcesEstimate < 2250);
  for (let index = 0; index < 4096; index++) store.recordRequest({ campaignId: "summer", sourceHash: index.toString(16).padStart(8, "0") + "0".repeat(56) });
  const saturated = campaign(await store.getSnapshot());
  assert.equal(saturated.distinctSourcesSaturated, true);
  assert.ok(Number.isFinite(saturated.distinctSourcesEstimate));
  assert.ok(saturated.distinctSourcesEstimate <= saturated.requests);
});

test("campaign allowlists and namespace validation prevent dynamic keys", () => {
  for (const campaignIds of [Array(33).fill("a"), ["summer", "summer"], ["a/b"], ["__unattributed__"], [null]]) assert.throws(() => createStore({ campaignIds }), TypeError);
  for (const namespace of ["a{tag}", "", "x".repeat(81)]) assert.throws(() => createStore({ namespace }), TypeError);
});

test("local conversion retries deduplicate across window changes and reject full dedupe storage", async t => {
  let clock = 86400000 + 1000;
  const store = createStore({ campaignIds: ["summer"], now: () => clock, windowSec: 10, maxLocalConversionIds: 2 });
  t.after(() => store.close());
  const event = { campaignId: "summer", eventIdHash: hash("conversion") };
  assert.deepEqual(await store.recordConversion(event), { accepted: true, duplicate: false, scope: "current_process" });
  assert.deepEqual(await store.recordConversion(event), { accepted: true, duplicate: true, scope: "current_process" });
  clock += 10000;
  assert.equal((await store.recordConversion(event)).duplicate, true);
  assert.equal(campaign(await store.getSnapshot()).conversions, 0);
  assert.equal((await store.recordConversion({ ...event, eventIdHash: hash("second") })).accepted, true);
  assert.deepEqual(await store.recordConversion({ ...event, eventIdHash: hash("third") }), { accepted: false, reason: "capacity" });
  assert.equal((await store.recordConversion(event)).duplicate, true, "capacity never evicts retry protection");
  clock += 86400000;
  assert.equal((await store.recordConversion(event)).duplicate, false);
  assert.equal((await store.recordConversion({ ...event, campaignId: "unknown" })).reason, "invalid_campaign");
  assert.equal((await store.recordConversion({ ...event, eventIdHash: "raw-customer-id" })).accepted, false);
});

test("Redis queue stays bounded and hanging commands cannot accumulate after timeout", async t => {
  let settle;
  let calls = 0;
  const client = { status: "ready", eval() { calls++; return new Promise(resolve => { settle = resolve; }); } };
  const store = createStore({ client, campaignIds: ["summer"], maxQueue: 3, operationTimeoutMs: 30 });
  t.after(() => store.close());
  for (let index = 0; index < 20; index++) store.recordRequest({ campaignId: "summer", sourceHash: hash(index) });
  assert.equal(store.getStatus().pendingOperations, 3);
  assert.equal(store.getStatus().droppedObservations, 17);
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(calls, 1);
  assert.equal(store.getStatus().uncertainObservations, 1);
  assert.equal(store.getStatus().droppedObservations, 19);
  const report = await store.getSnapshot();
  assert.equal(report.scope, "unavailable");
  assert.equal(report.storage.fallbackScope, "current_process");
  assert.equal(campaign(report).requests, 20);
  store.recordRequest({ campaignId: "summer" });
  assert.equal(calls, 1, "a timed-out underlying operation retains the only command slot");
  settle(1);
  await immediate();
});

test("Redis failures drop observations without retry and reject conversions instead of accepting locally", async t => {
  const client = new FakeRedis();
  client.fail = true;
  const store = createStore({ client, campaignIds: ["summer"] });
  t.after(() => store.close());
  store.recordRequest({ campaignId: "summer", proxy: true });
  await immediate();
  assert.equal(store.getStatus().uncertainObservations, 1);
  const conversion = await store.recordConversion({ campaignId: "summer", eventIdHash: hash("event") });
  assert.deepEqual(conversion, { accepted: false, reason: "unavailable" });
  const failed = await store.getSnapshot();
  assert.equal(failed.scope, "unavailable");
  assert.equal(campaign(failed).conversions, 0);
  assert.doesNotMatch(JSON.stringify(failed), /password|private-host|redis:\/\//);
  client.fail = false;
  const recovered = await store.getSnapshot();
  assert.equal(recovered.scope, "redis");
  assert.equal(campaign(recovered).requests, 0, "uncertain observations are never replayed");
  client.status = "reconnecting";
  assert.equal((await store.recordConversion({ campaignId: "summer", eventIdHash: hash("event") })).accepted, false);
});

test("Redis snapshot waits behind existing observations and conversion dedupe survives a new writer/day", async t => {
  const client = new FakeRedis();
  let clock = 86400000 - 100;
  const config = { client, campaignIds: ["summer"], now: () => clock, maxRedisConversionIdsPerDay: 1 };
  const first = createStore(config);
  const second = createStore(config);
  t.after(() => Promise.all([first.close(), second.close()]));
  first.recordRequest({ campaignId: "summer", sourceHash: hash("source"), headless: true });
  const report = await first.getSnapshot();
  assert.equal(report.scope, "redis");
  assert.equal(campaign(report).requests, 1);
  assert.equal(campaign(report).distinctSourcesEstimate, 1);
  const event = { campaignId: "summer", eventIdHash: hash("event") };
  assert.equal((await first.recordConversion(event)).duplicate, false);
  assert.equal((await second.recordConversion(event)).duplicate, true);
  assert.equal((await first.recordConversion({ ...event, eventIdHash: hash("other") })).reason, "capacity");
  clock += 200;
  assert.equal((await second.recordConversion(event)).duplicate, true, "previous UTC day is checked");
  assert.equal(campaign(await second.getSnapshot()).conversions, 0, "a retry does not add a conversion in a new window");
});

test("snapshot reads are single-flight and close promptly cancels bounded work", async () => {
  let resolveCommand;
  const client = { status: "ready", eval() { return new Promise(resolve => { resolveCommand = resolve; }); } };
  const store = createStore({ client, campaignIds: ["summer"], operationTimeoutMs: 100 });
  const first = store.getSnapshot();
  assert.equal(store.getSnapshot(), first);
  await immediate();
  await store.close();
  await store.close();
  assert.equal((await first).scope, "unavailable");
  assert.equal(store.recordRequest({ campaignId: "summer" }), false);
  assert.equal((await store.recordConversion({ campaignId: "summer", eventIdHash: hash("event") })).reason, "unavailable");
  resolveCommand([]);
  await immediate();
});

const redisUrl = process.env.TRAFFIC_METRICS_TEST_REDIS_URL;
test("real Redis shares risk totals, expires its keys, and deduplicates uncertain conversion replies", { skip: !redisUrl && "Set TRAFFIC_METRICS_TEST_REDIS_URL", timeout: 15000 }, async t => {
  const Redis = require("ioredis");
  const namespace = `risk-test-${randomUUID()}`;
  const client = new Redis(redisUrl, { lazyConnect: true, enableOfflineQueue: false, autoResendUnfulfilledCommands: false, commandTimeout: 1000, retryStrategy: null });
  client.on("error", () => {});
  await client.connect();
  let clock = Date.now();
  let loseReply = true;
  const wrapped = { get status() { return client.status; }, async eval(...args) {
    const value = await client.eval(...args);
    if (loseReply && args[0].includes("local last =")) { loseReply = false; throw new Error("reply lost"); }
    return value;
  } };
  const first = createStore({ client: wrapped, namespace, campaignIds: ["summer"], now: () => clock, windowSec: 10, maxRedisConversionIdsPerDay: 2 });
  const second = createStore({ client, namespace, campaignIds: ["summer"], now: () => clock, windowSec: 10, maxRedisConversionIdsPerDay: 2 });
  t.after(async () => {
    await Promise.all([first.close(), second.close()]);
    const keys = await client.keys(`campaign-risk:{${namespace}:v1}:*`);
    if (keys.length) await client.del(...keys);
    client.disconnect();
  });
  first.recordRequest({ campaignId: "summer", sourceHash: hash("same"), proxy: true, challengePassed: true });
  second.recordRequest({ campaignId: "summer", sourceHash: hash("same"), hosting: true, challengeFailed: true });
  await Promise.all([first.getSnapshot(), second.getSnapshot()]);
  const report = await first.getSnapshot();
  assert.equal(campaign(report).requests, 2);
  assert.equal(campaign(report).challengePassed, 1);
  assert.equal(campaign(report).challengeFailed, 1);
  assert.equal(campaign(report).distinctSourcesEstimate, 1);
  const event = { campaignId: "summer", eventIdHash: hash("event") };
  assert.equal((await first.recordConversion(event)).reason, "unavailable", "lost acknowledgment is safe to retry");
  assert.equal((await second.recordConversion(event)).duplicate, true);
  assert.equal(campaign(await second.getSnapshot()).conversions, 1);
  const keys = await client.keys(`campaign-risk:{${namespace}:v1}:*`);
  assert.ok(keys.length > 0 && keys.length <= 5);
  for (const key of keys) assert.ok(await client.pttl(key) > 0, "every risk key expires");
  const counterKey = keys.find(key => key.endsWith(":counts"));
  const dedupeKey = keys.find(key => key.includes(":dedupe:"));
  const originalConversions = await client.hget(counterKey, "conversions");
  await client.hset(counterKey, "conversions", "corrupt");
  const badEvent = { campaignId: "summer", eventIdHash: hash("bad-counter-event") };
  assert.equal((await second.recordConversion(badEvent)).reason, "unavailable");
  assert.equal(await client.hexists(dedupeKey, badEvent.eventIdHash), 0, "invalid counters reject before claiming a conversion ID");
  await client.hset(counterKey, "conversions", originalConversions);
  assert.equal((await second.recordConversion(badEvent)).accepted, true);
  assert.equal((await second.recordConversion({ ...event, eventIdHash: hash("over-cap") })).reason, "capacity");
  assert.equal((await first.recordConversion(event)).duplicate, true, "capacity preserves dedupe markers");
  clock += 10000;
  assert.equal(campaign(await second.getSnapshot()).requests, 0);
  assert.equal((await second.recordConversion(event)).duplicate, true);
});

test("checkpoint state restores current-window counters, bitmap estimates and conversion dedupe once", async t => {
  let clock = 300000;
  let dirty = 0;
  const config = { campaignIds: ["summer"], namespace: "checkpoint-test", windowSec: 10, now: () => clock };
  const first = createStore({ ...config, onDirty: () => { dirty++; } });
  const restored = createStore(config);
  t.after(() => Promise.all([first.close(), restored.close()]));
  first.recordRequest({ campaignId: "summer", sourceHash: hash("source"), challengePassed: true });
  first.recordRequest({ campaignId: "unknown", sourceHash: hash("other"), proxy: true });
  const event = { campaignId: "summer", eventIdHash: hash("trusted-event") };
  await first.recordConversion(event);
  assert.equal(dirty, 3);
  const saved = JSON.parse(JSON.stringify(first.exportState()));
  assert.equal(saved.dedupe.length, 1);
  assert.ok(!JSON.stringify(saved).includes("trusted-event"));
  assert.equal(restored.restoreState(saved), true);
  assert.equal(restored.restoreState(saved), false);
  assert.deepEqual((await restored.getSnapshot()).campaigns, (await first.getSnapshot()).campaigns);
  assert.equal((await restored.recordConversion(event)).duplicate, true);
  saved.campaigns[0].requests = 999;
  saved.dedupe.length = 0;
  assert.equal(campaign(await restored.getSnapshot()).requests, 1, "restore takes detached fixed-field copies");
  assert.equal((await restored.recordConversion(event)).duplicate, true);
  const exported = restored.exportState();
  clock += 10000;
  const nextWindow = createStore(config);
  t.after(() => nextWindow.close());
  assert.equal(nextWindow.restoreState(exported), true);
  assert.equal(campaign(await nextWindow.getSnapshot()).requests, 0, "past-window counters are discarded");
  assert.equal((await nextWindow.recordConversion(event)).duplicate, true, "24h retry protection crosses window boundaries");
  clock += 86400000;
  assert.equal(nextWindow.exportState().dedupe.length, 0, "expired hashes are not checkpointed");
});

test("checkpoint restore rejects malformed, oversized or mismatched state atomically", async t => {
  const config = { campaignIds: ["summer"], namespace: "restore-validation", now: () => 300000, maxLocalConversionIds: 2 };
  const original = createStore(config);
  t.after(() => original.close());
  original.recordRequest({ campaignId: "summer", sourceHash: hash("one") });
  const state = original.exportState();
  const mutations = [
    value => { value.version = 99; }, value => { value.namespace = "invalid{namespace}"; },
    value => { value.windowSec = 9; }, value => { value.windowStartedAt = 900000; },
    value => { value.campaigns[0].requests = -1; }, value => { value.campaigns[0].proxy = 2; },
    value => { value.campaigns[0].id = "unsafe/id"; }, value => { value.campaigns[1] = value.campaigns[0]; },
    value => { value.campaigns[0].bitmap = "x".repeat(684); }, value => { value.campaigns[0].bitmap = ""; },
    value => { value.dedupe = Array(3).fill(["summer", hash("event"), 300000]); },
    value => { value.dedupe = [["unsafe/id", hash("event"), 300000]]; },
    value => { value.dedupe = [["summer", "raw-id", 300000]]; },
    value => { value.dedupe = [["summer", hash("event"), 300001]]; },
    value => { value.dedupe = Array(2).fill(["summer", hash("event"), 300000]); }
  ];
  for (const mutate of mutations) {
    const copy = JSON.parse(JSON.stringify(state));
    mutate(copy);
    const store = createStore(config);
    t.after(() => store.close());
    assert.equal(store.restoreState(copy), false);
    assert.equal(campaign(await store.getSnapshot()).requests, 0, "invalid input changes no counters");
    assert.equal(store.exportState().dedupe.length, 0);
  }
  const used = createStore(config);
  t.after(() => used.close());
  used.recordRequest({ campaignId: "summer" });
  assert.equal(used.restoreState(state), false, "restore cannot overwrite live observations");
});

test("durable conversions wait for the checkpoint and retain retry protection through restart and shutdown", async t => {
  let resolveWrite;
  let saved;
  let calls = 0;
  let first;
  const config = { campaignIds: ["summer"], namespace: "durable-conversions", now: () => 300000 };
  const commit = async () => {
    calls++;
    saved = JSON.parse(JSON.stringify(first.exportState()));
    await new Promise(resolve => { resolveWrite = resolve; });
    return true;
  };
  first = createStore({ ...config, commit });
  t.after(() => first.close());
  const event = { campaignId: "summer", eventIdHash: hash("order") };
  let acknowledged = false;
  const pending = first.recordConversion(event).then(result => { acknowledged = true; return result; });
  await immediate();
  assert.equal(calls, 1);
  assert.equal(acknowledged, false);
  const inProgress = await first.getSnapshot();
  assert.equal(inProgress.scope, "disk");
  assert.equal(inProgress.storage.backend, "disk");
  assert.equal(inProgress.storage.pendingOperations, 1);
  assert.equal(campaign(inProgress).conversions, 1);
  resolveWrite();
  assert.deepEqual(await pending, { accepted: true, duplicate: false, scope: "disk" });
  await first.close();
  assert.equal(first.exportState().dedupe.length, 1, "shutdown retains state for the final aggregate checkpoint");
  const restarted = createStore({ ...config, commit: async () => true });
  t.after(() => restarted.close());
  assert.equal(restarted.restoreState(saved), true);
  const duplicates = await Promise.all(Array.from({ length: 3 }, () => restarted.recordConversion(event)));
  assert.ok(duplicates.every(result => result.accepted && result.duplicate));
  assert.equal(campaign(await restarted.getSnapshot()).conversions, 1);
});

test("disk readiness and commit failures reject conversions while preserving uncertain markers for retry", async t => {
  let ready = false;
  let persisted = false;
  let writes = 0;
  const store = createStore({ campaignIds: ["summer"], now: () => 300000, persistenceReady: () => ready,
    commit: async () => { writes++; return persisted; } });
  t.after(() => store.close());
  const event = { campaignId: "summer", eventIdHash: hash("event") };
  assert.deepEqual(await store.recordConversion(event), { accepted: false, reason: "unavailable" });
  const initial = await store.getSnapshot();
  assert.equal(initial.scope, "unavailable");
  assert.equal(initial.storage.backend, "disk");
  assert.equal(initial.storage.fallbackScope, "current_process");
  assert.equal(campaign(initial).conversions, 0);
  assert.equal(writes, 0);
  ready = true;
  assert.deepEqual(await store.recordConversion(event), { accepted: false, reason: "unavailable" });
  assert.equal(store.getStatus().uncertainConversions, 1);
  assert.equal(store.getStatus().lastError, "commit_failed");
  persisted = true;
  assert.deepEqual(await store.recordConversion(event), { accepted: true, duplicate: true, scope: "disk" });
  assert.equal(writes, 2);
  assert.equal(campaign(await store.getSnapshot()).conversions, 1);
});

test("disk conversion queue is bounded and a stalled checkpoint does not block reads or accumulate writes", async t => {
  let settle;
  let writes = 0;
  const store = createStore({ campaignIds: ["summer"], now: () => 300000, operationTimeoutMs: 30,
    commit: () => { writes++; return new Promise(resolve => { settle = resolve; }); } });
  t.after(() => store.close());
  const requests = Array.from({ length: 40 }, (_, index) => store.recordConversion({ campaignId: "summer", eventIdHash: hash(index) }));
  assert.equal(store.getStatus().pendingOperations, 32);
  assert.equal(store.getStatus().queueLimit, 32);
  const results = await Promise.all(requests);
  assert.equal(results.filter(result => result.reason === "capacity").length, 8);
  assert.equal(results.filter(result => result.reason === "unavailable").length, 32);
  assert.equal(writes, 1);
  assert.equal(store.getStatus().uncertainConversions, 1);
  const report = await store.getSnapshot();
  assert.equal(report.scope, "unavailable");
  assert.equal(report.storage.pendingOperations, 1);
  assert.equal((await store.recordConversion({ campaignId: "summer", eventIdHash: hash("late") })).reason, "unavailable");
  assert.equal(writes, 1);
  settle(true);
  await immediate();
  assert.equal(store.getStatus().pendingOperations, 0);
  assert.equal((await store.getSnapshot()).scope, "disk");
});

test("checkpoint migration tolerates campaign and window changes without losing retry protection", async t => {
  const config = { now: () => 300000, namespace: "campaign-migration", windowSec: 300 };
  const first = createStore({ ...config, campaignIds: ["summer", "removed"] });
  t.after(() => first.close());
  const event = { campaignId: "removed", eventIdHash: hash("conversion") };
  first.recordRequest({ campaignId: "summer", sourceHash: hash("source") });
  first.recordRequest({ campaignId: "removed" });
  await first.recordConversion(event);
  const changed = createStore({ ...config, campaignIds: ["summer", "added"] });
  t.after(() => changed.close());
  assert.equal(changed.restoreState(first.exportState()), true);
  assert.equal(campaign(await changed.getSnapshot(), "summer").requests, 1);
  assert.equal(campaign(await changed.getSnapshot(), "added").requests, 0);
  assert.equal(changed.exportState().dedupe.length, 1, "removed IDs retain bounded 24h dedupe entries");
  const readded = createStore({ ...config, windowSec: 10, campaignIds: ["summer", "removed"] });
  t.after(() => readded.close());
  assert.equal(readded.restoreState(changed.exportState()), true);
  assert.equal(campaign(await readded.getSnapshot(), "summer").requests, 0, "changed window configuration starts fresh counters");
  assert.equal((await readded.recordConversion(event)).duplicate, true);
});

test("valid namespace changes reset campaign hashes without rejecting the enclosing aggregate checkpoint", async t => {
  const config = { now: () => 300000, campaignIds: ["summer"] };
  const previous = createStore({ ...config, namespace: "old-risk" });
  t.after(() => previous.close());
  previous.recordRequest({ campaignId: "summer", sourceHash: hash("old-source"), challengePassed: true });
  const event = { campaignId: "summer", eventIdHash: hash("old-event") };
  await previous.recordConversion(event);
  const state = previous.exportState();
  const current = createStore({ ...config, namespace: "new-risk" });
  t.after(() => current.close());
  assert.equal(current.restoreState(state), true, "safe namespace migration preserves the enclosing checkpoint");
  const report = await current.getSnapshot();
  assert.ok(report.campaigns.every(row => row.requests === 0 && row.conversions === 0 && row.distinctSourcesEstimate === 0));
  assert.equal(current.exportState().namespace, "new-risk");
  assert.equal(current.exportState().dedupe.length, 0, "old namespace HMAC identifiers are not imported");
  assert.equal((await current.recordConversion(event)).duplicate, false);
  assert.equal(current.restoreState(state), false, "the one-attempt guard still applies");
});

test("namespace migration still rejects malformed saved namespaces, counters, bitmaps and dedupe", async t => {
  const config = { now: () => 300000, campaignIds: ["summer"] };
  const original = createStore({ ...config, namespace: "old-risk" });
  t.after(() => original.close());
  original.recordRequest({ campaignId: "summer", sourceHash: hash("source") });
  const originalState = original.exportState();
  for (const mutate of [
    state => { state.namespace = "invalid{tag}"; }, state => { state.namespace = ""; },
    state => { state.campaigns[0].requests = -1; }, state => { state.campaigns[0].hosting = 2; },
    state => { state.campaigns[0].bitmap = "broken"; },
    state => { state.dedupe = [["summer", "raw-event", 300000]]; }
  ]) {
    const state = JSON.parse(JSON.stringify(originalState));
    mutate(state);
    const current = createStore({ ...config, namespace: "new-risk" });
    t.after(() => current.close());
    assert.equal(current.restoreState(state), false, "a namespace change cannot bypass validation");
    assert.equal(campaign(await current.getSnapshot()).requests, 0);
    assert.equal(current.exportState().dedupe.length, 0);
  }
});
