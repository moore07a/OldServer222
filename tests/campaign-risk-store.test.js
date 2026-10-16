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
