"use strict";

const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const test = require("node:test");
const Redis = require("ioredis");
const createStore = require("../modules/runtime-utils/sharedTrafficMetricsStore");

// Optional service integration: regular npm test requires no Redis service.
const redisUrl = process.env.TRAFFIC_METRICS_TEST_REDIS_URL;
const options = { skip: !redisUrl && "Set TRAFFIC_METRICS_TEST_REDIS_URL to exercise real Redis", timeout: 15000 };

async function redisHarness(t) {
  const namespace = `integration-${randomUUID()}`;
  const clients = [];
  const stores = [];
  const ownedPattern = `traffic-metrics:{${namespace}:v1}:*`;
  const aggregateKey = `traffic-metrics:{${namespace}:v1}:aggregate`;

  async function client() {
    const connection = new Redis(redisUrl, {
      lazyConnect: true,
      enableOfflineQueue: false,
      connectTimeout: 2000,
      commandTimeout: 2000,
      maxRetriesPerRequest: 1,
      retryStrategy: null
    });
    connection.on("error", () => {});
    clients.push(connection);
    await connection.connect();
    return connection;
  }

  function store(connection) {
    const collector = createStore({ client: connection, namespace, flushIntervalMs: 60000 });
    stores.push(collector);
    return collector;
  }

  t.after(async () => {
    try {
      await Promise.all(stores.map(collector => collector.close()));
      const connection = clients.find(connection => connection.status === "ready");
      if (connection) {
        let cursor = "0";
        do {
          const [nextCursor, keys] = await connection.scan(cursor, "MATCH", ownedPattern, "COUNT", 100);
          cursor = nextCursor;
          // Every key is scoped to this test's randomly generated namespace.
          if (keys.length) await connection.del(...keys);
        } while (cursor !== "0");
      }
    } finally {
      await Promise.all(clients.map(async connection => {
        try {
          if (connection.status === "ready") await connection.quit();
        } finally {
          connection.disconnect();
        }
      }));
    }
  });
  return { namespace, aggregateKey, client, store };
}

test("real Redis combines independent writers and retains totals for a new collector", options, async t => {
  const harness = await redisHarness(t);
  const [firstClient, secondClient] = await Promise.all([harness.client(), harness.client()]);
  const first = harness.store(firstClient);
  const second = harness.store(secondClient);
  first.recordRequest({ kind: "get", completed: true, statusClass: "2xx", durationMs: 10.25 });
  first.recordRequest({ kind: "head", completed: false, statusClass: "2xx", durationMs: 999 });
  first.recordChallengeEvent("shown");
  second.recordRequest({ kind: "get", completed: true, statusClass: "3xx", durationMs: 30.75 });
  second.recordRequest({ kind: "operational", completed: true, statusClass: "5xx", durationMs: 60.5 });
  second.recordChallengeEvent("passed");
  second.recordChallengeEvent("redirected");

  assert.deepEqual(await Promise.all([first.flush(), second.flush()]), [true, true]);
  const [snapshot, otherSnapshot] = await Promise.all([first.getSnapshot(), second.getSnapshot()]);
  assert.deepEqual(otherSnapshot, snapshot, "separate clients see the same acknowledged aggregate");
  assert.equal(snapshot.scope, "redis");
  assert.equal(snapshot.namespace, harness.namespace);
  assert.ok(Number.isFinite(Date.parse(snapshot.startedAt)));
  assert.ok(Date.parse(snapshot.updatedAt) >= Date.parse(snapshot.startedAt));
  assert.equal(snapshot.total.requests, 4);
  assert.equal(snapshot.total.completed, 3);
  assert.equal(snapshot.total.aborted, 1);
  assert.deepEqual(snapshot.total.byStatusClass, { "1xx": 0, "2xx": 1, "3xx": 1, "4xx": 0, "5xx": 1, other: 0 });
  assert.deepEqual(snapshot.total.latencyMs, { mean: 101.5 / 3, max: 60.5 });
  assert.deepEqual(snapshot.byKind.get.latencyMs, { mean: 20.5, max: 30.75 });
  assert.equal(snapshot.byKind.get.requests, 2);
  assert.equal(snapshot.byKind.head.aborted, 1);
  assert.deepEqual(snapshot.byKind.head.latencyMs, { mean: null, max: null });
  assert.equal(snapshot.byKind.operational.byStatusClass["5xx"], 1);
  assert.equal(snapshot.challenges.shown, 1);
  assert.equal(snapshot.challenges.passed, 1);
  assert.equal(snapshot.challenges.redirected, 1);

  await Promise.all([first.close(), second.close()]);
  const fresh = harness.store(await harness.client());
  assert.deepEqual(await fresh.getSnapshot(), snapshot, "totals survive replacing all collectors");
});

test("real Lua deduplicates a lost reply and close persists the final pending batch", options, async t => {
  const harness = await redisHarness(t);
  const connection = await harness.client();
  let loseReply = true;
  const acknowledgments = [];
  const wrappedClient = {
    get status() { return connection.status; },
    async eval(...args) {
      const acknowledgment = await connection.eval(...args);
      acknowledgments.push(acknowledgment);
      if (loseReply) {
        loseReply = false;
        throw new Error("Simulated lost reply after Lua applied the batch");
      }
      return acknowledgment;
    },
    hgetall: key => connection.hgetall(key)
  };
  const store = harness.store(wrappedClient);
  store.recordRequest({ kind: "get", completed: true, statusClass: "3xx", durationMs: 4.25 });
  store.recordChallengeEvent("shown");
  assert.equal(await store.flush(), false);
  const applied = await connection.hgetall(harness.aggregateKey);
  assert.equal(applied["total:requests"], "1", "the first real script executed before its reply was lost");
  assert.equal(applied["challenge:shown"], "1");
  assert.equal(store.getStatus().uncertainBatches, 1);
  assert.equal(store.getStatus().pendingObservations, 2);

  store.recordRequest({ kind: "get", completed: true, statusClass: "2xx", durationMs: 15.75 });
  store.recordChallengeEvent("passed");
  assert.equal(await store.flush(), true, "retry acknowledges the original writer sequence");
  assert.equal(store.getStatus().pendingObservations, 2, "new observations remain for the final close flush");
  const closing = store.close();
  assert.equal(store.close(), closing);
  assert.equal(await closing, true);
  assert.deepEqual(acknowledgments, [1, 0, 1], "the Lua watermark suppresses a real duplicate batch");
  assert.equal(store.getStatus().pendingObservations, 0);
  assert.equal(store.recordChallengeEvent("failed"), false);

  const fresh = harness.store(await harness.client());
  const snapshot = await fresh.getSnapshot();
  assert.equal(snapshot.total.requests, 2);
  assert.equal(snapshot.total.completed, 2);
  assert.equal(snapshot.total.byStatusClass["2xx"], 1);
  assert.equal(snapshot.total.byStatusClass["3xx"], 1);
  assert.deepEqual(snapshot.total.latencyMs, { mean: 10, max: 15.75 });
  assert.equal(snapshot.challenges.shown, 1, "lost replies must never double the original count");
  assert.equal(snapshot.challenges.passed, 1, "close must save final observations");
  assert.equal(snapshot.challenges.failed, 0);
});
