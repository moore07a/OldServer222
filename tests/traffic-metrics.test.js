"use strict";

const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const test = require("node:test");
const createTrafficMetrics = require("../modules/runtime-utils/trafficMetrics");

function createHarness(options = {}) {
  let time = 0;
  const metrics = createTrafficMetrics({ now: () => time, ...options });
  function start({ method = "GET", path = "/landing", headers = {}, status = 200 } = {}) {
    const req = Object.assign(new EventEmitter(), { method, path, headers });
    const res = Object.assign(new EventEmitter(), { statusCode: status });
    let calls = 0;
    metrics.middleware(req, res, () => { calls += 1; });
    assert.equal(calls, 1);
    return {
      req,
      res,
      finish(duration = 0) {
        time += duration;
        res.emit("finish");
      }
    };
  }
  return { ...metrics, start };
}

test("traffic metrics distinguish request kinds without inferring humans or bots", () => {
  const metrics = createHarness();
  for (const path of [
    "/health?poll=1", "/readyz/", "/healthz", "/livez", "/admin/traffic-metrics",
    "/__debug/runtime", "/_debug/ip", "/stream-log", "/view-log", "/view-log-live",
    "/geo-debug", "/robots.txt", "/sitemap.xml", "/favicon.ico", "/ts-client-log",
    "/ads.txt", "/.well-known/security.txt",
    "/turnstile-sitekey", "/api/v1/status", "/_collect", "/_interact", "/_analytics.gif", "/__hp.gif"
  ]) {
    metrics.start({ method: "HEAD", path, headers: { purpose: "prefetch" } }).finish();
  }
  metrics.start({ method: "HEAD", headers: { purpose: "prefetch" } }).finish();
  for (const headers of [
    { purpose: "prefetch" },
    { "sec-purpose": "prefetch;anonymous-client-ip" },
    { "x-purpose": "PRERENDER" },
    { purpose: "preview, prefetch" }
  ]) metrics.start({ headers }).finish();
  metrics.start({ headers: { purpose: "not-prefetch", "user-agent": "a crawler" } }).finish();
  metrics.start({ path: "/administrator" }).finish();
  metrics.start({ path: "/health/landing" }).finish();
  metrics.start({ method: "POST", headers: { purpose: "prefetch" } }).finish();
  const snapshot = metrics.getSnapshot();
  assert.equal(snapshot.scope, "current_process");
  assert.ok(Number.isFinite(Date.parse(snapshot.startedAt)));
  assert.equal(snapshot.byKind.operational.completed, 23);
  assert.equal(snapshot.byKind.head.completed, 1);
  assert.equal(snapshot.byKind.prefetch.completed, 4);
  assert.equal(snapshot.byKind.get.completed, 3);
  assert.equal(snapshot.byKind.other.completed, 1);
  assert.equal(snapshot.total.completed, 32);
});

test("traffic metrics use the supplied optional-prefix matcher with normalized paths", () => {
  const metrics = createHarness({
    pathMatchesWithOptionalPrefix(path, expected, { allowChildren }) {
      const normalized = path.replace(/^\/private(?=\/)/, "");
      return normalized === expected || (allowChildren && normalized.startsWith(`${expected}/`));
    }
  });
  metrics.start({ path: "/private/admin/traffic-metrics/?day=today" }).finish();
  metrics.start({ path: "/private/healthz///?poll=1" }).finish();
  metrics.start({ path: "/private/healthz-extra" }).finish();
  assert.equal(metrics.getSnapshot().byKind.operational.completed, 2);
  assert.equal(metrics.getSnapshot().byKind.get.completed, 1);
});

test("utility routes and their prefixed variants do not inflate ordinary GET metrics", () => {
  const metrics = createHarness({
    pathMatchesWithOptionalPrefix(path, expected, { allowChildren }) {
      const normalized = path.replace(/^\/campaign(?=\/)/, "");
      return normalized === expected || (allowChildren && normalized.startsWith(`${expected}/`));
    }
  });
  metrics.start({ path: "/landing" }).finish(20);
  const before = metrics.getSnapshot();
  for (const prefix of ["", "/campaign"]) {
    for (const path of ["/ads.txt", "/.well-known/security.txt"]) {
      for (const suffix of ["", "/?source=probe"]) {
        metrics.start({ path: `${prefix}${path}${suffix}` }).finish(1000);
      }
    }
  }
  const after = metrics.getSnapshot();
  assert.deepEqual(after.byKind.get, before.byKind.get, "utility requests must not change GET counters or latency");
  assert.equal(after.byKind.operational.completed, 8);
  assert.equal(after.byKind.operational.byStatusClass["2xx"], 8);
  assert.equal(after.byKind.operational.latencyMs.mean, 1000);

  for (const path of ["/ads.txt/landing", "/.well-known/security.txt/landing", "/ads.txt-extra", "/.well-known/security.txt.bak"]) {
    metrics.start({ path }).finish();
  }
  assert.equal(metrics.getSnapshot().byKind.get.completed, 5, "utility classification must not extend to unrelated paths");
});

test("early responses are counted and completion events settle a request once", () => {
  const metrics = createHarness();
  const request = metrics.start({ status: 429 });
  assert.equal(metrics.getSnapshot().total.requests, 1);
  assert.equal(metrics.getSnapshot().total.inFlight, 1);
  request.finish(12);
  request.res.emit("close");
  request.res.emit("error", new Error("late socket error"));
  request.req.emit("aborted");
  request.finish(7);
  const snapshot = metrics.getSnapshot();
  assert.equal(snapshot.total.inFlight, 0);
  assert.equal(snapshot.total.completed, 1);
  assert.equal(snapshot.total.aborted, 0);
  assert.equal(snapshot.total.byStatusClass["4xx"], 1);
  assert.equal(snapshot.total.latencyMs.mean, 12);
  assert.equal(snapshot.byKind.get.completed, 1);
});

test("aborted requests never become successful responses or latency samples", () => {
  const metrics = createHarness();
  for (const event of ["close", "error", "aborted"]) {
    const request = metrics.start();
    if (event === "aborted") request.req.emit(event);
    else request.res.emit(event, new Error("socket closed"));
    request.req.emit("aborted");
    request.res.emit("close");
    request.finish(100);
  }
  const snapshot = metrics.getSnapshot();
  assert.equal(snapshot.total.requests, 3);
  assert.equal(snapshot.total.inFlight, 0);
  assert.equal(snapshot.total.aborted, 3);
  assert.equal(snapshot.total.completed, 0);
  assert.equal(Object.values(snapshot.total.byStatusClass).reduce((sum, value) => sum + value, 0), 0);
  assert.equal(snapshot.total.latencyMs.mean, null);
  assert.equal(snapshot.total.latencyMs.max, null);
  assert.deepEqual(snapshot.total.latencyMs.recent, {
    sampleCount: 0, sampleLimit: 512, p50: null, p95: null, p99: null
  });
});

test("completed responses have fixed status classes and nearest-rank latency percentiles", () => {
  const metrics = createHarness();
  const statuses = [101, 200, 302, 404, 503, 600];
  const durations = [2, 4, 6, 8, 10, 12];
  statuses.forEach((status, index) => metrics.start({ status }).finish(durations[index]));
  const snapshot = metrics.getSnapshot();
  assert.deepEqual(snapshot.total.byStatusClass, {
    "1xx": 1, "2xx": 1, "3xx": 1, "4xx": 1, "5xx": 1, other: 1
  });
  assert.deepEqual(snapshot.total.latencyMs, {
    mean: 7,
    max: 12,
    recent: { sampleCount: 6, sampleLimit: 512, p50: 6, p95: 12, p99: 12 }
  });
  assert.deepEqual(snapshot.byKind.get.latencyMs, snapshot.total.latencyMs);
});

test("recent latency samples evict old values while lifetime mean and max remain", () => {
  const metrics = createHarness();
  metrics.start().finish(1000);
  for (let duration = 1; duration <= 512; duration += 1) metrics.start().finish(duration);
  const snapshot = metrics.getSnapshot();
  assert.equal(snapshot.total.completed, 513);
  assert.equal(snapshot.total.latencyMs.mean, (1000 + 512 * 513 / 2) / 513);
  assert.equal(snapshot.total.latencyMs.max, 1000);
  assert.deepEqual(snapshot.total.latencyMs.recent, {
    sampleCount: 512, sampleLimit: 512, p50: 256, p95: 487, p99: 507
  });
  assert.deepEqual(snapshot.byKind.get.latencyMs, snapshot.total.latencyMs);
});

test("arbitrary paths and headers do not create stored keys, and snapshots are isolated", () => {
  const metrics = createHarness();
  const initial = metrics.getSnapshot();
  for (let index = 0; index < 600; index += 1) {
    metrics.start({
      method: `METHOD${index}`,
      path: `/private-destination-${index}?email=person${index}@example.test`,
      headers: { "user-agent": `agent-${index}`, "x-forwarded-for": `192.0.2.${index}`, purpose: `purpose-${index}` },
      status: 700 + index
    }).finish(1);
  }
  const snapshot = metrics.getSnapshot();
  assert.deepEqual(Object.keys(snapshot.byKind), Object.keys(initial.byKind));
  assert.deepEqual(Object.keys(snapshot.total.byStatusClass), Object.keys(initial.total.byStatusClass));
  assert.equal(snapshot.byKind.other.completed, 600);
  assert.equal(snapshot.total.latencyMs.recent.sampleCount, 512);
  assert.doesNotMatch(JSON.stringify(snapshot), /private-destination|person\d|agent-|192\.0\.2|purpose-/);
  snapshot.total.requests = -1;
  snapshot.total.byStatusClass.other = -1;
  snapshot.total.latencyMs.recent.p99 = -1;
  snapshot.byKind.other.completed = -1;
  delete snapshot.byKind.get;
  const fresh = metrics.getSnapshot();
  assert.equal(fresh.total.requests, 600);
  assert.equal(fresh.total.byStatusClass.other, 600);
  assert.equal(fresh.total.latencyMs.recent.p99, 1);
  assert.equal(fresh.byKind.other.completed, 600);
  assert.equal(fresh.byKind.get.completed, 0);
});

test("challenge observations use fixed labels and independent snapshots", () => {
  const events = [];
  const metrics = createHarness({ onChallengeEvent: event => events.push(event) });
  const expected = ["shown", "passed", "failed", "expired", "expiredOrDuplicate", "providerError", "redirected", "payloadExpired"];
  for (const event of expected) assert.equal(metrics.recordChallengeEvent(event), true);
  for (const event of ["__proto__", "constructor", "https://private.example/", "arbitrary-user-id"]) {
    assert.equal(metrics.recordChallengeEvent(event), false);
  }
  const snapshot = metrics.getSnapshot();
  assert.deepEqual(Object.keys(snapshot.challenges), expected);
  assert.deepEqual(Object.values(snapshot.challenges), expected.map(() => 1));
  assert.deepEqual(events, expected);
  snapshot.challenges.passed = -100;
  assert.equal(metrics.getSnapshot().challenges.passed, 1);
  assert.equal(metrics.getSnapshot().total.requests, 0);
});

test("persistence observers receive each settled request once without affecting responses", () => {
  const observations = [];
  const metrics = createHarness({ onRequest: observation => observations.push(observation) });
  const completed = metrics.start({ status: 403 });
  completed.finish(9);
  completed.res.emit("close");
  const aborted = metrics.start({ method: "HEAD" });
  aborted.req.emit("aborted");
  aborted.finish(10);
  assert.deepEqual(observations, [
    { kind: "get", completed: true, statusClass: "4xx", durationMs: 9 },
    { kind: "head", completed: false, statusClass: "2xx", durationMs: 0 }
  ]);
  const broken = createHarness({ onRequest() { throw new Error("storage unavailable"); }, onChallengeEvent() { throw new Error("storage unavailable"); } });
  assert.doesNotThrow(() => broken.start().finish(4));
  assert.doesNotThrow(() => broken.recordChallengeEvent("shown"));
  assert.equal(broken.getSnapshot().total.completed, 1);
  assert.equal(broken.getSnapshot().challenges.shown, 1);
});
