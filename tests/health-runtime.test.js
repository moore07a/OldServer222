"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const createHealthRuntime = require("../modules/runtime-lifecycle/healthRuntime");
const { readMsEnv, readPositiveIntEnv } = require("../modules/runtime-utils/runtimeConfig");

function withEnv(values, callback) {
  const previous = {};
  for (const [key, value] of Object.entries(values)) {
    previous[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }

  try {
    return callback();
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

function createRuntime(overrides = {}) {
  return createHealthRuntime({
    TURNSTILE_ORIGIN: "https://challenges.cloudflare.com",
    _health: { inflight: false, okStreak: 0, failStreak: 0 },
    addLog() {},
    async fetchWithTimeout() { return { ok: true, status: 200 }; },
    logActiveRequestDiagnostics() {},
    parseMinHourToMs(_value, fallback) { return fallback; },
    readMsEnv,
    readPositiveIntEnv,
    runtimeStats: { maxObservedEventLoopLagMs: 0, turnstileChecks: 0 },
    scheduleFatalExit() {},
    summarizeError(error) { return String(error); },
    trackIntervalHandle(_name, handle) { return handle; },
    ...overrides
  });
}

test("health runtime falls back safely for malformed event-loop settings", () => {
  withEnv({
    EVENT_LOOP_LAG_WARN_MS: "not-a-number",
    EVENT_LOOP_LAG_SAMPLE_MS: "",
    EVENT_LOOP_FATAL_MS: "Infinity",
    EVENT_LOOP_FATAL_CONSECUTIVE: "0"
  }, () => {
    const runtime = createRuntime();
    assert.equal(runtime.EVENT_LOOP_LAG_WARN_MS, 500);
    assert.equal(runtime.EVENT_LOOP_LAG_SAMPLE_MS, 1000);
    assert.equal(runtime.EVENT_LOOP_FATAL_MS, 20000);
    assert.equal(runtime.EVENT_LOOP_FATAL_CONSECUTIVE, 3);
  });
});

test("health runtime clamps event-loop settings to operational minimums", () => {
  withEnv({
    EVENT_LOOP_LAG_WARN_MS: "1",
    EVENT_LOOP_LAG_SAMPLE_MS: "2",
    EVENT_LOOP_FATAL_MS: "3",
    EVENT_LOOP_FATAL_CONSECUTIVE: "4"
  }, () => {
    const runtime = createRuntime();
    assert.equal(runtime.EVENT_LOOP_LAG_WARN_MS, 100);
    assert.equal(runtime.EVENT_LOOP_LAG_SAMPLE_MS, 250);
    assert.equal(runtime.EVENT_LOOP_FATAL_MS, 1000);
    assert.equal(runtime.EVENT_LOOP_FATAL_CONSECUTIVE, 4);
  });
});

test("health runtime keeps fatal lag independent from a lower timer cap", () => {
  withEnv({ EVENT_LOOP_FATAL_MS: undefined }, () => {
    const cappedReadMsEnv = (_name, fallback, minimum) => {
      return Math.max(minimum, Math.min(fallback, 5_000));
    };
    const runtime = createRuntime({ readMsEnv: cappedReadMsEnv });

    assert.equal(runtime.EVENT_LOOP_FATAL_MS, 20_000);
  });
});

test("health runtime keeps warning lag independent from a lower timer cap", () => {
  withEnv({ EVENT_LOOP_LAG_WARN_MS: undefined }, () => {
    const cappedReadMsEnv = (_name, fallback, minimum) => {
      return Math.max(minimum, Math.min(fallback, 200));
    };
    const runtime = createRuntime({ readMsEnv: cappedReadMsEnv });

    assert.equal(runtime.EVENT_LOOP_LAG_WARN_MS, 500);
  });
});

test("healthy provider checks still emit due heartbeats, update timestamps, and clear inflight state", async () => {
  const health = { ok: true, inflight: false, okStreak: 2, failStreak: 0, lastHeartbeat: 0 };
  const runtimeStats = { turnstileChecks: 0 };
  const logs = [];
  let providerCalls = 0;
  let finishProvider;
  const runtime = createRuntime({
    _health: health,
    runtimeStats,
    addLog(message) { logs.push(message); },
    fetchWithTimeout(url, options) {
      providerCalls += 1;
      assert.equal(url, "https://challenges.cloudflare.com/turnstile/v0/api.js");
      assert.equal(options.method, "HEAD");
      return new Promise(resolve => { finishProvider = resolve; });
    }
  });
  const startedAt = Date.now();
  const pending = runtime.checkTurnstileReachable();
  assert.equal(health.inflight, true, "an outstanding provider check is tracked");
  await runtime.checkTurnstileReachable();
  assert.equal(providerCalls, 1, "a pending check prevents overlapping provider requests");
  finishProvider({ ok: true, status: 200 });
  await pending;
  const finishedAt = Date.now();

  assert.equal(health.inflight, false);
  assert.equal(health.ok, true);
  assert.equal(health.okStreak, 3);
  assert.equal(health.failStreak, 0);
  assert.deepEqual(logs, ["[HEALTH] heartbeat status=ok okStreak=3 failStreak=0"]);
  assert.ok(health.lastHeartbeat >= startedAt && health.lastHeartbeat <= finishedAt);
  assert.equal(runtimeStats.turnstileChecks, 1);
  const checkedAt = Date.parse(runtimeStats.lastTurnstileCheckAt);
  assert.ok(checkedAt >= startedAt && checkedAt <= finishedAt);
  assert.ok(runtimeStats.lastTurnstileLatencyMs >= 0);
  assert.equal(runtimeStats.lastTurnstileError, null);
});
