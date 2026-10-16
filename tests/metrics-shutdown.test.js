"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const lifecycleSource = fs.readFileSync(require.resolve("../modules/runtime-lifecycle/processLifecycle"), "utf8");

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

function harness({ closeMetrics, closeLogFileWriter = async () => {} } = {}) {
  const events = [];
  const exits = [];
  const incidents = [];
  const deadlines = new Map();
  const module = { exports: {} };
  let drain;
  const fakeProcess = {
    pid: 100,
    ppid: 1,
    uptime: () => 10,
    memoryUsage: () => ({ rss: 1024 * 1024 }),
    exit: code => { events.push(`exit:${code}`); exits.push(code); }
  };
  // The module receives a private process and private timers. The actual test
  // runner's process.exit, signal handlers, and timers remain untouched.
  vm.runInNewContext(lifecycleSource, {
    module,
    process: fakeProcess,
    setImmediate: callback => callback(),
    setTimeout(callback, milliseconds) {
      const timer = {};
      deadlines.set(timer, { callback, milliseconds });
      events.push("deadline:start");
      return timer;
    },
    clearTimeout(timer) {
      deadlines.delete(timer);
      events.push("deadline:clear");
    }
  }, { filename: "processLifecycle.js" });
  const runtimeStats = { shutdownSignals: 0, inFlightRequests: 1 };
  const activeTrackedRequests = new Map([["request", {}]]);
  const dependencies = {
    LOG_LISTENERS: new Set([{ end: () => events.push("sse:end") }]),
    SHUTDOWN_GRACE_MS: 1500,
    activeTrackedRequests,
    addLog() {},
    buildActiveRequestDiagnostics: () => ({}),
    clearBackgroundTasks: () => events.push("background:clear"),
    async closeLogFileWriter(timeout) {
      events.push("logs:start");
      assert.equal(timeout, 1500);
      await closeLogFileWriter();
      events.push("logs:done");
    },
    formatRuntimeCorrelationSuffix: () => "test-correlation",
    getProcessRuntimeMetadata: () => ({}),
    getRuntimeCorrelationMetadata: () => ({}),
    logActiveRequestDiagnostics() {},
    openSockets: new Set([{ destroy: () => events.push("socket:destroy") }]),
    recordRuntimeIncident: kind => incidents.push(kind),
    runtimeStats,
    safeLogValue: String,
    server: {
      close(callback) { events.push("server:drain"); drain = callback; },
      closeIdleConnections() { events.push("server:closeIdle"); }
    },
    summarizeError: String
  };
  if (closeMetrics) {
    dependencies.closeMetrics = async () => {
      events.push("metrics:start");
      await closeMetrics();
      events.push("metrics:done");
    };
  }
  const lifecycle = module.exports(dependencies);
  return {
    ...lifecycle,
    events,
    exits,
    incidents,
    deadlines,
    runtimeStats,
    activeTrackedRequests,
    drain: () => drain(),
    async fireDeadline() {
      assert.equal(deadlines.size, 1);
      const [timer, { callback, milliseconds }] = deadlines.entries().next().value;
      assert.equal(milliseconds, 1500);
      deadlines.delete(timer);
      await callback();
    }
  };
}

test("shutdown drains HTTP before metrics and keeps the deadline until all cleanup completes", { timeout: 2000 }, async () => {
  const metrics = deferred();
  const logs = deferred();
  const logsStarted = deferred();
  const lifecycle = harness({
    closeMetrics: () => metrics.promise,
    closeLogFileWriter: () => { logsStarted.resolve(); return logs.promise; }
  });
  await lifecycle.gracefulShutdown("SIGTERM");
  assert.deepEqual(lifecycle.events, ["background:clear", "sse:end", "deadline:start", "server:drain", "server:closeIdle"]);
  assert.equal(lifecycle.activeTrackedRequests.size, 0);
  assert.equal(lifecycle.runtimeStats.inFlightRequests, 0);

  const draining = lifecycle.drain();
  assert.equal(lifecycle.events.at(-1), "metrics:start");
  assert.equal(lifecycle.deadlines.size, 1, "the original deadline covers metrics cleanup too");
  assert.deepEqual(lifecycle.exits, []);
  await lifecycle.gracefulShutdown("SIGINT");
  assert.equal(lifecycle.runtimeStats.shutdownSignals, 2);
  assert.equal(lifecycle.events.filter(event => event === "server:drain").length, 1);
  assert.equal(lifecycle.incidents.includes("shutdown_signal_while_closing"), true);

  metrics.resolve();
  await logsStarted.promise;
  assert.equal(lifecycle.deadlines.size, 1, "log cleanup remains under the same deadline");
  assert.deepEqual(lifecycle.exits, []);
  logs.resolve();
  await draining;
  assert.deepEqual(lifecycle.events.slice(5), ["metrics:start", "metrics:done", "logs:start", "logs:done", "deadline:clear", "exit:0"]);
  assert.deepEqual(lifecycle.exits, [0]);
  assert.equal(lifecycle.deadlines.size, 0);
});

test("stalled metrics cleanup reaches the deadline and cannot later report a successful exit", { timeout: 2000 }, async () => {
  const metrics = deferred();
  const lifecycle = harness({ closeMetrics: () => metrics.promise });
  await lifecycle.gracefulShutdown("SIGTERM");
  const draining = lifecycle.drain();
  assert.equal(lifecycle.events.at(-1), "metrics:start");
  assert.equal(lifecycle.deadlines.size, 1);
  await lifecycle.fireDeadline();
  assert.deepEqual(lifecycle.exits, [1]);
  assert.equal(lifecycle.incidents.includes("shutdown_forced"), true);
  assert.equal(lifecycle.events.includes("socket:destroy"), true);

  metrics.resolve();
  await draining;
  assert.deepEqual(lifecycle.exits, [1], "a late cleanup completion must preserve the forced failure status");
  assert.equal(lifecycle.events.includes("deadline:clear"), false);
});

test("an HTTP drain completing after the deadline does not start metrics cleanup", async () => {
  const lifecycle = harness({ closeMetrics: async () => {} });
  await lifecycle.gracefulShutdown("SIGTERM");
  await lifecycle.fireDeadline();
  await lifecycle.drain();
  assert.deepEqual(lifecycle.exits, [1]);
  assert.equal(lifecycle.events.includes("metrics:start"), false);
});

test("a failed metrics cleanup still closes logs and clears the deadline", async () => {
  const lifecycle = harness({ closeMetrics: async () => { throw new Error("metrics offline"); } });
  await lifecycle.gracefulShutdown("SIGTERM");
  await lifecycle.drain();
  assert.deepEqual(lifecycle.exits, [0]);
  assert.equal(lifecycle.events.includes("logs:done"), true);
  assert.equal(lifecycle.deadlines.size, 0);
});

test("metrics cleanup remains optional for lifecycle callers", async () => {
  const lifecycle = harness();
  await lifecycle.gracefulShutdown("SIGTERM");
  await lifecycle.drain();
  assert.deepEqual(lifecycle.exits, [0]);
  assert.equal(lifecycle.events.includes("metrics:start"), false);
  assert.equal(lifecycle.deadlines.size, 0);
});
