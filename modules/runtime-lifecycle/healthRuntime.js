"use strict";

module.exports = function createHealthRuntime(dependencies) {
  const {
    TURNSTILE_ORIGIN, _health, addLog, fetchWithTimeout,
    logActiveRequestDiagnostics, parseMinHourToMs, runtimeStats,
    scheduleFatalExit, summarizeError, trackIntervalHandle
  } = dependencies;

  const HEALTH_INTERVAL_MS = parseMinHourToMs(process.env.HEALTH_INTERVAL ?? "5m", 5 * 60 * 1000);
  const HEALTH_HEARTBEAT_MS = parseMinHourToMs(process.env.HEALTH_HEARTBEAT ?? "2h", 2 * 60 * 60 * 1000);

  // Event-loop monitor settings are immutable after startup.
  const EVENT_LOOP_LAG_WARN_MS = Math.max(100, parseInt(process.env.EVENT_LOOP_LAG_WARN_MS || "500", 10));
  const EVENT_LOOP_LAG_SAMPLE_MS = Math.max(250, parseInt(process.env.EVENT_LOOP_LAG_SAMPLE_MS || "1000", 10));
  const EVENT_LOOP_FATAL_MS = Math.max(1000, parseInt(process.env.EVENT_LOOP_FATAL_MS || "20000", 10));
  const EVENT_LOOP_FATAL_CONSECUTIVE = Math.max(1, parseInt(process.env.EVENT_LOOP_FATAL_CONSECUTIVE || "3", 10));
  let eventLoopStallConsecutiveHits = 0;

  function startEventLoopLagMonitor() {
    let expected = Date.now() + EVENT_LOOP_LAG_SAMPLE_MS;
    const interval = setInterval(() => {
      const now = Date.now();
      const lag = now - expected;
      expected = now + EVENT_LOOP_LAG_SAMPLE_MS;

      if (lag > runtimeStats.maxObservedEventLoopLagMs) {
        runtimeStats.maxObservedEventLoopLagMs = lag;
        runtimeStats.lastEventLoopLagAt = new Date(now).toISOString();
      }

      if (lag >= EVENT_LOOP_FATAL_MS) {
        eventLoopStallConsecutiveHits += 1;
      } else {
        eventLoopStallConsecutiveHits = 0;
      }

      if (lag >= EVENT_LOOP_FATAL_MS && eventLoopStallConsecutiveHits >= EVENT_LOOP_FATAL_CONSECUTIVE) {
        addLog(`[FATAL] event-loop-stall lag=${Math.round(lag)}ms threshold=${EVENT_LOOP_FATAL_MS}ms hits=${eventLoopStallConsecutiveHits}`);
        logActiveRequestDiagnostics("event_loop_stall", now);
        scheduleFatalExit("eventLoopStall", new Error(`event loop lag ${Math.round(lag)}ms >= ${EVENT_LOOP_FATAL_MS}ms for ${eventLoopStallConsecutiveHits} sample(s)`));
        return;
      }

      if (lag < EVENT_LOOP_LAG_WARN_MS) return;

      const mem = process.memoryUsage();
      const rssMb = Math.round((mem.rss / (1024 * 1024)) * 10) / 10;
      const heapUsedMb = Math.round((mem.heapUsed / (1024 * 1024)) * 10) / 10;
      addLog(`[HEALTH] event-loop-lag=${Math.round(lag)}ms sample=${EVENT_LOOP_LAG_SAMPLE_MS}ms rssMb=${rssMb} heapUsedMb=${heapUsedMb}`);
    }, EVENT_LOOP_LAG_SAMPLE_MS);
    return trackIntervalHandle("eventLoopLag", interval);
  }

  async function checkTurnstileReachable() {
    if (_health.inflight) return;
    _health.inflight = true;

    const now = Date.now();
    const startedAtMs = Date.now();
    runtimeStats.turnstileChecks += 1;
    runtimeStats.lastTurnstileCheckAt = new Date(startedAtMs).toISOString();

    try {
      const url = `${TURNSTILE_ORIGIN}/turnstile/v0/api.js`;
      const r = await fetchWithTimeout(url, { method: "HEAD" }, process.env.TURNSTILE_HEALTH_TIMEOUT_MS || 5000);
      const ok = r.ok;
      runtimeStats.lastTurnstileLatencyMs = Date.now() - startedAtMs;
      runtimeStats.lastTurnstileError = null;

      if (ok) { _health.okStreak++; _health.failStreak = 0; }
      else    { _health.failStreak++; _health.okStreak  = 0; }

      if (_health.ok !== ok) {
        addLog(`[HEALTH] turnstile HEAD ${r.status} ${ok ? "ok" : "not-ok"} (change)`);
        _health.ok = ok;
        _health.lastHeartbeat = now;
      } else if (now - _health.lastHeartbeat >= HEALTH_HEARTBEAT_MS) {
        addLog(`[HEALTH] heartbeat status=${ok ? "ok" : "not-ok"} okStreak=${_health.okStreak} failStreak=${_health.failStreak}`);
        _health.lastHeartbeat = now;
      }
    } catch (e) {
      runtimeStats.turnstileCheckErrors += 1;
      const errSummary = summarizeError(e);
      runtimeStats.lastTurnstileLatencyMs = Date.now() - startedAtMs;
      runtimeStats.lastTurnstileError = {
        at: new Date().toISOString(),
        message: errSummary
      };

      if (errSummary && /timeout|aborted|aborterror/i.test(errSummary)) {
        runtimeStats.turnstileCheckTimeouts += 1;
      }

      _health.failStreak++; _health.okStreak = 0;
      if (_health.ok !== false) {
        addLog(`[HEALTH] turnstile HEAD error ${String(e)} (change)`);
        _health.ok = false;
        _health.lastHeartbeat = now;
      } else if (now - _health.lastHeartbeat >= HEALTH_HEARTBEAT_MS) {
        addLog(`[HEALTH] heartbeat status=not-ok okStreak=${_health.okStreak} failStreak=${_health.failStreak}`);
        _health.lastHeartbeat = now;
      }
    } finally {
      _health.inflight = false;
    }
  }

  return {
    EVENT_LOOP_FATAL_CONSECUTIVE, EVENT_LOOP_FATAL_MS, EVENT_LOOP_LAG_SAMPLE_MS,
    EVENT_LOOP_LAG_WARN_MS, HEALTH_HEARTBEAT_MS, HEALTH_INTERVAL_MS,
    checkTurnstileReachable, startEventLoopLagMonitor
  };
};
