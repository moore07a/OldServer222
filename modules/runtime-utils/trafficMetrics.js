"use strict";

const { performance } = require("node:perf_hooks");

const SAMPLE_LIMIT = 512;
const KINDS = ["operational", "head", "prefetch", "get", "other"];
const STATUS_CLASSES = ["1xx", "2xx", "3xx", "4xx", "5xx", "other"];
const CHALLENGE_EVENTS = ["shown", "passed", "failed", "expired", "expiredOrDuplicate", "providerError", "redirected", "payloadExpired"];
// Include retired log paths so their rejected child paths are not visitor traffic.
const OPERATIONAL_SUBTREES = ["/admin", "/__debug", "/_debug", "/stream-log", "/view-log", "/view-log-live"];
const OPERATIONAL_PATHS = [
  "/health", "/readyz", "/healthz", "/livez",
  "/geo-debug",
  "/robots.txt", "/sitemap.xml", "/favicon.ico",
  "/ads.txt", "/.well-known/security.txt",
  "/ts-client-log", "/turnstile-sitekey", "/api/v1/status",
  "/_collect", "/_interact", "/_analytics.gif", "/__hp.gif"
];

function createTrafficMetrics({ pathMatchesWithOptionalPrefix, now = () => performance.now(), onRequest = () => {}, onChallengeEvent = () => {} } = {}) {
  const startedAt = new Date().toISOString();
  const matchesPath = pathMatchesWithOptionalPrefix || ((pathValue, expected, { allowChildren }) => (
    pathValue === expected || (allowChildren && pathValue.startsWith(`${expected}/`))
  ));

  function createCounters() {
    return {
      requests: 0,
      inFlight: 0,
      completed: 0,
      aborted: 0,
      byStatusClass: Object.fromEntries(STATUS_CLASSES.map((key) => [key, 0])),
      durationSum: 0,
      durationMax: 0,
      samples: [],
      nextSample: 0
    };
  }

  const total = createCounters();
  const byKind = Object.fromEntries(KINDS.map((kind) => [kind, createCounters()]));
  const challenges = Object.fromEntries(CHALLENGE_EVENTS.map((event) => [event, 0]));

  function recordChallengeEvent(event) {
    if (!Object.hasOwn(challenges, event)) return false;
    challenges[event] += 1;
    try { onChallengeEvent(event); } catch {}
    return true;
  }

  function classifyRequest(req) {
    const pathValue = String(req.path || req.originalUrl || req.url || "/")
      .split(/[?#]/, 1)[0].replace(/\/+$/, "") || "/";
    if (
      OPERATIONAL_PATHS.some((expected) => matchesPath(pathValue, expected, { allowChildren: false })) ||
      OPERATIONAL_SUBTREES.some((expected) => matchesPath(pathValue, expected, { allowChildren: true }))
    ) return "operational";

    const method = String(req.method || "GET").toUpperCase();
    if (method === "HEAD") return "head";
    if (method !== "GET") return "other";

    const isPrefetch = ["purpose", "sec-purpose", "x-purpose"].some((name) => {
      const value = typeof req.get === "function" ? req.get(name) : (req.headers || {})[name];
      return /(?:^|[\s,;])(?:prefetch|prerender)(?=$|[\s,;])/i.test(String(value || ""));
    });
    return isPrefetch ? "prefetch" : "get";
  }

  function recordCompletion(counters, statusClass, duration) {
    counters.completed += 1;
    counters.byStatusClass[statusClass] += 1;
    counters.durationSum += duration;
    counters.durationMax = Math.max(counters.durationMax, duration);
    counters.samples[counters.nextSample] = duration;
    counters.nextSample = (counters.nextSample + 1) % SAMPLE_LIMIT;
  }

  function middleware(req, res, next) {
    const kind = classifyRequest(req);
    const counters = byKind[kind];
    const started = now();
    for (const group of [total, counters]) {
      group.requests += 1;
      group.inFlight += 1;
    }

    let settled = false;
    function settle(completed) {
      if (settled) return;
      settled = true;
      const status = Number(res.statusCode);
      const statusClass = Number.isInteger(status) && status >= 100 && status < 600
        ? `${Math.floor(status / 100)}xx` : "other";
      const duration = completed ? Math.max(0, now() - started) : 0;
      for (const group of [total, counters]) {
        group.inFlight -= 1;
        if (completed) recordCompletion(group, statusClass, duration);
        else group.aborted += 1;
      }
      try { onRequest({ kind, completed, statusClass, durationMs: duration }); } catch {}
    }

    res.on("finish", () => settle(true));
    res.on("close", () => settle(false));
    res.on("error", () => settle(false));
    req.on("aborted", () => settle(false));
    next();
  }

  function snapshotCounters(counters) {
    const sorted = counters.samples.slice().sort((a, b) => a - b);
    const percentile = (percent) => sorted.length ? sorted[Math.ceil(sorted.length * percent / 100) - 1] : null;
    return {
      requests: counters.requests,
      inFlight: counters.inFlight,
      completed: counters.completed,
      aborted: counters.aborted,
      byStatusClass: { ...counters.byStatusClass },
      latencyMs: {
        mean: counters.completed ? counters.durationSum / counters.completed : null,
        max: counters.completed ? counters.durationMax : null,
        recent: {
          sampleCount: sorted.length,
          sampleLimit: SAMPLE_LIMIT,
          p50: percentile(50),
          p95: percentile(95),
          p99: percentile(99)
        }
      }
    };
  }

  function getSnapshot() {
    return {
      scope: "current_process",
      startedAt,
      total: snapshotCounters(total),
      byKind: Object.fromEntries(KINDS.map((kind) => [kind, snapshotCounters(byKind[kind])])),
      challenges: { ...challenges }
    };
  }

  return { middleware, getSnapshot, recordChallengeEvent };
}

module.exports = createTrafficMetrics;
