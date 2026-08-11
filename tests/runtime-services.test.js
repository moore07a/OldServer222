"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const createRuntimeServices = require("../modules/runtime-utils/runtimeServices");

function createServices(fetchImpl) {
  return createRuntimeServices({
    BROWNOUT_DURATION_MS: 1_000,
    BROWNOUT_TIMEOUT_THRESHOLD: 3,
    BROWNOUT_WINDOW_MS: 1_000,
    CIRCUIT_BREAKER_COOLDOWN_MS: 1_000,
    CIRCUIT_BREAKER_THRESHOLD: 3,
    FETCH_TIMEOUT_MS_DEFAULT: 1_000,
    GEO_ENRICH_CACHE_MAX_ENTRIES: 10,
    GEO_ENRICH_IPAPI_ENABLED: false,
    GEO_ENRICH_IPAPI_TIMEOUT_MS: 500,
    GEO_ENRICH_IPAPI_TTL_MS: 1_000,
    GEO_SOURCE_DEBUG: false,
    IPINFO_LITE_CACHE_MAX_ENTRIES: 10,
    IPINFO_LITE_CACHE_TTL_MS: 1_000,
    IPINFO_LITE_ENABLED: false,
    IPINFO_LITE_NEGATIVE_CACHE_TTL_MS: 100,
    IPINFO_LITE_TIMEOUT_MS: 500,
    IPINFO_TOKEN: "",
    MAX_TIMER_MS: 2_147_483_647,
    addLog() {},
    boundedMapSet(map, key, value) { map.set(key, value); },
    clampMs(value, min, max) { return Math.min(max, Math.max(min, value)); },
    evictOldestMapEntry() { return false; },
    fetch: fetchImpl,
    isKnownProxyIp() { return false; },
    normalizeIpv4Mapped(value) { return value; },
    safeLogValue(value) { return String(value); },
    summarizeError(error) { return String(error); }
  });
}

function pendingFetch(_url, { signal }) {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(signal.reason);
    signal.addEventListener("abort", () => reject(signal.reason), { once: true });
  });
}

test("fetchWithTimeout preserves cancellation from an already-aborted caller signal", async () => {
  const services = createServices(pendingFetch);
  const caller = new AbortController();
  const reason = new Error("request disconnected");
  caller.abort(reason);

  await assert.rejects(
    services.fetchWithTimeout("https://example.test", { signal: caller.signal }, 5_000),
    (error) => error === reason
  );
});

test("fetchWithTimeout forwards caller cancellation while a fetch is in flight", async () => {
  const services = createServices(pendingFetch);
  const caller = new AbortController();
  const reason = new Error("request cancelled");
  const request = services.fetchWithTimeout(
    "https://example.test",
    { signal: caller.signal },
    5_000
  );

  caller.abort(reason);

  await assert.rejects(request, (error) => error === reason);
});

test("fetchWithTimeout still enforces its own deadline", async () => {
  const services = createServices(pendingFetch);

  await assert.rejects(
    services.fetchWithTimeout("https://example.test", {}, 5),
    /fetch timeout after 5ms/
  );
});
