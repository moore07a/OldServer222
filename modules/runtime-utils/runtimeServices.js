module.exports = function createRuntimeServices(dependencies) {
  const {
    BROWNOUT_DURATION_MS, BROWNOUT_TIMEOUT_THRESHOLD, BROWNOUT_WINDOW_MS,
    CIRCUIT_BREAKER_COOLDOWN_MS, CIRCUIT_BREAKER_THRESHOLD, FETCH_TIMEOUT_MS_DEFAULT,
    GEO_ENRICH_CACHE_MAX_ENTRIES, GEO_ENRICH_IPAPI_ENABLED, GEO_ENRICH_IPAPI_TIMEOUT_MS,
    GEO_ENRICH_IPAPI_TTL_MS, GEO_SOURCE_DEBUG, IPINFO_LITE_CACHE_MAX_ENTRIES,
    IPINFO_LITE_CACHE_TTL_MS, IPINFO_LITE_ENABLED, IPINFO_LITE_NEGATIVE_CACHE_TTL_MS,
    IPINFO_LITE_TIMEOUT_MS, IPINFO_TOKEN, MAX_TIMER_MS, addLog, boundedMapSet, clampMs,
    evictOldestMapEntry, fetch, isKnownProxyIp, normalizeIpv4Mapped, safeLogValue, summarizeError
  } = dependencies;
const backgroundTaskHandles = {
  health: null,
  eventLoopLag: null,
  memoryCleanup: null,
  logFlush: null,
  behavioralCleanup: null,
  rateLimiterCleanup: null
};
const dependencyCircuitState = new Map();
const timeoutTimestamps = [];
let brownoutUntilMs = 0;

function trackIntervalHandle(name, handle) {
  if (!handle) return null;
  backgroundTaskHandles[name] = handle;
  if (typeof handle.unref === "function") handle.unref();
  return handle;
}

function clearBackgroundTasks() {
  for (const [name, handle] of Object.entries(backgroundTaskHandles)) {
    if (!handle) continue;
    try { clearInterval(handle); } catch {}
    backgroundTaskHandles[name] = null;
  }
}

function normalizeTimeoutMs(ms, fallbackMs = FETCH_TIMEOUT_MS_DEFAULT) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 0) {
    return clampMs(fallbackMs, 1, MAX_TIMER_MS);
  }
  return clampMs(Math.trunc(n), 1, MAX_TIMER_MS);
}

async function fetchWithTimeout(url, options = {}, timeoutMs = FETCH_TIMEOUT_MS_DEFAULT) {
  const controller = new AbortController();
  const timeout = normalizeTimeoutMs(timeoutMs, 8000);
  const callerSignal = options && options.signal;
  const forwardCallerAbort = () => {
    const reason = callerSignal && callerSignal.reason;
    controller.abort(reason === undefined ? new Error("fetch aborted by caller") : reason);
  };

  if (callerSignal) {
    if (callerSignal.aborted) forwardCallerAbort();
    else callerSignal.addEventListener("abort", forwardCallerAbort, { once: true });
  }
  const timer = setTimeout(() => controller.abort(new Error(`fetch timeout after ${timeout}ms`)), timeout);

  try {
    const merged = {
      ...options,
      signal: controller.signal
    };
    return await fetch(url, merged);
  } finally {
    clearTimeout(timer);
    if (callerSignal) callerSignal.removeEventListener("abort", forwardCallerAbort);
  }
}

async function fetchWithRuntimeSpan(spanName, url, options = {}, timeoutMs = FETCH_TIMEOUT_MS_DEFAULT) {
  const circuit = dependencyCircuitState.get(spanName) || { failures: 0, openUntil: 0 };
  if (circuit.openUntil > Date.now()) {
    addLog(`[DEP:open] span=${safeLogValue(spanName, 64)} openForMs=${circuit.openUntil - Date.now()}`);
    throw new Error(`circuit_open:${spanName}`);
  }

  const started = Date.now();
  try {
    const response = await fetchWithTimeout(url, options, timeoutMs);
    const shouldCountAsFailure = response.status >= 500 || response.status === 429;
    if (shouldCountAsFailure) {
      const priorFailures = dependencyCircuitState.get(spanName)?.failures || 0;
      const failures = priorFailures + 1;
      const openUntil = failures >= CIRCUIT_BREAKER_THRESHOLD ? Date.now() + CIRCUIT_BREAKER_COOLDOWN_MS : 0;
      dependencyCircuitState.set(spanName, { failures, openUntil });
      if (openUntil > 0) {
        addLog(`[DEP:breaker-open] span=${safeLogValue(spanName, 64)} failures=${failures} cooldownMs=${CIRCUIT_BREAKER_COOLDOWN_MS} status=${response.status}`);
      }
    } else {
      dependencyCircuitState.set(spanName, { failures: 0, openUntil: 0 });
    }
    addLog(`[DEP:finish] span=${safeLogValue(spanName, 64)} status=${response.status} durationMs=${Date.now() - started}`);
    return response;
  } catch (err) {
    const priorFailures = dependencyCircuitState.get(spanName)?.failures || 0;
    const failures = priorFailures + 1;
    const openUntil = failures >= CIRCUIT_BREAKER_THRESHOLD ? Date.now() + CIRCUIT_BREAKER_COOLDOWN_MS : 0;
    dependencyCircuitState.set(spanName, { failures, openUntil });
    if (openUntil > 0) {
      addLog(`[DEP:breaker-open] span=${safeLogValue(spanName, 64)} failures=${failures} cooldownMs=${CIRCUIT_BREAKER_COOLDOWN_MS}`);
    }
    addLog(`[DEP:error] span=${safeLogValue(spanName, 64)} durationMs=${Date.now() - started} err=${safeLogValue(summarizeError(err), 180)}`);
    throw err;
  }
}

function markTimeoutAndMaybeBrownout(now = Date.now()) {
  timeoutTimestamps.push(now);
  while (timeoutTimestamps.length && (now - timeoutTimestamps[0]) > BROWNOUT_WINDOW_MS) {
    timeoutTimestamps.shift();
  }
  if (timeoutTimestamps.length >= BROWNOUT_TIMEOUT_THRESHOLD) {
    brownoutUntilMs = Math.max(brownoutUntilMs, now + BROWNOUT_DURATION_MS);
    addLog(`[BROWNOUT] enabled windowMs=${BROWNOUT_WINDOW_MS} durationMs=${BROWNOUT_DURATION_MS} threshold=${BROWNOUT_TIMEOUT_THRESHOLD} observed=${timeoutTimestamps.length}`);
  }
}

function isBrownoutActive(now = Date.now()) {
  return brownoutUntilMs > now;
}

// Optional IPinfo Lite API fallback if trusted edge/platform geo is unavailable
const ipinfoLiteCache = new Map();
const ipinfoLiteStatusLine = IPINFO_LITE_ENABLED
  ? `ℹ️ IPinfo Lite API enabled as country/ASN fallback ttlMs=${IPINFO_LITE_CACHE_TTL_MS} timeoutMs=${IPINFO_LITE_TIMEOUT_MS}`
  : "⚠️ IPinfo Lite API disabled; ALLOWED_COUNTRIES depends on trusted upstream geo headers";

function getGeoIpFreshnessLines() {
  return [];
}

function normalizeAsn(value) {
  const raw = String(value || "").trim().toUpperCase();
  if (!raw) return null;
  const match = raw.match(/^(?:AS)?\s*(\d+)$/i);
  if (match) return `AS${match[1]}`;
  return raw;
}

function normalizeIpinfoLitePayload(data) {
  if (!data || typeof data !== "object") return null;
  const country = String(data.country_code || data.country || "").trim().toUpperCase();
  const asn = normalizeAsn(data.asn);
  if (!country && !asn) return null;
  return {
    country: country || null,
    asn,
    asName: data.as_name ? String(data.as_name).slice(0, 120) : null,
    asDomain: data.as_domain ? String(data.as_domain).slice(0, 120) : null,
    source: "ipinfo-lite"
  };
}

function pruneIpinfoLiteCache(now = Date.now()) {
  if (ipinfoLiteCache.size <= IPINFO_LITE_CACHE_MAX_ENTRIES) return;
  for (const [key, value] of ipinfoLiteCache) {
    if (!value || (now - (value.ts || 0)) >= IPINFO_LITE_CACHE_TTL_MS) ipinfoLiteCache.delete(key);
  }
  while (ipinfoLiteCache.size > IPINFO_LITE_CACHE_MAX_ENTRIES) evictOldestMapEntry(ipinfoLiteCache);
}

async function lookupIpinfoLite(ip) {
  if (!IPINFO_LITE_ENABLED || !IPINFO_TOKEN) return null;
  const normalizedIp = normalizeIpv4Mapped(ip);
  if (!normalizedIp || isKnownProxyIp(normalizedIp)) return null;

  const now = Date.now();
  pruneIpinfoLiteCache(now);
  const cached = ipinfoLiteCache.get(normalizedIp);
  if (cached) {
    const ttl = cached.status === "ok" ? IPINFO_LITE_CACHE_TTL_MS : IPINFO_LITE_NEGATIVE_CACHE_TTL_MS;
    if ((now - cached.ts) < ttl) return cached.value || null;
  }

  const url = `https://api.ipinfo.io/lite/${encodeURIComponent(normalizedIp)}?token=${encodeURIComponent(IPINFO_TOKEN)}`;
  try {
    const response = await fetchWithRuntimeSpan("ipinfo_lite", url, {
      headers: {
        "Accept": "application/json",
        "User-Agent": "aes-turnstile-geoip/1.0"
      }
    }, IPINFO_LITE_TIMEOUT_MS);

    if (!response.ok) {
      throw new Error(`status_${response.status}`);
    }

    const payload = await response.json();
    const value = normalizeIpinfoLitePayload(payload);
    boundedMapSet(ipinfoLiteCache, normalizedIp, { ts: now, value, status: "ok" }, IPINFO_LITE_CACHE_MAX_ENTRIES);
    return value;
  } catch (err) {
    boundedMapSet(ipinfoLiteCache, normalizedIp, { ts: now, value: null, status: err && err.name === "AbortError" ? "timeout" : "error" }, IPINFO_LITE_CACHE_MAX_ENTRIES);
    if (GEO_SOURCE_DEBUG || process.env.IP_DEBUG === "1") {
      addLog(`[GEO-SOURCE] ip=${safeLogValue(normalizedIp)} source=ipinfo-lite err=${safeLogValue(String(err && err.message || err), 80)}`);
    }
    return null;
  }
}

const geoEnrichCache = new Map();
function maybeEnrichGeoAsync(ip, resolvedCountry, source) {
  if (!GEO_ENRICH_IPAPI_ENABLED) return;
  const normalizedIp = normalizeIpv4Mapped(ip);
  if (!normalizedIp || isKnownProxyIp(normalizedIp)) return;

  const now = Date.now();
  if (geoEnrichCache.size > GEO_ENRICH_CACHE_MAX_ENTRIES) {
    for (const [k, v] of geoEnrichCache) {
      if (!v || (now - (v.ts || 0)) >= GEO_ENRICH_IPAPI_TTL_MS) geoEnrichCache.delete(k);
    }
    while (geoEnrichCache.size > GEO_ENRICH_CACHE_MAX_ENTRIES) evictOldestMapEntry(geoEnrichCache);
  }
  const cached = geoEnrichCache.get(normalizedIp);
  if (cached && (now - cached.ts) < GEO_ENRICH_IPAPI_TTL_MS) return;
  boundedMapSet(geoEnrichCache, normalizedIp, { ts: now }, GEO_ENRICH_CACHE_MAX_ENTRIES);

  const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
  const timeout = setTimeout(() => {
    if (controller) controller.abort();
  }, Math.max(100, GEO_ENRICH_IPAPI_TIMEOUT_MS));

  const url = `https://ipapi.co/${encodeURIComponent(normalizedIp)}/json/`;
  fetch(url, { signal: controller ? controller.signal : undefined })
    .then(r => r.ok ? r.json() : Promise.reject(new Error(`status_${r.status}`)))
    .then(data => {
      const country = String(data?.country_code || "").toUpperCase();
      const asn = String(data?.asn || "").toUpperCase();
      addLog(`[GEO-ENRICH] ip=${safeLogValue(normalizedIp)} source=${safeLogValue(source, 32)} appCountry=${safeLogValue(String(resolvedCountry || ""), 8)} ipapiCountry=${safeLogValue(country, 8)} ipapiAsn=${safeLogValue(asn, 32)}`);
    })
    .catch(err => {
      addLog(`[GEO-ENRICH] ip=${safeLogValue(normalizedIp)} source=${safeLogValue(source, 32)} err=${safeLogValue(String(err && err.message || err), 80)}`);
    })
    .finally(() => clearTimeout(timeout));
}



  return {
    backgroundTaskHandles,
    dependencyCircuitState,
    timeoutTimestamps,
    trackIntervalHandle,
    clearBackgroundTasks,
    normalizeTimeoutMs,
    fetchWithTimeout,
    fetchWithRuntimeSpan,
    markTimeoutAndMaybeBrownout,
    isBrownoutActive,
    ipinfoLiteCache,
    ipinfoLiteStatusLine,
    getGeoIpFreshnessLines,
    normalizeAsn,
    normalizeIpinfoLitePayload,
    pruneIpinfoLiteCache,
    lookupIpinfoLite,
    geoEnrichCache,
    maybeEnrichGeoAsync,
  };
};
