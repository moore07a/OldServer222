"use strict";

const { isIP } = require("node:net");
const { performance } = require("node:perf_hooks");

const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_DAILY_BUDGET = 1000;
const MAX_RESPONSE_BYTES = 16 * 1024;
const SAFE_CODES = new Set([
  "risk_provider_aborted", "risk_provider_network", "risk_provider_invalid_ip",
  "risk_provider_budget_exhausted", "risk_provider_redirect", "risk_provider_rate_limited",
  "risk_provider_http_error", "risk_provider_invalid_response", "risk_provider_response_too_large",
  "risk_provider_api_error", "risk_provider_invalid_indicator_types",
]);
const INDICATOR_FIELDS = ["is_datacenter", "is_proxy", "is_vpn"];

function indicatorType(value, present) {
  if (!present) return "absent";
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

function providerError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

async function discardBody(response) {
  try {
    await response?.body?.cancel?.();
  } catch {}
}

async function readBoundedJson(response, maximumBytes, signal) {
  const declaredLength = response.headers?.get?.("content-length");
  if (declaredLength && Number(declaredLength) > maximumBytes) {
    await discardBody(response);
    throw providerError("risk_provider_response_too_large");
  }
  // Read the byte stream rather than response.json()/text(), which can allocate
  // an unbounded response before its size can be checked.
  if (typeof response.body?.getReader !== "function") {
    await discardBody(response);
    throw providerError("risk_provider_invalid_response");
  }
  const reader = response.body.getReader();
  let completed = false;
  let cancellation = null;
  const bytes = Buffer.allocUnsafe(maximumBytes);
  let length = 0;
  function cancelReader() {
    if (!cancellation) {
      try { cancellation = Promise.resolve(reader.cancel()).catch(() => {}); }
      catch { cancellation = Promise.resolve(); }
    }
    return cancellation;
  }
  const onAbort = () => { void cancelReader(); };
  signal?.addEventListener("abort", onAbort, { once: true });
  try {
    while (true) {
      if (signal?.aborted) throw providerError("risk_provider_aborted");
      const next = await reader.read();
      if (signal?.aborted) throw providerError("risk_provider_aborted");
      if (next.done) break;
      if (!(next.value instanceof Uint8Array)) throw providerError("risk_provider_invalid_response");
      length += next.value.byteLength;
      if (length > maximumBytes) throw providerError("risk_provider_response_too_large");
      // Copy into one fixed buffer, retaining neither unbounded chunk metadata
      // nor a tiny view onto an upstream chunk's larger ArrayBuffer.
      bytes.set(next.value, length - next.value.byteLength);
    }
    completed = true;
    try {
      return JSON.parse(bytes.subarray(0, length).toString("utf8"));
    } catch {
      throw providerError("risk_provider_invalid_response");
    }
  } finally {
    signal?.removeEventListener("abort", onAbort);
    // A caller-visible deadline is enforced by the cache. Keep ownership of
    // an ignored read/cancel until its original operation actually settles.
    if (!completed) await cancelReader();
    try { reader.releaseLock(); } catch {}
  }
}

// Official reference: https://github.com/ipapi-is/ipapi#the-ip-api documents
// anonymous access (1,000 requests/day), is_datacenter, is_proxy and is_vpn.
// IPQuery's official account and SDK document a free HTTPS API with the same
// booleans inside `risk`: https://github.com/ipqwery/ipqwery and
// https://github.com/ipqwery/ipapi-py/blob/main/ipapi/client.py . No claim is
// made about unlimited use. The application keeps its conservative daily cap.
// Neither adapter documents residential-proxy classification; do not infer it.
// This adapter makes no calls until explicitly enabled. The caller owns its
// bounded cache, concurrency and timeout; failed attempts also consume budget.
function createFreeIpIntelligenceProvider({
  enabled = false,
  provider = "ipapi.is",
  fetch: fetchImpl = globalThis.fetch,
  dailyBudget = 900,
  maxResponseBytes = MAX_RESPONSE_BYTES,
  now = () => performance.now(),
} = {}) {
  const budget = Number.isFinite(Number(dailyBudget))
    ? Math.min(MAX_DAILY_BUDGET, Math.max(0, Math.floor(Number(dailyBudget)))) : 900;
  const byteLimit = Number.isFinite(Number(maxResponseBytes))
    ? Math.min(MAX_RESPONSE_BYTES, Math.max(1, Math.floor(Number(maxResponseBytes)))) : MAX_RESPONSE_BYTES;
  const providerId = ["ipapi.is", "ipquery"].includes(provider) ? provider : null;
  const configured = providerId !== null && typeof fetchImpl === "function";
  const active = enabled === true && configured;
  // At most 1,000 timestamps are retained, independent of unique visitor IPs.
  const attempts = [];
  let failureCode = null;
  let lastResult = null;
  let unknownReason = null;
  let indicatorTypes = null;
  let lastHttpStatus = null;

  function prune() {
    const instant = now();
    while (attempts.length && instant - attempts[0] >= DAY_MS) attempts.shift();
    return instant;
  }

  function getStatus() {
    const instant = prune();
    return {
      enabled: active,
      configured,
      provider: providerId,
      dailyBudget: budget,
      used: attempts.length,
      remaining: Math.max(0, budget - attempts.length),
      resetAfterSec: attempts.length ? Math.max(0, Math.ceil((DAY_MS - (instant - attempts[0])) / 1000)) : 0,
      quotaScope: "process",
      failureCode,
      lastResult,
      unknownReason,
      indicatorTypes: indicatorTypes ? { ...indicatorTypes } : null,
      lastHttpStatus,
    };
  }

  async function lookup(ip, { signal } = {}) {
    if (!active) return null;
    let summary = null;
    let httpStatus = null;
    try {
      if (typeof ip !== "string" || ip.length > 45 || !isIP(ip) || ip.includes("%")) {
        throw providerError("risk_provider_invalid_ip");
      }
      if (signal?.aborted) throw providerError("risk_provider_aborted");
      const instant = prune();
      if (attempts.length >= budget) throw providerError("risk_provider_budget_exhausted");
      attempts.push(instant);
      const endpoint = providerId === "ipquery"
        ? new URL(`https://api.ipquery.io/${encodeURIComponent(ip)}`)
        : new URL("https://api.ipapi.is/");
      if (providerId === "ipapi.is") endpoint.searchParams.set("q", ip);
      // Do not race cancellation against this promise. If an injected fetch
      // ignores AbortSignal, its cache slot must stay occupied until it settles.
      const response = await fetchImpl(endpoint.href, {
        method: "GET",
        headers: { Accept: "application/json" },
        signal,
        redirect: "error",
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
      });
      httpStatus = Number.isInteger(response?.status) && response.status >= 100 && response.status <= 599
        ? response.status : null;
      if (signal?.aborted) {
        await discardBody(response);
        throw providerError("risk_provider_aborted");
      }
      if (response?.redirected || (response?.status >= 300 && response.status < 400)) {
        await discardBody(response);
        throw providerError("risk_provider_redirect");
      }
      if (response?.status === 429) {
        await discardBody(response);
        throw providerError("risk_provider_rate_limited");
      }
      if (!response?.ok) {
        await discardBody(response);
        throw providerError("risk_provider_http_error");
      }
      const payload = await readBoundedJson(response, byteLimit, signal);
      if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
        throw providerError("risk_provider_invalid_response");
      }
      let indicators = payload;
      if (providerId === "ipquery") {
        if (payload.risk != null && (typeof payload.risk !== "object" || Array.isArray(payload.risk))) {
          throw providerError(payload.error ? "risk_provider_api_error" : "risk_provider_invalid_response");
        }
        indicators = payload.risk || {};
      }
      summary = Object.fromEntries(INDICATOR_FIELDS.map(field => [field, indicatorType(indicators[field], Object.hasOwn(indicators, field))]));
      if (payload.error) throw providerError("risk_provider_api_error");
      if (INDICATOR_FIELDS.some(field => !["absent", "null", "boolean"].includes(summary[field]))) {
        throw providerError("risk_provider_invalid_indicator_types");
      }
      const booleanOrUnknown = value => typeof value === "boolean" ? value : null;
      const available = INDICATOR_FIELDS.some(field => summary[field] === "boolean");
      failureCode = null;
      lastResult = available ? "known" : "unknown";
      unknownReason = available ? null : "indicators_unavailable";
      indicatorTypes = summary;
      lastHttpStatus = httpStatus;
      return {
        ...(!available ? { state: "unknown", reason: "indicators_unavailable" } : {}),
        hosting: booleanOrUnknown(indicators.is_datacenter),
        proxy: booleanOrUnknown(indicators.is_proxy),
        vpn: booleanOrUnknown(indicators.is_vpn),
        residentialProxy: null,
        source: providerId,
      };
    } catch (error) {
      // Only fixed adapter codes escape. In particular, fetch errors and JSON
      // errors can include request URLs, IPs or response text; never expose them.
      const code = error?.code;
      failureCode = SAFE_CODES.has(code)
        ? code : signal?.aborted ? "risk_provider_aborted" : "risk_provider_network";
      lastResult = "error";
      unknownReason = null;
      indicatorTypes = summary;
      lastHttpStatus = httpStatus;
      throw providerError(failureCode);
    }
  }

  return { lookup, getStatus };
}

module.exports = createFreeIpIntelligenceProvider;
