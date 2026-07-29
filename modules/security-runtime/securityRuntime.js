module.exports = function createSecurityRuntime(dependencies) {
  const crypto = require("crypto");
  const {
    FORWARDER_AUTH_HEADER, GEO_SOURCE_DEBUG, IN_MEM_BANS_MAX_ENTRIES,
    IN_MEM_BUCKETS_MAX_ENTRIES, IN_MEM_DENY_CACHE_MAX_ENTRIES,
    IN_MEM_STRIKES_MAX_ENTRIES, LOG_AGGREGATION_MAX_ENTRIES,
    MDS_FORWARDER_AUTH_SECRET, PER_IP_REQUEST_COUNTS_MAX_ENTRIES,
    RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECONDS, RE_B64URL_SEGMENT,
    SCANNER_AGG_ALERT_THRESHOLD, TRUST_CLOUDFLARE_XFF_CHAIN,
    TRUST_UPSTREAM_GEO_HEADERS, UNKNOWN_SCANNER_DENY_TTL_SECONDS,
    VISIBLE_IP_REPUTATION_DENY_TTL_SECONDS, VISIBLE_IP_REPUTATION_WEIGHTS,
    KNOWN_SCANNER_DENY_TTL_SECONDS, KNOWN_SCANNER_VISIBLE_IP_DENY_TTL_SECONDS,
    boundedMapSet, clampMs, formatLocal, fs, getConfiguredEmailDelimiters,
    getMaxBruteSplitPayloadLength, lookupIpinfoLite, maybeEnrichGeoAsync, normalizeAsn, os,
    parseRedirectPayload, path, readMsEnv, readPositiveIntEnv, runtimeStats,
    safeDecode, safeLogValue, sanitizeOneLine, summarizeError, trustProxyEffective,
    withOptionalUrlPrefix
  } = dependencies;
  const ALLOWLIST_DOMAINS = {
    some(callback) {
      return dependencies.getAllowlistDomains().some(callback);
    }
  };
function hasCloudflareHeaders(req) {
  return Boolean(
    req.headers["cf-connecting-ip"] ||
    req.headers["cf-ray"] ||
    req.headers["cf-visitor"]
  );
}

function decodeB64Any(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64 + "===".slice((b64.length + 3) % 4);
  return Buffer.from(pad, "base64");
}

function b64ToBuf(s, flavor = 'url') {
  try {
    let normalized = s || "";
    if (flavor === 'url') {
      normalized = normalized.replace(/-/g, "+").replace(/_/g, "/");
    }
    while (normalized.length % 4) normalized += "=";
    return Buffer.from(normalized, "base64");
  } catch { return null; }
}

function b64urlToBuf(s) {
  return b64ToBuf(s, 'url');
}

function b64stdToBuf(s) {
  return b64ToBuf(s, 'std');
}

function tryBase64UrlToUtf8(s) {
  try {
    const norm = (s || "").replace(/-/g, "+").replace(/_/g, "/");
    return Buffer.from(norm, "base64").toString("utf8");
  } catch { return null; }
}

function decodeB64urlLoose(s) {
  if (!s) return "";
  try {
    let u = s.replace(/-/g, '+').replace(/_/g, '/');
    while (u.length % 4) u += '=';
    return Buffer.from(u, 'base64').toString('utf8');
  } catch {}
  try {
    let u = s;
    while (u.length % 4) u += '=';
    return Buffer.from(u, 'base64').toString('utf8');
  } catch {}
  return "";
}

function hashFirstSeg(pathStr) {
  const parsed = parseRedirectPayload(pathStr, {
    decodeBase64UrlLoose: decodeB64urlLoose,
    decodeFallback: safeDecode,
    isValidEmail: isLikelyEmail
  });
  let first = parsed.ciphertext || parsed.rawUrl || "";

  if (!first) {
    const decoded = safeDecode(String(pathStr || ""));
    const splitOn = ["//", "__", "--", "~~", "/"];
    first = decoded;
    for (const d of splitOn) {
      const i = decoded.indexOf(d);
      if (i >= 0) { first = decoded.slice(0, i); break; }
    }
  }

  return crypto.createHash("sha256").update(first).digest("base64url").slice(0, 32);
}

function isLikelyEmail(s) {
  const v = String(s || '').trim();
  if (!v || v.length > 254 || /[^!-~]/.test(v)) return false;
  if (!/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(v)) return false;

  const [local = '', domain = ''] = v.split('@');
  if (!local || !domain || local.length > 64) return false;
  if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) return false;

  const labels = domain.split('.');
  if (!labels.length) return false;
  for (const label of labels) {
    if (!label || label.length > 63 || label.startsWith('-') || label.endsWith('-')) return false;
  }
  const tld = labels[labels.length - 1];
  return /^[A-Za-z]{2,63}$/.test(tld);
}

function extractSingleCleanEmailToken(s) {
  const input = String(s || '');
  if (!input) return '';

  const hasBinaryNoise = /[^ -~]/.test(input);
  if (!hasBinaryNoise) return '';

  const tokenRe = /(^|[^A-Za-z0-9])([A-Za-z0-9](?:[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{0,62}[A-Za-z0-9])?@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(?=$|[^A-Za-z0-9])/g;
  const matches = [];
  for (const m of input.matchAll(tokenRe)) {
    const leading = m[1] || '';
    const candidate = m[2] || '';
    if (!candidate) continue;

    const start = (m.index || 0) + leading.length;
    const end = start + candidate.length;
    const domain = candidate.split('@')[1] || '';
    const labels = domain.split('.');
    const tld = labels[labels.length - 1] || '';

    // Conservative recovery guard: if a recovered token runs to end-of-string,
    // only allow short/common-length TLDs so trailing ASCII noise does not get
    // absorbed as part of the TLD (e.g. "alice@example.comabc").
    if (end === input.length && tld.length > 4) continue;

    matches.push(candidate);
  }

  const uniqueMatches = [...new Set(matches)];
  if (uniqueMatches.length !== 1) return '';

  const candidate = uniqueMatches[0];
  const [localPart = ''] = candidate.split('@');
  if (!/^[A-Za-z0-9]/.test(localPart) || !/[A-Za-z0-9]$/.test(localPart)) return '';

  return isLikelyEmail(candidate) ? candidate : '';
}

function maskEmail(e) {
  const [user, host=''] = e.split('@');
  const [dom, ...rest] = host.split('.');
  const u = user.length <= 2
    ? user[0] + '*'
    : user[0] + '*'.repeat(Math.max(1, user.length - 2)) + user.slice(-1);
  const d = dom ? (dom[0] + '*'.repeat(Math.max(1, dom.length - 2)) + dom.slice(-1)) : '';
  return `${u}@${[d, ...rest].join('.')}`;
}

function decodeEmailPart(emailPart) {
  const emailRaw = String(emailPart || '').replace(/[\/~]+$/, '');
  if (!emailRaw) return { email: '', decoded: '', source: 'empty' };

  const safeDecoded = String(safeDecode(emailRaw) || '').trim();
  if (safeDecoded && isLikelyEmail(safeDecoded)) {
    return { email: safeDecoded, decoded: safeDecoded, source: safeDecoded === emailRaw ? 'raw' : 'url' };
  }

  const b64Decoded = String(decodeB64urlLoose(emailRaw) || '').trim();
  if (b64Decoded && isLikelyEmail(b64Decoded)) {
    return { email: b64Decoded, decoded: b64Decoded, source: 'b64' };
  }

  if (b64Decoded) {
    const recoveredEmail = extractSingleCleanEmailToken(b64Decoded);
    if (recoveredEmail) {
      return { email: recoveredEmail, decoded: b64Decoded, source: 'recovered' };
    }
  }

  return { email: '', decoded: b64Decoded || safeDecoded, source: 'invalid' };
}

function normHost(h) {
  const raw = String(h || "").trim().toLowerCase().replace(/\.$/, "");
  if (!raw) return "";
  if (raw.startsWith("[") && raw.endsWith("]")) return raw;
  const colonCount = (raw.match(/:/g) || []).length;
  if (colonCount === 1) return raw.split(":")[0];
  return raw;
}

function normalizeSuffixPattern(value) {
  let s = String(value || "").trim().toLowerCase();
  if (!s) return null;

  let includeApex = true;
  let allowSubdomains = false;
  if (s.startsWith("*.")) {
    includeApex = false;
    allowSubdomains = true;
    s = s.slice(2);
  } else if (s.startsWith(".")) {
    includeApex = false;
    allowSubdomains = true;
    s = s.slice(1);
  }

  const suffix = normHost(s);
  if (!suffix) return null;
  return { suffix, includeApex, allowSubdomains };
}

function hostMatchesSuffix(hostname, pattern) {
  const host = normHost(hostname);
  if (!host || !pattern || !pattern.suffix) return false;
  if (host === pattern.suffix) return pattern.includeApex;
  return pattern.allowSubdomains && host.endsWith(`.${pattern.suffix}`);
}

function isHostAllowlisted(hostname) {
  return ALLOWLIST_DOMAINS.some(pattern => hostMatchesSuffix(hostname, pattern));
}

function parseMinHourToMs(v, fallbackMs, defaultUnit = "m") {
  const s = String(v ?? "").trim().toLowerCase();
  if (!s) return fallbackMs;
  const m = s.match(/^(\d+)\s*(ms|s|m|h)?$/);
  if (!m) return fallbackMs;
  const n = parseInt(m[1], 10);
  const unit = m[2] || defaultUnit;
  const multipliers = { ms: 1, s: 1000, m: 60 * 1000, h: 60 * 60 * 1000 };
  return n * (multipliers[unit] || multipliers[defaultUnit] || 60 * 1000);
}

function fmtDurMH(ms) {
  const minutes = Math.round(ms / 60000);
  if (minutes % 60 === 0) return `${minutes / 60}h`;
  return `${minutes}m`;
}

function explainDecryptFailure({ tried = [], lastErr = null, segLen = 0 }) {
  const t = tried.join("|") || "none";
  const msg = (lastErr && String(lastErr.message || lastErr)) || "";

  if (/authenticate|authentic/i.test(msg)) {
    return `likely AES key mismatch (GCM auth failed); tried=${t}`;
  }
  if (/Invalid key length|Invalid key|unsupported/i.test(msg)) {
    return `server key invalid or wrong size; tried=${t}`;
  }
  if (/bad decrypt|mac check/i.test(msg)) {
    return `ciphertext/tag corrupted; tried=${t}`;
  }
  if (segLen < 40) {
    return `input too short to be a valid iv||ct||tag; tried=${t}`;
  }
  return `not a recognized encrypted format (wrong delimiter, bad base64, or truncated payload); tried=${t}`;
}

function gcmDecryptWithKey(key, iv, ct, tag) {
  const dec = crypto.createDecipheriv("aes-256-gcm", key, iv);
  dec.setAuthTag(tag);
  return Buffer.concat([dec.update(ct), dec.final()]);
}

function gcmDecryptAnyKey(iv, ct, tag) {
  let lastErr = null;
  for (let i = 0; i < AES_KEYS.length; i++) {
    const key = AES_KEYS[i];
    try {
      const out = gcmDecryptWithKey(key, iv, ct, tag);
      return { buf: out, keyIndex: i, err: null };
    } catch (e) {
      lastErr = e;
    }
  }
  return { buf: null, keyIndex: -1, err: lastErr };
}

function tryDecryptAny(segment) {
  if (!segment) return { url: null, tried: [], lastErr: null };

  let s = safeDecode(segment);

  const tried = [];
  let lastErr = null;

  if (s.includes(':')) {
    const parts = s.split(':');
    if (parts.length === 3) {
      for (const toBuf of [b64urlToBuf, b64stdToBuf]) {
        const flavor = toBuf === b64urlToBuf ? "url" : "std";
        tried.push(`colon-${flavor}`);
        const iv = toBuf(parts[0]), ct = toBuf(parts[1]), tag = toBuf(parts[2]);
        if (iv && ct && tag && iv.length >= 12 && tag.length === 16) {
          const r = gcmDecryptAnyKey(iv, ct, tag);
          if (r.buf) return { url: r.buf.toString("utf8"), tried, lastErr: null };
          lastErr = r.err || lastErr;
        }
      }
    }
  }

  for (const toBuf of [b64urlToBuf, b64stdToBuf]) {
    const flavor = toBuf === b64urlToBuf ? "url" : "std";
    tried.push(`single-${flavor}`);
    const buf = toBuf(s);
    if (buf && buf.length > 28) {
      for (const ivLen of [12, 16]) {
        if (buf.length > (ivLen + 16)) {
          const iv = buf.slice(0, ivLen), ct = buf.slice(ivLen, -16), tag = buf.slice(-16);
          const r = gcmDecryptAnyKey(iv, ct, tag);
          if (r.buf) return { url: r.buf.toString("utf8"), tried, lastErr: null };
          lastErr = r.err || lastErr;
        }
      }
    }
  }

  const maybe = tryBase64UrlToUtf8(s) || (b64stdToBuf(s)?.toString('utf8'));
  if (maybe && /^https?:\/\//i.test(maybe)) {
    tried.push("plain-b64-url");
    return { url: maybe, tried, lastErr: null };
  }

  return { url: null, tried, lastErr };
}

function getBruteSplitCandidatePrefixLengths(s) {
  const value = String(s || "");
  const minPrefix = 40;
  const candidates = new Set();

  let slashIndex = value.indexOf("/", minPrefix);
  while (slashIndex >= minPrefix) {
    if (slashIndex < value.length - 1) candidates.add(slashIndex);
    slashIndex = value.indexOf("/", slashIndex + 1);
  }

  for (const delimiter of getConfiguredEmailDelimiters()) {
    let index = value.indexOf(delimiter, minPrefix);
    while (index >= minPrefix) {
      if (index + delimiter.length < value.length) candidates.add(index);
      index = value.indexOf(delimiter, index + delimiter.length);
    }
  }

  return Array.from(candidates).sort((a, b) => b - a);
}

function hasBruteSplitRecoverySuffix(s) {
  return getBruteSplitCandidatePrefixLengths(s).length > 0;
}

function tryDecryptAtKnownDelimiterBoundaries(s){
  if (!s || s.length > getMaxBruteSplitPayloadLength()) return null;
  const candidatePrefixLengths = getBruteSplitCandidatePrefixLengths(s);
  if (candidatePrefixLengths.length === 0) return null;
  // The hard payload cap is the DoS boundary here. Only try actual suffix or
  // delimiter boundaries so invalid single-segment payloads cannot trigger one
  // decrypt attempt per byte while valid long ignored-suffix links still recover.
  for (const k of candidatePrefixLengths) {
    const prefix = s.slice(0, k);
    const got = tryDecryptAny(prefix);
    if (got && got.url && /^https?:\/\//i.test(got.url)) {
      const rest = s.slice(k);
      let emailRaw = rest;
      const j = rest.lastIndexOf('/');
      if (j >= 0) emailRaw = rest.slice(j+1);
      return { url: got.url, emailRaw, kTried: k };
    }
  }
  return null;
}

// Backward-compatible alias for existing tests and diagnostics. The implementation
// is bounded to discovered delimiter positions; it does not try every byte.
const bruteSplitDecryptFull = tryDecryptAtKnownDelimiterBoundaries;

const openSockets = new Set();

const createLogging = require("../logging/logging.js");
const {
  LOG_TO_FILE,
  LOG_FILE,
  LOG_FILE_MAX_BYTES,
  LOG_FILE_MAX_FILES,
  BACKLOG_ON_CONNECT,
  RUNTIME_INCIDENT_FILE,
  NPM_DEBUG_LOG_DIR,
  formatRailwayRuntimeLine,
  getRuntimeCorrelationMetadata,
  formatRuntimeCorrelationSuffix,
  LOGS,
  LOG_IDS,
  LOG_LISTENERS,
  getRuntimeResourceGauges,
  maybeEmitRuntimeGaugeAlerts,
  getProcessRuntimeMetadata,
  buildRuntimeIncidentPayload,
  recordRuntimeIncident,
  readRuntimeIncidents,
  getLogFileStatus,
  readLogFileTail,
  closeLogFileWriter,
  AGG_FLUSH_MS,
  aggregatePerIpEvent,
  flushAggregatedLogs,
  sseSend,
  analyzeLogIntegrity,
  addLog,
  addSpacer
} = createLogging({
  LOG_AGGREGATION_MAX_ENTRIES,
  SCANNER_AGG_ALERT_THRESHOLD,
  boundedMapSet,
  clampMs,
  formatLocal,
  fs,
  openSockets,
  os,
  path,
  readPositiveIntEnv,
  runtimeStats,
  safeLogValue,
  sanitizeOneLine,
  summarizeError
});
// ================== SECURITY & RATE LIMITING ==================
const RATE_CAPACITY = parseInt(process.env.RATE_CAPACITY || "5", 10);
const RATE_WINDOW_SECONDS = parseInt(process.env.RATE_WINDOW_SECONDS || "600", 10);
const RATE_PER_MS = RATE_CAPACITY / (RATE_WINDOW_SECONDS*1000);
const inMemBuckets = new Map();

function inMemTokenBucket(key, now) {
  let st = inMemBuckets.get(key); if (!st) st = { tokens: RATE_CAPACITY, ts: now };
  if (now > st.ts) { const d=now-st.ts; st.tokens = Math.min(RATE_CAPACITY, st.tokens + d*RATE_PER_MS); st.ts=now; }
  let allowed=false, retryAfterMs=0;
  if (st.tokens>=1){ st.tokens-=1; allowed=true; } else { retryAfterMs = Math.ceil((1-st.tokens)/RATE_PER_MS); }
  boundedMapSet(inMemBuckets, key, st, IN_MEM_BUCKETS_MAX_ENTRIES);
  return { allowed, retryAfterMs };
}

// Helper function to sanitize IP for use as Map keys
function sanitizeIpForKey(ip) {
  if (!ip || ip === 'unknown' || ip === '') {
    // Use a stable key to avoid bucket bypass while grouping unknown IPs safely
    return 'invalid_unknown';
  }

  // Basic IP format validation - if it looks like a valid IP, use it as-is
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip) || /^[0-9a-fA-F:]+$/.test(ip)) {
    return ip;
  }

  // For malformed IPs, create a deterministic sanitized key
  return `malformed_${crypto.createHash('sha256').update(String(ip)).digest('base64url').slice(0, 16)}`;
}

async function isRateLimited(ip) {
  const safeIp = sanitizeIpForKey(ip);
  const { allowed, retryAfterMs } = inMemTokenBucket(`rl:${safeIp}`, Date.now());
  return { limited: !allowed, retryAfterMs };
}

// ================== PER-IP RATE LIMITER (Change 3) ==================
// Simple sliding-window counter keyed by client IP.  Configurable via
// RATE_LIMIT_WINDOW_SECONDS (default 60) and RATE_LIMIT_MAX_REQUESTS (default 100).
// Old entries are pruned periodically to prevent unbounded memory growth.
const perIpRequestCounts = new Map(); // ip -> { count, windowStart }

function checkPerIpRateLimit(ip) {
  const safeIp = sanitizeIpForKey(ip);
  const now = Date.now();
  const windowMs = RATE_LIMIT_WINDOW_SECONDS * 1000;
  const st = perIpRequestCounts.get(safeIp);

  if (!st || now - st.windowStart >= windowMs) {
    boundedMapSet(perIpRequestCounts, safeIp, { count: 1, windowStart: now }, PER_IP_REQUEST_COUNTS_MAX_ENTRIES);
    return { limited: false };
  }

  st.count += 1;
  // Refresh active IPs on every hit so bounded eviction behaves like LRU and
  // high unique-IP churn cannot reset an active client's sliding-window count.
  boundedMapSet(perIpRequestCounts, safeIp, st, PER_IP_REQUEST_COUNTS_MAX_ENTRIES);
  if (st.count > RATE_LIMIT_MAX_REQUESTS) {
    const retryAfterSec = Math.ceil((st.windowStart + windowMs - now) / 1000);
    return { limited: true, retryAfterSec: Math.max(1, retryAfterSec) };
  }
  return { limited: false };
}

function prunePerIpRateLimitMap(now = Date.now()) {
  const windowMs = RATE_LIMIT_WINDOW_SECONDS * 1000;
  for (const [key, st] of perIpRequestCounts.entries()) {
    if (now - st.windowStart >= windowMs * 2) {
      perIpRequestCounts.delete(key);
    }
  }
}

const BAN_TTL_SEC       = parseInt(process.env.BAN_TTL_SEC || "3600", 10);
const BAN_AFTER_STRIKES = parseInt(process.env.BAN_AFTER_STRIKES || "4", 10);
const STRIKE_WEIGHT_HP  = parseInt(process.env.STRIKE_WEIGHT_HP || "3", 10);
const STRIKE_TTL_MS_RAW = parseInt(process.env.STRIKE_TTL_MS || String(24 * 60 * 60 * 1000), 10);
const STRIKE_TTL_MS = Math.max(60 * 1000, Number.isFinite(STRIKE_TTL_MS_RAW) ? STRIKE_TTL_MS_RAW : 24 * 60 * 60 * 1000);
const inMemBans = new Map();
const inMemStrikes = new Map();

const DENY_CACHE_TTL_SEC = parseInt(process.env.DENY_CACHE_TTL_SEC || "300", 10);
const inMemDenyCache = new Map();

function addDenyCache(ip, reason, ttlSec = DENY_CACHE_TTL_SEC) {
  const safeIp = sanitizeIpForKey(ip);
  boundedMapSet(inMemDenyCache, safeIp, { until: Date.now() + (ttlSec * 1000), reason: safeLogValue(reason, 32) }, IN_MEM_DENY_CACHE_MAX_ENTRIES);
}

function getDenyCache(ip) {
  const safeIp = sanitizeIpForKey(ip);
  const st = inMemDenyCache.get(safeIp);
  if (!st) return null;
  if (Date.now() > st.until) {
    inMemDenyCache.delete(safeIp);
    return null;
  }
  return st;
}

function isScannerDenyCacheReason(reason) {
  return reason === "known_scanner" || reason === "known_scanner_visible" || reason === "unknown_scanner" || reason === "visible_ip_reputation";
}

function getScannerDenyCacheLogReason(reason) {
  if (reason === "known_scanner") return "known_scanner_deny_cache";
  if (reason === "known_scanner_visible") return "known_scanner_visible_ip_deny_cache";
  if (reason === "visible_ip_reputation") return "visible_ip_reputation_deny_cache";
  return "unknown_scanner_deny_cache";
}

function getScannerDenyCacheRetryAfter(reason) {
  if (reason === "known_scanner") return KNOWN_SCANNER_DENY_TTL_SECONDS;
  if (reason === "known_scanner_visible") return KNOWN_SCANNER_VISIBLE_IP_DENY_TTL_SECONDS;
  if (reason === "visible_ip_reputation") return VISIBLE_IP_REPUTATION_DENY_TTL_SECONDS;
  return UNKNOWN_SCANNER_DENY_TTL_SECONDS;
}

function getScannerDenyCacheForRequest(req, identity = {}) {
  const denyCacheIp = identity.denyCacheIp || getDenyCacheIp(req);
  const denyHit = getDenyCache(denyCacheIp);
  if (denyHit && isScannerDenyCacheReason(denyHit.reason)) {
    return { hit: denyHit, key: denyCacheIp };
  }

  const displayIp = identity.ip || getClientIp(req);
  if (displayIp && displayIp !== denyCacheIp) {
    const displayHit = getDenyCache(displayIp);
    if (displayHit && isScannerDenyCacheReason(displayHit.reason)) {
      return { hit: displayHit, key: displayIp };
    }
  }

  return null;
}

const ALERT_WINDOW_MS = parseInt(process.env.ALERT_WINDOW_MS || "600000", 10);
const ALERT_UNIQUE_OFFENDER_THRESHOLD = parseInt(process.env.ALERT_UNIQUE_OFFENDER_THRESHOLD || "25", 10);
const ALERT_COUNTRY_SPIKE_THRESHOLD = parseInt(process.env.ALERT_COUNTRY_SPIKE_THRESHOLD || "20", 10);
const ALERT_ASN_SPIKE_THRESHOLD = parseInt(process.env.ALERT_ASN_SPIKE_THRESHOLD || "20", 10);
const alertState = {
  offenders: new Map(),
  countries: new Map(),
  asns: new Map(),
  challengeBypass: new Map(),
  dedupe: new Map()
};

function incrementWindowCounter(map, key, now = Date.now()) {
  const st = map.get(key);
  if (!st || now - st.windowStart > ALERT_WINDOW_MS) {
    map.set(key, { count: 1, windowStart: now });
    return 1;
  }
  st.count += 1;
  map.set(key, st);
  return st.count;
}

function pruneAlertMap(map, now, windowMs = ALERT_WINDOW_MS) {
  for (const [k, ts] of map.entries()) {
    if (now - ts > windowMs) map.delete(k);
  }
}

function pruneWindowCounterMap(map, now, windowMs = ALERT_WINDOW_MS) {
  for (const [k, st] of map.entries()) {
    if (!st || typeof st.windowStart !== "number" || now - st.windowStart > windowMs) {
      map.delete(k);
    }
  }
}

function pruneAlertState(now = Date.now()) {
  pruneAlertMap(alertState.offenders, now);
  pruneAlertMap(alertState.challengeBypass, now);
  pruneAlertMap(alertState.dedupe, now, ALERT_WINDOW_MS * 2);
  pruneWindowCounterMap(alertState.countries, now);
  pruneWindowCounterMap(alertState.asns, now);
}

function shouldEmitAlert(key, now = Date.now()) {
  const last = alertState.dedupe.get(key);
  if (last && (now - last) < ALERT_WINDOW_MS) return false;
  boundedMapSet(alertState.dedupe, key, now, LOG_AGGREGATION_MAX_ENTRIES);
  return true;
}

function recordOffenderSignals(req, context = {}) {
  const now = Date.now();
  const ip = sanitizeIpForKey(getClientIp(req));
  const country = context.country || getCountry(req) || "--";
  const asn = context.asn || getASN(req) || "--";

  alertState.offenders.set(ip, now);
  const countryHits = incrementWindowCounter(alertState.countries, country, now);
  const asnHits = incrementWindowCounter(alertState.asns, asn, now);

  pruneAlertState(now);

  if (alertState.offenders.size >= ALERT_UNIQUE_OFFENDER_THRESHOLD && shouldEmitAlert("unique-offenders", now)) {
    addLog(`[ALERT] unique offender spike offenders=${alertState.offenders.size} window=${Math.round(ALERT_WINDOW_MS / 60000)}m`);
    addSpacer();
  }

  if (country !== "--" && countryHits >= ALERT_COUNTRY_SPIKE_THRESHOLD && shouldEmitAlert(`country-${country}`, now)) {
    addLog(`[ALERT] country spike country=${safeLogValue(country, 8)} hits=${countryHits} window=${Math.round(ALERT_WINDOW_MS / 60000)}m`);
    addSpacer();
  }

  if (asn !== "--" && asnHits >= ALERT_ASN_SPIKE_THRESHOLD && shouldEmitAlert(`asn-${asn}`, now)) {
    addLog(`[ALERT] asn spike asn=${safeLogValue(asn, 32)} hits=${asnHits} window=${Math.round(ALERT_WINDOW_MS / 60000)}m`);
    addSpacer();
  }
}

function recordChallengeBypassAttempt(req, reason) {
  const now = Date.now();
  const ip = sanitizeIpForKey(getClientIp(req));
  alertState.challengeBypass.set(ip, now);
  pruneAlertState(now);
  if (shouldEmitAlert(`challenge-bypass-${ip}`, now)) {
    addLog(`[ALERT] challenge bypass attempt ip=${safeLogValue(getClientIp(req), 80)} reason=${safeLogValue(reason, 60)} path=${safeLogValue(req.path, 120)}`);
    addSpacer();
  }
}

function createChallengeRedirect(baseString, req, reason, extras = {}) {
  const ip = getClientIp(req);
  const token = createChallengeToken(baseString, req, reason || "auth_required");
  const hostParam = extras.host ? `&host=${encodeURIComponent(extras.host)}` : "";
  const reasonParam = reason ? `&cr=${encodeURIComponent(sanitizeChallengeReason(reason))}` : "";
  addLog(`[CHALLENGE] tokenized redirect ip=${safeLogValue(ip)} reason=${safeLogValue(reason || "auth_required", 40)} len=${baseString.length}`);
  return `${withOptionalUrlPrefix("/challenge")}?ct=${encodeURIComponent(token)}${reasonParam}${hostParam}`;
}

function isBanned(ip) {
  const safeIp = sanitizeIpForKey(ip);
  const until = inMemBans.get(safeIp);
  if (!until) return false;
  if (Date.now() > until) { inMemBans.delete(safeIp); return false; }
  return true;
}

function getStrikeCount(safeIp, now = Date.now()) {
  const st = inMemStrikes.get(safeIp);
  if (st == null) return 0;

  // Backward compatibility for numeric strike values.
  if (typeof st === "number") {
    inMemStrikes.set(safeIp, { count: st, updatedAt: now });
    return st;
  }

  if (!st || typeof st.count !== "number") {
    inMemStrikes.delete(safeIp);
    return 0;
  }

  if (now - (st.updatedAt || 0) > STRIKE_TTL_MS) {
    inMemStrikes.delete(safeIp);
    return 0;
  }

  return st.count;
}

function addStrike(ip, weight=1){
  const safeIp = sanitizeIpForKey(ip);
  const now = Date.now();
  const c = getStrikeCount(safeIp, now) + weight;
  boundedMapSet(inMemStrikes, safeIp, { count: c, updatedAt: now }, IN_MEM_STRIKES_MAX_ENTRIES);
  if (c >= BAN_AFTER_STRIKES) {
    boundedMapSet(inMemBans, safeIp, now + BAN_TTL_SEC*1000, IN_MEM_BANS_MAX_ENTRIES);
    inMemStrikes.delete(safeIp);
    addLog(`[BAN] ip=${safeLogValue(ip)} for ${BAN_TTL_SEC}s`);
  addSpacer();
  }
}

function makeIpLimiter({ capacity, windowSec, keyPrefix }) {
  const RATE_PER_MS_LOCAL = capacity / (windowSec * 1000);
  const buckets = new Map();
  const cleanupEveryMs = 60 * 1000;
  const bucketTtlMs = Math.max(windowSec * 1000 * 4, 10 * 60 * 1000);
  const bucketMaxEntries = 20000;
  let lastCleanupAt = 0;

  function pruneBuckets(now) {
    if ((now - lastCleanupAt) < cleanupEveryMs && buckets.size <= bucketMaxEntries) return;
    lastCleanupAt = now;

    for (const [k, st] of buckets.entries()) {
      if (!st || typeof st.ts !== "number" || (now - st.ts) > bucketTtlMs) {
        buckets.delete(k);
      }
    }

    if (buckets.size <= bucketMaxEntries) return;
    const oldest = [...buckets.entries()].sort((a, b) => (a[1]?.ts || 0) - (b[1]?.ts || 0));
    const pruneCount = Math.max(1, buckets.size - bucketMaxEntries);
    for (let i = 0; i < pruneCount; i += 1) {
      const item = oldest[i];
      if (!item) break;
      buckets.delete(item[0]);
    }
  }

  return function ipLimit(req, res, next) {
    if (isAdmin?.(req) || isAdminSSE?.(req)) return next();
    const identity = getRequestIdentity(req);
    const ip = identity.ip || "unknown";
    const safeIp = sanitizeIpForKey(identity.rateLimitKey || ip);
    const key = `${keyPrefix}:${safeIp}`;
    const now = Date.now();

    pruneBuckets(now);

    let st = buckets.get(key);
    if (!st) st = { tokens: capacity, ts: now };
    if (now > st.ts) {
      const d = now - st.ts;
      st.tokens = Math.min(capacity, st.tokens + d * RATE_PER_MS_LOCAL);
      st.ts = now;
    }
    if (st.tokens >= 1) {
      st.tokens -= 1;
      buckets.set(key, st);
      return next();
    }
    const retryAfterMs = Math.ceil((1 - st.tokens) / RATE_PER_MS_LOCAL);
    res.setHeader("Retry-After", Math.ceil(retryAfterMs / 1000));
    addLog(`[RL:${keyPrefix}] 429 ip=${safeLogValue(ip)} path=${safeLogValue(req.path)}`);
  addSpacer();
    return res.status(429).send("Too many requests");
  };
}

// ================== ADMIN AUTH ==================
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";

function timingSafeEqualStr(a, b) {
  const aBuf = Buffer.from(String(a || ""));
  const bBuf = Buffer.from(String(b || ""));
  if (aBuf.length !== bBuf.length) return false;
  try { return crypto.timingSafeEqual(aBuf, bBuf); } catch { return false; }
}

function isAdmin(req) {
  if (!ADMIN_TOKEN) return false;
  const h = req.headers["authorization"];
  if (!h || typeof h !== "string") return false;
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return false;
  return timingSafeEqualStr(m[1], ADMIN_TOKEN);
}

function requireAdmin(req, res, next) {
  if (!isAdmin(req)) {
    return res.status(401).type("text/plain").send("Unauthorized");
  }
  return next();
}

const EPHEMERAL_TTL_MS = 5 * 60 * 1000;
const EPHEMERAL_SECRET = process.env.ADMIN_TOKEN || "dev-secret";
const EPHEMERAL_SECRET_EFFECTIVE = (() => {
  const explicit = (process.env.EPHEMERAL_SECRET || "").trim();
  if (explicit) return explicit;
  if (process.env.ADMIN_TOKEN && process.env.ADMIN_TOKEN.length >= 16) return process.env.ADMIN_TOKEN;

  // Avoid predictable fallback in non-prod; rotate per process when no strong admin token exists.
  const randomFallback = crypto.randomBytes(32).toString("base64url");
  console.warn("⚠️ EPHEMERAL_SECRET not provided and ADMIN_TOKEN is weak/missing; using process-random ephemeral secret.");
  return randomFallback;
})();

function mintEphemeralToken() {
  const exp = Date.now() + EPHEMERAL_TTL_MS;
  const msg = `sse:${exp}`;
  const sig = crypto.createHmac('sha256', EPHEMERAL_SECRET_EFFECTIVE).update(msg).digest('base64url');
  return `ts:${exp}:${sig}`;
}

function verifyEphemeralToken(tok) {
  const m = /^ts:(\d+):([A-Za-z0-9_-]+)$/.exec(tok || "");
  if (!m) return false;
  const exp = +m[1], sig = m[2];
  if (Date.now() > exp) return false;
  const msg = `sse:${exp}`;
  const expect = crypto.createHmac('sha256', EPHEMERAL_SECRET_EFFECTIVE).update(msg).digest('base64url');
  return timingSafeEqualStr(sig, expect);
}

function isAdminSSE(req) {
  const hasStaticAdminToken = ADMIN_TOKEN.length > 0;

  const hdr = req.headers.authorization || "";
  if (hasStaticAdminToken && hdr.startsWith("Bearer ") && timingSafeEqualStr(hdr.slice(7), ADMIN_TOKEN)) return true;

  const qTok = req.query.token && String(req.query.token);
  if (!qTok) return false;

  if (hasStaticAdminToken && timingSafeEqualStr(qTok, ADMIN_TOKEN)) return true;
  return verifyEphemeralToken(qTok);
}

// ================== AES KEY MANAGEMENT ==================
const DEBUG_SHOW_KEYS_ON_START   = (process.env.DEBUG_SHOW_KEYS_ON_START || "0") === "1";
const DEBUG_ALLOW_PLAINTEXT_KEYS = (process.env.DEBUG_ALLOW_PLAINTEXT_KEYS || "0") === "1";
const EXPECT_AES_SHA256          = (process.env.AES_KEY_SHA256 || "").toLowerCase().replace(/[^0-9a-f]/g, "");

function loadKeysFromEnv() {
  const keys = [];

  const hex = (process.env.AES_KEY_HEX || "").trim();
  if (hex) {
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error("AES_KEY_HEX must be 64 hex chars");
    keys.push(Buffer.from(hex, "hex"));
  }

  const rawList = (process.env.AES_KEYS || process.env.AES_KEY || "")
    .split(",").map(s => s.trim()).filter(Boolean);
  for (const k of rawList) {
    if (!/^[A-Za-z0-9_-]+$/.test(k)) {
      throw new Error("AES_KEY(S) must be base64url (A–Z a–z 0–9 _ -)");
    }
    const buf = decodeB64Any(k);
    if (buf.length !== 32) throw new Error("Each AES key must decode to 32 bytes");
    keys.push(buf);
  }

  if (!keys.length) throw new Error("No AES key configured. Set AES_KEYS or AES_KEY or AES_KEY_HEX");
  return keys;
}

const AES_KEYS = loadKeysFromEnv();

if (EXPECT_AES_SHA256) {
  const got = crypto.createHash("sha256").update(AES_KEYS[0]).digest("hex");
  if (!got.startsWith(EXPECT_AES_SHA256)) {
    console.error(`[FATAL] AES key fingerprint mismatch. expected=${EXPECT_AES_SHA256.slice(0,10)}… got=${got.slice(0,10)}…`);
    process.exit(1);
  }
}

if (DEBUG_SHOW_KEYS_ON_START) {
  const raw = (process.env.AES_KEYS || process.env.AES_KEY || process.env.AES_KEY_HEX || "").trim();
  console.log("[DEBUG] AES_KEY(S) raw:", raw);
}

const LINK_HMAC_KEY = process.env.LINK_HMAC_KEY
  ? Buffer.from(process.env.LINK_HMAC_KEY, "utf8")
  : AES_KEYS[0];

function computeLinkHmac(url, destHost) {
  if (!url || !destHost || !LINK_HMAC_KEY) return null;
  try {
    return crypto.createHmac("sha256", LINK_HMAC_KEY)
      .update(`${destHost}|${url}`)
      .digest("base64url");
  } catch {
    return null;
  }
}

function verifyLinkHmac(url, destHost, provided) {
  const expected = computeLinkHmac(url, destHost);
  if (!expected || !provided) return { ok: false, expected };
  return { ok: timingSafeEqualStr(expected, provided), expected };
}

// ================== CHALLENGE TOKEN FUNCTIONS ==================
function hashIpForToken(ip) {
  try {
    return crypto.createHash("sha256")
      .update(String(ip || ""))
      .digest("base64")
      .slice(0, 16);
  } catch {
    return "";
  }
}

function hashUaForToken(ua) {
  try {
    return crypto.createHash("sha256")
      .update(String(ua || ""))
      .digest("base64")
      .slice(0, 16);
  } catch {
    return "";
  }
}

const CHALLENGE_REASON_MAX_LEN = 80;
const CHALLENGE_TOKEN_SECRET = ADMIN_TOKEN || EPHEMERAL_SECRET_EFFECTIVE;

function sanitizeChallengeReason(reason) {
  if (!reason) return "";
  return String(reason)
    .replace(/[^\x20-\x7E]+/g, "")
    .slice(0, CHALLENGE_REASON_MAX_LEN);
}

function createChallengeToken(nextEnc, req, reason) {
  const raw = parseInt(process.env.CHALLENGE_TOKEN_TTL_MIN || "10", 10);
  const ttlMin = Number.isFinite(raw) && raw > 0 ? raw : 10; // guard
  const exp = Date.now() + ttlMin * 60 * 1000;
  const cr = sanitizeChallengeReason(reason);

  const ip = getClientIp(req);
  const ua = req && req.get ? (req.get("user-agent") || "") : "";

  const payload = {
    next: nextEnc,
    exp,
    ts: Date.now(),
    ih: hashIpForToken(ip),
    uh: hashUaForToken(ua),
    cr: cr || undefined
  };
  const token = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto
    .createHmac("sha256", CHALLENGE_TOKEN_SECRET)
    .update(token)
    .digest("base64url");
  return `${token}.${sig}`;
}

function verifyChallengeToken(challengeToken, req) {
  if (!challengeToken || typeof challengeToken !== "string") return null;

  const parts = challengeToken.split(".");
  if (parts.length !== 2) return null;

  const [token, sig] = parts;

  const expectedSig = crypto
    .createHmac("sha256", CHALLENGE_TOKEN_SECRET)
    .update(token)
    .digest("base64url");
  if (sig !== expectedSig) return null;

  try {
    const payload = JSON.parse(Buffer.from(token, "base64url").toString());
    if (Date.now() > payload.exp) return null;

    if (payload.ih || payload.uh) {
      const ip = getClientIp(req);
      const ua = req && req.get ? (req.get("user-agent") || "") : "";
      const ihNow = hashIpForToken(ip);
      const uhNow = hashUaForToken(ua);
      if ((payload.ih && payload.ih !== ihNow) || (payload.uh && payload.uh !== uhNow)) {
        return null;
      }
    }

    return payload;
  } catch (e) {
    return null;
  }
}

function encryptChallengeData(payload) {
  const json = JSON.stringify(payload);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', AES_KEYS[0], iv);
  const encrypted = Buffer.concat([cipher.update(json, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, encrypted, tag]).toString('base64url');
}

function decryptChallengeData(encryptedData) {
  try {
    const buf = Buffer.from(encryptedData, 'base64url');
    const iv = buf.slice(0, 12);
    const ciphertext = buf.slice(12, -16);
    const tag = buf.slice(-16);

    const decipher = crypto.createDecipheriv('aes-256-gcm', AES_KEYS[0], iv);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(decrypted.toString('utf8'));
  } catch (e) {
    return null;
  }
}

const createClientGeo = require("../client-security/clientGeo.js");
const {
  getClientIp,
  getDenyCacheIp,
  getRequestIdentity,
  formatRequestIdentityLogSuffix,
  isKnownProxyIp,
  normalizeIpv4Mapped,
  getCountryResolutionAsync,
  getCountry,
  getASN
} = createClientGeo({
  FORWARDER_AUTH_HEADER,
  GEO_SOURCE_DEBUG,
  MDS_FORWARDER_AUTH_SECRET,
  TRUST_CLOUDFLARE_XFF_CHAIN,
  TRUST_UPSTREAM_GEO_HEADERS,
  addLog,
  hasCloudflareHeaders,
  lookupIpinfoLite,
  maybeEnrichGeoAsync,
  normalizeAsn,
  safeLogValue,
  trustProxyEffective
});

  return {
    LOG_TO_FILE,
    LOG_FILE,
    LOG_FILE_MAX_BYTES,
    LOG_FILE_MAX_FILES,
    BACKLOG_ON_CONNECT,
    RUNTIME_INCIDENT_FILE,
    NPM_DEBUG_LOG_DIR,
    formatRailwayRuntimeLine,
    getRuntimeCorrelationMetadata,
    formatRuntimeCorrelationSuffix,
    LOGS,
    LOG_IDS,
    LOG_LISTENERS,
    getRuntimeResourceGauges,
    maybeEmitRuntimeGaugeAlerts,
    getProcessRuntimeMetadata,
    buildRuntimeIncidentPayload,
    recordRuntimeIncident,
    readRuntimeIncidents,
    getLogFileStatus,
    readLogFileTail,
    closeLogFileWriter,
    AGG_FLUSH_MS,
    aggregatePerIpEvent,
    flushAggregatedLogs,
    sseSend,
    analyzeLogIntegrity,
    addLog,
    addSpacer,
    getClientIp,
    getDenyCacheIp,
    getRequestIdentity,
    formatRequestIdentityLogSuffix,
    isKnownProxyIp,
    normalizeIpv4Mapped,
    getCountryResolutionAsync,
    getCountry,
    getASN,
    hasCloudflareHeaders,
    decodeB64Any,
    b64ToBuf,
    b64urlToBuf,
    b64stdToBuf,
    tryBase64UrlToUtf8,
    decodeB64urlLoose,
    hashFirstSeg,
    isLikelyEmail,
    extractSingleCleanEmailToken,
    maskEmail,
    decodeEmailPart,
    normHost,
    normalizeSuffixPattern,
    hostMatchesSuffix,
    isHostAllowlisted,
    fmtDurMH,
    explainDecryptFailure,
    gcmDecryptWithKey,
    gcmDecryptAnyKey,
    tryDecryptAny,
    getBruteSplitCandidatePrefixLengths,
    hasBruteSplitRecoverySuffix,
    tryDecryptAtKnownDelimiterBoundaries,
    bruteSplitDecryptFull,
    openSockets,
    RATE_CAPACITY,
    RATE_WINDOW_SECONDS,
    RATE_PER_MS,
    inMemBuckets,
    inMemTokenBucket,
    sanitizeIpForKey,
    isRateLimited,
    perIpRequestCounts,
    checkPerIpRateLimit,
    prunePerIpRateLimitMap,
    BAN_TTL_SEC,
    BAN_AFTER_STRIKES,
    STRIKE_WEIGHT_HP,
    STRIKE_TTL_MS_RAW,
    STRIKE_TTL_MS,
    inMemBans,
    inMemStrikes,
    DENY_CACHE_TTL_SEC,
    inMemDenyCache,
    addDenyCache,
    getDenyCache,
    isScannerDenyCacheReason,
    getScannerDenyCacheLogReason,
    getScannerDenyCacheRetryAfter,
    getScannerDenyCacheForRequest,
    ALERT_WINDOW_MS,
    ALERT_UNIQUE_OFFENDER_THRESHOLD,
    ALERT_COUNTRY_SPIKE_THRESHOLD,
    ALERT_ASN_SPIKE_THRESHOLD,
    alertState,
    incrementWindowCounter,
    pruneAlertMap,
    pruneWindowCounterMap,
    pruneAlertState,
    shouldEmitAlert,
    recordOffenderSignals,
    recordChallengeBypassAttempt,
    createChallengeRedirect,
    isBanned,
    getStrikeCount,
    addStrike,
    makeIpLimiter,
    ADMIN_TOKEN,
    timingSafeEqualStr,
    isAdmin,
    requireAdmin,
    EPHEMERAL_TTL_MS,
    EPHEMERAL_SECRET,
    EPHEMERAL_SECRET_EFFECTIVE,
    mintEphemeralToken,
    verifyEphemeralToken,
    isAdminSSE,
    DEBUG_SHOW_KEYS_ON_START,
    DEBUG_ALLOW_PLAINTEXT_KEYS,
    EXPECT_AES_SHA256,
    loadKeysFromEnv,
    AES_KEYS,
    LINK_HMAC_KEY,
    computeLinkHmac,
    verifyLinkHmac,
    hashIpForToken,
    hashUaForToken,
    CHALLENGE_REASON_MAX_LEN,
    CHALLENGE_TOKEN_SECRET,
    sanitizeChallengeReason,
    createChallengeToken,
    verifyChallengeToken,
    encryptChallengeData,
    decryptChallengeData,
  };
};
