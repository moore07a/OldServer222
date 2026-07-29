module.exports = function createScannerBehaviorPolicy(dependencies) {
  const crypto = require("crypto");
  const {
    ARCHIVE_PROBE_NAME_REGEX, ARCHIVE_PROBE_SUFFIX_REGEX,
    SEARCH_BOT_DNS_CACHE_MAX_ENTRIES, SEARCH_BOT_DNS_CACHE_TTL_MS,
    SEARCH_BOT_DNS_NEGATIVE_TTL_MS, SEARCH_BOT_DNS_TIMEOUT_MS,
    SEARCH_BOT_DNS_VERIFY_ENABLED, addDenyCache, addLog, aggregatePerIpEvent,
    boundedMapSet, classifyScannerDetectionSource, detectScanner, detectScannerEnhanced, dns, getClientIp,
    getCurrentPublicPathSet, getDenyCacheIp, getRequestIdentity,
    isLikelyFlexibleRedirectPayloadCandidate, isLikelyRawUrlRedirectPayload,
    isLikelyRedirectPayloadPathCandidate, isPublicContentSurfaceEnabled,
    matchesConfiguredScannerProfile, net, pathMatchesUnknownScannerSkipPrefix, pathMatchesWithOptionalPrefix,
    readPositiveIntEnv, safeLogValue, sanitizeIpForKey, stripOptionalUrlPrefix
  } = dependencies;
  const PUBLIC_CANONICAL_ALIASES = {
    has(value) {
      return dependencies.getPublicCanonicalAliases().has(value);
    }
  };
  const IMPERSONATE_MIN_CONFIDENCE = {
    valueOf() {
      return dependencies.getImpersonateMinConfidence();
    }
  };
const VISIBLE_IP_REPUTATION_WEIGHTS = {
  scanner_probe: 5,
  unknown_scanner: 6,
  invalid_scanner_path: 4,
  invalid_catch_all: 1,
  headless: 5,
  challenge_abuse: 4,
  honeypot: 6,
  public_walk: 3
};
const VISIBLE_IP_REPUTATION_HIGH_SIGNAL_CATEGORIES = new Set([
  "scanner_probe",
  "unknown_scanner",
  "invalid_scanner_path",
  "headless",
  "challenge_abuse",
  "honeypot"
]);

function getVisibleIpReputationHistoryByKey(key, now = Date.now()) {
  if (!key || key === "unknown") return [];
  const windowMs = Math.max(1, VISIBLE_IP_REPUTATION_WINDOW_SECONDS) * 1000;
  const existing = VISIBLE_IP_REPUTATION_HISTORY.get(key) || [];
  const fresh = existing.filter(entry => entry && (now - entry.ts) <= windowMs);
  if (fresh.length !== existing.length) {
    if (fresh.length === 0) VISIBLE_IP_REPUTATION_HISTORY.delete(key);
    else boundedMapSet(VISIBLE_IP_REPUTATION_HISTORY, key, fresh, UNKNOWN_SCANNER_HISTORY_MAX_ENTRIES);
  }
  return fresh;
}

function getVisibleIpReputationHistory(ip, now = Date.now()) {
  const key = sanitizeIpForKey(ip || "unknown");
  return getVisibleIpReputationHistoryByKey(key, now);
}

function summarizeVisibleIpReputationEvents(events = []) {
  const categories = new Set();
  let score = 0;
  let highSignal = false;
  for (const entry of events) {
    if (!entry || !entry.signal) continue;
    const signal = String(entry.signal);
    const weight = Number.isFinite(entry.weight) ? entry.weight : (VISIBLE_IP_REPUTATION_WEIGHTS[signal] || 1);
    score += Math.max(0, weight);
    categories.add(signal);
    if (VISIBLE_IP_REPUTATION_HIGH_SIGNAL_CATEGORIES.has(signal)) highSignal = true;
  }
  return { score, categories: Array.from(categories), highSignal };
}

function hasVisibleIpReputationSignal(ip, options = {}) {
  const exclude = new Set(options.exclude || []);
  return getVisibleIpReputationHistory(ip).some(entry => entry && entry.signal && !exclude.has(entry.signal));
}

function recordVisibleIpReputationSignal(ip, signal, options = {}) {
  if (!VISIBLE_IP_REPUTATION_ENABLED) return { shouldDeny: false, score: 0, categories: [] };
  const key = sanitizeIpForKey(ip || "unknown");
  if (!key || key === "unknown") return { shouldDeny: false, score: 0, categories: [] };
  const now = options.now || Date.now();
  const history = getVisibleIpReputationHistoryByKey(key, now);
  const normalizedSignal = String(signal || "unknown").replace(/[^a-z0-9_-]/gi, "_").toLowerCase();
  const weight = Number.isFinite(options.weight)
    ? Math.max(0, Math.trunc(options.weight))
    : (VISIBLE_IP_REPUTATION_WEIGHTS[normalizedSignal] || 1);
  history.push({
    ts: now,
    signal: normalizedSignal,
    weight,
    detail: options.detail ? String(options.detail).slice(0, 80) : ""
  });
  if (history.length > VISIBLE_IP_REPUTATION_MAX_EVENTS_PER_IP) {
    history.splice(0, history.length - VISIBLE_IP_REPUTATION_MAX_EVENTS_PER_IP);
  }
  boundedMapSet(VISIBLE_IP_REPUTATION_HISTORY, key, history, UNKNOWN_SCANNER_HISTORY_MAX_ENTRIES);

  const summary = summarizeVisibleIpReputationEvents(history);
  const shouldDeny = summary.highSignal &&
    summary.score >= VISIBLE_IP_REPUTATION_DENY_THRESHOLD &&
    summary.categories.length >= VISIBLE_IP_REPUTATION_MIN_CATEGORIES;
  return { shouldDeny, score: summary.score, categories: summary.categories, count: history.length };
}

function summarizePathHistory(history = [], rapidWindowMs = UNKNOWN_SCANNER_RAPID_WINDOW_SECONDS * 1000, now = Date.now()) {
  const rapidHistory = history.filter(entry => entry && (now - entry.ts) <= rapidWindowMs);
  return {
    requestCount: history.length,
    uniquePathCount: new Set(history.map(entry => entry.path)).size,
    rapidUniquePathCount: new Set(rapidHistory.map(entry => entry.path)).size
  };
}

function getUnknownScannerHistorySummary(req) {
  const historyIp = getDenyCacheIp(req);
  const safeIp = sanitizeIpForKey(historyIp);
  const now = Date.now();
  const history = (UNKNOWN_SCANNER_HISTORY.get(safeIp) || [])
    .filter(entry => entry && (now - entry.ts) <= UNKNOWN_SCANNER_WINDOW_SECONDS * 1000);
  return summarizePathHistory(history, UNKNOWN_SCANNER_RAPID_WINDOW_SECONDS * 1000, now);
}

function recordVisibleIpPublicWalkPath(ip, req, now = Date.now()) {
  const key = sanitizeIpForKey(ip || "unknown");
  if (!key || key === "unknown") return { requestCount: 0, uniquePathCount: 0, rapidUniquePathCount: 0 };

  const windowMs = UNKNOWN_SCANNER_WINDOW_SECONDS * 1000;
  const normalizedPath = String((req && req.path) || "/").split("?")[0].toLowerCase() || "/";
  const current = VISIBLE_IP_PUBLIC_WALK_HISTORY.get(key) || [];
  const history = current.filter(entry => entry && (now - entry.ts) <= windowMs);
  history.push({ ts: now, path: normalizedPath, method: String((req && req.method) || "GET").toUpperCase() });
  if (history.length > UNKNOWN_SCANNER_MAX_HISTORY_PER_IP) {
    history.splice(0, history.length - UNKNOWN_SCANNER_MAX_HISTORY_PER_IP);
  }
  boundedMapSet(VISIBLE_IP_PUBLIC_WALK_HISTORY, key, history, UNKNOWN_SCANNER_HISTORY_MAX_ENTRIES);
  return summarizePathHistory(history, UNKNOWN_SCANNER_RAPID_WINDOW_SECONDS * 1000, now);
}

function canDenyCacheVisibleIp(identity, ip) {
  return Boolean(
    !identity ||
    (identity.source === "client" && (identity.ip === ip || identity.displayIp === ip || identity.denyCacheKey === ip))
  );
}

function maybeDenyForVisibleIpReputation(req, ip, signal, options = {}) {
  const result = recordVisibleIpReputationSignal(ip, signal, options);
  if (!result.shouldDeny) return result;

  const identity = req ? getRequestIdentity(req) : null;
  if (!canDenyCacheVisibleIp(identity, ip)) {
    return {
      ...result,
      denyCacheSkipped: true,
      denyCacheSkipReason: "untrusted_visible_ip",
      trustedDenyCacheKey: identity && identity.denyCacheKey
    };
  }

  addDenyCache(ip, "visible_ip_reputation", VISIBLE_IP_REPUTATION_DENY_TTL_SECONDS);
  const shouldLog = aggregatePerIpEvent("REPUTATION-DENY", {
    ip,
    reason: signal,
    suppressFirst: false
  });
  if (shouldLog) {
    addLog(`[REPUTATION-DENY] ip=${safeLogValue(ip, 64)} signal=${safeLogValue(signal, 40)} score=${result.score} categories=${safeLogValue(result.categories.join("|"), 160)} ttl=${VISIBLE_IP_REPUTATION_DENY_TTL_SECONDS}s path=${safeLogValue(req && (req.path || req.url), 120)}`);
  }
  return result;
}

const UNKNOWN_SCANNER_SHIELD_ENABLED = (process.env.UNKNOWN_SCANNER_SHIELD_ENABLED || "1") !== "0";
const UNKNOWN_SCANNER_WINDOW_SECONDS = readPositiveIntEnv("UNKNOWN_SCANNER_WINDOW_SECONDS", 60);
const UNKNOWN_SCANNER_RAPID_WINDOW_SECONDS = readPositiveIntEnv("UNKNOWN_SCANNER_RAPID_WINDOW_SECONDS", 10);
const UNKNOWN_SCANNER_UNIQUE_PATHS = readPositiveIntEnv("UNKNOWN_SCANNER_UNIQUE_PATHS", 12);
const UNKNOWN_SCANNER_RAPID_UNIQUE_PATHS = readPositiveIntEnv("UNKNOWN_SCANNER_RAPID_UNIQUE_PATHS", 8);
const UNKNOWN_SCANNER_HEADER_ANOMALY_PATHS = readPositiveIntEnv("UNKNOWN_SCANNER_HEADER_ANOMALY_PATHS", 6);
const UNKNOWN_SCANNER_MAX_HISTORY_PER_IP = readPositiveIntEnv("UNKNOWN_SCANNER_MAX_HISTORY_PER_IP", 64);
const UNKNOWN_SCANNER_DENY_TTL_SECONDS = readPositiveIntEnv("UNKNOWN_SCANNER_DENY_TTL_SECONDS", 120);
const KNOWN_SCANNER_DENY_THRESHOLD = readPositiveIntEnv("KNOWN_SCANNER_DENY_THRESHOLD", 12);
const KNOWN_SCANNER_DENY_TTL_SECONDS = readPositiveIntEnv("KNOWN_SCANNER_DENY_TTL_SECONDS", 900);
const KNOWN_SCANNER_VISIBLE_IP_THRESHOLD = readPositiveIntEnv("KNOWN_SCANNER_VISIBLE_IP_THRESHOLD", 18);
const KNOWN_SCANNER_VISIBLE_IP_DENY_TTL_SECONDS = readPositiveIntEnv("KNOWN_SCANNER_VISIBLE_IP_DENY_TTL_SECONDS", 900);
const VISIBLE_IP_REPUTATION_ENABLED = (process.env.VISIBLE_IP_REPUTATION_ENABLED || "1") !== "0";
const VISIBLE_IP_REPUTATION_WINDOW_SECONDS = readPositiveIntEnv("VISIBLE_IP_REPUTATION_WINDOW_SECONDS", 1800);
const VISIBLE_IP_REPUTATION_DENY_THRESHOLD = readPositiveIntEnv("VISIBLE_IP_REPUTATION_DENY_THRESHOLD", 12);
const VISIBLE_IP_REPUTATION_MIN_CATEGORIES = readPositiveIntEnv("VISIBLE_IP_REPUTATION_MIN_CATEGORIES", 2);
const VISIBLE_IP_REPUTATION_DENY_TTL_SECONDS = readPositiveIntEnv("VISIBLE_IP_REPUTATION_DENY_TTL_SECONDS", 900);
const VISIBLE_IP_REPUTATION_MAX_EVENTS_PER_IP = readPositiveIntEnv("VISIBLE_IP_REPUTATION_MAX_EVENTS_PER_IP", 64);
const VISIBLE_IP_PUBLIC_WALK_UNIQUE_PATHS = readPositiveIntEnv("VISIBLE_IP_PUBLIC_WALK_UNIQUE_PATHS", UNKNOWN_SCANNER_UNIQUE_PATHS);
const VISIBLE_IP_PUBLIC_WALK_RAPID_UNIQUE_PATHS = readPositiveIntEnv("VISIBLE_IP_PUBLIC_WALK_RAPID_UNIQUE_PATHS", UNKNOWN_SCANNER_RAPID_UNIQUE_PATHS);
const CRAWLER_PUBLIC_WALK_THROTTLE_ENABLED = (process.env.CRAWLER_PUBLIC_WALK_THROTTLE_ENABLED || "1") !== "0";
const CRAWLER_PUBLIC_WALK_WINDOW_SECONDS = readPositiveIntEnv("CRAWLER_PUBLIC_WALK_WINDOW_SECONDS", 10);
const CRAWLER_PUBLIC_WALK_MAX_PATHS = readPositiveIntEnv("CRAWLER_PUBLIC_WALK_MAX_PATHS", 14);
const CRAWLER_PUBLIC_WALK_SEARCH_MAX_PATHS = readPositiveIntEnv("CRAWLER_PUBLIC_WALK_SEARCH_MAX_PATHS", Math.max(CRAWLER_PUBLIC_WALK_MAX_PATHS * 2, 30));
const CRAWLER_PUBLIC_WALK_COOLDOWN_SECONDS = readPositiveIntEnv("CRAWLER_PUBLIC_WALK_COOLDOWN_SECONDS", 120);
const CRAWLER_PUBLIC_WALK_MAX_ENTRIES = readPositiveIntEnv("CRAWLER_PUBLIC_WALK_MAX_ENTRIES", 100000);
const KNOWN_SCANNER_BURST_HISTORY_MAX_ENTRIES = readPositiveIntEnv("KNOWN_SCANNER_BURST_HISTORY_MAX_ENTRIES", 100000);
const UNKNOWN_SCANNER_HISTORY_MAX_ENTRIES = readPositiveIntEnv("UNKNOWN_SCANNER_HISTORY_MAX_ENTRIES", 100000);
const UNKNOWN_SCANNER_HISTORY = new Map();
const SEARCH_BOT_VERIFICATION_CACHE = new Map();
const KNOWN_SCANNER_BURST_HISTORY = new Map();
const KNOWN_SCANNER_VISIBLE_IP_BURST_HISTORY = new Map();
const VISIBLE_IP_REPUTATION_HISTORY = new Map();
const VISIBLE_IP_PUBLIC_WALK_HISTORY = new Map();
const CRAWLER_PUBLIC_WALK_HISTORY = new Map();
const CRAWLER_PUBLIC_WALK_DENY_CACHE = new Map();
const CRAWLER_PUBLIC_WALK_IP_HISTORY = new Map();
const CRAWLER_PUBLIC_WALK_IP_DENY_CACHE = new Map();

const UNKNOWN_SCANNER_SKIP_PREFIXES = [
  "/health", "/healthz", "/readyz", "/livez", "/admin", "/view-log", "/stream-log",
  "/challenge", "/challenge-fragment", "/ts-client-log", "/turnstile-sitekey",
  "/e", "/favicon.ico", "/robots.txt", "/sitemap.xml", "/__hp.gif"
];
const UNKNOWN_SCANNER_STATIC_ASSET_REGEX = /\.(?:css|js|mjs|map|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|mp4|webm|txt|xml)$/i;
const NON_BROWSER_CRAWLER_UA_REGEX = /(?:googlebot|bingbot|duckduckbot|baiduspider|yandexbot|slurp|facebookexternalhit|facebot|ia_archiver|linkedinbot|twitterbot|pinterestbot|ahrefsbot|semrushbot|mj12bot|dotbot|petalbot|gptbot|crawler|spider)/i;
const NO_BYPASS_CRAWLER_INDEXER_UA_REGEX = /(?:claude-searchbot|meta-webindexer|mj12bot|baiduspider|bingbot|sitelockspider)/i;
const SCRIPT_CLIENT_UA_REGEX = /(?:curl|wget|python-requests|aiohttp|scrapy|java\/|go-http-client|okhttp|libwww-perl|httpclient)/i;
const SEARCH_BOT_REVERSE_DNS_SUFFIXES = {
  google: [".googlebot.com", ".google.com"],
  bing: [".search.msn.com"]
};

function getClaimedSearchBotVendorFromUa(ua = "") {
  const value = String(ua || "").toLowerCase();
  if (/\bgooglebot\b|\bgoogle-inspectiontool\b|\bgoogleother\b/.test(value)) return "google";
  if (/\bbingbot\b|\badidxbot\b|\bmsnbot\b/.test(value)) return "bing";
  return null;
}

function classifyCrawlerIndexerUa(ua = "") {
  const value = String(ua || "").toLowerCase();
  if (!value) return null;
  if (/claude-searchbot/.test(value)) return "ai_search_indexer";
  if (/meta-webindexer/.test(value)) return "search_indexer";
  if (/mj12bot|baiduspider|bingbot|sitelockspider/.test(value)) return "search_crawler";
  if (NON_BROWSER_CRAWLER_UA_REGEX.test(value)) return "crawler";
  return null;
}

function getClaimedSearchBotVendor(req) {
  const headers = (req && req.headers) || {};
  return getClaimedSearchBotVendorFromUa(headers["user-agent"] || "");
}

function normalizeDnsName(name = "") {
  return String(name || "").trim().toLowerCase().replace(/\.+$/, "");
}

function searchBotHostnameMatchesVendor(hostname, vendor) {
  const normalized = normalizeDnsName(hostname);
  const suffixes = SEARCH_BOT_REVERSE_DNS_SUFFIXES[vendor] || [];
  return suffixes.some(suffix => normalized.endsWith(suffix));
}

function normalizeIpForDnsVerification(ip = "") {
  const value = String(ip || "").trim().replace(/^::ffff:/i, "");
  return net.isIP(value) ? value : "";
}

function isVerifiedSearchBotRequest(req) {
  return Boolean(req && req.searchBotVerification && req.searchBotVerification.verified === true);
}

function getSearchBotVerificationCacheKey(ip, vendor) {
  return `${vendor}:${normalizeIpForDnsVerification(ip)}`;
}

async function withDnsTimeout(promise, timeoutMs) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("dns_timeout")), timeoutMs);
        if (timer && typeof timer.unref === "function") timer.unref();
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function cacheSearchBotVerification(key, result) {
  const ttlMs = result.verified ? SEARCH_BOT_DNS_CACHE_TTL_MS : SEARCH_BOT_DNS_NEGATIVE_TTL_MS;
  boundedMapSet(SEARCH_BOT_VERIFICATION_CACHE, key, { ...result, expiresAt: Date.now() + ttlMs }, SEARCH_BOT_DNS_CACHE_MAX_ENTRIES);
  return result;
}

async function verifySearchBotIp(ip, vendor) {
  const normalizedVendor = String(vendor || "").toLowerCase();
  const normalizedIp = normalizeIpForDnsVerification(ip);
  const base = { vendor: normalizedVendor, ip: normalizedIp || String(ip || ""), verified: false };
  if (!SEARCH_BOT_DNS_VERIFY_ENABLED) return { ...base, skipped: true, reason: "disabled" };
  if (!SEARCH_BOT_REVERSE_DNS_SUFFIXES[normalizedVendor]) return { ...base, reason: "unsupported_vendor" };
  if (!normalizedIp) return { ...base, reason: "invalid_ip" };

  const cacheKey = getSearchBotVerificationCacheKey(normalizedIp, normalizedVendor);
  const cached = SEARCH_BOT_VERIFICATION_CACHE.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) return { ...cached, cached: true };
  if (cached) SEARCH_BOT_VERIFICATION_CACHE.delete(cacheKey);

  try {
    const ptrHostnames = await withDnsTimeout(dns.promises.reverse(normalizedIp), SEARCH_BOT_DNS_TIMEOUT_MS);
    const matchedHostname = (ptrHostnames || []).map(normalizeDnsName).find(host => searchBotHostnameMatchesVendor(host, normalizedVendor));
    if (!matchedHostname) return cacheSearchBotVerification(cacheKey, { ...base, ptrHostnames, reason: "ptr_suffix_mismatch" });

    const addresses = await withDnsTimeout(dns.promises.lookup(matchedHostname, { all: true }), SEARCH_BOT_DNS_TIMEOUT_MS);
    const forwardIps = (addresses || []).map(entry => normalizeIpForDnsVerification(entry && entry.address)).filter(Boolean);
    const verified = forwardIps.includes(normalizedIp);
    return cacheSearchBotVerification(cacheKey, {
      ...base,
      verified,
      hostname: matchedHostname,
      ptrHostnames,
      forwardIps,
      reason: verified ? "verified" : "forward_mismatch"
    });
  } catch (error) {
    return cacheSearchBotVerification(cacheKey, { ...base, reason: error && error.message ? error.message : "dns_error" });
  }
}

function isLikelyNonBrowserCrawler(req) {
  const headers = (req && req.headers) || {};
  const ua = String(headers["user-agent"] || "");
  const accept = String(headers.accept || "").toLowerCase();
  const claimedSearchBotVendor = getClaimedSearchBotVendorFromUa(ua);
  // Search engines/indexers are classified for attribution/logging, not for bypass.
  // Let the unknown-scanner shield evaluate claimed Google/Bing and noisy indexers like other visitors.
  if (claimedSearchBotVendor || NO_BYPASS_CRAWLER_INDEXER_UA_REGEX.test(ua)) return false;
  if (!NON_BROWSER_CRAWLER_UA_REGEX.test(ua) || SCRIPT_CLIENT_UA_REGEX.test(ua)) return false;
  return !accept || accept.includes("text/html") || accept.includes("application/xhtml+xml") || accept === "*/*";
}

function shouldSkipUnknownScannerShield(req) {
  const method = String((req && req.method) || "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") return true;
  if (isLikelyNonBrowserCrawler(req)) return true;
  const pathValue = String((req && req.path) || "/");
  if (UNKNOWN_SCANNER_SKIP_PREFIXES.some(prefix => pathMatchesUnknownScannerSkipPrefix(pathValue, prefix))) return true;
  if (isLikelyRedirectPayloadPathCandidate(pathValue) || isLikelyFlexibleRedirectPayloadCandidate(pathValue)) return true;
  if (isLikelyRawUrlRedirectPayload(pathValue)) return true;
  return UNKNOWN_SCANNER_STATIC_ASSET_REGEX.test(pathValue);
}

function getUnknownScannerHeaderAnomalies(req) {
  const headers = (req && req.headers) || {};
  const accept = String(headers.accept || "").toLowerCase();
  const anomalies = [];
  if (!headers["accept-language"]) anomalies.push("missing_accept_language");
  if (!headers["sec-ch-ua"]) anomalies.push("missing_sec_ch_ua");
  if (!headers["sec-fetch-site"]) anomalies.push("missing_sec_fetch_site");
  if (!headers["sec-fetch-mode"]) anomalies.push("missing_sec_fetch_mode");
  if (!accept) anomalies.push("missing_accept");
  if (accept === "*/*" || (!accept.includes("text/html") && !accept.includes("application/xhtml+xml"))) {
    anomalies.push("accept_not_html");
  }
  return anomalies;
}

function hasUnknownScannerClientSignal(req, anomalies = []) {
  const method = String((req && req.method) || "GET").toUpperCase();
  const ua = String(((req && req.headers) || {})["user-agent"] || "");
  if (method === "HEAD") return true;
  if (SCRIPT_CLIENT_UA_REGEX.test(ua)) return true;
  if (anomalies.includes("missing_accept") || anomalies.includes("accept_not_html")) return true;
  return anomalies.length >= 3;
}

function normalizeScannerConfidence(value, fallback = 0.9) {
  if (value === undefined || value === null || value === "") return fallback;
  const confidence = Number(value);
  return Number.isFinite(confidence) ? confidence : fallback;
}

function shouldTrackVisibleIpPublicWalk(req, hasPriorVisibleIpReputation) {
  return Boolean(
    UNKNOWN_SCANNER_SHIELD_ENABLED &&
    hasPriorVisibleIpReputation &&
    !shouldSkipUnknownScannerShield(req)
  );
}

function getCrawlerPublicWalkSignal(req) {
  const headers = (req && req.headers) || {};
  const ua = String(headers["user-agent"] || "");
  const anomalies = getUnknownScannerHeaderAnomalies(req);
  const crawlerClassification = classifyCrawlerIndexerUa(ua);
  const claimedSearchBotVendor = getClaimedSearchBotVendorFromUa(ua);
  const scriptClient = SCRIPT_CLIENT_UA_REGEX.test(ua);

  // Keep this deliberately narrow: browsers, even on shared IPs, do not match
  // unless they also present automation/crawler traits. Verified search bots are
  // not exempted here; verification is attribution, not a challenge bypass.
  if (!crawlerClassification && !claimedSearchBotVendor && !scriptClient) return null;
  if (!scriptClient && anomalies.length < 2) return null;

  return {
    crawlerClassification: crawlerClassification || (claimedSearchBotVendor ? "search_crawler" : (scriptClient ? "script_client" : "crawler")),
    claimedSearchBotVendor,
    anomalies
  };
}

function getCrawlerPublicWalkKey(req) {
  const identity = getRequestIdentity(req);
  const ua = String(((req && req.headers) || {})["user-agent"] || "-").toLowerCase().slice(0, 300);
  const uaHash = crypto.createHash("sha256").update(ua).digest("base64url").slice(0, 16);
  return `${sanitizeIpForKey(identity.denyCacheKey || identity.rateLimitKey || identity.ip)}:${uaHash}`;
}

function getCrawlerPublicWalkIpKey(req) {
  const identity = getRequestIdentity(req);
  return sanitizeIpForKey(identity.denyCacheKey || identity.rateLimitKey || identity.ip);
}

function normalizeCrawlerPublicWalkPath(req) {
  let pathValue = String((req && req.path) || "/").split("?")[0] || "/";
  try {
    pathValue = decodeURIComponent(pathValue);
  } catch (_) {}
  pathValue = pathValue.replace(/\/{2,}/g, "/");
  if (!pathValue.startsWith("/")) pathValue = `/${pathValue}`;
  if (pathValue.length > 1) pathValue = pathValue.replace(/\/+$/, "");
  pathValue = pathValue.toLowerCase();
  return pathValue || "/";
}

function hasCrawlerPublicWalkSearchAllowance(req, signal) {
  if (signal && signal.crawlerClassification === "search_crawler") return true;
  const claimedVendor = getClaimedSearchBotVendor(req);
  if (claimedVendor === "google" || claimedVendor === "bing") return true;
  const verifiedVendor = req && req.searchBotVerification && req.searchBotVerification.verified === true
    ? String(req.searchBotVerification.vendor || "").toLowerCase()
    : "";
  return verifiedVendor === "google" || verifiedVendor === "bing";
}

function isPublicWalkThrottleCandidatePath(req) {
  const method = String((req && req.method) || "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") return false;

  const pathValue = normalizeCrawlerPublicWalkPath(req);
  if (pathValue === "/") return true;
  if (UNKNOWN_SCANNER_STATIC_ASSET_REGEX.test(pathValue)) return false;
  if (UNKNOWN_SCANNER_SKIP_PREFIXES.some(prefix => pathMatchesUnknownScannerSkipPrefix(pathValue, prefix))) return false;

  try {
    const current = getCurrentPublicPathSet();
    const publicSurfaceEnabled = typeof isPublicContentSurfaceEnabled === "function" && isPublicContentSurfaceEnabled();
    if (publicSurfaceEnabled && current && current.paths && current.paths.has(pathValue)) return true;
  } catch (_) {}

  const publicSurfaceEnabled = typeof isPublicContentSurfaceEnabled === "function" && isPublicContentSurfaceEnabled();
  return publicSurfaceEnabled && PUBLIC_CANONICAL_ALIASES.has(pathValue);
}

function checkCrawlerPublicWalkThrottle(req, now = Date.now()) {
  if (!CRAWLER_PUBLIC_WALK_THROTTLE_ENABLED) return { limited: false };
  if (!isPublicWalkThrottleCandidatePath(req)) return { limited: false };

  const key = getCrawlerPublicWalkKey(req);
  if (hasTrustedExternalScannerDetection(req)) return { limited: false, publicWalkAllowed: true, trustedExternalScanner: true };

  const deny = CRAWLER_PUBLIC_WALK_DENY_CACHE.get(key);
  if (deny && deny.until > now) {
    return {
      limited: true,
      cached: true,
      retryAfterSec: Math.max(1, Math.ceil((deny.until - now) / 1000)),
      ...deny.details
    };
  }
  if (deny) CRAWLER_PUBLIC_WALK_DENY_CACHE.delete(key);

  const signal = getCrawlerPublicWalkSignal(req);
  if (!signal) return { limited: false };

  const ipKey = getCrawlerPublicWalkIpKey(req);
  const ipDeny = CRAWLER_PUBLIC_WALK_IP_DENY_CACHE.get(ipKey);
  if (ipDeny && ipDeny.until > now) {
    return {
      limited: true,
      cached: true,
      ipBackstop: true,
      retryAfterSec: Math.max(1, Math.ceil((ipDeny.until - now) / 1000)),
      ...ipDeny.details
    };
  }
  if (ipDeny) CRAWLER_PUBLIC_WALK_IP_DENY_CACHE.delete(ipKey);

  const maxUniquePaths = hasCrawlerPublicWalkSearchAllowance(req, signal)
    ? CRAWLER_PUBLIC_WALK_SEARCH_MAX_PATHS
    : CRAWLER_PUBLIC_WALK_MAX_PATHS;

  const windowMs = CRAWLER_PUBLIC_WALK_WINDOW_SECONDS * 1000;
  const pathValue = normalizeCrawlerPublicWalkPath(req);
  const current = CRAWLER_PUBLIC_WALK_HISTORY.get(key) || [];
  const history = current.filter(entry => entry && (now - entry.ts) <= windowMs);
  history.push({ ts: now, path: pathValue });
  if (history.length > Math.max(maxUniquePaths * 2, 32)) {
    history.splice(0, history.length - Math.max(maxUniquePaths * 2, 32));
  }
  boundedMapSet(CRAWLER_PUBLIC_WALK_HISTORY, key, history, CRAWLER_PUBLIC_WALK_MAX_ENTRIES);

  const currentIpHistory = CRAWLER_PUBLIC_WALK_IP_HISTORY.get(ipKey) || [];
  const ipHistory = currentIpHistory.filter(entry => entry && (now - entry.ts) <= windowMs);
  ipHistory.push({ ts: now, path: pathValue });
  if (ipHistory.length > Math.max(maxUniquePaths * 2, 32)) {
    ipHistory.splice(0, ipHistory.length - Math.max(maxUniquePaths * 2, 32));
  }
  boundedMapSet(CRAWLER_PUBLIC_WALK_IP_HISTORY, ipKey, ipHistory, CRAWLER_PUBLIC_WALK_MAX_ENTRIES);

  const uniquePaths = new Set(history.map(entry => entry.path));
  const ipUniquePaths = new Set(ipHistory.map(entry => entry.path));
  const ipBackstopTriggered = ipUniquePaths.size > maxUniquePaths;
  if (uniquePaths.size <= maxUniquePaths && !ipBackstopTriggered) {
    return { limited: false, publicWalkAllowed: true, uniquePathCount: uniquePaths.size, ipUniquePathCount: ipUniquePaths.size, requestCount: history.length, maxUniquePaths, ...signal };
  }

  const details = {
    uniquePathCount: uniquePaths.size,
    ipUniquePathCount: ipUniquePaths.size,
    requestCount: history.length,
    maxUniquePaths,
    crawlerClassification: signal.crawlerClassification,
    anomalies: signal.anomalies
  };
  boundedMapSet(CRAWLER_PUBLIC_WALK_DENY_CACHE, key, {
    until: now + CRAWLER_PUBLIC_WALK_COOLDOWN_SECONDS * 1000,
    details: { ...details, ipBackstop: ipBackstopTriggered }
  }, CRAWLER_PUBLIC_WALK_MAX_ENTRIES);
  if (ipBackstopTriggered) {
    boundedMapSet(CRAWLER_PUBLIC_WALK_IP_DENY_CACHE, ipKey, {
      until: now + CRAWLER_PUBLIC_WALK_COOLDOWN_SECONDS * 1000,
      details: { ...details, ipBackstop: true }
    }, CRAWLER_PUBLIC_WALK_MAX_ENTRIES);
  }

  return { limited: true, retryAfterSec: CRAWLER_PUBLIC_WALK_COOLDOWN_SECONDS, ipBackstop: ipBackstopTriggered, ...details };
}

function pruneCrawlerPublicWalkState(now = Date.now()) {
  const historyTtlMs = CRAWLER_PUBLIC_WALK_WINDOW_SECONDS * 1000 * 2;
  for (const historyMap of [CRAWLER_PUBLIC_WALK_HISTORY, CRAWLER_PUBLIC_WALK_IP_HISTORY]) {
    for (const [key, entries] of historyMap.entries()) {
      const fresh = (entries || []).filter(entry => entry && (now - entry.ts) <= historyTtlMs);
      if (!fresh.length) historyMap.delete(key);
      else if (fresh.length !== entries.length) boundedMapSet(historyMap, key, fresh, CRAWLER_PUBLIC_WALK_MAX_ENTRIES);
    }
  }
  for (const denyMap of [CRAWLER_PUBLIC_WALK_DENY_CACHE, CRAWLER_PUBLIC_WALK_IP_DENY_CACHE]) {
    for (const [key, deny] of denyMap.entries()) {
      if (!deny || deny.until <= now) denyMap.delete(key);
    }
  }
}

function hasTrustedExternalScannerDetection(req) {
  const scannerDetections = typeof detectScannerEnhanced === "function" ? detectScannerEnhanced(req) : [];
  if (!Array.isArray(scannerDetections)) return false;
  return scannerDetections.some(detection =>
    detection &&
    detection.trustedExternalScanner === true &&
    Number(detection.confidence || 0) >= IMPERSONATE_MIN_CONFIDENCE
  );
}

function classifyUnknownScannerBehavior(req) {
  if (!UNKNOWN_SCANNER_SHIELD_ENABLED || shouldSkipUnknownScannerShield(req)) return null;
  if (hasTrustedExternalScannerDetection(req)) return null;

  const ip = getClientIp(req);
  const historyIp = getDenyCacheIp(req);
  const safeIp = sanitizeIpForKey(historyIp);
  const now = Date.now();
  const windowMs = UNKNOWN_SCANNER_WINDOW_SECONDS * 1000;
  const rapidWindowMs = UNKNOWN_SCANNER_RAPID_WINDOW_SECONDS * 1000;
  const normalizedPath = String((req && req.path) || "/").split("?")[0].toLowerCase() || "/";
  const current = UNKNOWN_SCANNER_HISTORY.get(safeIp) || [];
  const history = current.filter(entry => entry && (now - entry.ts) <= windowMs);
  history.push({ ts: now, path: normalizedPath, method: String((req && req.method) || "GET").toUpperCase() });
  if (history.length > UNKNOWN_SCANNER_MAX_HISTORY_PER_IP) {
    history.splice(0, history.length - UNKNOWN_SCANNER_MAX_HISTORY_PER_IP);
  }
  boundedMapSet(UNKNOWN_SCANNER_HISTORY, safeIp, history, UNKNOWN_SCANNER_HISTORY_MAX_ENTRIES);

  const uniquePaths = new Set(history.map(entry => entry.path));
  const rapidHistory = history.filter(entry => (now - entry.ts) <= rapidWindowMs);
  const rapidUniquePaths = new Set(rapidHistory.map(entry => entry.path));
  const anomalies = getUnknownScannerHeaderAnomalies(req);
  const clientSignal = hasUnknownScannerClientSignal(req, anomalies);
  const crawlerClassification = classifyCrawlerIndexerUa(((req && req.headers) || {})["user-agent"] || "");

  let reason = null;
  if (clientSignal && rapidUniquePaths.size >= UNKNOWN_SCANNER_RAPID_UNIQUE_PATHS) {
    reason = "rapid_unique_path_scan";
  } else if (clientSignal && uniquePaths.size >= UNKNOWN_SCANNER_UNIQUE_PATHS) {
    reason = "wide_unique_path_scan";
  } else if (
    uniquePaths.size >= UNKNOWN_SCANNER_HEADER_ANOMALY_PATHS &&
    anomalies.length >= 2 &&
    (anomalies.includes("missing_accept") || anomalies.includes("accept_not_html"))
  ) {
    reason = "header_anomaly_path_scan";
  } else if (
    clientSignal &&
    history.length >= UNKNOWN_SCANNER_UNIQUE_PATHS + 4 &&
    uniquePaths.size / history.length >= 0.75
  ) {
    reason = "high_ratio_path_scan";
  }

  if (!reason) return null;
  return {
    ip,
    reason,
    uniquePathCount: uniquePaths.size,
    rapidUniquePathCount: rapidUniquePaths.size,
    requestCount: history.length,
    anomalies,
    clientSignal,
    crawlerClassification,
    historyIp
  };
}

function pruneUnknownScannerHistory(now = Date.now()) {
  const ttlMs = UNKNOWN_SCANNER_WINDOW_SECONDS * 1000 * 2;
  for (const [key, entries] of UNKNOWN_SCANNER_HISTORY.entries()) {
    const fresh = Array.isArray(entries)
      ? entries.filter(entry => entry && (now - entry.ts) <= ttlMs)
      : [];
    if (fresh.length === 0) {
      UNKNOWN_SCANNER_HISTORY.delete(key);
    } else if (fresh.length !== entries.length) {
      boundedMapSet(UNKNOWN_SCANNER_HISTORY, key, fresh, UNKNOWN_SCANNER_HISTORY_MAX_ENTRIES);
    }
  }
}
function isLikelyArchiveProbePath(candidatePath) {
  const normalized = String(candidatePath || "").toLowerCase().replace(/^\/+/, "");
  if (!normalized || normalized.includes("/")) return false;
  if (!ARCHIVE_PROBE_SUFFIX_REGEX.test(normalized)) return false;
  if (!ARCHIVE_PROBE_NAME_REGEX.test(normalized)) return false;
  // base64url payloads are expected to be opaque and usually avoid dots/known archive suffixes.
  return true;
}

const CRAWLER_PROBE_PATHS = new Set([
  "sitemap.txt",
  "sitemaps.xml",
  "sitemap_index.xml",
  "wp-sitemap.xml",
  "news-sitemap.xml",
  "atom.xml",
  "rss.xml",
  "feed.xml",
  "th1s_1s_a_4o4.html"
]);

function isLikelyCrawlerProbePath(pathValue) {
  const raw = String(pathValue || "/").split("?")[0].split("#")[0] || "/";
  const candidate = raw.startsWith("/") ? raw.slice(1) : raw;
  const { payloadPath } = stripOptionalUrlPrefix(candidate);
  const normalizedPayloadPath = String(payloadPath || "").replace(/^\/+/, "").toLowerCase();
  if (!normalizedPayloadPath || normalizedPayloadPath.includes("/")) return false;
  return CRAWLER_PROBE_PATHS.has(normalizedPayloadPath);
}

const LOCALE_ONLY_PROBE_PATH_REGEX = /^[a-z]{2}(?:-[a-z]{2})?$/i;

function isLikelyLocaleOnlyProbePath(pathValue) {
  const raw = String(pathValue || "/").split("?")[0].split("#")[0] || "/";
  const candidate = raw.startsWith("/") ? raw.slice(1) : raw;
  const { payloadPath } = stripOptionalUrlPrefix(candidate);
  const normalizedPayloadPath = String(payloadPath || "").replace(/^\/+/, "").toLowerCase();
  return LOCALE_ONLY_PROBE_PATH_REGEX.test(normalizedPayloadPath);
}


  return {
    VISIBLE_IP_REPUTATION_WEIGHTS,
    VISIBLE_IP_REPUTATION_HIGH_SIGNAL_CATEGORIES,
    getVisibleIpReputationHistoryByKey,
    getVisibleIpReputationHistory,
    summarizeVisibleIpReputationEvents,
    hasVisibleIpReputationSignal,
    recordVisibleIpReputationSignal,
    summarizePathHistory,
    getUnknownScannerHistorySummary,
    recordVisibleIpPublicWalkPath,
    canDenyCacheVisibleIp,
    maybeDenyForVisibleIpReputation,
    UNKNOWN_SCANNER_SHIELD_ENABLED,
    UNKNOWN_SCANNER_WINDOW_SECONDS,
    UNKNOWN_SCANNER_RAPID_WINDOW_SECONDS,
    UNKNOWN_SCANNER_UNIQUE_PATHS,
    UNKNOWN_SCANNER_RAPID_UNIQUE_PATHS,
    UNKNOWN_SCANNER_HEADER_ANOMALY_PATHS,
    UNKNOWN_SCANNER_MAX_HISTORY_PER_IP,
    UNKNOWN_SCANNER_DENY_TTL_SECONDS,
    KNOWN_SCANNER_DENY_THRESHOLD,
    KNOWN_SCANNER_DENY_TTL_SECONDS,
    KNOWN_SCANNER_VISIBLE_IP_THRESHOLD,
    KNOWN_SCANNER_VISIBLE_IP_DENY_TTL_SECONDS,
    VISIBLE_IP_REPUTATION_ENABLED,
    VISIBLE_IP_REPUTATION_WINDOW_SECONDS,
    VISIBLE_IP_REPUTATION_DENY_THRESHOLD,
    VISIBLE_IP_REPUTATION_MIN_CATEGORIES,
    VISIBLE_IP_REPUTATION_DENY_TTL_SECONDS,
    VISIBLE_IP_REPUTATION_MAX_EVENTS_PER_IP,
    VISIBLE_IP_PUBLIC_WALK_UNIQUE_PATHS,
    VISIBLE_IP_PUBLIC_WALK_RAPID_UNIQUE_PATHS,
    CRAWLER_PUBLIC_WALK_THROTTLE_ENABLED,
    CRAWLER_PUBLIC_WALK_WINDOW_SECONDS,
    CRAWLER_PUBLIC_WALK_MAX_PATHS,
    CRAWLER_PUBLIC_WALK_SEARCH_MAX_PATHS,
    CRAWLER_PUBLIC_WALK_COOLDOWN_SECONDS,
    CRAWLER_PUBLIC_WALK_MAX_ENTRIES,
    KNOWN_SCANNER_BURST_HISTORY_MAX_ENTRIES,
    UNKNOWN_SCANNER_HISTORY_MAX_ENTRIES,
    UNKNOWN_SCANNER_HISTORY,
    SEARCH_BOT_VERIFICATION_CACHE,
    KNOWN_SCANNER_BURST_HISTORY,
    KNOWN_SCANNER_VISIBLE_IP_BURST_HISTORY,
    VISIBLE_IP_REPUTATION_HISTORY,
    VISIBLE_IP_PUBLIC_WALK_HISTORY,
    CRAWLER_PUBLIC_WALK_HISTORY,
    CRAWLER_PUBLIC_WALK_DENY_CACHE,
    CRAWLER_PUBLIC_WALK_IP_HISTORY,
    CRAWLER_PUBLIC_WALK_IP_DENY_CACHE,
    UNKNOWN_SCANNER_SKIP_PREFIXES,
    UNKNOWN_SCANNER_STATIC_ASSET_REGEX,
    NON_BROWSER_CRAWLER_UA_REGEX,
    NO_BYPASS_CRAWLER_INDEXER_UA_REGEX,
    SCRIPT_CLIENT_UA_REGEX,
    SEARCH_BOT_REVERSE_DNS_SUFFIXES,
    getClaimedSearchBotVendorFromUa,
    classifyCrawlerIndexerUa,
    getClaimedSearchBotVendor,
    normalizeDnsName,
    searchBotHostnameMatchesVendor,
    normalizeIpForDnsVerification,
    isVerifiedSearchBotRequest,
    getSearchBotVerificationCacheKey,
    withDnsTimeout,
    cacheSearchBotVerification,
    verifySearchBotIp,
    isLikelyNonBrowserCrawler,
    pathMatchesUnknownScannerSkipPrefix,
    shouldSkipUnknownScannerShield,
    getUnknownScannerHeaderAnomalies,
    hasUnknownScannerClientSignal,
    normalizeScannerConfidence,
    shouldTrackVisibleIpPublicWalk,
    getCrawlerPublicWalkSignal,
    getCrawlerPublicWalkKey,
    getCrawlerPublicWalkIpKey,
    normalizeCrawlerPublicWalkPath,
    hasCrawlerPublicWalkSearchAllowance,
    isPublicWalkThrottleCandidatePath,
    checkCrawlerPublicWalkThrottle,
    pruneCrawlerPublicWalkState,
    hasTrustedExternalScannerDetection,
    classifyUnknownScannerBehavior,
    pruneUnknownScannerHistory,
    isLikelyArchiveProbePath,
    CRAWLER_PROBE_PATHS,
    isLikelyCrawlerProbePath,
    LOCALE_ONLY_PROBE_PATH_REGEX,
    isLikelyLocaleOnlyProbePath,
  };
};
