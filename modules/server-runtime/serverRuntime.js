// AES Redirector v5.0.6 :- Cloudflare Turnstile Hardened + Advance Beta Widget + Interstitial Improved + ScannerHeader Fix + No resource leak
require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const dns = require("dns");
const net = require("net");
const http = require("http");
const https = require("https");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const os = require("os");
const DEFAULT_MAX_TIMER_MS = 2_147_483_647;

function readMaxTimerMsEnv(name = "MAX_TIMER_MS", fallbackMs = DEFAULT_MAX_TIMER_MS) {
  const raw = process.env[name];
  if (raw == null || raw === "") return fallbackMs;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 1) return fallbackMs;
  return Math.min(DEFAULT_MAX_TIMER_MS, Math.trunc(parsed));
}

const MAX_TIMER_MS = readMaxTimerMsEnv();

// fetch (Node 18+ has global fetch)
let fetchFn = globalThis.fetch;
if (!fetchFn) {
  try {
    fetchFn = require("node-fetch");
  } catch (_) {
    // Keep startup failure explicit below instead of a later TypeError in runtime paths.
  }
}
if (typeof fetchFn !== "function") {
  throw new Error(
    "Fetch API is unavailable. Use Node.js 18+ or install node-fetch."
  );
}
const fetch = fetchFn;

function clampMs(value, minMs = 0, maxMs = MAX_TIMER_MS) {
  return Math.min(maxMs, Math.max(minMs, value));
}

function readMsEnv(name, defaultMs, minMs = 1000, maxMs = MAX_TIMER_MS) {
  const raw = process.env[name];
  const normalizedRaw = typeof raw === "string" ? raw.trim() : raw;
  if (normalizedRaw == null || normalizedRaw === "") {
    return clampMs(defaultMs, minMs, maxMs);
  }
  const parsed = Number(normalizedRaw);
  const safe = Number.isFinite(parsed) ? Math.trunc(parsed) : defaultMs;
  return clampMs(safe, minMs, maxMs);
}


const FETCH_TIMEOUT_MS_DEFAULT = readMsEnv("FETCH_TIMEOUT_MS", 8000, 1000);
const REQUEST_TIMEOUT_MS = readMsEnv("REQUEST_TIMEOUT_MS", 30000, 1000);
const SERVER_KEEP_ALIVE_TIMEOUT_MS = readMsEnv("SERVER_KEEP_ALIVE_TIMEOUT_MS", 5000, 1000);
const SERVER_HEADERS_TIMEOUT_MS = Math.max(
  SERVER_KEEP_ALIVE_TIMEOUT_MS + 1000,
  readMsEnv("SERVER_HEADERS_TIMEOUT_MS", SERVER_KEEP_ALIVE_TIMEOUT_MS + 1000, SERVER_KEEP_ALIVE_TIMEOUT_MS + 1000)
);
const SHUTDOWN_GRACE_MS = readMsEnv("SHUTDOWN_GRACE_MS", 10000, 1000);
function readPositiveIntEnv(name, fallback) {
  const raw = process.env[name];
  if (raw == null || raw === "") return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) return fallback;
  const value = Math.trunc(parsed);
  if (value < 1) return fallback;
  return value;
}

const SERVER_MAX_REQUESTS_PER_SOCKET = readPositiveIntEnv("SERVER_MAX_REQUESTS_PER_SOCKET", 1000);
const MAX_CATCHALL_CONCURRENCY = readPositiveIntEnv("MAX_CATCHALL_CONCURRENCY", 200);
const CIRCUIT_BREAKER_THRESHOLD = readPositiveIntEnv("CIRCUIT_BREAKER_THRESHOLD", 5);
const CIRCUIT_BREAKER_COOLDOWN_MS = readMsEnv("CIRCUIT_BREAKER_COOLDOWN_MS", 30000, 1000);
const BROWNOUT_TIMEOUT_THRESHOLD = readPositiveIntEnv("BROWNOUT_TIMEOUT_THRESHOLD", 8);
const BROWNOUT_WINDOW_MS = readMsEnv("BROWNOUT_WINDOW_MS", 60000, 1000);
const BROWNOUT_DURATION_MS = readMsEnv("BROWNOUT_DURATION_MS", 120000, 1000);

const PER_IP_REQUEST_COUNTS_MAX_ENTRIES = readPositiveIntEnv("PER_IP_REQUEST_COUNTS_MAX_ENTRIES", 100000);
const IN_MEM_BUCKETS_MAX_ENTRIES = readPositiveIntEnv("IN_MEM_BUCKETS_MAX_ENTRIES", 100000);
const IN_MEM_STRIKES_MAX_ENTRIES = readPositiveIntEnv("IN_MEM_STRIKES_MAX_ENTRIES", 100000);
const CLIENT_ERROR_RAW_PACKET_PREVIEW_BYTES = readPositiveIntEnv("CLIENT_ERROR_RAW_PACKET_PREVIEW_BYTES", 48);
const IN_MEM_BANS_MAX_ENTRIES = readPositiveIntEnv("IN_MEM_BANS_MAX_ENTRIES", 100000);
const MAX_REDIRECT_PAYLOAD_LENGTH = readPositiveIntEnv("MAX_REDIRECT_PAYLOAD_LENGTH", 8192);
const MAX_REDIRECT_URL_PATH_LENGTH = readPositiveIntEnv("MAX_REDIRECT_URL_PATH_LENGTH", 16384);
const REDIRECT_PAYLOAD_OVERSIZE_MODE = String(process.env.REDIRECT_PAYLOAD_OVERSIZE_MODE || "log").trim().toLowerCase();
const MAX_BRUTE_SPLIT_PAYLOAD_LENGTH = readPositiveIntEnv("MAX_BRUTE_SPLIT_PAYLOAD_LENGTH", MAX_REDIRECT_URL_PATH_LENGTH);
const IN_MEM_DENY_CACHE_MAX_ENTRIES = readPositiveIntEnv("IN_MEM_DENY_CACHE_MAX_ENTRIES", 100000);
const GEO_ENRICH_CACHE_MAX_ENTRIES = readPositiveIntEnv("GEO_ENRICH_CACHE_MAX_ENTRIES", 10000);
const IPINFO_LITE_CACHE_MAX_ENTRIES = readPositiveIntEnv("IPINFO_LITE_CACHE_MAX_ENTRIES", 50000);
const IPINFO_TOKEN = String(process.env.IPINFO_TOKEN || process.env.IPINFO_ACCESS_TOKEN || "").trim();
const IPINFO_LITE_ENABLED = ["1", "true", "yes", "on"].includes(String(process.env.IPINFO_LITE_ENABLED || (IPINFO_TOKEN ? "1" : "0")).trim().toLowerCase());
const IPINFO_LITE_TIMEOUT_MS = readMsEnv("IPINFO_LITE_TIMEOUT_MS", 800, 100, 5000);
const IPINFO_LITE_CACHE_TTL_MS = readMsEnv("IPINFO_LITE_CACHE_TTL_MS", 6 * 60 * 60 * 1000, 60 * 1000);
const ADMIN_HITS_MAX_ENTRIES = readPositiveIntEnv("ADMIN_HITS_MAX_ENTRIES", 100000);
const LOG_AGGREGATION_MAX_ENTRIES = readPositiveIntEnv("LOG_AGGREGATION_MAX_ENTRIES", 100000);
const SCANNER_AGG_ALERT_THRESHOLD = readPositiveIntEnv("SCANNER_AGG_ALERT_THRESHOLD", 100);
const SEARCH_BOT_DNS_VERIFY_ENABLED = (process.env.SEARCH_BOT_DNS_VERIFY_ENABLED || "1") !== "0";
const SEARCH_BOT_DNS_TIMEOUT_MS = readMsEnv("SEARCH_BOT_DNS_TIMEOUT_MS", 900, 100, 5000);
const SEARCH_BOT_DNS_CACHE_TTL_MS = readMsEnv("SEARCH_BOT_DNS_CACHE_TTL_MS", 6 * 60 * 60 * 1000, 60 * 1000);
const SEARCH_BOT_DNS_NEGATIVE_TTL_MS = readMsEnv("SEARCH_BOT_DNS_NEGATIVE_TTL_MS", 15 * 60 * 1000, 30 * 1000);
const SEARCH_BOT_DNS_CACHE_MAX_ENTRIES = readPositiveIntEnv("SEARCH_BOT_DNS_CACHE_MAX_ENTRIES", 20000);
const SCANNER_FETCH_ENABLED = ["1", "true", "yes", "on"].includes(String(process.env.SCANNER_FETCH_ENABLED || "0").trim().toLowerCase());
const SCANNER_FETCH_TIMEOUT_MS = readMsEnv("SCANNER_FETCH_TIMEOUT_MS", 5000, 1000);
const SCANNER_FETCH_PREVIEW_BYTES = readPositiveIntEnv("SCANNER_FETCH_PREVIEW_BYTES", 4096);
const IPINFO_LITE_NEGATIVE_CACHE_TTL_MS = readMsEnv("IPINFO_LITE_NEGATIVE_CACHE_TTL_MS", 5 * 60 * 1000, 30 * 1000, IPINFO_LITE_CACHE_TTL_MS);
const MEMORY_PRESSURE_HEAP_USED_MB = readPositiveIntEnv("MEMORY_PRESSURE_HEAP_USED_MB", 512);
const MEMORY_PRESSURE_HEAP_USED_RATIO = Math.min(0.99, Math.max(0.1, Number(process.env.MEMORY_PRESSURE_HEAP_USED_RATIO || "0.85") || 0.85));

// --- Scanner safe-HTML settings ---
const SCANNER_SAFE_HTML_ENABLED = ["1", "true", "yes", "on"].includes(
  String(process.env.SCANNER_SAFE_HTML_ENABLED || "0").trim().toLowerCase()
);
const parseMinHourToMs = require("../runtime-utils/parseMinHourToMs.js");
const eSCANNER_CONFIG_RELOAD_MS = parseMinHourToMs(process.env.eSCANNER_CONFIG_RELOAD_MS, 600000, "ms");
// -------------------------------------------------

function evictOldestMapEntry(map) {
  if (!map || map.size <= 0) return false;
  const oldest = map.keys().next();
  if (!oldest || oldest.done) return false;
  return map.delete(oldest.value);
}

function boundedMapSet(map, key, value, maxEntries) {
  const cap = Number(maxEntries);
  if (!map || !Number.isFinite(cap) || cap < 1) {
    map.set(key, value);
    return map;
  }

  if (map.has(key)) {
    map.delete(key);
  } else {
    while (map.size >= cap) {
      if (!evictOldestMapEntry(map)) break;
    }
  }

  map.set(key, value);
  while (map.size > cap) {
    if (!evictOldestMapEntry(map)) break;
  }
  return map;
}

// Per-IP rate limiter (Change 3)
const RATE_LIMIT_WINDOW_SECONDS = readPositiveIntEnv("RATE_LIMIT_WINDOW_SECONDS", 60);
const RATE_LIMIT_MAX_REQUESTS = readPositiveIntEnv("RATE_LIMIT_MAX_REQUESTS", 100);

// Scanner probe path prefixes used for fast O(1) string matching (Change 1)
const SCANNER_PROBE_EXACT_PATHS = new Set([
  "env", "env.backup", "env.bak", "env.old", "env.txt",
  "wp", "old", "login", "register", "user/login",
  "application.yml", "application.yaml", "application-production.properties",
  "dockerfile", "local.settings.json", "settings.py", "local_settings.py",
  "settings/production.py", "var/log/app.log", ".yarnrc.yml",
  "heapdump", "threaddump", "dump", "trace", "logfile", "configprops",
  "api/env", "api/heapdump", "api/threaddump", "api/dump",
  "api/trace", "api/logfile", "api/configprops",
  "_profiler", "profiler", "profiler/phpinfo", "_ignition/execute-solution",
  "helm/values.yaml",
  "api-keys", "account/api-keys", "asset-manifest.json",
  "assets-manifest.json", "manifest.json", "build-manifest.json",
  "build/manifest.json", "webpack-stats.json", "loadable-stats.json",
  "precache-manifest.json", "llms.txt", "swagger.json",
  "var/task/serverless.yml", "var/task/serverless.yaml",
  "var/task/serverless.json", "app/serverless.yml",
  "app/serverless.yaml", "app/serverless.json",
  "plugins/payments/stripe.json"
]);

const SCANNER_PROBE_PREFIXES = [
  ".env", ".git", ".htaccess", ".htpasswd", ".DS_Store",
  "wp-admin", "wp-login.php", "wp-config.php", "wp-includes", "wp-json",
  "phpmyadmin", "pma", "myadmin",
  "admin.php", "administrator",
  "xmlrpc.php",
  "cgi-bin",
  "actuator", "actuator/", "api/actuator", "api/actuator/",
  "server-status", "server-info",
  "hnap1",
  "boaform",
  "vendor/phpunit",
  "storage/logs",
  "info.php", "phpinfo.php",
  "shell.php", "cmd.php", "c99.php", "r57.php", "b374k.php",
  "config.php", "setup.php", "install.php", "upgrade.php",
  "backup.php", "db.php", "database.php",
  "eval.php", "exec.php",
  "webshell", "webadmin",
  "console", "jmx-console", "web-console",
  "solr/", "jenkins/", "hudson/",
  "telescope/", "horizon/",
  "_profiler/", "profiler/",
  "debug/default/view",
  "aws/credentials", ".aws/",
  "docker-compose", "Dockerfile", "application.properties",
  "config/database", "config/",
  "server/php", "logs/", "tmp/", "templates/emails/", "utils/",
  "firebase.json", ".firebaserc", "dnscfg.cgi",
  "wp-content", "wordpress", "wp.php",
  "feed/", "readme.html",
  "node_modules",
  "laravel/", "symfony/", "vendor/",
  ".aws", ".docker",
  ".next/", ".vite/", ".astro/", "_nuxt/",
];

const ARCHIVE_PROBE_SUFFIX_REGEX = /\.(?:zip|tar|tar\.gz|tgz|tar\.xz|tar\.bz2|7z|rar|gz|bz2|zst|sql|sql\.gz|sql\.bz2)$/i;
const ARCHIVE_PROBE_NAME_REGEX = /^[a-z0-9._-]{2,80}$/i;

const NESTED_SCANNER_SUBSTRINGS = [
  "/.env", "/.env.", "/.git/", "/.git/config",
  "/wp-login.php", "/wp-admin/", "/wp-includes/", "/wp-json/",
  "/xmlrpc.php", "/wlwmanifest.xml",
  "/.vscode/", "/sftp-config.json",
  "/config/", "/backup/", "/database/",
  "/symfony/public/_profiler/", "/_profiler/", "/profiler/", "/debug/default/view",
  "/actuator/", "/heapdump", "/threaddump", "/configprops", "/logfile",
  "/.next/", "/.vite/", "/.astro/", "/_nuxt/",
  "/asset-manifest.json", "/assets-manifest.json", "/build-manifest.json",
  "/required-server-files.json", "/webpack-stats.json", "/loadable-stats.json",
  "/precache-manifest.json", "/swagger.json", "/serverless.yml",
  "/serverless.yaml", "/serverless.json", "/plugins/payments/stripe.json",
  "/templatedetails.xml",
  "/vendor/phpunit/", "/phpmyadmin/", "/pma/"
];

const SCANNER_OPTIONAL_URL_PREFIX = String(process.env.OPTIONAL_URL_PREFIX || "")
  .trim()
  .replace(/^\/+|\/+$/g, "")
  .split("/")
  .map((part) => part.trim())
  .filter((segment) => segment && /^[A-Za-z0-9._~-]+$/.test(segment))
  .join("/");
const createScannerProbeMatching = require("../scanner-security/scannerProbeMatching.js");
const {
  decodePathForScannerMatching,
  SENSITIVE_CONFIG_PROBE_BASENAME_REGEX,
  SENSITIVE_CONFIG_PROBE_PATH_REGEX,
  API_CONFIG_PROBE_PATH_REGEX,
  normalizeScannerProbeCandidate,
  stripOptionalScannerPrefixPreserveCase,
  isEmailSafePathCandidate,
  FLEXIBLE_REDIRECT_PAYLOAD_MIN_SEGMENT_LENGTH,
  REDIRECT_PAYLOAD_SEGMENT_REGEX,
  getScannerConfiguredEmailDelimiters,
  hasScannerConfiguredEmailDelimiter,
  isLikelyRedirectPayloadPathCandidate,
  isLikelyIgnoredPrefixRedirectPayloadCandidate,
  isLikelyFlexibleRedirectPayloadCandidate,
  isScannerExactProbePath,
  isLikelyApiConfigProbePath,
  isLikelySensitiveConfigProbePath,
  stripOptionalUrlPrefixForScannerPayload,
  isLikelyRawUrlRedirectPayload,
  classifyScannerProbeCandidate,
  chooseScannerProbeCategory,
  pathMatchesUnknownScannerSkipPrefix,
 } = createScannerProbeMatching({
  NESTED_SCANNER_SUBSTRINGS, OPTIONAL_URL_PREFIX: SCANNER_OPTIONAL_URL_PREFIX,
  SCANNER_PROBE_EXACT_PATHS, SCANNER_PROBE_PREFIXES,
  isLikelyArchiveProbePath: (...args) => isLikelyArchiveProbePath(...args),
  isLikelyEmail: (...args) => isLikelyEmail(...args),
  looksLikeHttpUrl: (...args) => looksLikeHttpUrl(...args),
  parseRedirectPayload: (...args) => parseRedirectPayload(...args),
  safeDecode: (...args) => safeDecode(...args),
  decodeB64urlLoose: (...args) => decodeB64urlLoose(...args),
  validateBase64Url: (...args) => validateBase64Url(...args)
});

const createScannerBehaviorPolicy = require("../scanner-security/scannerBehaviorPolicy.js");
const {
  recordKnownScannerBurstInHistory,
  recordKnownScannerProbeBurst,
  recordKnownScannerVisibleIpBurst,
  shouldTrackVisibleIpKnownScannerBurst,
  getKnownScannerDenyKey,
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
 } = createScannerBehaviorPolicy({
  ARCHIVE_PROBE_NAME_REGEX, ARCHIVE_PROBE_SUFFIX_REGEX,
  SEARCH_BOT_DNS_CACHE_MAX_ENTRIES, SEARCH_BOT_DNS_CACHE_TTL_MS,
  SEARCH_BOT_DNS_NEGATIVE_TTL_MS, SEARCH_BOT_DNS_TIMEOUT_MS, SEARCH_BOT_DNS_VERIFY_ENABLED,
  addDenyCache: (...args) => addDenyCache(...args), addLog: (...args) => addLog(...args),
  aggregatePerIpEvent: (...args) => aggregatePerIpEvent(...args), boundedMapSet,
  detectScannerEnhanced: (...args) => detectScannerEnhanced(...args), dns,
  getClientIp: (...args) => getClientIp(...args),
  getCurrentPublicPathSet: (...args) => getCurrentPublicPathSet(...args),
  getDenyCacheIp: (...args) => getDenyCacheIp(...args),
  getRequestIdentity: (...args) => getRequestIdentity(...args),
  getImpersonateMinConfidence: () => IMPERSONATE_MIN_CONFIDENCE,
  getPublicCanonicalAliases: () => PUBLIC_CANONICAL_ALIASES,
  isLikelyFlexibleRedirectPayloadCandidate,
  isLikelyRawUrlRedirectPayload,
  isLikelyRedirectPayloadPathCandidate,
  isPublicContentSurfaceEnabled: (...args) => isPublicContentSurfaceEnabled(...args),
  matchesConfiguredScannerProfile: (...args) => matchesConfiguredScannerProfile(...args),
  net, pathMatchesUnknownScannerSkipPrefix: (...args) => pathMatchesUnknownScannerSkipPrefix(...args),
  pathMatchesWithOptionalPrefix: (...args) => pathMatchesWithOptionalPrefix(...args),
  readPositiveIntEnv, safeLogValue: (...args) => safeLogValue(...args),
  sanitizeIpForKey: (...args) => sanitizeIpForKey(...args),
  stripOptionalUrlPrefix: (...args) => stripOptionalUrlPrefix(...args)
});
const createRequestRuntime = require("../request-runtime/requestRuntime.js");
const {
  attachRequestId,
  startRuntimeRequestTracking,
  createRuntimeRequestFinalizer,
  attachRuntimeCompletionLogging,
  attachRequestTimeoutEnforcement,
  runtimeRequestTracker,
  SANITIZATION_MAX_LENGTH,
  UA_TRUNCATE_LENGTH,
  PATH_TRUNCATE_LENGTH,
  ACCEPT_TRUNCATE_LENGTH,
  REFERER_TRUNCATE_LENGTH,
  LOG_ENTRY_MAX_LENGTH,
  EMAIL_DISPLAY_MAX_LENGTH,
  URL_DISPLAY_MAX_LENGTH,
  RE_B64URL_SEGMENT,
  RE_B64URL_PAYLOAD,
  RE_CONTROL_CHARS,
  RE_SCANNER_PATH,
  runtimeStats,
  activeTrackedRequests,
  TRACKED_REQUEST_STALE_GRACE_MS,
  ACTIVE_REQUEST_DUMP_LIMIT,
  ACTIVE_REQUEST_TOP_PATH_LIMIT,
  getTrackedRequestStartedAt,
  pruneStaleTrackedRequests,
  getTrackedInFlightCount,
  buildActiveRequestDiagnostics,
  logActiveRequestDiagnostics,
  sanitizeRequestPath,
  getEventTimestamp,
  isOperationalBypassPath,
  getRequestPathForPolicy,
  getNormalizedRequestPathForPolicy,
  shouldTrackRuntimeRequest,
  shouldEnforceRequestTimeout,
  isLikelyScannerProbePath,
  summarizeError,
  summarizeClientError,
  getClientErrorStatusCode,
  getClientErrorStatusMessage,
  isNoisyClientAbortParseError,
  getClientErrorAggregateIp,
  roundMetric,
  getRuntimeUsageSnapshot,
  app,
  resolveOrCreateRequestId,
  parseTrustProxyValue,
  resolveSaferTrustProxySetting,
  trustProxyEffective,
  SECURITY_HEADER_VALUES,
  setBaselineSecurityHeaders,
  applyEarlyBaselineSecurityHeaders,
  applyNoIndexToEarlyErrorResponses,
 } = createRequestRuntime({
  ARCHIVE_PROBE_NAME_REGEX, ARCHIVE_PROBE_SUFFIX_REGEX, CLIENT_ERROR_RAW_PACKET_PREVIEW_BYTES, REQUEST_TIMEOUT_MS,
  SCANNER_PROBE_EXACT_PATHS, SCANNER_PROBE_PREFIXES,
  addLog: (...args) => addLog(...args),
  classifyScannerProbeCandidate, crypto, decodePathForScannerMatching,
  decodeB64urlLoose: (...args) => decodeB64urlLoose(...args), express,
  formatRequestIdentityLogSuffix: (...args) => formatRequestIdentityLogSuffix(...args),
  getClientIp: (...args) => getClientIp(...args),
  getConfiguredEmailDelimiters: (...args) => getConfiguredEmailDelimiters(...args),
  getRequestIdentity: (...args) => getRequestIdentity(...args),
  isLikelyEmail: (...args) => isLikelyEmail(...args), isScannerExactProbePath,
  markTimeoutAndMaybeBrownout: (...args) => markTimeoutAndMaybeBrownout(...args),
  normalizeScannerProbeCandidate, os,
  parseRedirectPayload: (...args) => parseRedirectPayload(...args),
  pathMatchesWithOptionalPrefix: (...args) => pathMatchesWithOptionalPrefix(...args),
  readPositiveIntEnv, safeDecode: (...args) => safeDecode(...args),
  safeLogValue: (...args) => safeLogValue(...args),
  stripOptionalUrlPrefix: (...args) => stripOptionalUrlPrefix(...args)
});

const TRUST_CLOUDFLARE_XFF_CHAIN = process.env.TRUST_CLOUDFLARE_XFF_CHAIN === "1";
const FORWARDER_AUTH_HEADER = "x-mds-forwarder-auth";
const MDS_FORWARDER_AUTH_SECRET = String(
  process.env.MDS_FORWARDER_AUTH_SECRET || process.env.TRUSTED_FORWARDER_AUTH_SECRET || ""
).trim();

const REQUIRE_CF_HEADERS = (process.env.REQUIRE_CF_HEADERS || "").toLowerCase() === "true";
const GEO_SOURCE_DEBUG = (process.env.GEO_SOURCE_DEBUG || "").toLowerCase() === "true";
const TRUST_UPSTREAM_GEO_HEADERS = ["1", "true", "yes"].includes(String(process.env.TRUST_UPSTREAM_GEO_HEADERS || "").trim().toLowerCase());
const GEO_ENRICH_IPAPI_ENABLED = (process.env.GEO_ENRICH_IPAPI_ENABLED || "").toLowerCase() === "true";
const GEO_ENRICH_IPAPI_TIMEOUT_MS = parseInt(process.env.GEO_ENRICH_IPAPI_TIMEOUT_MS || "1200", 10);
const GEO_ENRICH_IPAPI_TTL_MS = parseInt(process.env.GEO_ENRICH_IPAPI_TTL_MS || String(24 * 60 * 60 * 1000), 10);

const createRuntimeServices = require("../runtime-utils/runtimeServices.js");
const {
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
 } = createRuntimeServices({
  BROWNOUT_DURATION_MS, BROWNOUT_TIMEOUT_THRESHOLD, BROWNOUT_WINDOW_MS,
  CIRCUIT_BREAKER_COOLDOWN_MS, CIRCUIT_BREAKER_THRESHOLD, FETCH_TIMEOUT_MS_DEFAULT,
  GEO_ENRICH_CACHE_MAX_ENTRIES, GEO_ENRICH_IPAPI_ENABLED, GEO_ENRICH_IPAPI_TIMEOUT_MS,
  GEO_ENRICH_IPAPI_TTL_MS, GEO_SOURCE_DEBUG, IPINFO_LITE_CACHE_MAX_ENTRIES,
  IPINFO_LITE_CACHE_TTL_MS, IPINFO_LITE_ENABLED, IPINFO_LITE_NEGATIVE_CACHE_TTL_MS,
  IPINFO_LITE_TIMEOUT_MS, IPINFO_TOKEN, MAX_TIMER_MS,
  addLog: (...args) => addLog(...args), boundedMapSet, clampMs, evictOldestMapEntry, fetch,
  isKnownProxyIp: (...args) => isKnownProxyIp(...args),
  normalizeIpv4Mapped: (...args) => normalizeIpv4Mapped(...args),
  safeLogValue: (...args) => safeLogValue(...args),
  summarizeError: (...args) => summarizeError(...args)
});



function normalizePathPreservingEmbeddedUrls(pathValue) {
  const raw = String(pathValue || "");
  if (!raw) return raw;
  if (!/https?:\/\//i.test(raw)) return raw.replace(/\/{2,}/g, "/");
  // If an embedded absolute URL is present in the path payload, avoid
  // slash-collapsing entirely so destination semantics are preserved
  // (e.g. https://example.com//asset must remain unchanged).
  return raw;
}

app.use((req, _res, next) => {
  const rawUrl = String(req.url || "/");
  const qIndex = rawUrl.indexOf("?");
  const pathPart = qIndex >= 0 ? rawUrl.slice(0, qIndex) : rawUrl;
  const queryPart = qIndex >= 0 ? rawUrl.slice(qIndex) : "";
  const normalizedPath = normalizePathPreservingEmbeddedUrls(pathPart);
  if (normalizedPath !== pathPart) {
    req.url = normalizedPath + queryPart;
    const ip = getClientIp(req);
    const scannerLikeCanonicalizePath =
      isLikelyScannerProbePath(pathPart) || isLikelyScannerProbePath(normalizedPath);
    const shouldLog = aggregatePerIpEvent("PATH-CANONICALIZE", {
      ip,
      reason: scannerLikeCanonicalizePath ? "scanner_like_path" : "general_path",
      suppressFirst: scannerLikeCanonicalizePath
    });
    if (shouldLog) {
      addLog(`[PATH-CANONICALIZE] ip=${safeLogValue(ip, 64)} from=${safeLogValue(pathPart, 140)} to=${safeLogValue(normalizedPath, 140)}`);
    }
  }
  next();
});

// ================== EARLY-EXIT MIDDLEWARE ==================

async function verifyClaimedSearchBotMiddleware(req, _res, next) {
  const vendor = getClaimedSearchBotVendor(req);
  if (!vendor) return next();
  try {
    const result = await verifySearchBotIp(getClientIp(req), vendor);
    req.searchBotVerification = result;
    const shouldLog = aggregatePerIpEvent("BOT-VERIFY", {
      ip: getClientIp(req),
      reason: `${vendor}_${result.verified ? "verified" : result.reason || "failed"}`,
      suppressFirst: false
    });
    if (shouldLog) {
      addLog(`[BOT-VERIFY] vendor=${safeLogValue(vendor, 16)} verified=${result.verified ? "1" : "0"} reason=${safeLogValue(result.reason || "unknown", 80)} ip=${safeLogValue(getClientIp(req), 64)} host=${safeLogValue(result.hostname || "-", 120)}`);
    }
  } catch (error) {
    req.searchBotVerification = { vendor, verified: false, reason: "middleware_error" };
    addLog(`[BOT-VERIFY] vendor=${safeLogValue(vendor, 16)} verified=0 reason=middleware_error ip=${safeLogValue(getClientIp(req), 64)} err=${safeLogValue(error && error.message ? error.message : "unknown", 120)}`);
  }
  return next();
}

app.use(verifyClaimedSearchBotMiddleware);

// Change 1: Scanner probe blocker — runs before any expensive middleware.
// Matches well-known vulnerability scanner paths using simple string prefix
// checks (no regex) and returns 404 in <1ms.
const createScannerProbeBlocker = require("../scanner-security/scannerProbeBlocker.js");
app.use(createScannerProbeBlocker(() => ({
  KNOWN_SCANNER_DENY_TTL_SECONDS,
  KNOWN_SCANNER_VISIBLE_IP_DENY_TTL_SECONDS,
  NESTED_SCANNER_SUBSTRINGS,
  OPS_METRICS,
  SCANNER_PROBE_PREFIXES,
  addDenyCache,
  addLog,
  aggregatePerIpEvent,
  canDenyCacheVisibleIp,
  chooseScannerProbeCategory,
  decodePathForScannerMatching,
  getKnownScannerDenyKey,
  getRequestIdentity,
  incrementOpsMetric,
  isEmailSafePathCandidate,
  isLikelyArchiveProbePath,
  isLikelyFlexibleRedirectPayloadCandidate,
  isLikelyRawUrlRedirectPayload,
  isLikelySensitiveConfigProbePath,
  isScannerExactProbePath,
  maybeDenyForVisibleIpReputation,
  normalizeScannerProbeCandidate,
  recordKnownScannerProbeBurst,
  recordKnownScannerVisibleIpBurst,
  safeLogValue,
  shouldTrackVisibleIpKnownScannerBurst,
  utcDayStamp
})));

// Adaptive shield for unknown scanners that do not match a named probe.
// This catches fast unique-path walks across otherwise valid public pages (for
// example /, /pricing, /docs, /blog, ... in seconds), which name-based probe
// lists cannot reliably identify.
app.use((req, res, next) => {
  const ip = getClientIp(req);
  const denyCacheIp = getDenyCacheIp(req);
  const scannerDeny = getScannerDenyCacheForRequest(req, { ip, denyCacheIp });
  const denyHit = scannerDeny && scannerDeny.hit;
  if (denyHit) {
    const denyReason = getScannerDenyCacheLogReason(denyHit.reason);
    const shouldLog = aggregatePerIpEvent("SCANNER-BLOCK", {
      ip,
      reason: denyReason,
      suppressFirst: true
    });
    if (shouldLog) {
      addLog(`[SCANNER-BLOCK] ip=${safeLogValue(ip, 64)} method=${safeLogValue(req.method, 12)} blockedPath=${safeLogValue(req.path, 120)} reason=${denyReason}`);
    }
    const retryAfter = getScannerDenyCacheRetryAfter(denyHit.reason);
    res.setHeader("Retry-After", String(retryAfter));
    return res.status(429).end("Too Many Requests");
  }

  const crawlerWalk = checkCrawlerPublicWalkThrottle(req);
  if (crawlerWalk.limited) {
    const day = utcDayStamp();
    incrementOpsMetric(OPS_METRICS.frictionByDay, day, "scanner_block_total", 1);
    incrementOpsMetric(OPS_METRICS.frictionByDay, day, "scanner_block_reason_crawler_public_walk", 1);
    incrementOpsMetric(OPS_METRICS.frictionByDay, day, "status_429", 1);
    incrementOpsMetric(OPS_METRICS.frictionByDay, day, "friction_total", 1);
    const shouldLog = aggregatePerIpEvent("CRAWLER-WALK-THROTTLE", {
      ip,
      reason: crawlerWalk.crawlerClassification || "crawler",
      suppressFirst: false
    });
    if (shouldLog) {
      addLog(`[CRAWLER-WALK-THROTTLE] ip=${safeLogValue(ip, 64)} method=${safeLogValue(req.method, 12)} path=${safeLogValue(req.path, 120)} unique=${crawlerWalk.uniquePathCount || 0} max=${crawlerWalk.maxUniquePaths || CRAWLER_PUBLIC_WALK_MAX_PATHS} requests=${crawlerWalk.requestCount || 0} window=${CRAWLER_PUBLIC_WALK_WINDOW_SECONDS}s cooldown=${CRAWLER_PUBLIC_WALK_COOLDOWN_SECONDS}s crawler=${safeLogValue(crawlerWalk.crawlerClassification || "-", 32)} anomalies=${safeLogValue((crawlerWalk.anomalies || []).join("|"), 120)} cached=${crawlerWalk.cached ? "1" : "0"}`);
    }
    res.setHeader("Retry-After", String(crawlerWalk.retryAfterSec || CRAWLER_PUBLIC_WALK_COOLDOWN_SECONDS));
    return res.status(429).end("Too Many Requests");
  }
  if (crawlerWalk.publicWalkAllowed) return next();

  const unknownScanner = classifyUnknownScannerBehavior(req);
  if (!unknownScanner) {
    const hasPriorVisibleIpReputation = hasVisibleIpReputationSignal(ip, { exclude: ["public_walk"] });
    const historySummary = getUnknownScannerHistorySummary(req);
    const keyHistoryTriggered = historySummary.rapidUniquePathCount >= UNKNOWN_SCANNER_RAPID_UNIQUE_PATHS ||
      historySummary.uniquePathCount >= UNKNOWN_SCANNER_UNIQUE_PATHS;
    let visibleHistorySummary = null;
    let visibleHistoryTriggered = false;
    if (shouldTrackVisibleIpPublicWalk(req, hasPriorVisibleIpReputation)) {
      visibleHistorySummary = recordVisibleIpPublicWalkPath(ip, req);
      visibleHistoryTriggered = visibleHistorySummary.rapidUniquePathCount >= VISIBLE_IP_PUBLIC_WALK_RAPID_UNIQUE_PATHS ||
        visibleHistorySummary.uniquePathCount >= VISIBLE_IP_PUBLIC_WALK_UNIQUE_PATHS;
    }

    if (hasPriorVisibleIpReputation && (keyHistoryTriggered || visibleHistoryTriggered)) {
      const visibleDetail = visibleHistorySummary
        ? `visibleUnique:${visibleHistorySummary.uniquePathCount}:visibleRapid:${visibleHistorySummary.rapidUniquePathCount}`
        : "visibleUnique:0:visibleRapid:0";
      maybeDenyForVisibleIpReputation(req, ip, "public_walk", {
        detail: `keyUnique:${historySummary.uniquePathCount}:keyRapid:${historySummary.rapidUniquePathCount}:${visibleDetail}`,
        weight: VISIBLE_IP_REPUTATION_WEIGHTS.public_walk
      });
    }
    return next();
  }
  // --- ADD THIS LINE RIGHT HERE ---
  addLog(`[UNKNOWN-SCANNER-HEADERS] reason=${unknownScanner.reason} ${safeLogJson(req.headers, 2000)}`);
  // --------------------------------
  const day = utcDayStamp();
  incrementOpsMetric(OPS_METRICS.frictionByDay, day, "scanner_block_total", 1);
  incrementOpsMetric(OPS_METRICS.frictionByDay, day, "scanner_block_reason_unknown_behavioral_scan", 1);
  addDenyCache(denyCacheIp, "unknown_scanner", UNKNOWN_SCANNER_DENY_TTL_SECONDS);
  addStrike(denyCacheIp, 1);
  maybeDenyForVisibleIpReputation(req, ip, "unknown_scanner", { detail: unknownScanner.reason });

  const shouldLog = aggregatePerIpEvent("SCANNER-BLOCK", {
    ip,
    reason: "unknown_behavioral_scan",
    suppressFirst: true
  });
  if (shouldLog) {
    addLog(`[SCANNER-BLOCK] ip=${safeLogValue(ip, 64)} method=${safeLogValue(req.method, 12)} blockedPath=${safeLogValue(req.path, 120)} reason=unknown_behavioral_scan detail=${safeLogValue(unknownScanner.reason, 64)} unique=${unknownScanner.uniquePathCount} rapidUnique=${unknownScanner.rapidUniquePathCount} requests=${unknownScanner.requestCount} anomalies=${safeLogValue((unknownScanner.anomalies || []).join("|"), 120)} crawler=${safeLogValue(unknownScanner.crawlerClassification || "-", 32)}`);
  }

  res.setHeader("Retry-After", String(UNKNOWN_SCANNER_DENY_TTL_SECONDS));
  return res.status(429).end("Too Many Requests");
});

// Change 3: Per-IP rate limiter — sliding-window counter keyed by client IP.
// Configurable via RATE_LIMIT_WINDOW_SECONDS / RATE_LIMIT_MAX_REQUESTS env vars.
app.use((req, res, next) => {
  // Skip internal/health paths to avoid false positives on monitoring traffic.
  const p = String(req.path || "/");
  if (
    p === "/health" || p === "/healthz" || p === "/readyz" || p === "/livez" ||
    p.startsWith("/stream-log") || p.startsWith("/view-log")
  ) {
    return next();
  }

  const identity = getRequestIdentity(req);
  const ip = identity.ip;
  const result = checkPerIpRateLimit(identity.rateLimitKey);
  if (result.limited) {
    const keySuffix = identity.rateLimitKey !== ip ? ` keyIp=${safeLogValue(identity.rateLimitKey, 64)}` : "";
    addLog(`[RATE-LIMIT-BLOCK] ip=${safeLogValue(ip, 64)}${keySuffix} path=${safeLogValue(p, 120)} window=${RATE_LIMIT_WINDOW_SECONDS}s max=${RATE_LIMIT_MAX_REQUESTS}`);
    res.setHeader("Retry-After", String(result.retryAfterSec || RATE_LIMIT_WINDOW_SECONDS));
    return res.status(429).end("Too Many Requests");
  }
  next();
});

app.use(runtimeRequestTracker);

// ------------ Enhanced Global Security Headers ---------------
app.use((req, res, next) => {
  // Generate a nonce for CSP
  const cspNonce = crypto.randomBytes(16).toString('base64');
  res.locals.cspNonce = cspNonce;

  // Avoid caching challenge pages/tokens
  res.setHeader("Cache-Control", "no-store");

  // Determine if secure connection
  const isSecure = req.secure || (req.headers["x-forwarded-proto"] || "").includes("https");
  if (isSecure) {
    res.setHeader("Strict-Transport-Security", SECURITY_HEADER_VALUES.hstsPreload);
  }

  // Private Access Tokens
  res.setHeader(
    "Permissions-Policy",
    'private-token=(self "https://challenges.cloudflare.com" "https://challenges.fed.cloudflare.com" "https://challenges-staging.cloudflare.com")'
  );

  // Enhanced CSP with nonce support
  const isChallengePage =
    pathMatchesWithOptionalPrefix(req.path, "/challenge", { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(req.path, "/challenge-fragment", { allowChildren: false });
  const cspDirectives = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${cspNonce}' https://challenges.cloudflare.com https://challenges.fed.cloudflare.com https://challenges-staging.cloudflare.com`,
    "style-src 'self' 'unsafe-inline' https://challenges.cloudflare.com",
    "img-src 'self' data: https:",
    "connect-src 'self' https://challenges.cloudflare.com https://challenges.fed.cloudflare.com https://challenges-staging.cloudflare.com",
    "font-src 'self' data:",
    "frame-src 'self' https://challenges.cloudflare.com",
    "worker-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'"
  ];

  // Add report-uri in production
  if (process.env.NODE_ENV === 'production' && process.env.CSP_REPORT_URI) {
    cspDirectives.push(`report-uri ${process.env.CSP_REPORT_URI}`);
    cspDirectives.push("report-to csp-endpoint");
  }

  res.setHeader("Content-Security-Policy", cspDirectives.join('; '));

  // Additional security headers
  setBaselineSecurityHeaders(res);
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("X-DNS-Prefetch-Control", "off");
  res.setHeader("X-Download-Options", "noopen");

  // Cross-origin headers
  // NOTE: Turnstile/challenge routes embed Cloudflare-owned cross-origin resources
  // that are not consistently CORP-marked. Enforcing COEP/COOP on those pages can
  // silently break challenge rendering and trap users in a loop.
  if (isChallengePage) {
    res.setHeader("Cross-Origin-Embedder-Policy", "unsafe-none");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
    res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
  } else {
    res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  }

  // Remove powered-by header
  res.removeHeader('X-Powered-By');

  next();
});

// ================== HELPER FUNCTIONS ==================
const createRedirectPayload = require("../redirect-payload/redirectPayload.js");
const {
  mask,
  safeZone,
  TIMEZONE,
  formatLocal,
  zoneLabel,
  safeLogValue,
  parseEmailDelimiterEnvValue,
  getConfiguredEmailDelimiters,
  findPreviousEmailDelimiter,
  findNextEmailDelimiter,
  safeLogJson,
  sanitizeOneLine,
  sanitizeLogLine,
  safeDecode,
  parseOptionalUrlPrefix,
  OPTIONAL_URL_PREFIX_SEGMENTS,
  OPTIONAL_URL_PREFIX,
  getOptionalUrlPrefixPath,
  withOptionalUrlPrefix,
  pathMatchesWithOptionalPrefix,
  pathMatchesExactRoute,
  stripOptionalUrlPrefix,
  extractEmailSafePayloadPath,
  looksLikeHttpUrl,
  detectEncodedEmailSegment,
  createRedirectPayloadResult,
  setRedirectPayloadMode,
  setRedirectPayloadIgnored,
  setRedirectPayloadCanonical,
  finishFlexibleRedirectPayload,
  joinCollapsedUrlParts,
  joinCollapsedUrlSegments,
  looksLikeCiphertextSegment,
  looksLikeRedirectPayloadSegment,
  parseIgnoredUrlCipherPayload,
  parseEmailFirstCipherPayload,
  isUnambiguousRawUrlEmailSuffix,
  isPartialRawEmailDelimiterSplit,
  findRawUrlEmailSuffixSplit,
  splitRawUrlPayload,
  splitRawUrlRemainder,
  parseRawUrlRedirectPayload,
  parseDelimitedCipherEmailPayload,
  parseFlexibleRedirectPayload,
  normalizeRedirectPayloadHelpers,
  hasConfiguredEmailDelimiter,
  hasValidIgnoredPrefixEmailDelimiter,
  rawUrlHostIsAllowlistedDestination,
  redirectPayloadSegmentDecrypts,
  parseDecryptableIgnoredUrlPrefixPayload,
  shouldPreserveRawHttpUrlBeforeIgnoredPrefix,
  shouldPreserveEncodedRawUrlBeforeIgnoredPrefix,
  parseRedirectPayload,
  getRedirectPayloadLimit,
  getRedirectTotalPathLimit,
  getRedirectOversizeMode,
  getMaxBruteSplitPayloadLength,
  shouldBlockOversizedRedirectPayload,
  getRedirectPayloadMeasuredLength,
  evaluateRedirectPayloadSize,
  maybeLogRedirectPayloadSizeDecision,
  isValidRedirectPayloadInput,
  validateBase64Url,
  isObviouslyNotPayloadPath,
  validateRRouteParams,
  validateSuspiciousQueryParams,
  validateCatchAllRedirectPath,
  validateRedirectParams,
  validateRedirectRequest,
} = createRedirectPayload({
  MAX_BRUTE_SPLIT_PAYLOAD_LENGTH,
  MAX_REDIRECT_PAYLOAD_LENGTH,
  MAX_REDIRECT_URL_PATH_LENGTH,
  REDIRECT_PAYLOAD_OVERSIZE_MODE,
  RE_B64URL_PAYLOAD,
  RE_CONTROL_CHARS,
  SANITIZATION_MAX_LENGTH,
  SCANNER_PROBE_PREFIXES,
  VISIBLE_IP_REPUTATION_WEIGHTS,
  addLog: (...args) => addLog(...args),
  addStrike: (...args) => addStrike(...args),
  aggregatePerIpEvent: (...args) => aggregatePerIpEvent(...args),
  decodeB64urlLoose: (...args) => decodeB64urlLoose(...args),
  getAllowlistDomains: () => ALLOWLIST_DOMAINS,
  getClientIp: (...args) => getClientIp(...args),
  hasInterstitialBypass: (...args) => hasInterstitialBypass(...args),
  isHostAllowlisted: (...args) => isHostAllowlisted(...args),
  isLikelyCrawlerProbePath,
  isLikelyEmail: (...args) => isLikelyEmail(...args),
  isLikelyLocaleOnlyProbePath,
  isLikelyScannerProbePath,
  maybeDenyForVisibleIpReputation,
  tryBase64UrlToUtf8: (...args) => tryBase64UrlToUtf8(...args),
  tryDecryptAny: (...args) => tryDecryptAny(...args),
  validationFailureLimiter: (...args) => validationFailureLimiter(...args)
});


const createSecurityRuntime = require("../security-runtime/securityRuntime.js");
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
 } = createSecurityRuntime({
  FORWARDER_AUTH_HEADER, GEO_SOURCE_DEBUG, IN_MEM_BANS_MAX_ENTRIES,
  IN_MEM_BUCKETS_MAX_ENTRIES, IN_MEM_DENY_CACHE_MAX_ENTRIES,
  IN_MEM_STRIKES_MAX_ENTRIES, LOG_AGGREGATION_MAX_ENTRIES,
  MDS_FORWARDER_AUTH_SECRET, PER_IP_REQUEST_COUNTS_MAX_ENTRIES,
  KNOWN_SCANNER_DENY_TTL_SECONDS, KNOWN_SCANNER_VISIBLE_IP_DENY_TTL_SECONDS,
  RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECONDS, RE_B64URL_SEGMENT,
  SCANNER_AGG_ALERT_THRESHOLD, TRUST_CLOUDFLARE_XFF_CHAIN,
  TRUST_UPSTREAM_GEO_HEADERS, UNKNOWN_SCANNER_DENY_TTL_SECONDS,
  VISIBLE_IP_REPUTATION_DENY_TTL_SECONDS, VISIBLE_IP_REPUTATION_WEIGHTS,
  boundedMapSet, clampMs, formatLocal, fs, getConfiguredEmailDelimiters,
  getMaxBruteSplitPayloadLength, getAllowlistDomains: () => ALLOWLIST_DOMAINS,
  lookupIpinfoLite, maybeEnrichGeoAsync,
  normalizeAsn, os, parseRedirectPayload, path, readMsEnv,
  readPositiveIntEnv, runtimeStats, safeDecode, safeLogValue, sanitizeOneLine,
  summarizeError, trustProxyEffective, withOptionalUrlPrefix
});
// ================== SECURITY POLICY FUNCTIONS ==================
const ALLOWED_COUNTRIES = (process.env.ALLOWED_COUNTRIES || "").split(",").map(s=>s.trim().toUpperCase()).filter(Boolean);
const BLOCKED_COUNTRIES = (process.env.BLOCKED_COUNTRIES || "").split(",").map(s=>s.trim().toUpperCase()).filter(Boolean);
const BLOCKED_ASNS      = (process.env.BLOCKED_ASNS || "").split(",").map(s=>s.trim().toUpperCase()).filter(Boolean);
const EXPECT_HOSTNAME   = process.env.TURNSTILE_EXPECT_HOSTNAME || "test.com,*.test.com"; // main url
const MAX_TOKEN_AGE_SEC = parseInt(process.env.TURNSTILE_MAX_TOKEN_AGE_SEC || "90", 10);
const ENFORCE_ACTION    = (process.env.TURNSTILE_ENFORCE_ACTION || "1") === "1";
const HEADLESS_BLOCK    = (process.env.HEADLESS_BLOCK || "0") === "1";
const HEADLESS_STRIKE_WEIGHT = parseInt(process.env.HEADLESS_STRIKE_WEIGHT || "3", 10);
const HEADLESS_SOFT_STRIKE   = (process.env.HEADLESS_SOFT_STRIKE || "0") === "1";

const ALLOWLIST_DOMAINS = (process.env.ALLOWLIST_DOMAINS || "test2.com,sub.test2.com") // landing
  .split(",").map(normalizeSuffixPattern).filter(Boolean);

const EXPECT_HOSTNAME_ENTRIES = (EXPECT_HOSTNAME || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);
const EXPECT_HOSTNAME_INVALID_ENTRIES = EXPECT_HOSTNAME_ENTRIES
  .filter(raw => !normalizeSuffixPattern(raw));
const EXPECT_HOSTNAME_PATTERNS = EXPECT_HOSTNAME_ENTRIES
  .map(normalizeSuffixPattern)
  .filter(Boolean);

// ================== CONFIGURATION VALIDATION ==================
const normalizeTurnstileEnv = (value) => String(value || "").trim();

function validateConfig() {
  const errors = [];
  const warnings = [];
  const addConfigIssue = (message, { fatalInProduction = false } = {}) => {
    const target = fatalInProduction && process.env.NODE_ENV === "production" ? errors : warnings;
    target.push(message);
  };
  const isTurnstileKey = (value) => {
    const trimmed = normalizeTurnstileEnv(value);
    if (!trimmed) return false;
    return /^(?:0x)?[0-9a-zA-Z_-]{20,}$/.test(trimmed);
  };

  // Validate AES keys (extra safety; loadKeysFromEnv already enforces this)
  if (!AES_KEYS || AES_KEYS.length === 0) {
    errors.push("No AES keys configured (set AES_KEYS, AES_KEY, or AES_KEY_HEX)");
  } else {
    AES_KEYS.forEach((key, idx) => {
      if (key.length !== 32) {
        errors.push(`AES key #${idx} must be 32 bytes, got ${key.length} bytes`);
      }
    });
  }

  // Validate allowlist configuration
  if (ALLOWLIST_DOMAINS.length === 0) {
    addConfigIssue("No allowlist domains configured - all redirects will be blocked unless explicitly allowed", { fatalInProduction: true });
  }

  if (EXPECT_HOSTNAME_INVALID_ENTRIES.length > 0) {
    errors.push(`Invalid TURNSTILE_EXPECT_HOSTNAME pattern(s): ${EXPECT_HOSTNAME_INVALID_ENTRIES.join(",")}`);
  }
  if (EXPECT_HOSTNAME_ENTRIES.length > 0 && EXPECT_HOSTNAME_PATTERNS.length === 0) {
    errors.push("TURNSTILE_EXPECT_HOSTNAME does not contain any valid host pattern");
  }

  // Validate TURNSTILE credentials format
  const turnstileSitekey = normalizeTurnstileEnv(process.env.TURNSTILE_SITEKEY);
  const turnstileSecret = normalizeTurnstileEnv(process.env.TURNSTILE_SECRET);
  if (!isTurnstileKey(turnstileSitekey)) {
    errors.push(`Invalid TURNSTILE_SITEKEY format (got: ${turnstileSitekey ? `${turnstileSitekey.slice(0, 8)}...` : "empty"})`);
  }
  if (!isTurnstileKey(turnstileSecret)) {
    errors.push(`Invalid TURNSTILE_SECRET format (got: ${turnstileSecret ? `${turnstileSecret.slice(0, 8)}...` : "empty"})`);
  }

  // Validate timezone
  const configuredTz = process.env.TIMEZONE || "UTC";
  if (safeZone(configuredTz) !== configuredTz) {
    warnings.push(`Invalid TIMEZONE: ${configuredTz}. Using UTC as fallback.`);
  }

  // Validate rate limit settings
  if (RATE_CAPACITY < 1 || RATE_CAPACITY > 1000) {
    errors.push(`RATE_CAPACITY must be between 1-1000, got ${RATE_CAPACITY}`);
  }
  if (RATE_WINDOW_SECONDS < 1 || RATE_WINDOW_SECONDS > 86400) {
    errors.push(`RATE_WINDOW_SECONDS must be between 1-86400, got ${RATE_WINDOW_SECONDS}`);
  }

  // Validate admin token
  if (!ADMIN_TOKEN || ADMIN_TOKEN.length < 16) {
    addConfigIssue("ADMIN_TOKEN is weak or missing. Admin endpoints may be insecure.", { fatalInProduction: true });
  }

  // Validate INTERSTITIAL_BYPASS_SECRET
  const bypassSecret = process.env.INTERSTITIAL_BYPASS_SECRET || "";
  if (bypassSecret && bypassSecret.length < 8) {
    addConfigIssue("INTERSTITIAL_BYPASS_SECRET is too short (min 8 chars)", { fatalInProduction: true });
  }

  return { errors, warnings };
}

// Run validation
const configValidation = validateConfig();
if (configValidation.errors.length > 0) {
  console.error("❌ Configuration errors:");
  configValidation.errors.forEach(err => console.error(`   ${err}`));
  if (process.env.NODE_ENV === "production") process.exit(1);
}
if (configValidation.warnings.length > 0) {
  console.warn("⚠️ Configuration warnings:");
  configValidation.warnings.forEach(warn => console.warn(`   ${warn}`));
}

// Hardening: fail fast in production if ADMIN_TOKEN is weak/missing.
if (process.env.NODE_ENV === "production" && (!ADMIN_TOKEN || ADMIN_TOKEN.length < 16)) {
  console.error("❌ ADMIN_TOKEN must be set with at least 16 characters in production.");
  process.exit(1);
}

function countryBlocked(country){
  if (!country) return false;
  if (ALLOWED_COUNTRIES.length && !ALLOWED_COUNTRIES.includes(country)) return true;
  if (BLOCKED_COUNTRIES.includes(country)) return true;
  return false;
}

function asnBlocked(asn){ return !!asn && BLOCKED_ASNS.includes(asn); }

const createScannerDetection = require("../scanner-security/scannerDetection.js");
const {
  IMPERSONATE_SCANNER,
  IMPERSONATE_SCANNER_STRICT,
  IMPERSONATE_MIN_CONFIDENCE,
  SCANNER_GENERIC_PROFILE,
  SCANNER_PROFILES,
  applyScannerProfileHeaders,
  renderScannerSafeHtmlForScanner,
  KNOWN_SCANNER_IPS,
  KNOWN_SCANNER_MAX,
  cleanupKnownScannerIps,
  recordScannerIp,
  isKnownScannerIp,
  pickScannerProfile,
  shouldImpersonateForRequest,
  shouldApplyProfileHeadersForRequest,
  findScannerProfileByName,
  assertScannerFetchTargetAllowed,
  buildPinnedScannerFetchUrl,
  makePinnedScannerRequestWithFallback,
  SCANNER_COMPAT_HEADERS_ENABLED,
  applyScannerCompatHeaders,
  SCANNER_INTERSTITIAL_SCOPE,
  shouldServeScannerInterstitial,
  loadScannerPatterns,
  compareScannerDetections,
  detectScannerEnhanced,
  SCANNER_STATS,
  SCANNER_DECISION_COUNTERS,
  OPS_METRICS,
  incrementScannerDecisionCounter,
  utcDayStamp,
  incrementOpsMetric,
  computeScannerStatsFromLogs,
  buildOpsScannerStatsForDay,
  selectScannerStatsForResponse,
  hashUAForStats
} = createScannerDetection({
  LOGS,
  SCANNER_FETCH_ENABLED,
  SCANNER_FETCH_TIMEOUT_MS,
  SECURITY_HEADER_VALUES,
  addLog,
  crypto,
  dns,
  eSCANNER_CONFIG_RELOAD_MS,
  fetchWithRuntimeSpan,
  getClientIp,
  http,
  https,
  net,
  normHost,
  normalizeIpv4Mapped,
  normalizeScannerConfidence,
  safeLogValue,
  withDnsTimeout
});
const createBehavioralDetection = require("../scanner-security/behavioralDetection.js");
const {
  BEHAVIORAL_CONFIG,
  REQUEST_HISTORY,
  cleanupRequestHistory,
  detectScannerEnhancedWithBehavior,
  buildScannerInterstitialContext,
  logScannerHit
} = createBehavioralDetection({
  ACCEPT_TRUNCATE_LENGTH,
  IMPERSONATE_MIN_CONFIDENCE,
  PATH_TRUNCATE_LENGTH,
  REFERER_TRUNCATE_LENGTH,
  SCANNER_GENERIC_PROFILE,
  SCANNER_STATS,
  SCANNER_SAFE_HTML_ENABLED,
  UA_TRUNCATE_LENGTH,
  addLog,
  addSpacer,
  boundedMapSet,
  compareScannerDetections,
  detectScannerEnhanced,
  getClientIp,
  hashUAForStats,
  isKnownScannerIp,
  pickScannerProfile,
  recordScannerIp,
  safeLogValue,
  shouldImpersonateForRequest,
  toReasonCode: (...args) => toReasonCode(...args),
  trackIntervalHandle
});
const createTurnstileSecurity = require("../challenge/turnstileSecurity.js");
const {
  headlessSuspicion,
  TURNSTILE_SITEKEY,
  TURNSTILE_SECRET,
  TURNSTILE_ORIGIN,
  verifyTurnstileToken
} = createTurnstileSecurity({
  ENFORCE_ACTION,
  EXPECT_HOSTNAME_ENTRIES,
  EXPECT_HOSTNAME_PATTERNS,
  MAX_TOKEN_AGE_SEC,
  addLog,
  addSpacer,
  fetchWithRuntimeSpan,
  hostMatchesSuffix,
  makeIpLimiter,
  normHost,
  normalizeTurnstileEnv,
  safeLogValue
});
// ================== RATE LIMITERS ==================
const limitChallengeView = makeIpLimiter({
  capacity: parseInt(process.env.CHALLENGE_VIEW_CAPACITY || "5", 10),
  windowSec: parseInt(process.env.CHALLENGE_VIEW_WINDOW_SEC || "300", 10),
  keyPrefix: "challenge_view"
});

const limitChallenge   = makeIpLimiter({ capacity: parseInt(process.env.CHALLENGE_CAPACITY || "12",10), windowSec: parseInt(process.env.CHALLENGE_WINDOW_SEC || "300",10), keyPrefix: "challenge" });
const limitTsClientLog = makeIpLimiter({ capacity: parseInt(process.env.TSLOG_CAPACITY || "30",10),      windowSec: parseInt(process.env.TSLOG_WINDOW_SEC || "300",10),      keyPrefix: "tslog" });
const limitSseUnauth   = makeIpLimiter({ capacity: parseInt(process.env.SSE_UNAUTH_CAPACITY || "10",10), windowSec: parseInt(process.env.SSE_UNAUTH_WINDOW_SEC || "60",10),  keyPrefix: "sse_unauth" });
const validationFailureLimiter = makeIpLimiter({ capacity: 10, windowSec: 300, keyPrefix: "validation_fail" });

const adminHits = new Map();
const ADMIN_HIT_TTL_MS = 10 * 60_000;

const createRedirectCore = require("../redirect-core/redirectCore.js");
const {
  INTERSTITIAL_REASON_HEADER_ENABLED,
  toReasonCode,
  applyMemoryPressureRelief,
  shouldApplyMemoryPressureRelief,
  markInterstitialHuman,
  INTERSTITIAL_BYPASS_SECRET,
  hasInterstitialBypass,
  renderScannerSafePage,
  sendScannerSafetyLaneHeadResponse,
  tryRenderTrustedScannerSafeHtmlForPayload,
  handleRedirectCore
} = createRedirectCore({
  ADMIN_HITS_MAX_ENTRIES,
  ADMIN_HIT_TTL_MS,
  BEHAVIORAL_CONFIG,
  EMAIL_DISPLAY_MAX_LENGTH,
  HEADLESS_BLOCK,
  HEADLESS_SOFT_STRIKE,
  HEADLESS_STRIKE_WEIGHT,
  IMPERSONATE_MIN_CONFIDENCE,
  IMPERSONATE_SCANNER,
  KNOWN_SCANNER_IPS,
  KNOWN_SCANNER_MAX,
  LOG_ENTRY_MAX_LENGTH,
  MAX_TOKEN_AGE_SEC,
  MEMORY_PRESSURE_HEAP_USED_MB,
  MEMORY_PRESSURE_HEAP_USED_RATIO,
  OPS_METRICS,
  PATH_TRUNCATE_LENGTH,
  REQUEST_HISTORY,
  REQUIRE_CF_HEADERS,
  SCANNER_GENERIC_PROFILE,
  SCANNER_INTERSTITIAL_SCOPE,
  SCANNER_SAFE_HTML_ENABLED,
  UA_TRUNCATE_LENGTH,
  URL_DISPLAY_MAX_LENGTH,
  VISIBLE_IP_REPUTATION_WEIGHTS,
  addDenyCache,
  addLog,
  addSpacer,
  addStrike,
  adminHits,
  aggregatePerIpEvent,
  app,
  applyScannerCompatHeaders,
  applyScannerProfileHeaders,
  asnBlocked,
  boundedMapSet,
  buildScannerInterstitialContext,
  countryBlocked,
  createChallengeRedirect,
  createChallengeToken,
  crypto,
  decodeB64urlLoose,
  decodeEmailPart,
  detectScannerEnhancedWithBehavior,
  evaluateRedirectPayloadSize,
  explainDecryptFailure,
  extractEmailSafePayloadPath,
  formatRequestIdentityLogSuffix,
  getASN,
  getClientIp,
  getCountryResolutionAsync,
  getDenyCache,
  getDenyCacheIp,
  getNormalizedRequestPathForPolicy,
  getRequestIdentity,
  hasCloudflareHeaders,
  hashFirstSeg,
  hashUaForToken,
  headlessSuspicion,
  incrementOpsMetric,
  incrementScannerDecisionCounter,
  isBanned,
  isBrownoutActive,
  isHostAllowlisted,
  isKnownScannerIp,
  isLikelyEmail,
  isOperationalBypassPath,
  isRateLimited,
  logScannerHit,
  maskEmail,
  maybeDenyForVisibleIpReputation,
  maybeLogRedirectPayloadSizeDecision,
  normHost,
  parseRedirectPayload,
  pathMatchesWithOptionalPrefix,
  pickScannerProfile,
  recordChallengeBypassAttempt,
  recordOffenderSignals,
  recordScannerIp,
  renderScannerSafeHtmlForScanner,
  safeDecode,
  safeLogJson,
  safeLogValue,
  sanitizeChallengeReason,
  shouldApplyProfileHeadersForRequest,
  shouldImpersonateForRequest,
  shouldServeScannerInterstitial,
  tryDecryptAny,
  tryDecryptAtKnownDelimiterBoundaries,
  utcDayStamp,
  verifyLinkHmac,
  verifyTurnstileToken,
  withOptionalUrlPrefix
});
// ================== MIDDLEWARE SETUP ==================
app.use(cors());
app.use(express.json({ limit: "64kb" }));
app.use(express.urlencoded({ extended: false, limit: "64kb" }));

const ADMIN_HIT_WINDOW_MS = 60_000;

function pruneAdminHits(now = Date.now()) {
  for (const [ip, rec] of adminHits.entries()) {
    const resetAt = Number(rec && rec.resetAt || 0);
    if (!resetAt || now - resetAt > ADMIN_HIT_TTL_MS) {
      adminHits.delete(ip);
    }
  }
}

app.use(["/view-log", "/__debug", "/admin"], (req, res, next) => {
  if (isAdmin(req) || isAdminSSE(req)) return next();
  const ip = getClientIp(req) || "unknown";
  const now = Date.now();
  const rec = adminHits.get(ip) || { count: 0, resetAt: now + ADMIN_HIT_WINDOW_MS };
  if (now > rec.resetAt) { rec.count = 0; rec.resetAt = now + ADMIN_HIT_WINDOW_MS; }
  rec.count++;
  boundedMapSet(adminHits, ip, rec, ADMIN_HITS_MAX_ENTRIES);
  if (rec.count > 120) return res.status(429).send("Too Many Requests");
  next();
});

const createPublicUtilities = require("../public-content/publicUtilities.js");
const {
  rotationSeed,
  hash32,
  deterministicPick,
  resolvePublicBaseUrls
} = createPublicUtilities({
  PUBLIC_ROTATION_MODE: (process.env.PUBLIC_ROTATION_MODE || "daily").trim().toLowerCase(),
  PUBLIC_SITE_BASE_URL: (process.env.TURNSTILE_EXPECT_HOSTNAME || "").trim(),
  crypto,
  isLikelyInternalHostname: (hostname) => {
    const normalized = String(hostname || "").toLowerCase().split(":")[0].trim();
    if (!normalized) return true;
    if (normalized === "localhost") return true;
    if (normalized.endsWith(".local")) return true;
    if (normalized.endsWith(".internal")) return true;
    if (normalized.endsWith(".up.railway.app")) return true;
    return false;
  }
});

const createPublicContent = require("../public-content/publicContent.js");
const {
  PUBLIC_CONTENT_SURFACE,
  PUBLIC_SITE_BASE_URL,
  PUBLIC_ROTATION_MODE,
  PUBLIC_ENABLE_BACKGROUND,
  PUBLIC_TRAFFIC_SUMMARY_EVERY,
  isPublicContentSurfaceEnabled,
  getActivePersona,
  PUBLIC_CORE_MARKETING_PATHS,
  PUBLIC_CANONICAL_ALIASES,
  generateAllPaths,
  startPublicBackgroundTraffic,
  registerEnhancedPublicRoutes,
  servePublicPathResponse,
  getCurrentPublicPathSet,
  shouldHandleAsDynamicPublicPath
} = createPublicContent({
  addLog,
  app,
  crypto,
  deterministicPick,
  express,
  hash32,
  pathMatchesWithOptionalPrefix,
  process,
  require,
  resolvePublicBaseUrls,
  rotationSeed,
  safeLogValue
});
// ================== INITIALIZATION ==================
function initEnhancedPublicContent() {
  if (!isPublicContentSurfaceEnabled()) return;

  // Register all routes
  registerEnhancedPublicRoutes();

  // Start background traffic
  startPublicBackgroundTraffic();
}

// Replace the old PUBLIC_CONTENT calls with this
initEnhancedPublicContent();

app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.type === "entity.parse.failed") {
    try { addLog(`[TS-CLIENT] JSON parse error: ${String(err.message||'').slice(0,120)}`); addSpacer(); } catch {}
    req.body = null;
    return next();
  }
  return next(err);
});

app.use((req, res, next) => {
  setBaselineSecurityHeaders(res, {
    includeRobots: true,
    permissionsPolicy: SECURITY_HEADER_VALUES.privacyPermissions
  });
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  if (process.env.ENABLE_HSTS === "1") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  }
  next();
});

const handleWellKnownDirectoryProbe = (_req, res) => res.status(404).send("Not Found");
const handleAdsTxt = (_req, res) => {
  res.type("text/plain").send("");
};
let handleSecurityTxtImpl;
const handleSecurityTxt = (...args) => handleSecurityTxtImpl(...args);

app.get("/.well-known/", handleWellKnownDirectoryProbe);
app.get("/ads.txt", handleAdsTxt);
if (OPTIONAL_URL_PREFIX) {
  app.get(withOptionalUrlPrefix("/.well-known/"), handleWellKnownDirectoryProbe);
  app.get(withOptionalUrlPrefix("/ads.txt"), handleAdsTxt);
}
app.get("/.well-known/security.txt", handleSecurityTxt);
if (OPTIONAL_URL_PREFIX) {
  app.get(withOptionalUrlPrefix("/.well-known/security.txt"), handleSecurityTxt);
}

app.use(validateRedirectRequest);

// Apply rate limiters BEFORE routes
app.use("/challenge",          limitChallenge);
app.use("/ts-client-log",      limitTsClientLog);
app.use("/interstitial-human", limitTsClientLog);
if (OPTIONAL_URL_PREFIX) {
  app.use(withOptionalUrlPrefix("/challenge"), limitChallenge);
  app.use(withOptionalUrlPrefix("/ts-client-log"), limitTsClientLog);
  app.use(withOptionalUrlPrefix("/interstitial-human"), limitTsClientLog);
}
app.use("/stream-log", (req, res, next) => {
  if (isAdminSSE(req)) return next();
  return limitSseUnauth(req, res, next);
});

// ✅ Put the debug route here (before your normal routes)
if (process.env.IP_DEBUG === '1') {
  app.get('/_debug/ip', (req, res) => {
    const clientIp = getClientIp(req); // Use the same function!
    res.json({
      trustProxy: req.app.get('trust proxy'),
      clientIp: clientIp,
      reqIp: req.ip,
      reqIps: req.ips,
      xff: req.headers['x-forwarded-for'] || null,
      xVercelForwarded: req.headers['x-vercel-forwarded-for'] || null,
      xReal: req.headers['x-real-ip'] || null,
      nf: req.headers['x-nf-client-connection-ip'] || null,
      allHeaders: {
        'x-forwarded-for': req.headers['x-forwarded-for'],
        'x-vercel-forwarded-for': req.headers['x-vercel-forwarded-for'],
        'x-real-ip': req.headers['x-real-ip'],
        'x-vercel-ip': req.headers['x-vercel-ip']
      }
    });
  });
}

let _health = { ok: null, lastHeartbeat: 0, okStreak: 0, failStreak: 0, inflight: false };

const createCoreRoutes = require("../runtime-routes/coreRoutes.js");
({
  handleSecurityTxt: handleSecurityTxtImpl
} = createCoreRoutes({
  ACTIVE_REQUEST_DUMP_LIMIT,
  ACTIVE_REQUEST_TOP_PATH_LIMIT,
  AES_KEYS,
  BACKLOG_ON_CONNECT,
  DEBUG_ALLOW_PLAINTEXT_KEYS,
  EXPECT_HOSTNAME_PATTERNS,
  LOGS,
  LOG_FILE,
  LOG_IDS,
  LOG_LISTENERS,
  LOG_TO_FILE,
  MAX_CATCHALL_CONCURRENCY,
  NPM_DEBUG_LOG_DIR,
  OPS_METRICS,
  OPTIONAL_URL_PREFIX,
  PUBLIC_ROTATION_MODE,
  PUBLIC_SITE_BASE_URL,
  RUNTIME_INCIDENT_FILE,
  SCANNER_DECISION_COUNTERS,
  SCANNER_FETCH_ENABLED,
  SCANNER_FETCH_PREVIEW_BYTES,
  SCANNER_FETCH_TIMEOUT_MS,
  SCANNER_GENERIC_PROFILE,
  SCANNER_PROFILES,
  SCANNER_STATS,
  STRIKE_WEIGHT_HP,
  TURNSTILE_ORIGIN,
  TURNSTILE_SITEKEY,
  UA_TRUNCATE_LENGTH,
  _health,
  addLog,
  addSpacer,
  addStrike,
  analyzeLogIntegrity,
  app,
  assertScannerFetchTargetAllowed,
  bruteSplitDecryptFull,
  buildActiveRequestDiagnostics,
  buildOpsScannerStatsForDay,
  buildPinnedScannerFetchUrl,
  buildRuntimeIncidentPayload,
  buildScannerInterstitialContext,
  computeScannerStatsFromLogs,
  createChallengeRedirect,
  createChallengeToken,
  crypto,
  decryptChallengeData,
  deterministicPick,
  encryptChallengeData,
  express,
  extractEmailSafePayloadPath,
  findScannerProfileByName,
  fs,
  getClientIp,
  getCountry,
  getCurrentPublicPathSet,
  getEventTimestamp,
  getLogFileStatus,
  getRuntimeResourceGauges,
  getRuntimeUsageSnapshot,
  getTrackedInFlightCount,
  handleRedirectCore,
  hash32,
  hashFirstSeg,
  inMemBans,
  inMemStrikes,
  incrementOpsMetric,
  isAdmin,
  isAdminSSE,
  isBrownoutActive,
  limitChallengeView,
  logScannerHit,
  makePinnedScannerRequestWithFallback,
  markInterstitialHuman,
  mask,
  maybeDenyForVisibleIpReputation,
  mintEphemeralToken,
  net,
  path,
  readLogFileTail,
  readRuntimeIncidents,
  recordChallengeBypassAttempt,
  renderScannerSafePage,
  require,
  requireAdmin,
  resolvePublicBaseUrls,
  rotationSeed,
  runtimeStats,
  safeDecode,
  safeLogJson,
  safeLogValue,
  sanitizeChallengeReason,
  sanitizeIpForKey,
  selectScannerStatsForResponse,
  sendScannerSafetyLaneHeadResponse,
  servePublicPathResponse,
  shouldHandleAsDynamicPublicPath,
  shouldTrackRuntimeRequest,
  sseSend,
  stripOptionalUrlPrefix,
  summarizeError,
  tryDecryptAny,
  tryRenderTrustedScannerSafeHtmlForPayload,
  utcDayStamp,
  validateBase64Url,
  verifyChallengeToken,
  withOptionalUrlPrefix
}));
// ================== HEALTH CHECK CONSTANTS ==================
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

// ================== STARTUP & HEALTH CHECKS ==================
function publicContentStartupSummaryLines() {
  const publicSurfaceEnabled = isPublicContentSurfaceEnabled();
  const backgroundTrafficEnabled = PUBLIC_ENABLE_BACKGROUND && PUBLIC_CONTENT_SURFACE;
  const publicForce = String(process.env.PUBLIC_CONTENT_SURFACE_FORCE || '').trim() ? 'set' : 'unset';
  const publicExplicit = String(process.env.PUBLIC_CONTENT_SURFACE || '').trim() ? 'set' : 'unset';
  const lines = [
    `[PUBLIC-CONTENT] Effective enabled=${publicSurfaceEnabled} declared=${PUBLIC_CONTENT_SURFACE} force=${publicForce} explicit=${publicExplicit}`
  ];

  if (!publicSurfaceEnabled) {
    lines.push("[PUBLIC-CONTENT] Disabled by safe default (set PUBLIC_CONTENT_SURFACE=1 or PUBLIC_CONTENT_SURFACE_FORCE=1 to enable)");
    return lines;
  }

  const persona = getActivePersona();
  const allPaths = generateAllPaths(persona, rotationSeed());
  const allPathSet = new Set(allPaths);
  const missingCore = PUBLIC_CORE_MARKETING_PATHS.filter(path => !allPathSet.has(path));
  const missingFooter = (persona.footerLinks || [])
    .map(link => link && link.path)
    .filter(path => path && path !== '/' && !allPathSet.has(path));

  lines.push(`[PUBLIC-CONTENT] Active persona: ${persona.name} (${persona.sitekey})`);
  lines.push(`[PUBLIC-CONTENT] Generated ${allPaths.length} unique paths, rotation=${PUBLIC_ROTATION_MODE}`);
  if (missingCore.length || missingFooter.length) {
    lines.push(`[PUBLIC-CONTENT] ⚠️ Path coverage gaps core=[${missingCore.join(',') || '-'}] footer=[${missingFooter.join(',') || '-'}]`);
  }
  if (backgroundTrafficEnabled) {
    lines.push(`[PUBLIC-TRAFFIC] Real inbound traffic observer started (persona: ${persona.sitekey})`);
    lines.push(`[PUBLIC-TRAFFIC] Summary logging every ${PUBLIC_TRAFFIC_SUMMARY_EVERY} visits/errors`);
  } else {
    lines.push(`[PUBLIC-TRAFFIC] Real inbound traffic observer disabled (PUBLIC_ENABLE_BACKGROUND=${PUBLIC_ENABLE_BACKGROUND}, PUBLIC_CONTENT_SURFACE=${PUBLIC_CONTENT_SURFACE})`);
  }
  return lines;
}

function startupSummary() {
  const keyPrints = AES_KEYS.map((k, i) => {
    const sha = crypto.createHash("sha256").update(k).digest("hex");
    return `#${i} len=${k.length} sha256=${sha.slice(0,10)}…`;
  }).join(", ");

  const healthLine = `  • Health: interval=${fmtDurMH(HEALTH_INTERVAL_MS)} heartbeat=${fmtDurMH(HEALTH_HEARTBEAT_MS)}`;
  const diagLine = `[DIAG] runtime incidents file=${RUNTIME_INCIDENT_FILE} npmDebugDir=${NPM_DEBUG_LOG_DIR}`;
  const railwayLine = formatRailwayRuntimeLine();
  const bypassLine = INTERSTITIAL_BYPASS_SECRET
    ? "[BYPASS] enabled for debug use"
    : "[BYPASS] disabled (no INTERSTITIAL_BYPASS_SECRET set)";

  return [
    "🛡️ Security profile",
    ipinfoLiteStatusLine,
    `[PROXY] Effective trust proxy setting: ${trustProxyEffective}`,
    ...getGeoIpFreshnessLines(),
    `🚀 Server running on port ${PORT}`,
    `[RUNTIME] bootId=${runtimeStats.bootId} startedAt=${runtimeStats.startedAt}`,
    `[KEY] Loaded ${AES_KEYS.length} AES key(s): ${keyPrints}`,
    `  • Time: zone=${zoneLabel()}`,
    `  • Turnstile: enforceAction=${ENFORCE_ACTION} maxAgeSec=${MAX_TOKEN_AGE_SEC} expectHost=[${EXPECT_HOSTNAME_PATTERNS.map(p => p.allowSubdomains ? `*.${p.suffix}` : p.suffix).join(",")||"-"}]`,
    `  • Turnstile sitekey=${mask(TURNSTILE_SITEKEY)} secret=${mask(TURNSTILE_SECRET)}`,
    `  • Geo: allow=[${ALLOWED_COUNTRIES.join(",")||"-"}] block=[${BLOCKED_COUNTRIES.join(",")||"-"}] asn=[${BLOCKED_ASNS.join(",")||"-"}]`,
    `  • Headless: block=${HEADLESS_BLOCK} hardWeight=${HEADLESS_STRIKE_WEIGHT} softStrike=${HEADLESS_SOFT_STRIKE}`,
    `  • Scanner impersonation: enabled=${IMPERSONATE_SCANNER} strict=${IMPERSONATE_SCANNER_STRICT} minConfidence=${IMPERSONATE_MIN_CONFIDENCE}`,
    `  • Scanner compatibility headers: enabled=${SCANNER_COMPAT_HEADERS_ENABLED}`,
    `  • Unknown scanner shield: enabled=${UNKNOWN_SCANNER_SHIELD_ENABLED} unique=${UNKNOWN_SCANNER_UNIQUE_PATHS}/${UNKNOWN_SCANNER_WINDOW_SECONDS}s rapid=${UNKNOWN_SCANNER_RAPID_UNIQUE_PATHS}/${UNKNOWN_SCANNER_RAPID_WINDOW_SECONDS}s perIpMax=${UNKNOWN_SCANNER_MAX_HISTORY_PER_IP} denyTtl=${UNKNOWN_SCANNER_DENY_TTL_SECONDS}s`,
    `  • Known scanner deny: keyThreshold=${KNOWN_SCANNER_DENY_THRESHOLD}/${UNKNOWN_SCANNER_WINDOW_SECONDS}s keyDenyTtl=${KNOWN_SCANNER_DENY_TTL_SECONDS}s visibleIpThreshold=${KNOWN_SCANNER_VISIBLE_IP_THRESHOLD}/${UNKNOWN_SCANNER_WINDOW_SECONDS}s visibleIpDenyTtl=${KNOWN_SCANNER_VISIBLE_IP_DENY_TTL_SECONDS}s`,
    `  • Visible IP reputation: enabled=${VISIBLE_IP_REPUTATION_ENABLED} threshold=${VISIBLE_IP_REPUTATION_DENY_THRESHOLD}/${VISIBLE_IP_REPUTATION_WINDOW_SECONDS}s minCategories=${VISIBLE_IP_REPUTATION_MIN_CATEGORIES} denyTtl=${VISIBLE_IP_REPUTATION_DENY_TTL_SECONDS}s publicWalk=${VISIBLE_IP_PUBLIC_WALK_UNIQUE_PATHS}/${UNKNOWN_SCANNER_WINDOW_SECONDS}s rapid=${VISIBLE_IP_PUBLIC_WALK_RAPID_UNIQUE_PATHS}/${UNKNOWN_SCANNER_RAPID_WINDOW_SECONDS}s`,
    `  • Crawler public-walk throttle: enabled=${CRAWLER_PUBLIC_WALK_THROTTLE_ENABLED} maxUnique=${CRAWLER_PUBLIC_WALK_MAX_PATHS}/${CRAWLER_PUBLIC_WALK_WINDOW_SECONDS}s searchMax=${CRAWLER_PUBLIC_WALK_SEARCH_MAX_PATHS}/${CRAWLER_PUBLIC_WALK_WINDOW_SECONDS}s cooldown=${CRAWLER_PUBLIC_WALK_COOLDOWN_SECONDS}s`,
    `  • Interstitial reason header: enabled=${INTERSTITIAL_REASON_HEADER_ENABLED}`,
    `  • Edge checks: requireCfHeaders=${REQUIRE_CF_HEADERS} trustUpstreamGeoHeaders=${TRUST_UPSTREAM_GEO_HEADERS}`,
    `  • Rate limits: fixedWindow=${RATE_LIMIT_MAX_REQUESTS}/${RATE_LIMIT_WINDOW_SECONDS}s tokenBucket=${RATE_CAPACITY}/${RATE_WINDOW_SECONDS}s`,
    `  • Bans: ttl=${BAN_TTL_SEC}s threshold=${BAN_AFTER_STRIKES} hpWeight=${STRIKE_WEIGHT_HP}`,
    `  • Allowlist patterns=[${ALLOWLIST_DOMAINS.map(p => p.allowSubdomains ? `*.${p.suffix}` : p.suffix).join(",")||"-"}]`,
    `  • Optional URL prefix: ${OPTIONAL_URL_PREFIX || "disabled"}`,
    `  • Redirect payload limits: payload=${MAX_REDIRECT_PAYLOAD_LENGTH} totalPath=${MAX_REDIRECT_URL_PATH_LENGTH} mode=${REDIRECT_PAYLOAD_OVERSIZE_MODE} bruteMaxPath=${MAX_BRUTE_SPLIT_PAYLOAD_LENGTH}`,
    `  • Challenge security: rateLimit=5/5min tokens=10min`,
    `  • Geo fallback active=${IPINFO_LITE_ENABLED ? "ipinfo-lite" : "headers-only"}`,
    healthLine,
    `  • Server timeouts: request=${REQUEST_TIMEOUT_MS}ms keepAlive=${SERVER_KEEP_ALIVE_TIMEOUT_MS}ms headers=${SERVER_HEADERS_TIMEOUT_MS}ms maxRequestsPerSocket=${SERVER_MAX_REQUESTS_PER_SOCKET}`,
    `  • File logging: enabled=${LOG_TO_FILE} rotation=${LOG_TO_FILE} file=${LOG_FILE} maxBytes=${LOG_FILE_MAX_BYTES} archives=${LOG_FILE_MAX_FILES}`,
    `  • Event loop monitor: sample=${EVENT_LOOP_LAG_SAMPLE_MS}ms warn=${EVENT_LOOP_LAG_WARN_MS}ms fatal=${EVENT_LOOP_FATAL_MS}ms hits=${EVENT_LOOP_FATAL_CONSECUTIVE}`,
    ...publicContentStartupSummaryLines(),
    bypassLine,
    diagLine,
    railwayLine
  ].join("\n");
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

const PORT = process.env.PORT || 8080;
const server = app.listen(PORT, async () => {
  await loadScannerPatterns();

  trackIntervalHandle("health", setInterval(checkTurnstileReachable, HEALTH_INTERVAL_MS));
  startEventLoopLagMonitor();

  // Memory cleanup interval
  const memoryCleanupInterval = setInterval(() => {
    const now = Date.now();
    const mem = process.memoryUsage();
    const heapUsedMb = Math.round(mem.heapUsed / (1024 * 1024));
    // Clean old rate limit buckets (older than 1 hour)
    for (const [key, value] of inMemBuckets.entries()) {
      if (now - value.ts > 3600000) { // 1 hour
        inMemBuckets.delete(key);
      }
    }

    for (const [key, st] of inMemDenyCache.entries()) {
      if (!st || now > st.until) inMemDenyCache.delete(key);
    }

    for (const [key, until] of inMemBans.entries()) {
      if (!until || now > until) inMemBans.delete(key);
    }

    for (const [key, st] of inMemStrikes.entries()) {
      if (typeof st === "number") {
        boundedMapSet(inMemStrikes, key, { count: st, updatedAt: now }, IN_MEM_STRIKES_MAX_ENTRIES);
        continue;
      }
      if (!st || typeof st.count !== "number") {
        inMemStrikes.delete(key);
        continue;
      }
      if (!st.updatedAt || now - st.updatedAt > STRIKE_TTL_MS) {
        inMemStrikes.delete(key);
      }
    }

    flushAggregatedLogs(now);
    pruneAdminHits(now);
    pruneAlertState(now);
    cleanupKnownScannerIps(now);
    cleanupRequestHistory(now);
    if (shouldApplyMemoryPressureRelief(mem)) {
      applyMemoryPressureRelief(now, "scheduled_cleanup");
    }
    pruneUnknownScannerHistory(now);
    pruneCrawlerPublicWalkState(now);
    for (const key of Array.from(VISIBLE_IP_REPUTATION_HISTORY.keys())) {
      getVisibleIpReputationHistoryByKey(key, now);
    }
    for (const [key, entries] of VISIBLE_IP_PUBLIC_WALK_HISTORY.entries()) {
      const fresh = Array.isArray(entries)
        ? entries.filter(entry => entry && (now - entry.ts) <= UNKNOWN_SCANNER_WINDOW_SECONDS * 1000 * 2)
        : [];
      if (fresh.length === 0) VISIBLE_IP_PUBLIC_WALK_HISTORY.delete(key);
      else if (fresh.length !== entries.length) boundedMapSet(VISIBLE_IP_PUBLIC_WALK_HISTORY, key, fresh, UNKNOWN_SCANNER_HISTORY_MAX_ENTRIES);
    }
    prunePerIpRateLimitMap(now);
    const staleTrackedPruned = pruneStaleTrackedRequests(now);
    if (staleTrackedPruned > 0) {
      addLog(`[MEMORY] pruned stale tracked requests count=${staleTrackedPruned} inFlight=${activeTrackedRequests.size}`);
    }
    maybeEmitRuntimeGaugeAlerts(now);
  }, 300000);
  trackIntervalHandle("memoryCleanup", memoryCleanupInterval);

  trackIntervalHandle("logFlush", setInterval(() => flushAggregatedLogs(Date.now()), AGG_FLUSH_MS));

  // Server + security summary logs
  addLog(startupSummary());
  checkTurnstileReachable();

  addSpacer();
});

server.keepAliveTimeout = SERVER_KEEP_ALIVE_TIMEOUT_MS;
server.headersTimeout = SERVER_HEADERS_TIMEOUT_MS;
server.requestTimeout = REQUEST_TIMEOUT_MS;
server.maxRequestsPerSocket = SERVER_MAX_REQUESTS_PER_SOCKET;

server.on("connection", (socket) => {
  openSockets.add(socket);
  socket.on("close", () => openSockets.delete(socket));
});

server.on("clientError", (error, socket) => {
  runtimeStats.serverClientErrors += 1;
  const statusCode = getClientErrorStatusCode(error);
  const statusMessage = getClientErrorStatusMessage(statusCode);
  const summary = summarizeClientError(error, socket);
  runtimeStats.lastServerClientError = {
    at: new Date().toISOString(),
    code: error && error.code ? String(error.code) : null,
    statusCode,
    message: summarizeError(error),
    bytesParsed: error && Number.isFinite(error.bytesParsed) ? Math.max(0, Math.trunc(error.bytesParsed)) : null,
    remoteAddress: socket && socket.remoteAddress ? String(socket.remoteAddress) : null,
    remotePort: socket && socket.remotePort ? Number(socket.remotePort) : null
  };
  const shouldLogClientError = isNoisyClientAbortParseError(error)
    ? aggregatePerIpEvent("SERVER-CLIENT-ERROR", {
        ip: getClientErrorAggregateIp(socket),
        reason: error.code,
        suppressFirst: true
      })
    : true;

  if (shouldLogClientError) {
    addLog(`[SERVER] clientError ${summary}`);
  }

  if (socket && socket.writable) {
    try {
      socket.end(`HTTP/1.1 ${statusCode} ${statusMessage}\r\nConnection: close\r\n\r\n`);
    } catch (_) {}
  }
});

server.on("error", (error) => {
  runtimeStats.serverErrors += 1;
  runtimeStats.lastServerError = {
    at: new Date().toISOString(),
    message: summarizeError(error)
  };
  addLog(`[SERVER] error ${safeLogValue(summarizeError(error), 180)}`);
  scheduleFatalExit("server.error", error);
});

process.on("unhandledRejection", (reason) => {
  runtimeStats.unhandledRejections += 1;
  runtimeStats.lastUnhandledRejection = {
    at: new Date().toISOString(),
    reason: summarizeError(reason)
  };
  addLog(`[PROCESS] unhandledRejection ${safeLogValue(summarizeError(reason), 180)}`);
  scheduleFatalExit("unhandledRejection", reason);
});

process.on("uncaughtException", (error) => {
  runtimeStats.uncaughtExceptions += 1;
  runtimeStats.lastUncaughtException = {
    at: new Date().toISOString(),
    message: summarizeError(error)
  };
  addLog(`[PROCESS] uncaughtException ${safeLogValue(summarizeError(error), 180)}`);
  scheduleFatalExit("uncaughtException", error);
});

process.on("warning", (warning) => {
  runtimeStats.processWarnings += 1;
  runtimeStats.lastProcessWarning = {
    at: new Date().toISOString(),
    name: safeLogValue(warning && warning.name ? warning.name : "Warning", 80),
    message: summarizeError(warning && warning.message ? warning.message : warning)
  };
  addLog(`[PROCESS] warning name=${safeLogValue(warning && warning.name ? warning.name : "Warning", 80)} msg=${safeLogValue(summarizeError(warning && warning.message ? warning.message : warning), 180)}`);
});

let fatalExitScheduled = false;
function scheduleFatalExit(origin, details) {
  if (fatalExitScheduled) return;
  fatalExitScheduled = true;

  const summary = safeLogValue(summarizeError(details), 180);
  const correlation = formatRuntimeCorrelationSuffix();
  recordRuntimeIncident("fatal", { origin, summary, correlation: getRuntimeCorrelationMetadata() });
  addLog(`[FATAL] ${safeLogValue(origin, 64)} scheduling process exit ${correlation} summary=${summary}`);

  setImmediate(() => {
    process.exitCode = 1;
    process.exit(1);
  });
}

let isShuttingDown = false;
let forcedShutdownTimedOut = false;
async function gracefulShutdown(signal) {
  runtimeStats.shutdownSignals += 1;

  if (isShuttingDown) {
    const correlation = formatRuntimeCorrelationSuffix();
    recordRuntimeIncident("shutdown_signal_while_closing", { signal, correlation: getRuntimeCorrelationMetadata() });
    addLog(`[SHUTDOWN] Received additional ${signal} while already closing (${correlation}); waiting for existing graceful shutdown`);
    return;
  }

  isShuttingDown = true;

  const uptimeSec = Math.round(process.uptime());
  const mem = process.memoryUsage();
  const rssMb = Math.round((mem.rss / (1024 * 1024)) * 100) / 100;
  const trackedInFlight = activeTrackedRequests.size;
  const correlation = formatRuntimeCorrelationSuffix();
  const activeRequestSnapshot = buildActiveRequestDiagnostics();
  recordRuntimeIncident("shutdown", {
    signal,
    source: "external_signal",
    note: "SIGTERM/SIGINT is delivered by the process supervisor, container runtime, npm parent, or user; it is not thrown by application code.",
    graceMs: SHUTDOWN_GRACE_MS,
    rssMb,
    trackedInFlight,
    activeRequests: activeRequestSnapshot,
    process: getProcessRuntimeMetadata(),
    correlation: getRuntimeCorrelationMetadata()
  });
  addLog(`[SHUTDOWN] Received ${signal} from external supervisor/runtime; closing server (${correlation} grace=${SHUTDOWN_GRACE_MS}ms uptimeSec=${uptimeSec} rssMb=${rssMb} trackedInFlight=${trackedInFlight} pid=${process.pid} ppid=${process.ppid})`);
  if (trackedInFlight > 0) logActiveRequestDiagnostics("shutdown");

  clearBackgroundTasks();
  activeTrackedRequests.clear();
  runtimeStats.inFlightRequests = 0;

  // End SSE log listeners before waiting on server.close(); long-lived streams can
  // otherwise keep the server open indefinitely and force timeout exits.
  for (const listenerRes of LOG_LISTENERS) {
    try { listenerRes.end(); } catch {}
  }

  const forceExitTimer = setTimeout(async () => {
    forcedShutdownTimedOut = true;
    recordRuntimeIncident("shutdown_forced", { signal, graceMs: SHUTDOWN_GRACE_MS, openSockets: openSockets.size, correlation: getRuntimeCorrelationMetadata() });
    addLog(`[SHUTDOWN] force exit after grace timeout (${correlation} grace=${SHUTDOWN_GRACE_MS}ms)`);
    for (const socket of openSockets) {
      try { socket.destroy(); } catch {}
    }
    await closeLogFileWriter(Math.min(2000, SHUTDOWN_GRACE_MS));
    process.exit(1);
  }, SHUTDOWN_GRACE_MS);

  server.close(async () => {
    clearTimeout(forceExitTimer);

    if (forcedShutdownTimedOut) {
      addLog(`[SHUTDOWN] server closed after grace timeout; preserving forced exit status (${correlation})`);
      return;
    }

    addLog(`[SHUTDOWN] server closed cleanly (${correlation})`);
    await closeLogFileWriter(Math.min(2000, SHUTDOWN_GRACE_MS));
    process.exit(0);
  });

  if (typeof server.closeIdleConnections === "function") {
    try { server.closeIdleConnections(); } catch {}
  }
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));
