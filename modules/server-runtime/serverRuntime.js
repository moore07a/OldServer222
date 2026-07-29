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

function decodePathForScannerMatching(pathValue) {
  const raw = String(pathValue || "");
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

const SENSITIVE_CONFIG_PROBE_BASENAME_REGEX = /^(?:appsettings(?:\.[a-z0-9_-]+)?\.json|application(?:-[a-z0-9_-]+)?\.(?:ya?ml|properties)|local\.settings\.json|settings\.py|local_settings\.py|\.yarnrc\.yml|\.npmrc|dockerfile|config\.(?:ya?ml|json|ini|toml)|secrets?\.(?:ya?ml|json|ini)|credentials?\.(?:ya?ml|json|ini)|(?:client[-_]?secret|google[-_](?:service[-_]?account|application[-_]?credentials|credentials)|gcp[-_]service[-_]?account|firebase[-_]service[-_]?account|service[-_]?account(?:[-_]?key)?|serviceaccountkey)\.json|docker-compose(?:\.[a-z0-9_-]+)?\.ya?ml|compose(?:\.[a-z0-9_-]+)?\.ya?ml|values\.ya?ml|serverless\.(?:ya?ml|json)|swagger(?:\.[a-z0-9_-]+)?\.json|stripe\.json|(?:asset|assets|build|precache)-manifest\.json|(?:webpack|loadable)-stats\.json|required-server-files\.json|api-keys|web\.config|phpinfo(?:\.php)?|info\.php)$/i;
const SENSITIVE_CONFIG_PROBE_PATH_REGEX = /(?:^|\/)(?:config|configs|configuration|backup|backups|database|db|secrets?|credentials?|aws|gcp|azure|private)(?:\/|$)|(?:^|\/)(?:aws|credentials|id_rsa|id_dsa|authorized_keys|known_hosts)(?:\.|$)|(?:^|\/)(?:\.openai|\.openclaw)(?:\/|$)|(?:^|\/)(?:docker-compose(?:\.[a-z0-9_-]+)?|compose(?:\.[a-z0-9_-]+)?|values)\.ya?ml$|(?:^|\/)(?:var\/task|app)\/serverless\.(?:ya?ml|json)$|(?:^|\/)plugins\/payments\/stripe\.json$|(?:^|\/)swagger(?:\.[a-z0-9_-]+)?\.json$|(?:^|\/)settings(?:\/|$)|(?:^|\/)var\/log(?:\/|$)/i;
const API_CONFIG_PROBE_PATH_REGEX = /^(?:api(?:\/[^\/]+)*\/config(?:\/|$)|api(?:\/[^\/]+)*\/(?:app|apps|user|index|common|system)\/config(?:\/|$)|api\/vue\/common\/config(?:\/|$)|api\/im\/v2\/app\/config(?:\/|$)|api\.php(?:\/|$)|public\/api\/index\/config(?:\/|$)|memberapi\/system\/config\/get(?:\/|$)|biz\/server\/config(?:\/|$)|[^\/]+\/config\/base(?:\/|$)|dock\/system\/config\/get(?:\/|$)|main\/config\/getkefudata(?:\/|$))/i;

function normalizeScannerProbeCandidate(candidatePath) {
  const normalized = String(candidatePath || "").toLowerCase().replace(/^\/+/, "");
  if (!normalized) return "";

  // Scanner matching is case-insensitive. Strip the optional URL prefix using
  // the same lowercase normalization so deployments with prefixes like
  // "Private" do not have the prefix segment treated as a sensitive path.
  const optionalPrefix = String(OPTIONAL_URL_PREFIX || "").toLowerCase();
  if (!optionalPrefix) return normalized;
  if (normalized === optionalPrefix) return "";
  const prefixWithSlash = `${optionalPrefix}/`;
  if (normalized.startsWith(prefixWithSlash)) {
    return normalized.slice(prefixWithSlash.length).replace(/^\/+/, "");
  }
  return normalized;
}

function stripOptionalScannerPrefixPreserveCase(candidatePath) {
  const original = String(candidatePath || "").replace(/^\/+/, "");
  if (!original) return "";

  const optionalPrefix = String(OPTIONAL_URL_PREFIX || "");
  if (!optionalPrefix) return original;

  const lower = original.toLowerCase();
  const optionalPrefixLower = optionalPrefix.toLowerCase();
  if (lower === optionalPrefixLower) return "";

  const prefixWithSlash = `${optionalPrefixLower}/`;
  if (lower.startsWith(prefixWithSlash)) {
    return original.slice(prefixWithSlash.length).replace(/^\/+/, "");
  }
  return original;
}

function isEmailSafePathCandidate(candidatePath) {
  const normalized = normalizeScannerProbeCandidate(candidatePath);
  return normalized === "e" || normalized.startsWith("e/");
}

const FLEXIBLE_REDIRECT_PAYLOAD_MIN_SEGMENT_LENGTH = 24;
const REDIRECT_PAYLOAD_SEGMENT_REGEX = /^[A-Za-z0-9_-]+={0,2}$/;

function getScannerConfiguredEmailDelimiters() {
  const raw = process.env.REDIRECT_EMAIL_DELIMITERS || process.env.DELIMITER || process.env.Delimiter || '//,__,--,~~';
  return Array.from(new Set(String(raw || '').split(',').map(value => value.trim()).filter(Boolean))).sort((a, b) => b.length - a.length);
}

function hasScannerConfiguredEmailDelimiter(value) {
  const source = String(value || '');
  return getScannerConfiguredEmailDelimiters().some(delimiter => source.includes(delimiter));
}

function isLikelyRedirectPayloadPathCandidate(candidatePath) {
  const normalized = normalizeScannerProbeCandidate(candidatePath);
  if (!normalized || isEmailSafePathCandidate(normalized)) return false;
  const preservedCandidate = stripOptionalScannerPrefixPreserveCase(candidatePath);
  const decodedPreservedCandidate = stripOptionalScannerPrefixPreserveCase(decodePathForScannerMatching(candidatePath));
  const firstSegment = normalized.split("/")[0] || "";
  const firstSegmentPreserved = preservedCandidate.split("/")[0] || "";
  const firstSegmentDecodedPreserved = decodedPreservedCandidate.split("/")[0] || "";
  if (firstSegment.length < FLEXIBLE_REDIRECT_PAYLOAD_MIN_SEGMENT_LENGTH) return false;
  if (!REDIRECT_PAYLOAD_SEGMENT_REGEX.test(firstSegment)) {
    if (!hasScannerConfiguredEmailDelimiter(firstSegmentPreserved) && !hasScannerConfiguredEmailDelimiter(firstSegmentDecodedPreserved)) return false;
    return validateBase64Url(preservedCandidate) || (
      decodedPreservedCandidate !== preservedCandidate && validateBase64Url(decodedPreservedCandidate)
    );
  }
  return validateBase64Url(preservedCandidate) || (
    decodedPreservedCandidate !== preservedCandidate && validateBase64Url(decodedPreservedCandidate)
  );
}

function isLikelyIgnoredPrefixRedirectPayloadCandidate(candidatePath) {
  const normalized = normalizeScannerProbeCandidate(candidatePath);
  const candidate = stripOptionalUrlPrefixForScannerPayload(candidatePath);
  if (!candidate || !candidate.includes("/") || isEmailSafePathCandidate(candidate)) return false;
  if (!validateBase64Url(candidate)) return false;
  if (typeof parseRedirectPayload !== "function") return false;
  const parsed = parseRedirectPayload(candidate, {
    decodeBase64UrlLoose: typeof decodeB64urlLoose === "function" ? decodeB64urlLoose : (() => ""),
    decodeFallback: typeof safeDecode === "function" ? safeDecode : (value => String(value || "")),
    isValidEmail: typeof isLikelyEmail === "function" ? isLikelyEmail : (() => false)
  });
  const parseMode = String((parsed && parsed.parseMode) || "");
  return !!(parsed && parsed.matchedNewFormat && (
    parseMode.startsWith("ignored_url_") ||
    parseMode === "email_payload"
  ));
}

function isLikelyFlexibleRedirectPayloadCandidate(candidatePath) {
  const normalized = normalizeScannerProbeCandidate(candidatePath);
  if (!normalized || !normalized.includes("/")) return false;
  // Preserve flexible redirect links such as /{payload}/config/foo where the
  // leading segment is a valid encrypted/raw redirect payload and trailing
  // segments are ignored tracking data. Require a long payload-shaped first
  // segment so ordinary scanner paths like /application/config/aws.yml do not
  // masquerade as flexible links.
  return isLikelyRedirectPayloadPathCandidate(normalized) || isLikelyIgnoredPrefixRedirectPayloadCandidate(candidatePath);
}

function isScannerExactProbePath(candidatePath) {
  const normalized = normalizeScannerProbeCandidate(candidatePath);
  return Boolean(normalized && SCANNER_PROBE_EXACT_PATHS.has(normalized));
}

function isLikelyApiConfigProbePath(candidatePath) {
  const normalized = normalizeScannerProbeCandidate(candidatePath);
  if (!normalized || isEmailSafePathCandidate(normalized)) return false;
  return API_CONFIG_PROBE_PATH_REGEX.test(normalized);
}

function isLikelySensitiveConfigProbePath(candidatePath) {
  const normalized = normalizeScannerProbeCandidate(candidatePath);
  if (!normalized || isEmailSafePathCandidate(normalized)) return false;
  if (isScannerExactProbePath(normalized) || isLikelyApiConfigProbePath(normalized)) return true;
  if (!normalized.includes("/")) return SENSITIVE_CONFIG_PROBE_BASENAME_REGEX.test(normalized);
  return SENSITIVE_CONFIG_PROBE_PATH_REGEX.test(normalized);
}

function stripOptionalUrlPrefixForScannerPayload(candidatePath = "") {
  const candidate = String(candidatePath || "").replace(/^\/+/, "");
  const optionalPrefix = String(OPTIONAL_URL_PREFIX || "");
  if (!optionalPrefix) return candidate;

  const lowerCandidate = candidate.toLowerCase();
  const lowerPrefix = optionalPrefix.toLowerCase();
  if (lowerCandidate === lowerPrefix) return "";
  if (lowerCandidate.startsWith(`${lowerPrefix}/`)) return candidate.slice(optionalPrefix.length + 1);
  return candidate;
}

function isLikelyRawUrlRedirectPayload(candidatePath = "", decodedCandidatePath = "") {
  const candidatePayload = stripOptionalUrlPrefixForScannerPayload(candidatePath);
  const decodedPayload = stripOptionalUrlPrefixForScannerPayload(decodedCandidatePath);
  return looksLikeHttpUrl(candidatePayload) || looksLikeHttpUrl(decodedPayload);
}


function classifyScannerProbeCandidate(candidatePath = "") {
  const candidate = normalizeScannerProbeCandidate(candidatePath);
  if (candidate.includes("..")) return "traversal_probe";
  if (isEmailSafePathCandidate(candidate) || isLikelyFlexibleRedirectPayloadCandidate(candidate)) return "generic_probe";
  if (isLikelyArchiveProbePath(candidate)) return "archive_probe";
  if (isScannerExactProbePath(candidate)) return "prefix_probe";
  if (isLikelySensitiveConfigProbePath(candidate)) return "config_probe";
  if (candidate.includes(".php") || candidate.includes(".asp") || candidate.includes(".jsp")) return "script_probe";
  if (NESTED_SCANNER_SUBSTRINGS.some(fragment => candidate.includes(fragment))) return "nested_probe";
  if (SCANNER_PROBE_PREFIXES.some(prefix => candidate.startsWith(prefix))) return "prefix_probe";
  return "generic_probe";
}

function chooseScannerProbeCategory(rawCandidate = "", decodedCandidate = "") {
  const decodedCategory = classifyScannerProbeCandidate(decodedCandidate);
  if (decodedCategory && decodedCategory !== "generic_probe") return decodedCategory;
  const rawCategory = classifyScannerProbeCandidate(rawCandidate);
  if (rawCategory) return rawCategory;
  return decodedCategory || "scanner_probe";
}

function recordKnownScannerBurstInHistory(history, ip, threshold, now = Date.now()) {
  const key = sanitizeIpForKey(ip || "unknown");
  if (!key || key === "unknown") return { shouldDeny: false, count: 0 };

  const windowMs = Math.max(1, UNKNOWN_SCANNER_WINDOW_SECONDS) * 1000;
  const st = history.get(key);
  if (!st || now - st.windowStart >= windowMs) {
    boundedMapSet(history, key, { count: 1, windowStart: now }, KNOWN_SCANNER_BURST_HISTORY_MAX_ENTRIES);
    return { shouldDeny: false, count: 1 };
  }

  st.count += 1;
  boundedMapSet(history, key, st, KNOWN_SCANNER_BURST_HISTORY_MAX_ENTRIES);
  return { shouldDeny: st.count >= threshold, count: st.count };
}

function recordKnownScannerProbeBurst(ip, now = Date.now()) {
  return recordKnownScannerBurstInHistory(KNOWN_SCANNER_BURST_HISTORY, ip, KNOWN_SCANNER_DENY_THRESHOLD, now);
}

function recordKnownScannerVisibleIpBurst(ip, now = Date.now()) {
  return recordKnownScannerBurstInHistory(KNOWN_SCANNER_VISIBLE_IP_BURST_HISTORY, ip, KNOWN_SCANNER_VISIBLE_IP_THRESHOLD, now);
}

function shouldTrackVisibleIpKnownScannerBurst(category) {
  return ["archive_probe", "config_probe", "nested_probe", "prefix_probe", "script_probe", "traversal_probe"].includes(category);
}

function getKnownScannerDenyKey(identity = {}) {
  if (identity.source && identity.source !== "client") return null;
  const key = identity.ip || identity.displayIp || identity.rateLimitKey || identity.denyCacheKey || identity.keyIp;
  return key && key !== "unknown" ? key : null;
}

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

function pathMatchesUnknownScannerSkipPrefix(pathname, basePath) {
  const cleanPath = String(pathname || "").toLowerCase();
  const normalizedBase = `/${String(basePath || "").replace(/^\/+/, "")}`.toLowerCase();

  if (cleanPath === normalizedBase) return true;
  if (cleanPath.startsWith(`${normalizedBase}/`)) return true;

  const optionalPrefix = String(OPTIONAL_URL_PREFIX || "").toLowerCase();
  if (!optionalPrefix) return false;

  const prefixedBase = `/${optionalPrefix}${normalizedBase}`;
  if (cleanPath === prefixedBase) return true;
  return cleanPath.startsWith(`${prefixedBase}/`);
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
  const timer = setTimeout(() => controller.abort(new Error(`fetch timeout after ${timeout}ms`)), timeout);

  try {
    const merged = {
      ...options,
      signal: controller.signal
    };
    return await fetch(url, merged);
  } finally {
    clearTimeout(timer);
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


// ================== CONSTANTS ==================
const SANITIZATION_MAX_LENGTH = 2000;
const UA_TRUNCATE_LENGTH = 160;
const PATH_TRUNCATE_LENGTH = 200;
const ACCEPT_TRUNCATE_LENGTH = 80;
const REFERER_TRUNCATE_LENGTH = 160;
const LOG_ENTRY_MAX_LENGTH = 300;
const EMAIL_DISPLAY_MAX_LENGTH = 80;
const URL_DISPLAY_MAX_LENGTH = 120;

// ================== PRE-COMPILED REGEX CONSTANTS ==================
// Compiled once at module load to avoid per-request recompilation overhead.
const RE_B64URL_SEGMENT    = /^[A-Za-z0-9_-]+=*$/;
const RE_B64URL_PAYLOAD    = /^[A-Za-z0-9_-]+(?:={0,2})?$/;
const RE_CONTROL_CHARS     = /[\x00-\x20\x7F]/;
const RE_SCANNER_PATH      = /^(cgi-bin|storage\/logs|phpmyadmin|wp-admin|wp-login\.php|\.env|vendor\/phpunit|actuator|server-status|hnap1|boaform|xmlrpc\.php|\.git\/head)\b/i;

const runtimeStats = {
  bootId: crypto.randomUUID(),
  startedAt: new Date().toISOString(),
  requestTimeouts: 0,
  shutdownSignals: 0,
  uncaughtExceptions: 0,
  unhandledRejections: 0,
  processWarnings: 0,
  serverClientErrors: 0,
  serverErrors: 0,
  totalRequests: 0,
  inFlightRequests: 0,
  completedRequests: 0,
  abortedRequests: 0,
  staleTrackedRequestsPruned: 0,
  lastRequestStartedAt: null,
  lastRequestCompletedAt: null,
  lastRequestPath: null,
  lastResponseStatus: null,
  maxObservedRequestDurationMs: 0,
  maxObservedEventLoopLagMs: 0,
  lastEventLoopLagAt: null,
  turnstileChecks: 0,
  turnstileCheckErrors: 0,
  turnstileCheckTimeouts: 0,
  lastTurnstileCheckAt: null,
  lastTurnstileLatencyMs: null,
  lastTurnstileError: null,
  lastUnhandledRejection: null,
  lastUncaughtException: null,
  lastServerClientError: null,
  lastServerError: null,
  lastProcessWarning: null
};
const activeTrackedRequests = new Map();
let nextTrackedRequestId = 1;
const TRACKED_REQUEST_STALE_GRACE_MS = 5000;
const ACTIVE_REQUEST_DUMP_LIMIT = readPositiveIntEnv("ACTIVE_REQUEST_DUMP_LIMIT", 20);
const ACTIVE_REQUEST_TOP_PATH_LIMIT = readPositiveIntEnv("ACTIVE_REQUEST_TOP_PATH_LIMIT", 10);

function getTrackedRequestStartedAt(tracked) {
  if (typeof tracked === "number") return tracked;
  if (tracked && typeof tracked.startedAtMs === "number") return tracked.startedAtMs;
  return NaN;
}

function pruneStaleTrackedRequests(nowMs = Date.now()) {
  const staleThresholdMs = REQUEST_TIMEOUT_MS + TRACKED_REQUEST_STALE_GRACE_MS;
  let removed = 0;
  for (const [trackedRequestId, tracked] of activeTrackedRequests.entries()) {
    const startedAtMs = getTrackedRequestStartedAt(tracked);
    if (!Number.isFinite(startedAtMs)) continue;
    if (nowMs - startedAtMs <= staleThresholdMs) continue;
    activeTrackedRequests.delete(trackedRequestId);
    runtimeStats.staleTrackedRequestsPruned += 1;
    removed += 1;
  }
  if (removed > 0) {
    runtimeStats.inFlightRequests = activeTrackedRequests.size;
  }
  return removed;
}

function getTrackedInFlightCount() {
  pruneStaleTrackedRequests();
  return activeTrackedRequests.size;
}

function buildActiveRequestDiagnostics(nowMs = Date.now(), options = {}) {
  const limit = Math.max(1, Number(options.limit || ACTIVE_REQUEST_DUMP_LIMIT));
  const topLimit = Math.max(1, Number(options.topLimit || ACTIVE_REQUEST_TOP_PATH_LIMIT));
  const requests = [];
  const byPath = new Map();

  for (const [id, tracked] of activeTrackedRequests.entries()) {
    const startedAtMs = getTrackedRequestStartedAt(tracked);
    const durationMs = Number.isFinite(startedAtMs) ? nowMs - startedAtMs : null;
    const pathValue = tracked && typeof tracked === "object" ? tracked.path : "unknown";
    const method = tracked && typeof tracked === "object" ? tracked.method : "unknown";
    const ip = tracked && typeof tracked === "object" ? tracked.ip : "unknown";
    const requestId = tracked && typeof tracked === "object" ? tracked.requestId : null;

    requests.push({ id, requestId, method, path: pathValue, ip, startedAt: Number.isFinite(startedAtMs) ? new Date(startedAtMs).toISOString() : null, durationMs });

    const key = `${method} ${pathValue}`;
    const existing = byPath.get(key) || { method, path: pathValue, count: 0, maxDurationMs: 0 };
    existing.count += 1;
    if (Number.isFinite(durationMs)) existing.maxDurationMs = Math.max(existing.maxDurationMs, durationMs);
    byPath.set(key, existing);
  }

  requests.sort((a, b) => (b.durationMs || 0) - (a.durationMs || 0));
  const topPaths = [...byPath.values()]
    .sort((a, b) => (b.count - a.count) || (b.maxDurationMs - a.maxDurationMs))
    .slice(0, topLimit);

  return {
    at: new Date(nowMs).toISOString(),
    total: activeTrackedRequests.size,
    topPaths,
    oldest: requests.slice(0, limit)
  };
}

function logActiveRequestDiagnostics(reason, nowMs = Date.now()) {
  const diag = buildActiveRequestDiagnostics(nowMs);
  const topSummary = diag.topPaths
    .map(item => `${safeLogValue(item.method, 12)} ${safeLogValue(item.path, 80)} count=${item.count} maxMs=${Math.round(item.maxDurationMs || 0)}`)
    .join(" | ") || "none";
  const oldestSummary = diag.oldest
    .slice(0, 5)
    .map(item => `${safeLogValue(item.method, 12)} ${safeLogValue(item.path, 80)} ms=${Math.round(item.durationMs || 0)} ip=${safeLogValue(item.ip, 64)}`)
    .join(" | ") || "none";
  addLog(`[ACTIVE-REQUESTS] reason=${safeLogValue(reason, 48)} total=${diag.total} top=${safeLogValue(topSummary, 500)} oldest=${safeLogValue(oldestSummary, 500)}`);
  return diag;
}

function sanitizeRequestPath(value) {
  const raw = String(value || '/');
  const noQuery = raw.split('?')[0].split('#')[0] || '/';

  const candidate = noQuery.startsWith('/') ? noQuery.slice(1) : noQuery;
  const { payloadPath } = stripOptionalUrlPrefix(candidate);
  const normalizedPayloadPath = String(payloadPath || '').replace(/^\/+/, '');

  if (normalizedPayloadPath.startsWith('tr/cl/')) {
    return '/tr/cl/[redacted]';
  }
  if (normalizedPayloadPath.startsWith('e/')) {
    return '/e/[redacted]';
  }

  if (
    normalizedPayloadPath &&
    !normalizedPayloadPath.includes('/') &&
    normalizedPayloadPath.length > 48 &&
    RE_B64URL_SEGMENT.test(normalizedPayloadPath)
  ) {
    return '/[encoded-redacted]';
  }

  const looksLikeSplitEncodedPayload = (() => {
    const delimiters = Array.from(new Set([...getConfiguredEmailDelimiters(), '//']));
    for (const delimiter of delimiters) {
      let index = normalizedPayloadPath.indexOf(delimiter);
      while (index >= 0) {
        if (delimiter === '//' && index > 0 && normalizedPayloadPath[index - 1] === ':') {
          index = normalizedPayloadPath.indexOf(delimiter, index + delimiter.length);
          continue;
        }
        const left = normalizedPayloadPath.slice(0, index);
        const right = normalizedPayloadPath.slice(index + delimiter.length);
        if (left && right && left.length >= 24 && right.length >= 8) {
          const leftLooksEncoded = RE_B64URL_SEGMENT.test(left);
          const rightEmailCandidate = right.split('/', 1)[0] || right;
          const rightLooksSensitive = RE_B64URL_SEGMENT.test(rightEmailCandidate) || /%40|@/i.test(rightEmailCandidate);
          if (leftLooksEncoded && rightLooksSensitive) return true;
        }
        index = normalizedPayloadPath.indexOf(delimiter, index + delimiter.length);
      }
    }
    return false;
  })();

  if (looksLikeSplitEncodedPayload) {
    if (candidate.toLowerCase().startsWith('tr/cl/')) {
      return '/tr/cl/[redacted]';
    }
    return '/[encoded-redacted]';
  }

  try {
    const parsedPayload = parseRedirectPayload(normalizedPayloadPath, {
      decodeBase64UrlLoose: decodeB64urlLoose,
      decodeFallback: safeDecode,
      isValidEmail: isLikelyEmail
    });
    const parseMode = String((parsedPayload && parsedPayload.parseMode) || '');
    if (parsedPayload && parsedPayload.matchedNewFormat && (
      parseMode === 'email_payload' ||
      parseMode.startsWith('ignored_url_')
    )) {
      return '/[encoded-redacted]';
    }
  } catch {}

  if (
    RE_SCANNER_PATH.test(normalizedPayloadPath) ||
    normalizedPayloadPath.includes('..')
  ) {
    return '/[scanner-probe]';
  }

  return safeLogValue(noQuery, 180);
}

function getEventTimestamp(meta) {
  if (!meta || typeof meta !== 'object') return null;
  return typeof meta.at === 'string' ? meta.at : null;
}

function isOperationalBypassPath(pathValue) {
  return (
    pathMatchesWithOptionalPrefix(pathValue, '/health', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/readyz', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/healthz', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/livez', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/__debug', { allowChildren: true }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/_debug', { allowChildren: true })
  );
}

function getRequestPathForPolicy(req) {
  return String(req && (req.path || req.originalUrl || req.url) || '/').split('?')[0].split('#')[0] || '/';
}

function getNormalizedRequestPathForPolicy(req) {
  const raw = getRequestPathForPolicy(req);
  return raw.length > 1 ? raw.replace(/\/+$/, '') : raw;
}

function shouldTrackRuntimeRequest(req) {
  const pathValue = getNormalizedRequestPathForPolicy(req);
  if (
    isOperationalBypassPath(pathValue) ||
    isLikelyScannerProbePath(pathValue) ||
    pathMatchesWithOptionalPrefix(pathValue, '/stream-log', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/view-log', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/view-log-live', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/geo-debug', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/ts-client-log', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/interstitial-human', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/challenge', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/challenge-fragment', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/decrypt-challenge-data', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/turnstile-sitekey', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/api/v1/status', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/_collect', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/_interact', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/_analytics.gif', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/_debug', { allowChildren: true }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/__debug', { allowChildren: true }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/admin', { allowChildren: true }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/__hp.gif', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/favicon.ico', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/robots.txt', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/sitemap.xml', { allowChildren: false })
  ) {
    return false;
  }
  return true;
}

function shouldEnforceRequestTimeout(req) {
  const pathValueRaw = String(req && (req.path || req.originalUrl || req.url) || '/').split('?')[0].split('#')[0];
  const pathValue = pathValueRaw.length > 1 ? pathValueRaw.replace(/\/+$/, '') : pathValueRaw;
  if (
    pathMatchesWithOptionalPrefix(pathValue, '/stream-log', { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(pathValue, '/view-log-live', { allowChildren: false })
  ) {
    return false;
  }
  return true;
}

function isLikelyScannerProbePath(pathValue) {
  const raw = String(pathValue || '/').split('?')[0].split('#')[0] || '/';
  const decodedRaw = decodePathForScannerMatching(raw).toLowerCase();
  const candidates = [raw, decodedRaw]
    .map(value => (value.startsWith('/') ? value.slice(1) : value))
    .map(candidate => stripOptionalUrlPrefix(candidate).payloadPath)
    .map(payloadPath => String(payloadPath || '').replace(/^\/+/, '').toLowerCase())
    .filter(Boolean);

  return candidates.some((normalizedPayloadPath) => {
    if (normalizedPayloadPath.includes('..')) return true;
    if (RE_SCANNER_PATH.test(normalizedPayloadPath)) return true;
    const category = classifyScannerProbeCandidate(normalizedPayloadPath);
    return Boolean(category && category !== 'generic_probe');
  });
}


function summarizeError(error, maxLen = 220) {
  if (error == null) return null;
  const value = String(error && error.stack ? error.stack : error);
  return value.length > maxLen ? `${value.slice(0, maxLen)}…` : value;
}

function summarizeClientError(error, socket, maxLen = 420) {
  const parts = [];
  if (error && error.code) parts.push(`code=${safeLogValue(error.code, 32)}`);
  if (error && error.reason) parts.push(`reason=${safeLogValue(error.reason, 80)}`);
  if (error && Number.isFinite(error.bytesParsed)) parts.push(`bytesParsed=${Math.max(0, Math.trunc(error.bytesParsed))}`);

  const rawPacket = error && Buffer.isBuffer(error.rawPacket) ? error.rawPacket : null;
  if (rawPacket) {
    const previewBytes = Math.max(1, Math.min(CLIENT_ERROR_RAW_PACKET_PREVIEW_BYTES, rawPacket.length));
    const preview = rawPacket.subarray(0, previewBytes);
    const asciiPreview = preview
      .toString("latin1")
      .replace(/[^\x20-\x7e]/g, ".");
    parts.push(`rawLen=${rawPacket.length}`);
    parts.push(`rawHex=${preview.toString("hex")}`);
    parts.push(`rawAscii=${safeLogValue(asciiPreview, previewBytes)}`);
  }

  if (socket) {
    const remote = `${socket.remoteAddress || "-"}:${socket.remotePort || "-"}`;
    const local = `${socket.localAddress || "-"}:${socket.localPort || "-"}`;
    parts.push(`remote=${safeLogValue(remote, 80)}`);
    parts.push(`local=${safeLogValue(local, 80)}`);
    if (Number.isFinite(socket.bytesRead)) parts.push(`bytesRead=${Math.max(0, Math.trunc(socket.bytesRead))}`);
    if (Number.isFinite(socket.bytesWritten)) parts.push(`bytesWritten=${Math.max(0, Math.trunc(socket.bytesWritten))}`);
    parts.push(`writable=${socket.writable ? "1" : "0"}`);
    parts.push(`destroyed=${socket.destroyed ? "1" : "0"}`);
  }

  parts.push(`message=${safeLogValue(summarizeError(error, 160), 180)}`);
  return safeLogValue(parts.join(" "), maxLen);
}

function getClientErrorStatusCode(error) {
  return error && error.code === "HPE_HEADER_OVERFLOW" ? 431 : 400;
}

function getClientErrorStatusMessage(statusCode) {
  return statusCode === 431 ? "Request Header Fields Too Large" : "Bad Request";
}

function isNoisyClientAbortParseError(error) {
  return Boolean(error && error.code === "HPE_INVALID_EOF_STATE");
}

function getClientErrorAggregateIp(socket) {
  if (!socket || !socket.remoteAddress) return "unknown";
  return String(socket.remoteAddress);
}

let cpuSnapshot = {
  timeNs: process.hrtime.bigint(),
  usage: process.cpuUsage()
};

function roundMetric(value, digits = 2) {
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  const pow = 10 ** digits;
  return Math.round(n * pow) / pow;
}

function getRuntimeUsageSnapshot() {
  const mem = process.memoryUsage();
  const nowNs = process.hrtime.bigint();
  const currentUsage = process.cpuUsage();

  const elapsedUs = Number(nowNs - cpuSnapshot.timeNs) / 1000;
  const deltaUserUs = currentUsage.user - cpuSnapshot.usage.user;
  const deltaSystemUs = currentUsage.system - cpuSnapshot.usage.system;
  const deltaTotalUs = deltaUserUs + deltaSystemUs;
  const cpuPercent = elapsedUs > 0 ? (deltaTotalUs / elapsedUs) * 100 : 0;
  const cpuCount = Math.max(1, os.cpus().length || 1);

  cpuSnapshot = {
    timeNs: nowNs,
    usage: currentUsage
  };

  return {
    cpu: {
      processPercent: roundMetric(cpuPercent),
      processPercentPerCore: roundMetric(cpuPercent / cpuCount, 4),
      cores: cpuCount,
      loadAvg1m: roundMetric(os.loadavg()[0]),
      loadAvg5m: roundMetric(os.loadavg()[1]),
      loadAvg15m: roundMetric(os.loadavg()[2]),
      note: "loadAvg* reflects host/container scheduler load and is not app-only CPU%"
    },
    memory: {
      rssMb: roundMetric(mem.rss / (1024 * 1024)),
      heapUsedMb: roundMetric(mem.heapUsed / (1024 * 1024)),
      heapTotalMb: roundMetric(mem.heapTotal / (1024 * 1024)),
      externalMb: roundMetric(mem.external / (1024 * 1024)),
      arrayBuffersMb: roundMetric((mem.arrayBuffers || 0) / (1024 * 1024))
    }
  };
}

const app = express();
function resolveOrCreateRequestId(req) {
  const headerValue = req.headers["x-request-id"];
  if (typeof headerValue === "string" && headerValue.trim()) {
    return headerValue.trim().slice(0, 120);
  }
  if (Array.isArray(headerValue) && headerValue.length > 0) {
    const first = String(headerValue[0] || "").trim();
    if (first) return first.slice(0, 120);
  }
  return crypto.randomUUID();
}
function parseTrustProxyValue(rawValue) {
  const raw = String(rawValue || '').trim();
  if (!raw) return null;

  if (raw.toLowerCase() === 'true') return true;
  if (raw.toLowerCase() === 'false') return false;
  if (Number.isFinite(+raw) && +raw >= 0) return +raw;
  return null;
}

// Safety override: prefer explicit/safer proxy trust behavior unless explicitly set.
function resolveSaferTrustProxySetting() {
  const parsedTrustProxy = parseTrustProxyValue(process.env.TRUST_PROXY_HOPS);
  const mode = String(process.env.TRUST_PROXY_MODE || 'safe').trim().toLowerCase();

  if (parsedTrustProxy !== null) return parsedTrustProxy;

  // In safe mode, default to explicit single hop on managed platforms, otherwise no trust.
  if (mode === 'safe') {
    if (process.env.VERCEL || process.env.NETLIFY || process.env.RENDER || process.env.RAILWAY || process.env.HEROKU) {
      return 1;
    }
    return false;
  }

  // Legacy behavior compatibility: trust all proxies when hops are unset.
  return true;
}

const trustProxyEffective = resolveSaferTrustProxySetting();
app.set('trust proxy', trustProxyEffective);

const SECURITY_HEADER_VALUES = Object.freeze({
  referrerPolicy: "no-referrer",
  contentTypeOptions: "nosniff",
  frameOptions: "DENY",
  hstsPreload: "max-age=63072000; includeSubDomains; preload",
  robotsNoIndex: "noindex, nofollow, noarchive",
  privacyPermissions: "interest-cohort=(), browsing-topics=()"
});

function setBaselineSecurityHeaders(res, { includeRobots = false, permissionsPolicy } = {}) {
  res.setHeader("Referrer-Policy", SECURITY_HEADER_VALUES.referrerPolicy);
  res.setHeader("X-Content-Type-Options", SECURITY_HEADER_VALUES.contentTypeOptions);
  res.setHeader("X-Frame-Options", SECURITY_HEADER_VALUES.frameOptions);
  if (includeRobots) {
    res.setHeader("X-Robots-Tag", SECURITY_HEADER_VALUES.robotsNoIndex);
  }
  if (permissionsPolicy) {
    res.setHeader("Permissions-Policy", permissionsPolicy);
  }
}

function applyEarlyBaselineSecurityHeaders(req, res) {
  setBaselineSecurityHeaders(res, {
    permissionsPolicy: SECURITY_HEADER_VALUES.privacyPermissions
  });

  const isSecure = req.secure || String(req.headers["x-forwarded-proto"] || "").includes("https");
  if (isSecure) {
    res.setHeader("Strict-Transport-Security", SECURITY_HEADER_VALUES.hstsPreload);
  }
}

function applyNoIndexToEarlyErrorResponses(res) {
  if (res.__earlyErrorNoIndexWrapped) return;
  res.__earlyErrorNoIndexWrapped = true;

  const originalWriteHead = res.writeHead;
  res.writeHead = function writeHeadWithEarlyErrorNoIndex(statusCode, ...args) {
    const numericStatus = Number(statusCode || res.statusCode);
    if (numericStatus >= 400 && !res.getHeader("X-Robots-Tag")) {
      res.setHeader("X-Robots-Tag", SECURITY_HEADER_VALUES.robotsNoIndex);
    }
    return originalWriteHead.call(this, statusCode, ...args);
  };
}

// Attach scanner-visible baseline headers before any early-exit middleware can
// return 404/429 responses. The full CSP/nonced header set is still applied by
// the enhanced security middleware below for normal route handling.
app.use((req, res, next) => {
  applyEarlyBaselineSecurityHeaders(req, res);
  applyNoIndexToEarlyErrorResponses(res);
  next();
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
function attachRequestId(req, res) {
  const requestId = resolveOrCreateRequestId(req);
  req.requestId = requestId;
  res.setHeader("x-request-id", requestId);
  return requestId;
}

function startRuntimeRequestTracking(req, requestId, requestStartedAtMs) {
  if (!shouldTrackRuntimeRequest(req)) return { tracked: false, trackedRequestId: null };
  const trackedRequestId = nextTrackedRequestId++;
  runtimeStats.totalRequests += 1;
  const identity = getRequestIdentity(req);
  const requestPath = sanitizeRequestPath(req.originalUrl || req.url || req.path || "-");
  activeTrackedRequests.set(trackedRequestId, {
    startedAtMs: requestStartedAtMs,
    requestId,
    method: String(req.method || "GET").toUpperCase(),
    path: requestPath,
    ip: identity.ip,
    keyIp: identity.keyIp
  });
  runtimeStats.inFlightRequests = getTrackedInFlightCount();
  runtimeStats.lastRequestStartedAt = new Date(requestStartedAtMs).toISOString();
  runtimeStats.lastRequestPath = requestPath;
  return { tracked: true, trackedRequestId };
}

function createRuntimeRequestFinalizer(trackingState, requestStartedAtMs) {
  let requestAccounted = false;
  return function finalizeTrackedRequest() {
    if (!trackingState.tracked || requestAccounted) return false;
    requestAccounted = true;
    activeTrackedRequests.delete(trackingState.trackedRequestId);
    runtimeStats.inFlightRequests = getTrackedInFlightCount();
    const durationMs = Date.now() - requestStartedAtMs;
    if (durationMs > runtimeStats.maxObservedRequestDurationMs) {
      runtimeStats.maxObservedRequestDurationMs = durationMs;
    }
    return true;
  };
}

function attachRuntimeCompletionLogging(req, res, requestId, requestStartedAtMs, finalizeTrackedRequest) {
  const recordRequestCompletion = () => {
    if (!finalizeTrackedRequest()) return;
    const durationMs = Date.now() - requestStartedAtMs;
    runtimeStats.completedRequests += 1;
    runtimeStats.lastRequestCompletedAt = new Date().toISOString();
    runtimeStats.lastResponseStatus = res.statusCode;
    const identity = getRequestIdentity(req);
    addLog(`[REQ:finish] id=${safeLogValue(requestId, 120)} ip=${safeLogValue(identity.ip, 64)}${formatRequestIdentityLogSuffix(req)} method=${safeLogValue(req.method, 12)} path=${safeLogValue(sanitizeRequestPath(req.originalUrl || req.url || req.path || "-"), 180)} status=${res.statusCode} durationMs=${durationMs}`);
  };

  const recordRequestAbort = () => {
    if (!finalizeTrackedRequest()) return;
    const durationMs = Date.now() - requestStartedAtMs;
    runtimeStats.abortedRequests += 1;
    const identity = getRequestIdentity(req);
    addLog(`[REQ:close] id=${safeLogValue(requestId, 120)} ip=${safeLogValue(identity.ip, 64)}${formatRequestIdentityLogSuffix(req)} method=${safeLogValue(req.method, 12)} path=${safeLogValue(sanitizeRequestPath(req.originalUrl || req.url || req.path || "-"), 180)} status=${res.statusCode || "-"} durationMs=${durationMs}`);
  };

  res.on("finish", recordRequestCompletion);
  res.on("close", recordRequestAbort);
  res.on("error", recordRequestAbort);
  req.on("aborted", recordRequestAbort);
}

function attachRequestTimeoutEnforcement(req, res) {
  if (!shouldEnforceRequestTimeout(req)) return;
  req.setTimeout(REQUEST_TIMEOUT_MS);
  res.setTimeout(REQUEST_TIMEOUT_MS);
  req.on("timeout", () => {
    runtimeStats.requestTimeouts += 1;
    markTimeoutAndMaybeBrownout();
    const identity = getRequestIdentity(req);
    const keySuffix = identity.keyIp && identity.keyIp !== identity.ip ? ` keyIp=${safeLogValue(identity.keyIp, 64)}` : "";
    addLog(`[TIMEOUT] request timeout ip=${safeLogValue(identity.ip, 64)}${keySuffix} method=${safeLogValue(req.method, 12)} path=${safeLogValue(req.path, 120)} timeoutMs=${REQUEST_TIMEOUT_MS}`);

    if (!res.headersSent) {
      res.status(408).json({ ok: false, error: "request_timeout" });
      return;
    }

    try {
      req.destroy();
    } catch (_) {}
  });
}

function runtimeRequestTracker(req, res, next) {
  const requestStartedAtMs = Date.now();
  const requestId = attachRequestId(req, res);
  const trackingState = startRuntimeRequestTracking(req, requestId, requestStartedAtMs);
  const finalizeTrackedRequest = createRuntimeRequestFinalizer(trackingState, requestStartedAtMs);
  attachRuntimeCompletionLogging(req, res, requestId, requestStartedAtMs, finalizeTrackedRequest);
  attachRequestTimeoutEnforcement(req, res);
  next();
}
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
function mask(s){ if (!s) return ""; return s.length<=6 ? "*".repeat(s.length) : s.slice(0,4)+"…"+s.slice(-2); }

function safeZone(tz) {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz }).format();
    return tz;
  } catch {
    return 'UTC';
  }
}

const TIMEZONE = safeZone(process.env.TIMEZONE || 'UTC');

function formatLocal(ts, tz = TIMEZONE) {
  const d = ts instanceof Date ? ts : new Date(ts);
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: tz,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: true
  }).formatToParts(d);
  const p = Object.fromEntries(parts.map(x => [x.type, x.value]));
  return `${p.month}-${p.day}-${p.year} - ${p.hour}:${p.minute}:${p.second} ${p.dayPeriod}`;
}

function zoneLabel(tz = TIMEZONE) {
  const now = new Date();
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      timeZoneName: 'shortOffset'
    }).formatToParts(now);

    const name = parts.find(p => p.type === 'timeZoneName')?.value || '';
    const utc = name.replace(/^GMT/, 'UTC');

    const m = utc.match(/^UTC([+-])(\d{1,2})(?::?(\d{2}))?$/);
    if (m) {
      const sign = m[1];
      const hh = String(m[2]).padStart(2, '0');
      const mm = String(m[3] || '00').padStart(2, '0');
      return `${tz} (UTC${sign}${hh}:${mm})`;
    }
    return `${tz} (${utc || 'UTC'})`;
  } catch {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      timeZoneName: 'short'
    }).formatToParts(now);
    const abbr = parts.find(p => p.type === 'timeZoneName')?.value || tz;
    return `${tz} (${abbr})`;
  }
}

// Enhanced log sanitization function (Critical Fix 5)
function safeLogValue(value, maxLength = 100) {
  return String(value || '')
    .replace(/\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g, '') // Strip ANSI/CSI escape sequences
    .replace(/[\x00-\x1F\x7F-\x9F]/g, '')  // Remove all control characters
    .replace(/[ \t]{2,}/g, ' ')            // Collapse multiple spaces/tabs
    .replace(/[\r\n]/g, ' ')               // Replace newlines with spaces
    .trim()
    .substring(0, maxLength);
}


function parseEmailDelimiterEnvValue(rawValue) {
  return String(rawValue || '')
    .split(',')
    .map(value => value.trim())
    .filter(Boolean);
}

function getConfiguredEmailDelimiters() {
  const envDelimiters = parseEmailDelimiterEnvValue(
    process.env.REDIRECT_EMAIL_DELIMITERS || process.env.DELIMITER || process.env.Delimiter
  );
  const configured = envDelimiters.length ? envDelimiters : ['//', '__', '--', '~~'];
  return Array.from(new Set(configured)).sort((a, b) => b.length - a.length);
}

function findPreviousEmailDelimiter(value, beforeIndex) {
  const source = String(value || '');
  const limit = beforeIndex == null ? source.length : beforeIndex;
  let best = null;
  for (const delimiter of getConfiguredEmailDelimiters()) {
    let index = source.lastIndexOf(delimiter, limit - 1);
    while (index >= 0) {
      if (delimiter === '//' && index > 0 && source[index - 1] === ':') {
        index = source.lastIndexOf(delimiter, index - 1);
        continue;
      }
      const end = index + delimiter.length;
      const bestEnd = best ? best.index + best.delimiter.length : -1;
      if (!best || end > bestEnd || (end === bestEnd && delimiter.length > best.delimiter.length)) {
        best = { index, delimiter };
      }
      break;
    }
  }
  return best;
}

function findNextEmailDelimiter(value, fromIndex = 0) {
  const source = String(value || '');
  let best = null;
  for (const delimiter of getConfiguredEmailDelimiters()) {
    let index = source.indexOf(delimiter, fromIndex);
    while (index >= 0) {
      if (delimiter === '//' && index > 0 && source[index - 1] === ':') {
        index = source.indexOf(delimiter, index + delimiter.length);
        continue;
      }
      if (!best || index < best.index || (index === best.index && delimiter.length > best.delimiter.length)) {
        best = { index, delimiter };
      }
      break;
    }
  }
  return best;
}

// Enhanced JSON logging with proper length handling
function safeLogJson(payload, maxLength = 500) {
  try {
    const jsonString = JSON.stringify(payload);
    return safeLogValue(jsonString, maxLength);
  } catch (e) {
    return safeLogValue(`[JSON-Error: ${e.message}] ${String(payload)}`, maxLength);
  }
}

// Enhanced sanitizeOneLine with additional protection
function sanitizeOneLine(s) {
  return safeLogValue(s, SANITIZATION_MAX_LENGTH);
}

const sanitizeLogLine = sanitizeOneLine;

// Keep all your existing functions as they are...
function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

function parseOptionalUrlPrefix(rawPrefix) {
  const normalized = String(rawPrefix || "")
    .trim()
    .replace(/^\/+|\/+$/g, "");

  if (!normalized) return [];

  // Express string routes are compiled by path-to-regexp, so characters like
  // ?, +, *, (), [] can be interpreted as pattern tokens and crash route setup.
  // Restrict the optional prefix to URL-safe literal segment characters only.
  const SAFE_PREFIX_SEGMENT_RE = /^[A-Za-z0-9._~-]+$/;
  const rawSegments = normalized
    .split("/")
    .map((part) => part.trim())
    .filter(Boolean);

  const safeSegments = rawSegments.filter((segment) => SAFE_PREFIX_SEGMENT_RE.test(segment));

  if (safeSegments.length !== rawSegments.length) {
    console.warn(`[CONFIG] OPTIONAL_URL_PREFIX contains unsupported characters and has been sanitized. raw='${normalized}' safe='${safeSegments.join("/")}'`);
  }

  return safeSegments;
}

const OPTIONAL_URL_PREFIX_SEGMENTS = parseOptionalUrlPrefix(process.env.OPTIONAL_URL_PREFIX || "");
const OPTIONAL_URL_PREFIX = OPTIONAL_URL_PREFIX_SEGMENTS.join("/");

function getOptionalUrlPrefixPath() {
  return OPTIONAL_URL_PREFIX ? `/${OPTIONAL_URL_PREFIX}` : "";
}

function withOptionalUrlPrefix(pathValue) {
  const normalizedPath = `/${String(pathValue || "").replace(/^\/+/, "")}`;
  const optionalPrefixPath = getOptionalUrlPrefixPath();
  if (!optionalPrefixPath) return normalizedPath;
  return `${optionalPrefixPath}${normalizedPath}`;
}

function pathMatchesWithOptionalPrefix(pathname, basePath, { allowChildren = true } = {}) {
  const cleanPath = String(pathname || "");
  const normalizedBase = `/${String(basePath || "").replace(/^\/+/, "")}`;

  if (cleanPath === normalizedBase) return true;
  if (allowChildren && cleanPath.startsWith(`${normalizedBase}/`)) return true;

  const optionalPrefixPath = getOptionalUrlPrefixPath();
  if (!optionalPrefixPath) return false;

  const prefixedBase = `${optionalPrefixPath}${normalizedBase}`;
  if (cleanPath === prefixedBase) return true;
  if (allowChildren && cleanPath.startsWith(`${prefixedBase}/`)) return true;

  return false;
}

function pathMatchesExactRoute(pathname, basePath, { allowOptionalPrefix = false } = {}) {
  const cleanPath = String(pathname || "");
  const normalizedBase = `/${String(basePath || "").replace(/^\/+/, "")}`;
  const baseWithTrailingSlash = normalizedBase === "/" ? normalizedBase : `${normalizedBase}/`;

  if (cleanPath === normalizedBase || cleanPath === baseWithTrailingSlash) return true;

  if (!allowOptionalPrefix) return false;

  const optionalPrefixPath = getOptionalUrlPrefixPath();
  if (!optionalPrefixPath) return false;

  const prefixedBase = `${optionalPrefixPath}${normalizedBase}`;
  const prefixedWithTrailingSlash = prefixedBase === "/" ? prefixedBase : `${prefixedBase}/`;
  return cleanPath === prefixedBase || cleanPath === prefixedWithTrailingSlash;
}

function stripOptionalUrlPrefix(pathValue) {
  const clean = safeDecode(String(pathValue || "")).replace(/^\/+|\/+$/g, "");
  if (!clean) {
    return { payloadPath: "", usedPrefix: false };
  }

  if (!OPTIONAL_URL_PREFIX) {
    return { payloadPath: clean, usedPrefix: false };
  }

  if (clean === OPTIONAL_URL_PREFIX) {
    return { payloadPath: "", usedPrefix: true };
  }

  const prefixWithSlash = `${OPTIONAL_URL_PREFIX}/`;
  if (clean.startsWith(prefixWithSlash)) {
    return { payloadPath: clean.slice(prefixWithSlash.length), usedPrefix: true };
  }

  return { payloadPath: clean, usedPrefix: false };
}

function extractEmailSafePayloadPath(req) {
  if (req && req.params && typeof req.params.data === "string") {
    return String(req.params.data);
  }

  const candidateRaw = String((req?.originalUrl || "").slice(1).split("?")[0] || "");
  const { payloadPath } = stripOptionalUrlPrefix(candidateRaw);
  if (!payloadPath) return "";
  if (payloadPath.startsWith("e/")) return payloadPath.slice(2);
  return payloadPath;
}

function looksLikeHttpUrl(value) {
  const raw = String(value || "").trim();
  if (!/^https?:\/\//i.test(raw)) return false;
  try {
    const u = new URL(raw);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function detectEncodedEmailSegment(segment, decodeBase64UrlLoose, decodeFallback, isValidEmail) {
  const raw = String(segment || '').trim();
  if (!raw) return { isEmail: false, raw: '', decoded: '' };

  const b64Decoded = String(decodeBase64UrlLoose(raw) || '').trim();
  if (b64Decoded && isValidEmail(b64Decoded)) {
    return { isEmail: true, raw, decoded: b64Decoded, source: 'b64url' };
  }

  const fallbackDecoded = String(decodeFallback(raw) || '').trim();
  if (fallbackDecoded && fallbackDecoded !== raw && isValidEmail(fallbackDecoded)) {
    return { isEmail: true, raw, decoded: fallbackDecoded, source: 'fallback' };
  }

  if (isValidEmail(raw)) {
    return { isEmail: true, raw, decoded: raw, source: 'raw' };
  }

  return { isEmail: false, raw, decoded: '' };
}

function createRedirectPayloadResult(input) {
  const clean = String(input || '').replace(/^\/+/, '').split('?')[0].replace(/\/+$/g, '');
  return {
    matched: false,
    mode: 'invalid',
    input: clean,
    ciphertext: null,
    canonicalBaseString: null,
    email: null,
    emailPart: null,
    emailSegment: null,
    ignored: null,
    rawUrl: null,
    ambiguityDetected: false,
    matchedNewFormat: false,
    parseMode: 'invalid',
    ignoredSegment: null,
    normalizedBaseString: null
  };
}

function setRedirectPayloadMode(result, mode) {
  result.matched = true;
  result.mode = mode;
  result.parseMode = mode;
  return result;
}

function setRedirectPayloadIgnored(result, ignored) {
  result.ignored = String(ignored || '').replace(/^\/+|\/+$/g, '') || null;
  result.ignoredSegment = result.ignored;
  return result;
}

function setRedirectPayloadCanonical(result, ciphertext, emailPart, helpers) {
  result.ciphertext = ciphertext || null;
  result.emailPart = emailPart || null;
  if (result.emailPart) {
    const emailCandidate = detectEncodedEmailSegment(result.emailPart, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
    result.email = emailCandidate.isEmail ? emailCandidate.decoded : null;
    result.canonicalBaseString = result.ciphertext ? `${result.ciphertext}/${result.emailPart}` : null;
  } else {
    result.email = null;
    result.canonicalBaseString = result.ciphertext || null;
  }
  result.normalizedBaseString = result.canonicalBaseString;
  return result;
}

function finishFlexibleRedirectPayload(result, mode, ciphertext, emailPart, ignored, emailSegment, helpers) {
  setRedirectPayloadMode(result, mode);
  result.matchedNewFormat = true;
  result.emailSegment = emailSegment;
  setRedirectPayloadIgnored(result, ignored);
  setRedirectPayloadCanonical(result, ciphertext, emailPart, helpers);
  return result;
}

function joinCollapsedUrlParts(left, right) {
  const combined = `${String(left || '').trim()}/${String(right || '').trim()}`;
  const raw = combined.startsWith('url=') ? combined.slice(4) : combined;
  return /^https?:\/[^/]/i.test(raw) ? combined : '';
}

function joinCollapsedUrlSegments(parts) {
  const list = Array.isArray(parts) ? parts.filter(Boolean) : [];
  if (list.length < 2) return '';
  const head = joinCollapsedUrlParts(list[0], list[1]);
  if (!head) return '';
  return list.length === 2 ? head : `${head}/${list.slice(2).join('/')}`;
}


function looksLikeCiphertextSegment(segment) {
  const raw = String(segment || '').trim();
  if (raw.length < 40) return false;
  const base64UrlRegex = typeof RE_B64URL_PAYLOAD !== "undefined"
    ? RE_B64URL_PAYLOAD
    : /^[A-Za-z0-9_-]+(?:={0,2})?$/;
  return base64UrlRegex.test(raw);
}

function looksLikeRedirectPayloadSegment(segment, helpers) {
  if (looksLikeCiphertextSegment(segment)) return true;
  const decoded = String(helpers.decodeBase64UrlLoose(segment) || helpers.decodeFallback(segment) || '').trim();
  return looksLikeHttpUrl(decoded);
}

const createParseIgnoredUrlCipherPayload = require("../ignored-cipher/parseIgnoredUrlCipherPayload.js");
const parseIgnoredUrlCipherPayload = createParseIgnoredUrlCipherPayload({
  detectEncodedEmailSegment,
  findPreviousEmailDelimiter,
  finishFlexibleRedirectPayload,
  isPartialRawEmailDelimiterSplit,
  looksLikeCiphertextSegment,
  looksLikeHttpUrl,
  looksLikeRedirectPayloadSegment
});

function parseEmailFirstCipherPayload(result, clean, helpers) {
  const source = String(clean || '').replace(/^\/+|\/+$/g, '');
  const firstSlash = source.indexOf('/');
  if (firstSlash <= 0) return false;

  const emailRaw = source.slice(0, firstSlash);
  const ciphertext = source.slice(firstSlash + 1);
  if (!emailRaw || !ciphertext || ciphertext.includes('/')) return false;
  if (!looksLikeRedirectPayloadSegment(ciphertext, helpers)) return false;

  const emailCandidate = detectEncodedEmailSegment(emailRaw, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
  if (!emailCandidate.isEmail) return false;

  finishFlexibleRedirectPayload(
    result,
    'email_payload',
    ciphertext,
    emailCandidate.raw,
    null,
    'segment1',
    helpers
  );
  return true;
}


function isUnambiguousRawUrlEmailSuffix(rawUrlCandidate, wasEncodedPrefix = false, emailCandidate = null, delimiter = '') {
  if (!looksLikeHttpUrl(rawUrlCandidate)) return false;
  if (wasEncodedPrefix) {
    if (/[?#]/.test(rawUrlCandidate) && emailCandidate && emailCandidate.source === 'fallback' && getConfiguredEmailDelimiters().includes(delimiter)) return false;
    return true;
  }
  if (/[?#]/.test(rawUrlCandidate)) return false;
  try {
    const parsed = new URL(rawUrlCandidate);
    const origin = `${parsed.protocol}//${parsed.host}`;
    return rawUrlCandidate === origin || rawUrlCandidate.endsWith('/');
  } catch {
    return false;
  }
}

function isPartialRawEmailDelimiterSplit(source, delimiterMatch, emailRaw, helpers, options = {}) {
  if (!delimiterMatch || !emailRaw) return false;
  const previousDelimiter = findPreviousEmailDelimiter(source, delimiterMatch.index);
  if (!previousDelimiter) return false;
  const possibleLocalPrefix = String(source || '').slice(previousDelimiter.index + previousDelimiter.delimiter.length, delimiterMatch.index);
  if (!possibleLocalPrefix && (!options.allowEmptyLocalPrefix || delimiterMatch.delimiter === '//')) return false;
  if (/[/?#]/.test(possibleLocalPrefix)) return false;
  const combinedEmailRaw = `${possibleLocalPrefix}${delimiterMatch.delimiter}${emailRaw}`;
  const combinedEmail = detectEncodedEmailSegment(combinedEmailRaw, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
  return combinedEmail.isEmail;
}

function findRawUrlEmailSuffixSplit(source, helpers) {
  const input = String(source || '');
  let delimiterSearchEnd = input.length;
  while (delimiterSearchEnd > 0) {
    const delimiterSuffix = findPreviousEmailDelimiter(input, delimiterSearchEnd);
    if (!delimiterSuffix) break;
    const rawUrlCandidateRaw = input.slice(0, delimiterSuffix.index);
    const decodedRawUrlCandidate = String(helpers.decodeFallback(rawUrlCandidateRaw) || '').trim();
    const rawUrlCandidateWasDecoded = !!(decodedRawUrlCandidate && decodedRawUrlCandidate !== rawUrlCandidateRaw && !rawUrlCandidateRaw.includes('/'));
    const rawUrlCandidate = rawUrlCandidateWasDecoded
      ? decodedRawUrlCandidate
      : rawUrlCandidateRaw;
    const emailAndTail = input.slice(delimiterSuffix.index + delimiterSuffix.delimiter.length);
    const tailSlash = emailAndTail.indexOf('/');
    const emailCandidateRaw = tailSlash >= 0 ? emailAndTail.slice(0, tailSlash) : emailAndTail;
    const ignoredTail = tailSlash >= 0 ? emailAndTail.slice(tailSlash + 1) : '';
    const emailCandidate = detectEncodedEmailSegment(emailCandidateRaw, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
    if (emailCandidate.isEmail && isPartialRawEmailDelimiterSplit(input, delimiterSuffix, emailCandidateRaw, helpers)) {
      delimiterSearchEnd = delimiterSuffix.index;
      continue;
    }
    if (isUnambiguousRawUrlEmailSuffix(rawUrlCandidate, rawUrlCandidateWasDecoded, emailCandidate, delimiterSuffix.delimiter) && emailCandidate.isEmail) {
      return {
        rawUrl: rawUrlCandidate,
        remainder: `${delimiterSuffix.delimiter}${emailCandidate.raw}${ignoredTail ? `/${ignoredTail}` : ''}`
      };
    }
    delimiterSearchEnd = delimiterSuffix.index;
  }
  return null;
}

function splitRawUrlPayload(rawClean, helpers) {
  const decodedWhole = String(helpers.decodeFallback(rawClean) || '').trim();
  const rawSuffixSplit = findRawUrlEmailSuffixSplit(rawClean, helpers);
  if (rawSuffixSplit) return rawSuffixSplit;

  const normalizedInput =
    rawClean.indexOf('/') < 0 && decodedWhole && decodedWhole !== rawClean && looksLikeHttpUrl(decodedWhole)
      ? decodedWhole
      : rawClean;

  if (normalizedInput !== rawClean) {
    const normalizedSuffixSplit = findRawUrlEmailSuffixSplit(normalizedInput, helpers);
    if (normalizedSuffixSplit) return normalizedSuffixSplit;
  }

  let rawUrl = '';
  let remainder = '';
  const firstSlash = normalizedInput.indexOf('/');
  if (firstSlash > 0) {
    const firstSeg = normalizedInput.slice(0, firstSlash);
    const decodedFirst = String(helpers.decodeFallback(firstSeg) || '').trim();
    if (looksLikeHttpUrl(decodedFirst)) {
      rawUrl = decodedFirst;
      remainder = normalizedInput.slice(firstSlash + 1);
      if (normalizedInput[firstSlash + 1] === '/') remainder = `/${remainder}`;
    }
  }

  if (!rawUrl && /^https?:\/\//i.test(normalizedInput)) {
    const from = normalizedInput.startsWith('https://') ? 8 : 7;
    const markerScope = normalizedInput.split(/[?#]/, 1)[0];
    const idxHttps = markerScope.indexOf('/https://', from);
    const idxHttp = markerScope.indexOf('/http://', from);
    const splitIdx = [idxHttps, idxHttp].filter(i => i > 0).sort((a, b) => a - b)[0] || -1;

    if (splitIdx > 0) {
      rawUrl = normalizedInput.slice(0, splitIdx);
      remainder = normalizedInput.slice(splitIdx + 1);
    } else {
      try {
        const u = new URL(normalizedInput);
        const origin = `${u.protocol}//${u.host}`;
        const tail = `${u.pathname || ''}${u.search || ''}${u.hash || ''}`;
        if (getConfiguredEmailDelimiters().includes('//') && tail.startsWith('//')) {
          rawUrl = origin;
          remainder = tail;
        } else if (/^\/https?:/i.test(tail)) {
          rawUrl = origin;
          remainder = tail.replace(/^\/+/, '');
        } else {
          rawUrl = normalizedInput;
          remainder = '';
        }
      } catch {
        rawUrl = normalizedInput;
        remainder = '';
      }
    }
  }

  return rawUrl && looksLikeHttpUrl(rawUrl) ? { rawUrl, remainder } : null;
}

function splitRawUrlRemainder(remainder, helpers) {
  const rawRemainder = String(remainder || '');
  let emailPart = '';
  let ignored = '';

  const firstDelimiter = findNextEmailDelimiter(rawRemainder, 0);
  if (firstDelimiter && firstDelimiter.index === 0) {
    const afterDelimiter = rawRemainder.slice(firstDelimiter.delimiter.length);
    const slash = afterDelimiter.indexOf('/');
    const emailRaw = slash >= 0 ? afterDelimiter.slice(0, slash) : afterDelimiter;
    const trailingIgnored = slash >= 0 ? afterDelimiter.slice(slash + 1) : '';
    const emailCandidate = detectEncodedEmailSegment(emailRaw, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
    if (emailCandidate.isEmail) {
      return { emailPart: emailCandidate.raw, ignored: trailingIgnored };
    }
    return { emailPart: '', ignored: rawRemainder };
  }

  let searchEnd = rawRemainder.length;
  while (searchEnd > 0) {
    const match = findPreviousEmailDelimiter(rawRemainder, searchEnd);
    if (!match || match.index <= 0) break;
    const candidateEmail = rawRemainder.slice(match.index + match.delimiter.length);
    if (!candidateEmail || candidateEmail.includes('/')) { searchEnd = match.index; continue; }
    const emailCandidate = detectEncodedEmailSegment(candidateEmail, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
    if (!emailCandidate.isEmail) { searchEnd = match.index; continue; }
    emailPart = emailCandidate.raw;
    ignored = rawRemainder.slice(0, match.index);
    break;
  }
  if (!emailPart) ignored = rawRemainder;
  return { emailPart, ignored };
}

function parseRawUrlRedirectPayload(result, rawClean, helpers) {
  const split = splitRawUrlPayload(rawClean, helpers);
  if (!split) return false;
  const suffix = splitRawUrlRemainder(split.remainder, helpers);
  setRedirectPayloadMode(result, 'raw_url');
  result.rawUrl = split.rawUrl;
  result.emailPart = suffix.emailPart || null;
  if (result.emailPart) {
    result.email = detectEncodedEmailSegment(result.emailPart, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail).decoded || null;
  }
  setRedirectPayloadIgnored(result, suffix.ignored);
  return true;
}

function parseDelimitedCipherEmailPayload(result, clean, helpers) {
  const rhsDecodesToEmail = (rhs) => detectEncodedEmailSegment(rhs, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
  let delimiterSearchEnd = clean.length;
  while (delimiterSearchEnd > 0) {
    const match = findPreviousEmailDelimiter(clean, delimiterSearchEnd);
    if (!match) break;
    const lhs = clean.slice(0, match.index);
    const rhs = clean.slice(match.index + match.delimiter.length);
    const emailCandidate = rhsDecodesToEmail(rhs);
    if (emailCandidate.isEmail && !lhs.includes('/')) {
      const previousDelimiter = findPreviousEmailDelimiter(clean, match.index);
      const delimiterBeforePrevious = previousDelimiter ? findPreviousEmailDelimiter(clean, previousDelimiter.index) : null;
      const possibleLocalPrefix = previousDelimiter
        ? clean.slice(previousDelimiter.index + previousDelimiter.delimiter.length, match.index)
        : '';
      const rawEmailDelimiterIsLeading = previousDelimiter && match.index === previousDelimiter.index + previousDelimiter.delimiter.length;
      const rawEmailRepeatedDelimiterLooksNested =
        previousDelimiter &&
        previousDelimiter.delimiter === match.delimiter &&
        delimiterBeforePrevious &&
        delimiterBeforePrevious.delimiter !== match.delimiter;
      const rawEmailDifferentDelimiterLooksNested =
        previousDelimiter &&
        previousDelimiter.delimiter !== match.delimiter &&
        (
          rawEmailDelimiterIsLeading ||
          match.delimiter === '--' ||
          match.delimiter === '~~' ||
          (previousDelimiter.delimiter.length >= 2 && /[a-z.]/.test(possibleLocalPrefix))
        );
      const rawEmailDelimiterLooksNested = previousDelimiter && (
        rawEmailRepeatedDelimiterLooksNested ||
        rawEmailDifferentDelimiterLooksNested
      );
      const shouldCheckPartialEmailSplit =
        rawEmailDelimiterLooksNested &&
        (emailCandidate.source === 'fallback' || emailCandidate.source === 'raw');
      if (shouldCheckPartialEmailSplit && isPartialRawEmailDelimiterSplit(clean, match, rhs, helpers, { allowEmptyLocalPrefix: rawEmailDelimiterIsLeading })) {
        delimiterSearchEnd = match.index;
        continue;
      }
      setRedirectPayloadMode(result, 'delimited');
      setRedirectPayloadCanonical(result, lhs, rhs, helpers);
      return true;
    }
    delimiterSearchEnd = match.index;
  }

  const j = clean.lastIndexOf('/');
  if (j > 0) {
    const lhs = clean.slice(0, j);
    const rhs = clean.slice(j + 1);
    const emailCandidate = rhsDecodesToEmail(rhs);
    if (emailCandidate.isEmail && !lhs.includes('/')) {
      setRedirectPayloadMode(result, 'delimited');
      setRedirectPayloadCanonical(result, lhs, rhs, helpers);
      return true;
    }
  }
  return false;
}

const createParseFlexibleRedirectPayload = require("../flexible-redirect/parseFlexibleRedirectPayload.js");
const parseFlexibleRedirectPayload = createParseFlexibleRedirectPayload({
  detectEncodedEmailSegment,
  findNextEmailDelimiter,
  findPreviousEmailDelimiter,
  finishFlexibleRedirectPayload,
  isPartialRawEmailDelimiterSplit,
  joinCollapsedUrlSegments,
  looksLikeRedirectPayloadSegment,
  setRedirectPayloadMode
});

function normalizeRedirectPayloadHelpers(helpers = {}) {
  return {
    decodeBase64UrlLoose: helpers.decodeBase64UrlLoose || (() => ''),
    decodeFallback: helpers.decodeFallback || (() => ''),
    isValidEmail: helpers.isValidEmail || (() => false)
  };
}


function hasConfiguredEmailDelimiter(value) {
  return !!findNextEmailDelimiter(value, 0);
}

function hasValidIgnoredPrefixEmailDelimiter(clean, helpers) {
  const source = String(clean || '');
  let searchFrom = 0;
  while (searchFrom < source.length) {
    const match = findNextEmailDelimiter(source, searchFrom);
    if (!match) break;
    const i = match.index;
    const delimiter = match.delimiter;

    const lhs = source.slice(0, i);
    const rhs = source.slice(i + delimiter.length);
    const suffixPayloadSlash = lhs.lastIndexOf('/');
    if (suffixPayloadSlash > 0) {
      const payloadPart = lhs.slice(suffixPayloadSlash + 1);
      const suffixEmail = detectEncodedEmailSegment(rhs, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
      if (!rhs.includes('/') && suffixEmail.isEmail && looksLikeRedirectPayloadSegment(payloadPart, helpers)) return true;
    }

    const firstRhsSlash = rhs.indexOf('/');
    if (firstRhsSlash > 0) {
      const emailRaw = rhs.slice(0, firstRhsSlash);
      const payloadPart = rhs.slice(firstRhsSlash + 1);
      const firstEmail = detectEncodedEmailSegment(emailRaw, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
      if (!payloadPart.includes('/') && firstEmail.isEmail && looksLikeRedirectPayloadSegment(payloadPart, helpers)) return true;
    }
    searchFrom = i + delimiter.length;
  }
  return false;
}

function rawUrlHostIsAllowlistedDestination(raw) {
  if (typeof ALLOWLIST_DOMAINS === "undefined" || typeof isHostAllowlisted !== "function") return false;
  try {
    const parsed = new URL(String(raw || ""));
    return isHostAllowlisted(parsed.hostname);
  } catch {
    return false;
  }
}

function redirectPayloadSegmentDecrypts(segment) {
  if (typeof tryDecryptAny !== "function") return false;
  try {
    const decrypted = tryDecryptAny(segment);
    return !!(decrypted && decrypted.url);
  } catch {
    return false;
  }
}

function parseDecryptableIgnoredUrlPrefixPayload(result, clean, helpers) {
  const source = String(clean || "");
  const candidates = [source];
  const addCandidate = (candidate) => {
    if (candidate && !candidates.includes(candidate)) candidates.push(candidate);
  };
  if (/^https?:\/\//i.test(source)) {
    const hashIndex = source.indexOf("#");
    if (hashIndex >= 0) addCandidate(source.slice(0, hashIndex));
  } else {
    const firstSlash = source.indexOf("/");
    if (firstSlash > 0) {
      const firstSegment = source.slice(0, firstSlash);
      const decodedFirst = String(helpers.decodeFallback(firstSegment) || "").trim();
      if (looksLikeHttpUrl(decodedFirst)) {
        const suffix = source.slice(firstSlash + 1);
        const encodedHashIndex = suffix.search(/%23/i);
        if (encodedHashIndex >= 0) addCandidate(source.slice(0, firstSlash + 1 + encodedHashIndex));
        const rawHashIndex = suffix.indexOf("#");
        if (rawHashIndex >= 0) addCandidate(source.slice(0, firstSlash + 1 + rawHashIndex));
      }
    }
  }

  for (const candidateSource of candidates) {
    const candidate = createRedirectPayloadResult(candidateSource);
    if (!parseIgnoredUrlCipherPayload(candidate, candidate.input, helpers)) continue;
    const parseMode = String(candidate.parseMode || "");
    if (!parseMode.startsWith("ignored_url_")) continue;
    if (!redirectPayloadSegmentDecrypts(candidate.ciphertext)) continue;
    Object.assign(result, candidate);
    return true;
  }
  return false;
}

function shouldPreserveRawHttpUrlBeforeIgnoredPrefix(clean, helpers) {
  const raw = String(clean || '');
  if (!/^https?:\/\//i.test(raw)) return false;
  try {
    const parsed = new URL(raw);
    if (parsed.search) return true;
    const pathSegments = String(parsed.pathname || '').split('/').filter(Boolean);
    const lastSegment = pathSegments[pathSegments.length - 1] || '';
    if (pathSegments.length >= 1 && lastSegment.length >= 48 && looksLikeRedirectPayloadSegment(lastSegment, helpers)) {
      if (redirectPayloadSegmentDecrypts(lastSegment)) return false;
      return rawUrlHostIsAllowlistedDestination(raw);
    }
  } catch {}
  return !hasConfiguredEmailDelimiter(raw) || !hasValidIgnoredPrefixEmailDelimiter(raw, helpers);
}

function shouldPreserveEncodedRawUrlBeforeIgnoredPrefix(clean, helpers) {
  const raw = String(clean || '');
  const firstSlash = raw.indexOf('/');
  if (firstSlash <= 0) return false;
  const decodedFirst = String(helpers.decodeFallback(raw.slice(0, firstSlash)) || '').trim();
  return looksLikeHttpUrl(decodedFirst);
}

function parseRedirectPayload(input, helpers = {}) {
  const normalizedHelpers = normalizeRedirectPayloadHelpers(helpers);
  const rawInput = String(input || '');
  const rawClean = rawInput.replace(/^\/+/, '');
  const result = createRedirectPayloadResult(input);
  const clean = result.input;

  if (!clean) return result;
  if (parseEmailFirstCipherPayload(result, clean, normalizedHelpers)) return result;
  if (parseDecryptableIgnoredUrlPrefixPayload(result, clean, normalizedHelpers)) return result;
  if (rawClean !== clean && /^https?:\/\//i.test(rawClean)) {
    try {
      const parsedRaw = new URL(rawClean);
      const rawPathSegments = String(parsedRaw.pathname || '').split('/').filter(Boolean);
      const lastRawSegment = rawPathSegments[rawPathSegments.length - 1] || '';
      if (parsedRaw.search && !redirectPayloadSegmentDecrypts(lastRawSegment) && parseRawUrlRedirectPayload(result, rawClean, normalizedHelpers)) return result;
    } catch {}
  }
  if (shouldPreserveRawHttpUrlBeforeIgnoredPrefix(clean, normalizedHelpers) && parseRawUrlRedirectPayload(result, rawClean, normalizedHelpers)) return result;
  if (shouldPreserveEncodedRawUrlBeforeIgnoredPrefix(clean, normalizedHelpers) && parseRawUrlRedirectPayload(result, rawClean, normalizedHelpers)) return result;
  if (parseIgnoredUrlCipherPayload(result, clean, normalizedHelpers)) return result;
  if (parseRawUrlRedirectPayload(result, rawClean, normalizedHelpers)) return result;
  if (parseDelimitedCipherEmailPayload(result, clean, normalizedHelpers)) return result;
  if (parseFlexibleRedirectPayload(result, clean, normalizedHelpers)) return result;

  setRedirectPayloadMode(result, 'ciphertext');
  setRedirectPayloadCanonical(result, clean, null, normalizedHelpers);
  return result;
}
// ================== REQUEST VALIDATION MIDDLEWARE ==================
function getRedirectPayloadLimit() {
  return typeof MAX_REDIRECT_PAYLOAD_LENGTH !== "undefined" ? MAX_REDIRECT_PAYLOAD_LENGTH : 8192;
}

function getRedirectTotalPathLimit() {
  return typeof MAX_REDIRECT_URL_PATH_LENGTH !== "undefined" ? MAX_REDIRECT_URL_PATH_LENGTH : 16384;
}

function getRedirectOversizeMode() {
  return typeof REDIRECT_PAYLOAD_OVERSIZE_MODE !== "undefined" ? REDIRECT_PAYLOAD_OVERSIZE_MODE : "log";
}

function getMaxBruteSplitPayloadLength() {
  return typeof MAX_BRUTE_SPLIT_PAYLOAD_LENGTH !== "undefined" ? MAX_BRUTE_SPLIT_PAYLOAD_LENGTH : getRedirectTotalPathLimit();
}

function shouldBlockOversizedRedirectPayload() {
  return ["block", "enforce", "reject", "1", "true"].includes(getRedirectOversizeMode());
}

function getRedirectPayloadMeasuredLength(parsedPayload, fallbackValue = "") {
  if (parsedPayload && typeof parsedPayload.ciphertext === "string" && parsedPayload.ciphertext) {
    return { length: parsedPayload.ciphertext.length, kind: "ciphertext" };
  }
  if (parsedPayload && typeof parsedPayload.rawUrl === "string" && parsedPayload.rawUrl) {
    return { length: parsedPayload.rawUrl.length, kind: "raw_url" };
  }
  if (parsedPayload && typeof parsedPayload.canonicalBaseString === "string" && parsedPayload.canonicalBaseString) {
    return { length: parsedPayload.canonicalBaseString.length, kind: "canonical" };
  }
  return { length: String(fallbackValue || "").length, kind: "path" };
}

function evaluateRedirectPayloadSize(parsedPayload, fallbackValue = "") {
  const totalPathLength = String(fallbackValue || "").length;
  const measured = getRedirectPayloadMeasuredLength(parsedPayload, fallbackValue);
  const payloadLimit = getRedirectPayloadLimit();
  const totalPathLimit = getRedirectTotalPathLimit();
  const overPayloadLimit = measured.length > payloadLimit;
  const overTotalPathLimit = totalPathLength > totalPathLimit;
  const shouldBlock = overTotalPathLimit || (overPayloadLimit && shouldBlockOversizedRedirectPayload());
  return {
    ok: !shouldBlock,
    shouldBlock,
    overPayloadLimit,
    overTotalPathLimit,
    measuredLength: measured.length,
    measuredKind: measured.kind,
    totalPathLength,
    payloadLimit,
    totalPathLimit,
    mode: getRedirectOversizeMode()
  };
}

function maybeLogRedirectPayloadSizeDecision(req, decision, context = "redirect") {
  if (!decision || (!decision.overPayloadLimit && !decision.overTotalPathLimit)) return;
  const ip = req ? getClientIp(req) : "unknown";
  const shouldLog = aggregatePerIpEvent("PAYLOAD-SIZE", {
    ip,
    reason: decision.shouldBlock ? "oversize_block" : "oversize_log",
    suppressFirst: false
  });
  if (!shouldLog) return;
  addLog(`[PAYLOAD-SIZE] action=${decision.shouldBlock ? "block" : "log"} context=${safeLogValue(context, 32)} ip=${safeLogValue(ip, 64)} kind=${safeLogValue(decision.measuredKind, 24)} len=${decision.measuredLength} totalPathLen=${decision.totalPathLength} limit=${decision.payloadLimit} totalLimit=${decision.totalPathLimit} mode=${safeLogValue(decision.mode, 16)}`);
}

function isValidRedirectPayloadInput(input) {
  if (!input || typeof input !== "string") return false;
  if (input.length > getRedirectTotalPathLimit()) return false;

  const clean = input.split("?")[0];
  if (clean.length > getRedirectTotalPathLimit()) return false;
  // Prefer canonical module-level regexes and only fall back to local literals
  // in isolated execution contexts (e.g., VM snippets).
  const base64UrlRegex = typeof RE_B64URL_PAYLOAD !== "undefined"
    ? RE_B64URL_PAYLOAD
    : /^[A-Za-z0-9_-]+(?:={0,2})?$/;
  const controlCharsRegex = typeof RE_CONTROL_CHARS !== "undefined"
    ? RE_CONTROL_CHARS
    : /[\x00-\x20\x7F]/;

  if (clean.length < 10) return false;
  if (controlCharsRegex.test(clean)) return false;

  const parsed = parseRedirectPayload(clean, {
    decodeBase64UrlLoose: decodeB64urlLoose,
    decodeFallback: safeDecode,
    isValidEmail: isLikelyEmail
  });

  const sizeDecision = evaluateRedirectPayloadSize(parsed, clean);
  if (!sizeDecision.ok) return false;

  if (parsed.rawUrl) return true;
  if (!parsed.ciphertext || !base64UrlRegex.test(parsed.ciphertext)) return false;
  if (parsed.ambiguityDetected) return false;
  if (!parsed.emailPart) return true;

  return !!parsed.email;
}

// Backward-compatible alias used by existing VM-based tests. New code should use
// isValidRedirectPayloadInput because raw URL payloads are also accepted.
const validateBase64Url = isValidRedirectPayloadInput;

function isObviouslyNotPayloadPath(candidate) {
  const candidateLower = String(candidate || "").toLowerCase().replace(/^\/+/, "");
  return candidateLower.includes(".php") ||
    candidateLower.includes(".asp") ||
    candidateLower.includes(".jsp") ||
    candidateLower.includes(".env") ||
    candidateLower.includes("..") ||
    SCANNER_PROBE_PREFIXES.some(p => candidateLower.startsWith(p));
}

function validateRRouteParams(req, errors) {
  const baseString = safeDecode(String(req.query.d || req.params.data || ""));

  if (!baseString) {
    errors.push("Missing required parameter: d");
  } else if (!isValidRedirectPayloadInput(baseString)) {
    errors.push("Invalid data format: must be valid base64url");

    if (baseString.length > 1000) {
      addLog(`[VALIDATION] Oversized payload ip=${safeLogValue(getClientIp(req))} len=${baseString.length}`);
    }
  }
}

function validateSuspiciousQueryParams(req, errors) {
  const suspiciousParams = ["javascript:", "data:", "vbscript:", "alert("];
  for (const [key, value] of Object.entries(req.query || {})) {
    if (typeof value !== "string") continue;
    for (const suspicious of suspiciousParams) {
      if (value.toLowerCase().includes(suspicious)) {
        errors.push(`Suspicious value in parameter ${key}`);
        break;
      }
    }
  }
}

function validateCatchAllRedirectPath(req, errors) {
  if (req.path === "/" || pathMatchesWithOptionalPrefix(req.path, "/r") || req.path.startsWith("/e/")) return;
  const candidateRaw = String((req.originalUrl || "").slice(1).split("?")[0] || "");
  const { payloadPath: candidate } = stripOptionalUrlPrefix(candidateRaw);

  if (!candidate || isObviouslyNotPayloadPath(candidate) || !isValidRedirectPayloadInput(candidate)) {
    errors.push("Invalid catch-all path: expected encoded redirect payload");
  }
}

function validateRedirectParams(req) {
  const errors = [];

  if (pathMatchesWithOptionalPrefix(req.path, "/r")) {
    validateRRouteParams(req, errors);
  }

  validateSuspiciousQueryParams(req, errors);
  validateCatchAllRedirectPath(req, errors);

  return errors;
}

function validateRedirectRequest(req, res, next) {
  const exactSkipPaths = [
    "/health", "/healthz", "/readyz", "/livez", "/geo-debug",
    "/favicon.ico", "/robots.txt", "/.well-known/security.txt", "/turnstile-sitekey", "/__hp.gif",
    "/decrypt-challenge-data", "/view-log-live",
    "/about", "/services", "/docs", "/status", "/contact",
    "/sitemap.xml", "/api/v1/status"
  ];
  const optionalExactSkipPaths = [
    "/health", "/healthz", "/readyz", "/livez", "/decrypt-challenge-data"
  ];
  const prefixedSkipPaths = [
    "/view-log", "/stream-log", "/admin", "/__debug", "/_debug",
    "/challenge", "/challenge-fragment", "/ts-client-log", "/interstitial-human"
  ];

  if (
    exactSkipPaths.some(path => pathMatchesExactRoute(req.path, path)) ||
    optionalExactSkipPaths.some(path => pathMatchesExactRoute(req.path, path, { allowOptionalPrefix: true })) ||
    prefixedSkipPaths.some(path => pathMatchesWithOptionalPrefix(req.path, path))
  ) {
    return next();
  }

  if (hasInterstitialBypass(req)) {
    return next();
  }

  const errors = validateRedirectParams(req);
  if (errors.length > 0) {
    const ip = getClientIp(req);
    const ua = req.get("user-agent") || "";
    const onlyCatchAllValidationError =
      errors.length === 1 && errors[0] === "Invalid catch-all path: expected encoded redirect payload";

    if (onlyCatchAllValidationError) {
      const scannerLikeCatchAllPath = isLikelyScannerProbePath(req.path);
      const crawlerLikeCatchAllPath = isLikelyCrawlerProbePath(req.path) || isLikelyLocaleOnlyProbePath(req.path);
      maybeDenyForVisibleIpReputation(req, ip, scannerLikeCatchAllPath || crawlerLikeCatchAllPath ? "invalid_scanner_path" : "invalid_catch_all", {
        detail: safeLogValue(req.path, 80),
        weight: scannerLikeCatchAllPath || crawlerLikeCatchAllPath ? VISIBLE_IP_REPUTATION_WEIGHTS.invalid_scanner_path : VISIBLE_IP_REPUTATION_WEIGHTS.invalid_catch_all
      });
      // Expected behavior for noisy scanner paths: suppress per-request logs
      // and rely on periodic [AGG:VALIDATION-FAILED] summary lines per IP.
      const shouldLog = aggregatePerIpEvent("VALIDATION-FAILED", {
        ip,
        reason: "invalid_catch_all_path",
        // Suppress first-hit logs for scanner-like catch-all probes only; keep
        // first-hit visibility for non-scanner client mistakes.
        suppressFirst: scannerLikeCatchAllPath || crawlerLikeCatchAllPath
      });

      if (shouldLog) {
        addLog(`[VALIDATION-FAILED] ip=${safeLogValue(ip)} path=${req.path} errors=${errors.join(", ")} ua="${safeLogValue(ua.slice(0, 100))}"`);
      }
    } else {
      addLog(`[VALIDATION-FAILED] ip=${safeLogValue(ip)} path=${req.path} errors=${errors.join(", ")} ua="${safeLogValue(ua.slice(0, 100))}"`);
    }

    if (errors.some(e => e.includes("Suspicious"))) {
      addStrike(ip, 2);
    }

    const sendValidationError = () => {
      if (pathMatchesWithOptionalPrefix(req.path, "/r", { allowChildren: false }) && !req.query.d) {
        return res.status(400).send("Missing required parameter: d");
      }
      if (errors.some(e => e.includes("Invalid catch-all path"))) {
        return res.status(404).send("Not Found");
      }
      return res.status(400).send("Invalid request");
    };

    if (pathMatchesWithOptionalPrefix(req.path, "/r")) {
      return validationFailureLimiter(req, res, sendValidationError);
    }

    return sendValidationError();
  }

  next();
}


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

// ================== LOGGING SYSTEM ==================
const LOG_TO_FILE   = process.env.LOG_TO_FILE === "1";
const LOG_FILE      = process.env.LOG_FILE || path.join(process.cwd(), "visitors.log");
const LOG_FILE_MAX_BYTES = readPositiveIntEnv("LOG_FILE_MAX_BYTES", 50 * 1024 * 1024);
const LOG_FILE_MAX_FILES = Math.min(100, readPositiveIntEnv("LOG_FILE_MAX_FILES", 5));
const MAX_LOG_LINES = readPositiveIntEnv("MAX_LOG_LINES", 2000);
const BACKLOG_ON_CONNECT = parseInt(process.env.BACKLOG_ON_CONNECT || "200", 10);
const RUNTIME_DIAG_DIR = process.env.RUNTIME_DIAG_DIR || process.env.LOG_DIR || path.join(process.cwd(), "runtime-diagnostics");
const RUNTIME_INCIDENT_FILE = process.env.RUNTIME_INCIDENT_FILE || path.join(RUNTIME_DIAG_DIR, "incidents.ndjson");
const NPM_DEBUG_LOG_DIR = process.env.NPM_CONFIG_LOGS_DIR || path.join(os.homedir(), ".npm", "_logs");
const RUNTIME_INCIDENT_HISTORY_LIMIT = Math.max(1, parseInt(process.env.RUNTIME_INCIDENT_HISTORY_LIMIT || "25", 10));
const RUNTIME_INCIDENT_NPM_LOG_LIMIT = Math.max(0, parseInt(process.env.RUNTIME_INCIDENT_NPM_LOG_LIMIT || "5", 10));
const RUNTIME_INCIDENT_READ_MAX_BYTES = Math.max(64 * 1024, parseInt(process.env.RUNTIME_INCIDENT_READ_MAX_BYTES || String(1024 * 1024), 10));
const RAILWAY_RUNTIME_ENV_KEYS = [
  "RAILWAY_DEPLOYMENT_ID",
  "RAILWAY_REPLICA_ID",
  "RAILWAY_REPLICA_REGION",
  "RAILWAY_SERVICE_ID",
  "RAILWAY_SERVICE_NAME",
  "RAILWAY_ENVIRONMENT_ID",
  "RAILWAY_ENVIRONMENT_NAME",
  "RAILWAY_PROJECT_ID",
  "RAILWAY_PROJECT_NAME",
  "RAILWAY_SNAPSHOT_ID",
  "RAILWAY_VOLUME_NAME",
  "RAILWAY_VOLUME_MOUNT_PATH",
  "RAILWAY_GIT_COMMIT_SHA",
  "RAILWAY_GIT_BRANCH",
  "RAILWAY_GIT_REPO_NAME",
  "RAILWAY_GIT_REPO_OWNER",
  "RAILWAY_DEPLOYMENT_OVERLAP_SECONDS",
  "RAILWAY_DEPLOYMENT_DRAINING_SECONDS"
];

function getRailwayRuntimeMetadata() {
  const out = {};
  for (const key of RAILWAY_RUNTIME_ENV_KEYS) {
    const value = process.env[key];
    if (value != null && value !== "") out[key] = safeLogValue(value, 160);
  }
  return out;
}

function formatRailwayRuntimeLine(metadata = getRailwayRuntimeMetadata()) {
  const entries = Object.entries(metadata);
  if (!entries.length) return "[RAILWAY] runtime metadata unavailable (not running on Railway or env vars not injected)";
  return `[RAILWAY] ${entries.map(([key, value]) => `${key}=${value}`).join(" ")}`;
}

function getRuntimeCorrelationMetadata() {
  const railway = getRailwayRuntimeMetadata();
  return {
    bootId: runtimeStats.bootId,
    deploymentId: railway.RAILWAY_DEPLOYMENT_ID || null,
    replicaId: railway.RAILWAY_REPLICA_ID || null,
    serviceId: railway.RAILWAY_SERVICE_ID || null,
    gitCommitSha: railway.RAILWAY_GIT_COMMIT_SHA || null
  };
}

function formatRuntimeCorrelationSuffix() {
  const ctx = getRuntimeCorrelationMetadata();
  return [
    `bootId=${ctx.bootId}`,
    ctx.deploymentId ? `deploymentId=${ctx.deploymentId}` : null,
    ctx.replicaId ? `replicaId=${ctx.replicaId}` : null,
    ctx.serviceId ? `serviceId=${ctx.serviceId}` : null,
    ctx.gitCommitSha ? `gitCommit=${String(ctx.gitCommitSha).slice(0, 12)}` : null
  ].filter(Boolean).join(" ");
}

const LOGS = [];
const LOG_IDS = [];
let LOG_SEQ = 0;
const LOG_LISTENERS = new Set();
let logFileWriteErrorAt = 0;
let logFileDropWarnAt = 0;
const LOG_FILE_QUEUE_MAX_LINES = Math.max(500, parseInt(process.env.LOG_FILE_QUEUE_MAX_LINES || "5000", 10));
const LOG_FILE_QUEUE_MAX_BYTES = Math.max(256 * 1024, parseInt(process.env.LOG_FILE_QUEUE_MAX_BYTES || String(2 * 1024 * 1024), 10));
let logFileStream = null;
let logFileQueue = [];
let logFileQueueBytes = 0;
let logFileDrainPending = false;
let logFileDroppedLines = 0;
let logFileWriterClosed = false;
let logFileClosePromise = null;
let logFileRetryAt = 0;
let logFileLastError = null;
let logFileLastOpenedAt = null;
let logFileBytes = 0;
let logFileRotationPending = false;
let logFileRotationPromise = null;
let logFileRotations = 0;
const LOG_FILE_RETRY_DELAY_MS = Math.max(250, parseInt(process.env.LOG_FILE_RETRY_DELAY_MS || "1000", 10));

const OPEN_SOCKETS_WARN_THRESHOLD = Math.max(50, parseInt(process.env.OPEN_SOCKETS_WARN_THRESHOLD || "400", 10));
const SSE_LISTENERS_WARN_THRESHOLD = Math.max(10, parseInt(process.env.SSE_LISTENERS_WARN_THRESHOLD || "120", 10));
const LOG_FILE_QUEUE_WARN_BYTES = Math.max(128 * 1024, parseInt(process.env.LOG_FILE_QUEUE_WARN_BYTES || String(1024 * 1024), 10));
let lastRuntimeGaugeAlertAt = 0;

function getRuntimeResourceGauges() {
  return {
    openSockets: typeof openSockets === "object" && openSockets ? openSockets.size : 0,
    sseListeners: LOG_LISTENERS.size,
    logFileQueueLines: logFileQueue.length,
    logFileQueueBytes,
    logFileDroppedLines,
    logFileDrainPending,
    logFileStreamReady: Boolean(logFileStream),
    logFilePath: LOG_FILE,
    logFileBytes,
    logFileMaxBytes: LOG_FILE_MAX_BYTES,
    logFileRotationEnabled: LOG_TO_FILE,
    logFileRotationPending,
    logFileRotations,
    logFileLastOpenedAt,
    logFileLastError
  };
}

function maybeEmitRuntimeGaugeAlerts(now = Date.now()) {
  if ((now - lastRuntimeGaugeAlertAt) < 60000) return;
  const gauges = getRuntimeResourceGauges();
  const alerts = [];

  if (gauges.openSockets >= OPEN_SOCKETS_WARN_THRESHOLD) {
    alerts.push(`openSockets=${gauges.openSockets}>=${OPEN_SOCKETS_WARN_THRESHOLD}`);
  }
  if (gauges.sseListeners >= SSE_LISTENERS_WARN_THRESHOLD) {
    alerts.push(`sseListeners=${gauges.sseListeners}>=${SSE_LISTENERS_WARN_THRESHOLD}`);
  }
  if (gauges.logFileQueueBytes >= LOG_FILE_QUEUE_WARN_BYTES) {
    alerts.push(`logQueueBytes=${gauges.logFileQueueBytes}>=${LOG_FILE_QUEUE_WARN_BYTES}`);
  }
  if (gauges.logFileDroppedLines > 0) {
    alerts.push(`droppedLogLines=${gauges.logFileDroppedLines}`);
  }

  if (!alerts.length) return;
  lastRuntimeGaugeAlertAt = now;
  addLog(`[ALERT:RUNTIME] ${alerts.join(" ")} queueLines=${gauges.logFileQueueLines} drainPending=${gauges.logFileDrainPending}`);
  addSpacer();
}

function ensureParentDirectoryForFile(filePath, label) {
  const dir = path.dirname(filePath);
  if (!dir || dir === ".") return true;

  try {
    fs.mkdirSync(dir, { recursive: true });
    return true;
  } catch (err) {
    const message = summarizeError(err);
    if (label === "log") {
      logFileLastError = { at: new Date().toISOString(), message };
    }
    console.error(`[${String(label || "file").toUpperCase()}] unable to create parent dir=${dir} file=${filePath} err=${safeLogValue(message, 180)}`);
    return false;
  }
}

function pruneLogArchives(filePath = LOG_FILE, maxFiles = LOG_FILE_MAX_FILES) {
  const directory = path.dirname(filePath);
  const baseName = path.basename(filePath);
  const prefix = `${baseName}.`;

  let entries;
  try {
    entries = fs.readdirSync(directory);
  } catch (_) {
    return;
  }

  for (const entry of entries) {
    if (!entry.startsWith(prefix)) continue;
    const suffix = entry.slice(prefix.length);
    if (!/^\d+$/.test(suffix) || Number(suffix) <= maxFiles) continue;
    fs.rmSync(path.join(directory, entry), { force: true });
  }
}

function rotateLogFiles(filePath = LOG_FILE, maxFiles = LOG_FILE_MAX_FILES) {
  pruneLogArchives(filePath, maxFiles);
  if (!fs.existsSync(filePath)) return;

  fs.rmSync(`${filePath}.${maxFiles}`, { force: true });

  for (let index = maxFiles - 1; index >= 1; index -= 1) {
    const source = `${filePath}.${index}`;
    if (!fs.existsSync(source)) continue;
    fs.renameSync(source, `${filePath}.${index + 1}`);
  }

  fs.renameSync(filePath, `${filePath}.1`);
}

function appendLogChunksSync(chunks, filePath = LOG_FILE, maxBytes = LOG_FILE_MAX_BYTES, maxFiles = LOG_FILE_MAX_FILES) {
  if (!Array.isArray(chunks) || chunks.length === 0) return 0;
  ensureParentDirectoryForFile(filePath, "log");

  let existing = fs.existsSync(filePath) ? fs.statSync(filePath) : null;
  let size = existing && existing.isFile() ? existing.size : 0;
  if (size >= maxBytes) {
    rotateLogFiles(filePath, maxFiles);
    size = 0;
  }

  for (const rawChunk of chunks) {
    const chunk = String(rawChunk || "");
    if (!chunk) continue;
    const chunkBytes = Buffer.byteLength(chunk, "utf8");

    if (size > 0 && size + chunkBytes > maxBytes) {
      rotateLogFiles(filePath, maxFiles);
      size = 0;
    }

    fs.appendFileSync(filePath, chunk, "utf8");
    size += chunkBytes;

    if (size >= maxBytes) {
      rotateLogFiles(filePath, maxFiles);
      size = 0;
    }
  }
  return size;
}

function rotateLogFileStream(streamToRotate) {
  if (!LOG_TO_FILE || logFileWriterClosed || logFileRotationPending) return logFileRotationPromise;
  logFileRotationPending = true;
  logFileDrainPending = false;
  if (logFileStream === streamToRotate) logFileStream = null;

  logFileRotationPromise = new Promise((resolve) => {
    let finished = false;
    const finishRotation = () => {
      if (finished) return;
      finished = true;
      try {
        rotateLogFiles();
        logFileBytes = 0;
        logFileRotations += 1;
      } catch (err) {
        logFileRetryAt = Date.now() + LOG_FILE_RETRY_DELAY_MS;
        logFileLastError = { at: new Date().toISOString(), message: summarizeError(err) };
        console.error(`[LOG] rotation failed file=${LOG_FILE} err=${safeLogValue(err && err.message ? err.message : err, 180)}`);
      } finally {
        logFileRotationPending = false;
        logFileRotationPromise = null;
        flushLogFileQueue();
        resolve();
      }
    };

    // The writable "finish" callback can run before fs.WriteStream closes its
    // descriptor. Rename only after "close" so rotation also works on Windows.
    streamToRotate.once("close", finishRotation);
    try {
      streamToRotate.end();
    } catch (_) {
      try { streamToRotate.destroy(); } catch {}
      if (streamToRotate.closed) finishRotation();
    }
  });
  return logFileRotationPromise;
}

function ensureLogFileStream() {
  if (!LOG_TO_FILE || logFileWriterClosed || logFileRotationPending) return null;
  if (logFileStream) return logFileStream;

  const now = Date.now();
  if (now < logFileRetryAt) return null;

  if (!ensureParentDirectoryForFile(LOG_FILE, "log")) {
    logFileRetryAt = now + LOG_FILE_RETRY_DELAY_MS;
    return null;
  }

  try {
    const existing = fs.existsSync(LOG_FILE) ? fs.statSync(LOG_FILE) : null;
    if (existing && existing.isFile() && existing.size >= LOG_FILE_MAX_BYTES) {
      rotateLogFiles();
      logFileRotations += 1;
      logFileBytes = 0;
    } else {
      logFileBytes = existing && existing.isFile() ? existing.size : 0;
    }
  } catch (err) {
    logFileRetryAt = now + LOG_FILE_RETRY_DELAY_MS;
    logFileLastError = { at: new Date(now).toISOString(), message: summarizeError(err) };
    return null;
  }

  const stream = fs.createWriteStream(LOG_FILE, { flags: "a" });
  logFileStream = stream;
  logFileLastOpenedAt = new Date().toISOString();
  logFileLastError = null;
  stream.on("error", (err) => {
    const errorAt = Date.now();
    logFileDrainPending = false;
    logFileRetryAt = errorAt + LOG_FILE_RETRY_DELAY_MS;
    logFileLastError = { at: new Date(errorAt).toISOString(), message: summarizeError(err) };

    try { stream.destroy(); } catch {}
    if (logFileStream === stream) logFileStream = null;

    if (errorAt - logFileWriteErrorAt > 30000) {
      logFileWriteErrorAt = errorAt;
      console.error(`[LOG] stream error file=${LOG_FILE} err=${safeLogValue(err && err.message ? err.message : err, 180)} retryInMs=${LOG_FILE_RETRY_DELAY_MS}`);
    }

    if (!logFileWriterClosed && logFileQueue.length > 0) {
      const retryTimer = setTimeout(() => flushLogFileQueue(), LOG_FILE_RETRY_DELAY_MS);
      if (typeof retryTimer.unref === "function") retryTimer.unref();
    }
  });
  stream.on("drain", () => {
    if (logFileStream !== stream) return;
    logFileDrainPending = false;
    flushLogFileQueue();
  });

  return stream;
}

function maybeWarnDroppedLogLines(now = Date.now()) {
  if (logFileDroppedLines <= 0) return;
  if (now - logFileDropWarnAt < 30000) return;
  logFileDropWarnAt = now;
  console.error(`[LOG] dropped lines due to queue pressure dropped=${logFileDroppedLines} queueLines=${logFileQueue.length} queueBytes=${logFileQueueBytes}`);
}

function flushLogFileQueue() {
  if (!LOG_TO_FILE || logFileWriterClosed || logFileDrainPending || logFileRotationPending) return;
  const stream = ensureLogFileStream();
  if (!stream) return;

  while (logFileQueue.length > 0) {
    const chunk = logFileQueue.shift();
    logFileQueueBytes -= Buffer.byteLength(chunk, "utf8");
    const ok = stream.write(chunk);
    logFileBytes += Buffer.byteLength(chunk, "utf8");
    if (logFileBytes >= LOG_FILE_MAX_BYTES) {
      rotateLogFileStream(stream);
      break;
    }
    if (!ok) {
      logFileDrainPending = true;
      break;
    }
  }
}

function appendLogFileLine(line) {
  if (!LOG_TO_FILE || logFileWriterClosed) return;
  const chunk = String(line || "");
  const chunkBytes = Buffer.byteLength(chunk, "utf8");

  while (
    logFileQueue.length >= LOG_FILE_QUEUE_MAX_LINES ||
    (logFileQueueBytes + chunkBytes) > LOG_FILE_QUEUE_MAX_BYTES
  ) {
    const dropped = logFileQueue.shift();
    if (!dropped) break;
    logFileQueueBytes -= Buffer.byteLength(dropped, "utf8");
    logFileDroppedLines += 1;
  }

  logFileQueue.push(chunk);
  logFileQueueBytes += chunkBytes;
  maybeWarnDroppedLogLines();
  flushLogFileQueue();
}

function ensureRuntimeIncidentFileParent() {
  return ensureParentDirectoryForFile(RUNTIME_INCIDENT_FILE, "diag");
}

function listRecentNpmDebugLogs(limit = RUNTIME_INCIDENT_NPM_LOG_LIMIT) {
  if (!limit || limit < 1) return [];

  try {
    if (!fs.existsSync(NPM_DEBUG_LOG_DIR)) return [];
    return fs.readdirSync(NPM_DEBUG_LOG_DIR, { withFileTypes: true })
      .filter((entry) => entry.isFile() && /-debug-\d+\.log$/i.test(entry.name))
      .map((entry) => {
        const file = path.join(NPM_DEBUG_LOG_DIR, entry.name);
        try {
          const st = fs.statSync(file);
          return { file, sizeBytes: st.size, mtime: st.mtime.toISOString(), mtimeMs: st.mtimeMs };
        } catch {
          return null;
        }
      })
      .filter(Boolean)
      .sort((a, b) => b.mtimeMs - a.mtimeMs)
      .slice(0, limit)
      .map(({ mtimeMs, ...entry }) => entry);
  } catch (err) {
    return [{ error: summarizeError(err), dir: NPM_DEBUG_LOG_DIR }];
  }
}

function getProcessRuntimeMetadata() {
  return {
    pid: process.pid,
    ppid: process.ppid,
    argv: process.argv.map((value) => safeLogValue(value, 240)),
    execPath: safeLogValue(process.execPath, 240),
    npmLifecycleEvent: process.env.npm_lifecycle_event || null,
    npmLifecycleScript: process.env.npm_lifecycle_script || null,
    npmCommand: process.env.npm_command || null,
    npmExecPath: process.env.npm_execpath || null,
    container: fs.existsSync("/.dockerenv") ? "docker" : null
  };
}

function buildRuntimeIncidentPayload(kind, details = {}) {
  const mem = process.memoryUsage();
  return {
    at: new Date().toISOString(),
    kind: safeLogValue(kind || "runtime", 80),
    bootId: runtimeStats.bootId,
    startedAt: runtimeStats.startedAt,
    uptimeSec: Math.round(process.uptime()),
    pid: process.pid,
    nodeVersion: process.version,
    platform: process.platform,
    process: getProcessRuntimeMetadata(),
    railway: getRailwayRuntimeMetadata(),
    correlation: getRuntimeCorrelationMetadata(),
    details,
    stats: {
      shutdownSignals: runtimeStats.shutdownSignals,
      uncaughtExceptions: runtimeStats.uncaughtExceptions,
      unhandledRejections: runtimeStats.unhandledRejections,
      processWarnings: runtimeStats.processWarnings,
      serverErrors: runtimeStats.serverErrors,
      serverClientErrors: runtimeStats.serverClientErrors,
      totalRequests: runtimeStats.totalRequests,
      inFlightRequests: runtimeStats.inFlightRequests,
      completedRequests: runtimeStats.completedRequests,
      abortedRequests: runtimeStats.abortedRequests,
      lastRequestStartedAt: runtimeStats.lastRequestStartedAt,
      lastRequestCompletedAt: runtimeStats.lastRequestCompletedAt,
      lastRequestPath: runtimeStats.lastRequestPath,
      lastResponseStatus: runtimeStats.lastResponseStatus,
      maxObservedEventLoopLagMs: runtimeStats.maxObservedEventLoopLagMs,
      resources: getRuntimeResourceGauges()
    },
    memory: {
      rssMb: Math.round((mem.rss / (1024 * 1024)) * 100) / 100,
      heapUsedMb: Math.round((mem.heapUsed / (1024 * 1024)) * 100) / 100,
      heapTotalMb: Math.round((mem.heapTotal / (1024 * 1024)) * 100) / 100,
      externalMb: Math.round((mem.external / (1024 * 1024)) * 100) / 100
    },
    recentNpmDebugLogs: listRecentNpmDebugLogs()
  };
}

function recordRuntimeIncident(kind, details = {}) {
  const payload = buildRuntimeIncidentPayload(kind, details);
  if (!ensureRuntimeIncidentFileParent()) return payload;

  try {
    fs.appendFileSync(RUNTIME_INCIDENT_FILE, JSON.stringify(payload) + "\n", "utf8");
  } catch (err) {
    console.error(`[DIAG] unable to write incident file=${RUNTIME_INCIDENT_FILE} err=${safeLogValue(err && err.message ? err.message : err, 180)}`);
  }

  return payload;
}

function parseRuntimeIncidentLines(text, limit) {
  return String(text || "")
    .trim()
    .split(/\n+/)
    .filter(Boolean)
    .slice(-limit)
    .map((line) => {
      try { return JSON.parse(line); } catch { return { parseError: true, raw: line.slice(0, 500) }; }
    });
}

function readRuntimeIncidents(limit = RUNTIME_INCIDENT_HISTORY_LIMIT) {
  try {
    const st = fs.existsSync(RUNTIME_INCIDENT_FILE) ? fs.statSync(RUNTIME_INCIDENT_FILE) : null;
    if (!st || !st.isFile() || st.size <= 0) return [];

    const maxBytes = Math.max(64 * 1024, RUNTIME_INCIDENT_READ_MAX_BYTES);
    const start = Math.max(0, st.size - maxBytes);
    const length = st.size - start;
    const fd = fs.openSync(RUNTIME_INCIDENT_FILE, "r");

    try {
      const buffer = Buffer.alloc(length);
      fs.readSync(fd, buffer, 0, length, start);
      let text = buffer.toString("utf8");

      // If reading from the middle of a large NDJSON file, discard the first
      // partial line so only complete incident records are parsed.
      if (start > 0) {
        const firstNewline = text.indexOf("\n");
        text = firstNewline >= 0 ? text.slice(firstNewline + 1) : "";
      }

      return parseRuntimeIncidentLines(text, limit);
    } finally {
      fs.closeSync(fd);
    }
  } catch (err) {
    return [{ error: summarizeError(err), file: RUNTIME_INCIDENT_FILE }];
  }
}

function getLogFileStatus() {
  try {
    const st = fs.existsSync(LOG_FILE) ? fs.statSync(LOG_FILE) : null;
    return {
      enabled: LOG_TO_FILE,
      file: LOG_FILE,
      exists: Boolean(st),
      isFile: st ? st.isFile() : false,
      sizeBytes: st ? st.size : 0,
      mtime: st ? st.mtime.toISOString() : null,
      queueLines: logFileQueue.length,
      queueBytes: logFileQueueBytes,
      droppedLines: logFileDroppedLines,
      streamReady: Boolean(logFileStream),
      rotationEnabled: LOG_TO_FILE,
      rotationPending: logFileRotationPending,
      rotations: logFileRotations,
      maxBytes: LOG_FILE_MAX_BYTES,
      maxFiles: LOG_FILE_MAX_FILES,
      trackedSizeBytes: logFileBytes,
      lastOpenedAt: logFileLastOpenedAt,
      lastError: logFileLastError
    };
  } catch (err) {
    return {
      enabled: LOG_TO_FILE,
      file: LOG_FILE,
      exists: false,
      error: summarizeError(err),
      lastError: logFileLastError
    };
  }
}

function readLogFileTail(maxBytes = 200 * 1024) {
  const status = getLogFileStatus();
  if (!status.exists || !status.isFile || status.sizeBytes <= 0) {
    return { status, text: "" };
  }

  const safeMaxBytes = clampMs(Number(maxBytes) || (200 * 1024), 1024, 1024 * 1024);
  const start = Math.max(0, status.sizeBytes - safeMaxBytes);
  const length = status.sizeBytes - start;
  const fd = fs.openSync(LOG_FILE, "r");
  try {
    const buffer = Buffer.alloc(length);
    fs.readSync(fd, buffer, 0, length, start);
    return { status, start, bytesRead: length, truncated: start > 0, text: buffer.toString("utf8") };
  } finally {
    fs.closeSync(fd);
  }
}

function closeLogFileWriter(timeoutMs = 2000) {
  if (!LOG_TO_FILE || logFileWriterClosed) return logFileClosePromise || Promise.resolve();
  if (logFileClosePromise) return logFileClosePromise;

  logFileWriterClosed = true;
  logFileClosePromise = new Promise((resolve) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      resolve();
    };
    const timeout = setTimeout(finish, Math.max(250, timeoutMs));

    const closeActiveStream = () => {
      const remainingChunks = logFileQueue;
      logFileQueue = [];
      logFileQueueBytes = 0;
      const stream = logFileStream;

      if (!stream) {
        if (remainingChunks.length > 0) {
          try {
            logFileBytes = appendLogChunksSync(remainingChunks);
          } catch {}
        }
        clearTimeout(timeout);
        finish();
        return;
      }

      let streamClosed = false;
      const finishAfterClose = () => {
        if (streamClosed) return;
        streamClosed = true;
        if (remainingChunks.length > 0) {
          try {
            logFileBytes = appendLogChunksSync(remainingChunks);
          } catch {}
        }
        clearTimeout(timeout);
        finish();
      };

      stream.once("close", finishAfterClose);
      try {
        stream.end();
      } catch {
        try { stream.destroy(); } catch {}
        if (stream.closed) finishAfterClose();
      }
    };

    if (logFileRotationPromise) {
      logFileRotationPromise.then(closeActiveStream, closeActiveStream);
    } else {
      closeActiveStream();
    }
  });

  logFileClosePromise.then(
    () => { logFileStream = null; },
    () => { logFileStream = null; }
  );
  return logFileClosePromise;
}

const AGG_WINDOW_MS = parseInt(process.env.LOG_AGG_WINDOW_MS || "60000", 10);
const AGG_FLUSH_MS = parseInt(process.env.LOG_AGG_FLUSH_MS || "15000", 10);
const logAggregation = new Map();

function aggregatePerIpEvent(eventKey, details = {}) {
  const suppressFirst = details && details.suppressFirst === true;
  const ip = safeLogValue(details.ip || "unknown", 80);
  const reasonKey = details && details.reason ? safeLogValue(details.reason, 80) : "";
  const key = `${eventKey}:${ip}`;
  const now = Date.now();
  const st = logAggregation.get(key);

  if (!st || now > st.windowStart + AGG_WINDOW_MS) {
    boundedMapSet(logAggregation, key, {
      count: 1,
      windowStart: now,
      lastDetails: details,
      reasonCounts: reasonKey ? new Map([[reasonKey, 1]]) : new Map()
    }, LOG_AGGREGATION_MAX_ENTRIES);
    return !suppressFirst;
  }

  st.count += 1;
  st.lastDetails = details;
  if (reasonKey) {
    st.reasonCounts.set(reasonKey, (st.reasonCounts.get(reasonKey) || 0) + 1);
  }
  boundedMapSet(logAggregation, key, st, LOG_AGGREGATION_MAX_ENTRIES);
  return false;
}

function flushAggregatedLogs(now = Date.now()) {
  for (const [key, st] of logAggregation.entries()) {
    if (now < st.windowStart + AGG_WINDOW_MS) continue;
    if (st.count > 1) {
      const [eventKey] = key.split(":");
      const ctry = st.lastDetails.country ? ` country=${safeLogValue(st.lastDetails.country, 8)}` : "";
      const topReason = st.reasonCounts && st.reasonCounts.size
        ? [...st.reasonCounts.entries()].sort((a, b) => b[1] - a[1])[0]
        : null;
      const reason = topReason ? ` reason=${safeLogValue(topReason[0], 80)}` : "";
      const reasonSpread = st.reasonCounts && st.reasonCounts.size > 1
        ? ` reasons=${safeLogValue([...st.reasonCounts.entries()].map(([name, count]) => `${name}:${count}`).join(","), 180)}`
        : "";
      addLog(`[AGG:${eventKey}] blocked=${st.count} ip=${safeLogValue(st.lastDetails.ip || "unknown", 80)} window=${Math.round(AGG_WINDOW_MS / 1000)}s${ctry}${reason}${reasonSpread}`);
      if ((eventKey === "SCANNER-BLOCK" || eventKey === "PATH-CANONICALIZE") && st.count >= SCANNER_AGG_ALERT_THRESHOLD) {
        addLog(`[ALERT:SCANNER-BURST] event=${safeLogValue(eventKey, 40)} blocked=${st.count} threshold=${SCANNER_AGG_ALERT_THRESHOLD} ip=${safeLogValue(st.lastDetails.ip || "unknown", 80)} window=${Math.round(AGG_WINDOW_MS / 1000)}s${reason}${reasonSpread}`);
      }
      addSpacer();
    }
    logAggregation.delete(key);
  }
}

function sseSend(res, text, id) {
  if (id != null) res.write(`id: ${id}\n`);
  String(text).split(/\r?\n/).forEach(line => {
    res.write(`data: ${line}\n`);
  });
  res.write('\n');
}

function broadcastLog(line, id) {
  for (const res of LOG_LISTENERS) {
    try { sseSend(res, line, id); } catch {}
  }
}

function appendInMemoryLog(entry, id) {
  LOGS.push(entry);
  LOG_IDS.push(id);

  const overflow = LOGS.length - MAX_LOG_LINES;
  if (overflow > 0) {
    LOGS.splice(0, overflow);
    LOG_IDS.splice(0, overflow);
  }
}

const LOG_INTEGRITY_EVENT_MARKERS = [
  "[REQ:finish]", "[REQ:close]", "[DEP:finish]", "[SCANNER]",
  "[SCANNER-BLOCK]", "[VALIDATION-FAILED]", "[AGG:", "[BOT-VERIFY]",
  "[REPUTATION-DENY]", "[CHALLENGE]", "[ALERT]"
];
const LOG_INTEGRITY_TIMESTAMP_REGEX = /\[(?:\d{2}-\d{2}-\d{4} - [^\]]+|\d{4}-\d{2}-\d{2}T[^\]]+)\]/g;

function countStringOccurrences(value, needle) {
  if (!needle) return 0;
  let count = 0;
  let pos = 0;
  const source = String(value || "");
  while ((pos = source.indexOf(needle, pos)) !== -1) {
    count += 1;
    pos += needle.length;
  }
  return count;
}

function analyzeLogIntegrity(lines = LOGS, ids = LOG_IDS) {
  const inputLines = Array.isArray(lines) ? lines : [];
  const inputIds = Array.isArray(ids) ? ids : [];
  const samples = { multiTimestamp: [], multiMarker: [], adjacentDuplicate: [], idGap: [] };
  let blankSpacerLines = 0;
  let multiTimestampLines = 0;
  let multiMarkerLines = 0;
  let adjacentExactDuplicates = 0;
  let idGaps = 0;

  for (let index = 0; index < inputLines.length; index += 1) {
    const line = String(inputLines[index] || "");
    if (!line.trim()) {
      blankSpacerLines += 1;
      continue;
    }

    const timestampMatches = line.match(LOG_INTEGRITY_TIMESTAMP_REGEX) || [];
    if (timestampMatches.length > 1) {
      multiTimestampLines += 1;
      if (samples.multiTimestamp.length < 5) samples.multiTimestamp.push({ index, id: inputIds[index] || null, preview: line.slice(0, 240) });
    }

    const markerCount = LOG_INTEGRITY_EVENT_MARKERS.reduce((sum, marker) => sum + countStringOccurrences(line, marker), 0);
    if (markerCount > 1) {
      multiMarkerLines += 1;
      if (samples.multiMarker.length < 5) samples.multiMarker.push({ index, id: inputIds[index] || null, markerCount, preview: line.slice(0, 240) });
    }

    if (index > 0 && line && line === String(inputLines[index - 1] || "")) {
      adjacentExactDuplicates += 1;
      if (samples.adjacentDuplicate.length < 5) samples.adjacentDuplicate.push({ index, id: inputIds[index] || null, preview: line.slice(0, 240) });
    }
  }

  for (let index = 1; index < inputIds.length; index += 1) {
    const prior = Number(inputIds[index - 1]);
    const current = Number(inputIds[index]);
    if (Number.isFinite(prior) && Number.isFinite(current) && current !== prior + 1) {
      idGaps += 1;
      if (samples.idGap.length < 5) samples.idGap.push({ index, previousId: prior, currentId: current });
    }
  }

  return {
    ok: multiTimestampLines === 0 && multiMarkerLines === 0 && adjacentExactDuplicates === 0 && idGaps === 0,
    lineCount: inputLines.length,
    firstId: inputIds.length ? inputIds[0] : null,
    lastId: inputIds.length ? inputIds[inputIds.length - 1] : null,
    blankSpacerLines,
    multiTimestampLines,
    multiMarkerLines,
    adjacentExactDuplicates,
    idGaps,
    samples
  };
}

function addLog(message) {
  const now = new Date();
  const tsLocal = formatLocal(now);

  const parts = String(message).replace(/\r\n/g, "\n").split("\n");

  for (const raw of parts) {
    const line = sanitizeOneLine(raw);
    const entry = `[${tsLocal}] ${line}`;
    const id = ++LOG_SEQ;

    console.log(entry);

    appendInMemoryLog(entry, id);

    broadcastLog(entry, id);
    appendLogFileLine(entry + "\n");
  }
}

function addSpacer() {
  // Keep the in-memory/file/SSE spacer, but avoid emitting empty stdout lines.
  // Some platform log viewers render empty stdout writes as standalone `[inf]`
  // rows, which makes exported logs look concatenated or duplicated.
  const id = ++LOG_SEQ;
  appendInMemoryLog("", id);
  appendLogFileLine("\n");
  broadcastLog("", id);
}

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

// ================== CLIENT IP & GEO FUNCTIONS ==================

// Proper IP address parser that handles IPv4, IPv6, and ports correctly
function parseIpAddress(ip) {
  if (!ip || typeof ip !== 'string') return ip;

  // Remove any surrounding whitespace
  ip = ip.trim();

  // Handle IPv6 with port format: [2001:db8::1]:8080
  if (ip.startsWith('[') && ip.includes(']')) {
    const endBracket = ip.indexOf(']');
    return ip.slice(1, endBracket);
  }

  // Handle IPv4 with port: 192.168.1.1:8080
  if (ip.includes('.') && ip.includes(':')) {
    const lastColon = ip.lastIndexOf(':');
    // Verify it's actually a port by checking if the part after colon is numeric
    const potentialPort = ip.slice(lastColon + 1);
    if (/^\d+$/.test(potentialPort)) {
      return ip.slice(0, lastColon);
    }
  }

  // Plain IPv4, IPv6 without port, or unknown format
  return ip;
}

function getClientIp(req) {
  const trustedCloudflareClientIp = getTrustedCloudflareClientIp(req);
  if (trustedCloudflareClientIp) return trustedCloudflareClientIp;

  // Prefer trusted platform-normalized client-ip headers after proven Cloudflare forwarding.
  if (req.headers['x-vercel-forwarded-for']) {
    const ips = String(req.headers['x-vercel-forwarded-for']).split(',').map(ip => ip.trim());
    const clientIp = ips[0];
    if (clientIp && clientIp !== '') {
      return parseIpAddress(clientIp);
    }
  }

  if (req.headers['x-nf-client-connection-ip']) {
    const ip = String(req.headers['x-nf-client-connection-ip']).trim();
    if (ip && ip !== '') return parseIpAddress(ip);
  }

  if (req.headers['x-render-ip']) {
    const ip = String(req.headers['x-render-ip']).trim();
    if (ip && ip !== '') return parseIpAddress(ip);
  }

  if (req.headers['x-railway-ip']) {
    const ip = String(req.headers['x-railway-ip']).trim();
    if (ip && ip !== '') return parseIpAddress(ip);
  }

  // Do not blindly trust CF-Connecting-IP here: direct clients can spoof it.
  // Cloudflare-origin requests resolve through proven CF context plus edge-CIDR
  // or trusted-proxy provenance above, or through platform/forwarded headers below.

  // Heroku, AWS ELB, Google Cloud, Azure, and most other platforms
  if (req.headers['x-forwarded-for']) {
    const ips = String(req.headers['x-forwarded-for']).split(',').map(ip => ip.trim());
    // Get the first IP that's not a known proxy IP
    for (const ip of ips) {
      if (ip && ip !== '' && !isKnownProxyIp(ip)) {
        return parseIpAddress(ip);
      }
    }
    // Fallback to first IP if all are proxy IPs
    if (ips[0] && ips[0] !== '') {
      return parseIpAddress(ips[0]);
    }
  }

  // Standard headers
  const standardHeaders = [
    "x-real-ip",
    "true-client-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "forwarded"
  ];

  for (const header of standardHeaders) {
    const value = req.headers[header];
    if (value) {
      let ip = String(value).trim();

      // Handle Forwarded header (RFC 7239)
      if (header === "forwarded") {
        const forMatch = ip.match(/for=([^,;]+)/i);
        if (forMatch) {
          ip = forMatch[1].replace(/^\[?"?'?|"?'?\]?$/g, '').trim();
        }
      }

      if (ip && ip !== '') {
        return parseIpAddress(ip);
      }
    }
  }

  // Final fallback to Express
  return parseIpAddress(req.ip || "");
}

function getDirectRemoteIp(req) {
  const remote =
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    req.ip ||
    "";
  return parseIpAddress(String(remote || "").trim());
}

function shouldTrustClientIpHeaders(req) {
  if (process.env.TRUST_CLIENT_IP_HEADERS === "1") return true;

  // If proxy trust is explicitly disabled, do not trust forwarded client-ip headers.
  if (trustProxyEffective === false) return false;

  // Cloudflare deployments can trust cf-connecting-ip only when cf context is present.
  if (req.headers["cf-connecting-ip"] && hasCloudflareHeaders(req)) return true;

  // Common managed platforms where upstream populates/normalizes forwarding headers.
  if (process.env.VERCEL || process.env.NETLIFY || process.env.RENDER || process.env.RAILWAY || process.env.HEROKU) return true;

  return false;
}

function getDenyCacheIp(req) {
  const directIp = getDirectRemoteIp(req);
  const trustedCloudflareClientIp = getTrustedCloudflareClientIp(req);
  if (trustedCloudflareClientIp) return trustedCloudflareClientIp;

  // Prefer Express-normalized req.ip when proxy trust is enabled. This is
  // stable across appended forwarding chains and avoids header-driven churn.
  if (trustProxyEffective !== false) {
    const trustedReqIp = parseIpAddress(String(req.ip || "").trim());
    if (trustedReqIp) return trustedReqIp;
  }

  if (shouldTrustClientIpHeaders(req)) {
    const clientIp = getClientIp(req);
    if (clientIp) return clientIp;
  }

  return directIp || "unknown";
}

function getRequestIdentity(req) {
  const displayIp = getClientIp(req) || "unknown";
  const keyIp = getDenyCacheIp(req) || displayIp || "unknown";
  const rateLimitKey = displayIp || keyIp || "unknown";
  const source = keyIp === displayIp ? "client" : "trusted_proxy_key";
  return {
    ip: displayIp,
    displayIp,
    keyIp,
    rateLimitKey,
    banKey: keyIp,
    denyCacheKey: keyIp,
    source,
    rateLimitSource: rateLimitKey === displayIp ? "client" : "fallback_key"
  };
}

function formatRequestIdentityLogSuffix(req, options = {}) {
  const identity = getRequestIdentity(req);
  const parts = [
    `identity=${safeLogValue(identity.source, 40)}`,
    `rateKey=${safeLogValue(identity.rateLimitKey, 64)}`,
    `rateSource=${safeLogValue(identity.rateLimitSource, 40)}`
  ];
  if (identity.keyIp && identity.keyIp !== identity.ip) {
    parts.unshift(`keyIp=${safeLogValue(identity.keyIp, 64)}`);
  }
  if (options.geoSource) {
    parts.push(`geoSource=${safeLogValue(options.geoSource, 48)}`);
  }
  return parts.length ? ` ${parts.join(" ")}` : "";
}

// Helper function to identify known proxy IPs
function isKnownProxyIp(ip) {
  const proxyRanges = [
    /^3\.\d+\.\d+\.\d+$/,  // Vercel AWS IPs
    /^54\.\d+\.\d+\.\d+$/, // AWS us-east-1
    /^52\.\d+\.\d+\.\d+$/, // AWS us-east-1
    /^34\.\d+\.\d+\.\d+$/, // Google Cloud
    /^35\.\d+\.\d+\.\d+$/, // Google Cloud
    /^13\.\d+\.\d+\.\d+$/, // AWS
    /^10\.\d+\.\d+\.\d+$/, // Private
    /^192\.168\.\d+\.\d+$/, // Private
    /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$/, // Private
    /^127\.\d+\.\d+\.\d+$/, // Localhost
    /^::1$/, // IPv6 localhost
    /^f[cd][0-9a-f]{2}:/i, // IPv6 private (fc00::/7)
  ];

  return proxyRanges.some(pattern => pattern.test(ip));
}

function hasIndependentCloudflareProof(req) {
  return Boolean(req.headers["cf-ray"] || req.headers["cf-visitor"]);
}

function getForwardedForIps(req) {
  return String(req.headers["x-forwarded-for"] || "")
    .split(",")
    .map(value => parseIpAddress(value.trim()))
    .filter(Boolean);
}

function hasAuthenticatedForwarder(req) {
  if (!MDS_FORWARDER_AUTH_SECRET || !req || !req.headers) return false;
  const provided = String(req.headers[FORWARDER_AUTH_HEADER] || "").trim();
  return Boolean(provided && provided === MDS_FORWARDER_AUTH_SECRET);
}

function hasTrustedCloudflareForwardedForChain(req, cloudflareClientIp) {
  if (!TRUST_CLOUDFLARE_XFF_CHAIN) return false;
  const trustedByAuthenticatedForwarder = hasAuthenticatedForwarder(req);
  if (!trustedByAuthenticatedForwarder && (!hasTrustedProxyProvenance(req) || hasManagedPlatformSourceHeader(req))) return false;

  const forwardedForIps = getForwardedForIps(req);
  if (forwardedForIps.length < 2 || !cloudflareClientIp) return false;

  const firstForwardedIp = forwardedForIps[0];
  if (firstForwardedIp !== cloudflareClientIp) return false;

  return forwardedForIps.slice(1).some(ip => isCloudflareEdgeIp(ip));
}

function hasManagedPlatformSourceHeader(req) {
  return Boolean(
    req.headers["x-railway-ip"] ||
    req.headers["x-vercel-id"] ||
    req.headers["x-nf-client-connection-ip"] ||
    req.headers["x-render-ip"]
  );
}

function getTrustedCloudflareClientIp(req) {
  if (!hasIndependentCloudflareProof(req) || !req.headers["cf-connecting-ip"]) return null;

  const ip = parseIpAddress(String(req.headers["cf-connecting-ip"]).trim());
  if (!ip) return null;

  const directIp = getDirectRemoteIp(req);
  const trustedByCloudflareEdge = isCloudflareEdgeIp(directIp);
  const trustedByAuthenticatedForwarder = hasAuthenticatedForwarder(req);
  const trustedByForwardedForChain = hasTrustedCloudflareForwardedForChain(req, ip);

  if (!trustedByCloudflareEdge && !trustedByAuthenticatedForwarder && !trustedByForwardedForChain) {
    return null;
  }

  return ip;
}

function normalizeIpv4Mapped(ip) {
  const raw = String(ip || "").trim();
  const m = raw.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  return m ? m[1] : raw;
}

const CLOUDFLARE_IPV4_CIDRS = [
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
  "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
  "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
  "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
  "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
];

const CLOUDFLARE_IPV6_CIDRS = [
  "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
  "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
  "2c0f:f248::/32"
];

function ipv4ToInt(ip) {
  const parts = String(ip || "").split(".");
  if (parts.length !== 4) return null;
  let out = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out = (out * 256) + n;
  }
  return out >>> 0;
}

function isIpv4InCidr(ip, cidr) {
  const [base, bitsRaw] = String(cidr || "").split("/");
  const bits = Number(bitsRaw);
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt == null || baseInt == null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

function expandIpv6ToBigInt(ip) {
  const normalized = String(ip || "").toLowerCase();
  if (!normalized || normalized.includes(".")) return null;
  const halves = normalized.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":").filter(Boolean) : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":").filter(Boolean) : [];
  const missing = 8 - (left.length + right.length);
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;
  const groups = [...left, ...Array(missing).fill("0"), ...right];
  if (groups.length !== 8) return null;
  let out = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(group)) return null;
    out = (out << 16n) + BigInt(parseInt(group, 16));
  }
  return out;
}

function isIpv6InCidr(ip, cidr) {
  const [base, bitsRaw] = String(cidr || "").split("/");
  const bits = Number(bitsRaw);
  const ipInt = expandIpv6ToBigInt(ip);
  const baseInt = expandIpv6ToBigInt(base);
  if (ipInt == null || baseInt == null || !Number.isInteger(bits) || bits < 0 || bits > 128) return false;
  if (bits === 0) return true;
  const shift = BigInt(128 - bits);
  return (ipInt >> shift) === (baseInt >> shift);
}

function isCloudflareEdgeIp(ip) {
  const normalized = normalizeIpv4Mapped(parseIpAddress(String(ip || "")));
  if (!normalized) return false;
  if (normalized.includes(".")) {
    return CLOUDFLARE_IPV4_CIDRS.some(cidr => isIpv4InCidr(normalized, cidr));
  }
  if (normalized.includes(":")) {
    return CLOUDFLARE_IPV6_CIDRS.some(cidr => isIpv6InCidr(normalized, cidr));
  }
  return false;
}

function isPrivateOrLocalProxyIp(ip) {
  const normalized = normalizeIpv4Mapped(ip);
  const privateRanges = [
    /^10\.\d+\.\d+\.\d+$/,
    /^192\.168\.\d+\.\d+$/,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$/,
    /^127\.\d+\.\d+\.\d+$/,
    /^::1$/i,
    /^f[cd][0-9a-f]{2}:/i,
  ];
  return privateRanges.some(pattern => pattern.test(normalized));
}

function hasTrustedProxyProvenance(req) {
  const socketRemote =
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    "";
  const directIp = parseIpAddress(String(socketRemote || "").trim());
  if (!directIp) return false;

  // Only accept upstream-provided client-ip headers when the immediate
  // sender looks like a private/local proxy hop. This avoids trusting
  // broad public cloud client ranges as proxy provenance.
  return isPrivateOrLocalProxyIp(directIp);
}

function hasHeader(req, name) {
  return Boolean(req && req.headers && req.headers[name]);
}

function hasExplicitUpstreamGeoTrust(req) {
  return Boolean(TRUST_UPSTREAM_GEO_HEADERS && hasTrustedProxyProvenance(req));
}

function hasVercelGeoProvenance(req) {
  return Boolean(
    process.env.VERCEL ||
    (hasExplicitUpstreamGeoTrust(req) && (
      hasHeader(req, "x-vercel-forwarded-for") ||
      hasHeader(req, "x-vercel-id") ||
      hasHeader(req, "x-vercel-proxied-for")
    ))
  );
}

function hasNetlifyGeoProvenance(req) {
  return Boolean(
    process.env.NETLIFY ||
    (hasExplicitUpstreamGeoTrust(req) && (
      hasHeader(req, "x-nf-client-connection-ip") ||
      hasHeader(req, "x-nf-request-id") ||
      hasHeader(req, "x-nf-geo")
    ))
  );
}

function hasRenderGeoProvenance(req) {
  return Boolean(process.env.RENDER || (hasExplicitUpstreamGeoTrust(req) && hasHeader(req, "x-render-ip")));
}

function hasRailwayGeoProvenance(req) {
  return Boolean(process.env.RAILWAY || (hasExplicitUpstreamGeoTrust(req) && hasHeader(req, "x-railway-ip")));
}

function hasCloudflareGeoProvenance(req) {
  if (!(hasHeader(req, "cf-ipcountry") || hasHeader(req, "cf-edge-country"))) return false;
  if (!hasHeader(req, "cf-connecting-ip") || !hasIndependentCloudflareProof(req)) return false;

  const cloudflareClientIp = parseIpAddress(String(req.headers["cf-connecting-ip"] || "").trim());
  if (!cloudflareClientIp) return false;

  return Boolean(
    isCloudflareEdgeIp(getDirectRemoteIp(req)) ||
    hasAuthenticatedForwarder(req) ||
    hasTrustedCloudflareForwardedForChain(req, cloudflareClientIp) ||
    (hasTrustedProxyProvenance(req) && !hasManagedPlatformSourceHeader(req))
  );
}

function canTrustGeoCountryHeader(req, header, platform) {
  if (!req || !req.headers || !req.headers[header]) return false;
  switch (platform) {
    case "cloudflare":
      return hasCloudflareGeoProvenance(req);
    case "vercel":
      return hasVercelGeoProvenance(req);
    case "netlify":
      return hasNetlifyGeoProvenance(req);
    case "render":
      return hasRenderGeoProvenance(req);
    case "railway":
      return hasRailwayGeoProvenance(req);
    default:
      return false;
  }
}

function shouldTrustGeoHeaders(req) {
  return hasCloudflareGeoProvenance(req) ||
    hasVercelGeoProvenance(req) ||
    hasNetlifyGeoProvenance(req) ||
    hasRenderGeoProvenance(req) ||
    hasRailwayGeoProvenance(req);
}

function getCountryResolution(req) {
  const h = req.headers;
  const trustGeoHeaders = shouldTrustGeoHeaders(req);
  const requestIp = getClientIp(req) || "unknown";
  const geoDebug = GEO_SOURCE_DEBUG || process.env.IP_DEBUG === "1";
  const logGeoSource = (source, country) => {
    if (!geoDebug) return;
    addLog(`[GEO-SOURCE] ip=${safeLogValue(requestIp)} source=${safeLogValue(source, 40)} country=${safeLogValue(String(country || ""), 8)} trustedHeaders=${trustGeoHeaders ? "1" : "0"}`);
    maybeEnrichGeoAsync(requestIp, country, source);
  };

  // Platform-specific country headers
  const countryHeaders = [
    ["x-vercel-ip-country", "vercel"],
    ["cf-ipcountry", "cloudflare"],
    ["cf-edge-country", "cloudflare"],
    ["x-nf-country", "netlify"],
    ["x-render-country", "render"],
    ["x-railway-country", "railway"],
  ];

  if (trustGeoHeaders) {
    for (const [header, platform] of countryHeaders) {
      const value = h[header];
      if (value && canTrustGeoCountryHeader(req, header, platform)) {
        const country = String(value).toUpperCase();
        logGeoSource(`${platform}:${header}`, country);
        return { country, source: `${platform}:${header}` };
      }
    }

    // Netlify geo JSON
    if (h["x-nf-geo"] && hasNetlifyGeoProvenance(req)) {
      try {
        const geo = JSON.parse(h["x-nf-geo"]);
        if (geo.country) {
          const country = String(geo.country).toUpperCase();
          logGeoSource("netlify:x-nf-geo", country);
          return { country, source: "netlify:x-nf-geo" };
        }
      } catch {}
    }
  }

  // Fly.io region (sometimes contains country)
  // Keep this outside header-trust gating: Fly region is often the only
  // platform signal when the IPinfo Lite fallback is unavailable.
  if (h["fly-region"]) {
    const region = String(h["fly-region"]).toLowerCase();
    const regionToCountry = {
      'iad': 'US', 'atl': 'US', 'dfw': 'US', 'den': 'US', 'lax': 'US', 'mia': 'US',
      'ord': 'US', 'phx': 'US', 'qro': 'MX', 'scl': 'CL', 'bog': 'CO', 'eze': 'AR',
      'gru': 'BR', 'lhr': 'GB', 'cdg': 'FR', 'ams': 'NL', 'fra': 'DE', 'mad': 'ES',
      'waw': 'PL', 'arn': 'SE', 'nrt': 'JP', 'hkg': 'HK', 'sin': 'SG', 'bom': 'IN',
      'syd': 'AU', 'mel': 'AU'
    };
    if (regionToCountry[region]) {
      const country = regionToCountry[region];
      logGeoSource(`fly:fly-region:${region}`, country);
      return { country, source: `fly:fly-region:${region}` };
    }
  }

  return null;
}

async function getCountryResolutionAsync(req) {
  const resolution = getCountryResolution(req);
  if (resolution) return resolution;

  const requestIp = getClientIp(req) || "unknown";
  const ipinfo = await lookupIpinfoLite(requestIp);
  const geoDebug = GEO_SOURCE_DEBUG || process.env.IP_DEBUG === "1";
  if (ipinfo) {
    if (geoDebug) {
      addLog(`[GEO-SOURCE] ip=${safeLogValue(requestIp)} source=ipinfo-lite country=${safeLogValue(ipinfo.country || "", 8)} trustedHeaders=${shouldTrustGeoHeaders(req) ? "1" : "0"}`);
    }
    return ipinfo;
  }

  if (geoDebug) {
    addLog(`[GEO-SOURCE] ip=${safeLogValue(requestIp)} source=none country= trustedHeaders=${shouldTrustGeoHeaders(req) ? "1" : "0"}`);
  }
  return null;
}

function getCountry(req) {
  const resolution = getCountryResolution(req);
  return resolution ? resolution.country : null;
}

function getASN(req) {
  const asnHeaders = [
    "cf-asn",
    "x-asn",
    "x-vercel-ip-asn",
    "x-nf-asn",
    "x-render-asn"
  ];

  for (const header of asnHeaders) {
    const value = req.headers[header];
    if (value) {
      return normalizeAsn(value);
    }
  }
  return null;
}

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

// ================== SCANNER DETECTION ==================
const SCANNER_PATTERNS = {
  // High-signal vendor/user-agent substrings (case-insensitive)
  uaSubstrings: [
    // Microsoft / Outlook / EOP / SafeLinks
    'safelinks', 'protection.outlook.com', 'microsoft eop', 'exchange online',
    'microsoft-office', 'outlook', 'x-owa',

    // Proofpoint
    'proofpoint', 'urldefense.proofpoint.com', 'ppops-', 'tap/',

    // Mimecast
    'mimecast', 'mimecast-control-center', 'protect-us.mimecast.com',
    'protect-eu.mimecast.com', 'protect-au.mimecast.com',

    // Barracuda
    'barracuda', 'bemailhec', 'linkprotect.cudasvc.com',

    // Cisco / IronPort
    'ironport', 'cisco secure email', 'sesa.cisco',

    // Trend Micro
    'trendmicro', 'tmurl', 'tmresponse', 'deep discovery', 'ddan',

    // McAfee / Trellix / FireEye / Cloudmark
    'mcafee', 'clickprotect', 'trellix', 'fireeye', 'cloudmark',

    // Zscaler / Forcepoint / Fortinet
    'zscaler', 'zscloud', 'forcepoint', 'websense', 'fortimail', 'fortinet',

    // Google/Gmail prefetch
    'googleimageproxy', 'gmail proxy', 'google proxy',

    // Apple Mail Privacy
    'apple mail privacy', 'mailprivacy',

    // Generic
    'url defense', 'urlrewrite', 'link protect', 'linkprotect',
    'link-scanner', 'security scan', 'sandbox url'
  ],

  // Strong regex hits for vendor/rewriter signatures
  uaRegexes: [
    // Microsoft SafeLinks / EOP / Outlook apps
    /safelinks\.protection\.outlook\.com|(?:nam|eur|apc)\d+\.safelinks/i,
    /(microsoft[- ]?office|outlook|exchange).*(scan|eop)/i,
    /Microsoft[- ]?Office\/[0-9.]+/i,
    /Outlook-(?:Android|iOS)\/[0-9.]+/i,

    // Proofpoint
    /urldefense\.(proofpoint|com)/i,
    /Proofpoint(?:|-[A-Za-z]+)\/[0-9.]+/i,
    /ppops-[a-z0-9-]+/i,

    // Mimecast
    /mimecast|protect-(?:us|eu|au)\.mimecast\.com/i,

    // Barracuda
    /barracuda|bemailhec|linkprotect\.cudasvc\.com/i,

    // Cisco / IronPort
    /ironport|secure\.email|sesa\.cisco/i,

    // Trend Micro
    /trend[\s-]?micro|tmurl|tmresponse|deep\s*discovery|ddan/i,

    // McAfee / Trellix / FireEye / Cloudmark
    /mcafee|clickprotect|cp\.mcafee\.com/i,
    /trellix|fireeye|cloudmark/i,

    // Zscaler / Forcepoint / Fortinet
    /zscaler|zsgov|zscloud|zscalertwo|zscalerthree/i,
    /forcepoint|websense/i,
    /fortinet|fortimail|fortiguard/i,

    // Headless/automation (keep weight low in your scoring)
    /(headless|puppeteer|playwright|phantomjs|selenium|wdio|cypress|curl|wget|python-requests|aiohttp|okhttp|java\/|go-http)/i,
  ],

  // Header fingerprints (browser hints often missing in scanners)
  headerRules: [
    // Missing typical browser hints
    (h) => !h['accept-language'],
    (h) => !h['sec-ch-ua'],
    (h) => !h['sec-fetch-mode'],
    (h) => !h['upgrade-insecure-requests'],

    // Suspicious combinations
    (h) => (h['sec-fetch-site']||'').toLowerCase() === 'none',
    (h) => (h['sec-fetch-mode']||'').toLowerCase() === 'no-cors',

    // No cookies or referer on a deep/first touch
    (h) => !h['cookie'],
    (h) => !h['referer'],
  ],

  // Methods scanners often use for "peek" fetches
  methods: ['HEAD', 'OPTIONS'],

  // Optional infra hints if you later pipe in reverse DNS / ASN (leave empty if unused)
  rdnsHints: [
    // 'pphosted.com', 'mimecast.com', 'barracudanetworks.com'
  ],
};

const IMPERSONATE_SCANNER = (process.env.IMPERSONATE_SCANNER || "0") === "1";
const IMPERSONATE_SCANNER_STRICT = (process.env.IMPERSONATE_SCANNER_STRICT || "1") === "1";
const IMPERSONATE_MIN_CONFIDENCE = Number(process.env.IMPERSONATE_MIN_CONFIDENCE || "0.85");
const SCANNER_PROFILE_DEBUG_HEADERS = (process.env.SCANNER_PROFILE_DEBUG_HEADERS || "0") === "1";
const GENERIC_FALLBACK_CONF_HIGH = Number(process.env.GENERIC_FALLBACK_CONF_HIGH || "0.93");
const GENERIC_FALLBACK_CONF_MED = Number(process.env.GENERIC_FALLBACK_CONF_MED || "0.86");
const GENERIC_FALLBACK_CONF_LOW = Number(process.env.GENERIC_FALLBACK_CONF_LOW || "0.80");

const SCANNER_GENERIC_PROFILE = {
  name: "Generic_Scanner",
  ua: "Mozilla/5.0 (compatible; URLScanner/1.0; +https://security.example)",
  match: /.*/i,
  requestHeaders: {},
  responseHeaders: {}
};

const SCANNER_PROFILES = [
  {
    name: "Microsoft_SafeLinks",
    ua: "safelinks.protection.outlook.com",
    match: /(safelinks|outlook|exchange|microsoft)/i,
    requestHeaders: {
      "X-MS-Exchange-Organization-AuthAs": "Anonymous",
      "X-MS-Exchange-Organization-SCL": "-1"
    },
    responseHeaders: {
      "X-MS-Exchange-Organization-Network-Message-Id": () => crypto.randomBytes(16).toString("hex"),
      "X-MS-Exchange-Organization-AuthAs": "Internal",
      "X-MS-Exchange-Organization-AuthSource": "DB7P191MB0757.EURP191.PROD.OUTLOOK.COM"
    }
  },
  {
    name: "Proofpoint",
    ua: "urldefense.proofpoint.com",
    match: /(proofpoint|urldefense|ppops)/i,
    requestHeaders: {
      "X-Proofpoint-Virus-Version": "vendor=baseguard engine=6.0.0 definitions=0",
      "X-Proofpoint-Spam-Details": "rule=none policy=default"
    },
    responseHeaders: {
      "X-Proofpoint-Version": "v3",
      "X-Proofpoint-Scan-Id": () => crypto.randomBytes(8).toString("hex")
    }
  },
  {
    name: "Mimecast",
    ua: "mimecast.com",
    match: /(mimecast)/i,
    requestHeaders: {
      "X-Mimecast-Spam-Score": "0",
      "X-Mimecast-Server": "mimecast"
    },
    responseHeaders: {
      "X-Mimecast-Origin": "cloud",
      "X-Mimecast-Scan-Id": () => `mc${Date.now()}${crypto.randomBytes(4).toString("hex")}`
    }
  },
  {
    name: "Barracuda",
    ua: "barracudanetworks.com",
    match: /(barracuda|cudasvc)/i,
    requestHeaders: {
      "X-Barracuda-Cloud": "active",
      "X-Barracuda-App": "link-protection"
    },
    responseHeaders: {
      "X-Barracuda-Connect": "scanner",
      "X-Barracuda-Scan-Time": () => Date.now().toString()
    }
  }
];

// Modify applyScannerProfileHeaders to merge dynamic headers
function applyScannerProfileHeaders(res, profile) {
  if (!IMPERSONATE_SCANNER || !res || !profile || !profile.responseHeaders) return;
  // static headers
  const headers = materializeProfileHeaders(profile);
  for (const [headerName, headerValue] of Object.entries(headers)) {
    if (!res.getHeader(headerName)) {
      res.setHeader(headerName, headerValue);
    }
  }
  // dynamic headers (override static ones if present)
  const dynamic = dynamicResponseHeaders[profile.name];
  if (dynamic) {
    for (const [headerName, headerValue] of Object.entries(dynamic)) {
      const value = typeof headerValue === 'function' ? headerValue() : headerValue;
      res.setHeader(headerName, value);
    }
  }
  if (!res.getHeader("X-Scanner-Profile") && SCANNER_PROFILE_DEBUG_HEADERS) {
    res.setHeader("X-Scanner-Profile", profile.name);
  }
  if (!res.getHeader("X-Scanner-Processed") && SCANNER_PROFILE_DEBUG_HEADERS) {
    res.setHeader("X-Scanner-Processed", new Date().toISOString());
  }
}

// ... (keep the rest of the existing functions: applyScannerProfileHeaders, materializeProfileHeaders, etc. unchanged, but ensure they use dynamic)

function getScannerResponseHeader(headers, headerName) {
  if (!headers || !headerName) return null;
  if (typeof headers.get === "function") return headers.get(headerName);

  const wanted = String(headerName).toLowerCase();
  if (typeof headers.entries === "function") {
    for (const [key, value] of headers.entries()) {
      if (String(key).toLowerCase() === wanted) return value;
    }
  }

  for (const [key, value] of Object.entries(headers)) {
    if (String(key).toLowerCase() === wanted) {
      return Array.isArray(value) ? value.join(", ") : String(value ?? "");
    }
  }
  return null;
}

function buildScannerSafeHealthTipsHtml() {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Simple Wellness Habits for Everyday Health</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root{color-scheme:light;--bg:#f5f7f4;--card:#fff;--text:#1f2933;--muted:#52616b;--accent:#2f7d58;--border:#dfe7dd;}
    *{box-sizing:border-box;}
    body{margin:0;font-family:Arial,Helvetica,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;}
    .page{max-width:880px;margin:0 auto;padding:32px 18px;}
    header,article,footer{background:var(--card);border:1px solid var(--border);border-radius:14px;box-shadow:0 2px 10px rgba(31,41,51,.06);}
    header{padding:28px 30px;margin-bottom:18px;}
    article{padding:8px 30px 26px;}
    footer{margin-top:18px;padding:16px 30px;color:var(--muted);font-size:.92rem;}
    h1{margin:0 0 10px;color:var(--accent);font-size:2rem;line-height:1.2;}
    h2{margin:24px 0 8px;font-size:1.15rem;color:#20362b;}
    p{margin:0 0 12px;}
    .summary{color:var(--muted);max-width:680px;}
    .meta{font-size:.9rem;color:var(--muted);}
    ul{padding-left:1.25rem;margin:8px 0 0;}
    li{margin:6px 0;}
  </style>
</head>
<body>
  <main class="page">
    <header>
      <p class="meta">General wellness information</p>
      <h1>Simple Wellness Habits for Everyday Health</h1>
      <p class="summary">Small daily routines can support energy, focus, and general well-being. These practical reminders are intended for everyday lifestyle awareness.</p>
    </header>
    <article aria-label="Daily wellness guide">
      <section>
        <h2>Hydration</h2>
        <p>Keep water nearby during the day and consider starting the morning with a glass of water before caffeinated drinks.</p>
      </section>
      <section>
        <h2>Movement</h2>
        <p>Short walking or stretching breaks can help reduce stiffness during long periods of sitting.</p>
      </section>
      <section>
        <h2>Balanced Meals</h2>
        <p>A simple plate with vegetables, whole grains, and protein can make everyday meals more satisfying.</p>
      </section>
      <section>
        <h2>Sleep Routine</h2>
        <p>Consistent sleep and wake times, a quiet room, and reduced screen use before bed can support better rest.</p>
      </section>
      <section>
        <h2>Stress Management</h2>
        <p>Brief breathing breaks, journaling, or a few quiet minutes can make it easier to reset during a busy day.</p>
      </section>
      <section>
        <h2>Quick Daily Checklist</h2>
        <ul>
          <li>Drink water regularly.</li>
          <li>Take short movement breaks.</li>
          <li>Choose balanced meals when possible.</li>
          <li>Keep a consistent sleep routine.</li>
          <li>Pause for a few calm minutes when needed.</li>
        </ul>
      </section>
    </article>
    <footer>
      <p>This page provides general lifestyle information only and is not a substitute for professional medical advice.</p>
    </footer>
  </main>
</body>
</html>`;
}

function resolveScannerProfile(req, explicitProfile = null) {
  let profile = explicitProfile || null;
  const ua = req.get("User-Agent") || "";
  if (!profile) {
    if (/safelinks|outlook|exchange|microsoft/i.test(ua)) {
      profile = SCANNER_PROFILES.find(p => p.name === 'Microsoft_SafeLinks') || null;
    } else if (/proofpoint|urldefense|ppops/i.test(ua)) {
      profile = SCANNER_PROFILES.find(p => p.name === 'Proofpoint') || null;
    } else if (/mimecast/i.test(ua)) {
      profile = SCANNER_PROFILES.find(p => p.name === 'Mimecast') || null;
    } else if (/barracuda|cudasvc/i.test(ua)) {
      profile = SCANNER_PROFILES.find(p => p.name === 'Barracuda') || null;
    }
  }
  return profile || SCANNER_GENERIC_PROFILE;
}

function applyScannerSafeHtmlHeaders(res) {
  if (!res || typeof res.setHeader !== "function") return;
  res.setHeader("Cache-Control", "no-store, max-age=0");
  res.setHeader("X-" + "Content-Type-Options", SECURITY_HEADER_VALUES.contentTypeOptions);
  res.setHeader("Referrer-Policy", SECURITY_HEADER_VALUES.referrerPolicy);
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
  );
}

function getScannerSafeHtmlLogFields(decryptResult, profile) {
  let destinationHost = "unknown";
  try {
    destinationHost = normHost(new URL(decryptResult.finalUrl || "").hostname) || "unknown";
  } catch (_) {
    destinationHost = "invalid";
  }

  return {
    mode: "scanner-safe-html",
    host: safeLogValue(destinationHost, 120),
    linkHash: safeLogValue(decryptResult.linkHash || "unknown", 64),
    profile: safeLogValue((profile && profile.name) || "unknown", 80)
  };
}

// ================== renderScannerSafeHtmlForScanner ==================
async function renderScannerSafeHtmlForScanner(req, res, decryptResult) {
  // We intentionally DO NOT fetch the destination URL in this path. High-confidence
  // scanner requests receive harmless static HTML after the same URL validation used
  // by normal redirects has already run in handleRedirectCore.
  const profile = resolveScannerProfile(req, decryptResult && decryptResult.scannerProfile);

  // Apply scanner compatibility/profile headers and static-page security headers.
  applyScannerCompatHeaders(res);
  applyScannerProfileHeaders(res, profile);
  applyScannerSafeHtmlHeaders(res);

  // Send the health tips page with 200 OK
  res.status(200).type('html').send(buildScannerSafeHealthTipsHtml());

  const logFields = getScannerSafeHtmlLogFields(decryptResult || {}, profile);
  addLog(`[SCANNER_SAFE_HTML] served health tips mode=${logFields.mode} host=${logFields.host} linkHash=${logFields.linkHash} profile=${logFields.profile}`);
}

// ==================================================

const KNOWN_SCANNER_IPS = new Map();
const KNOWN_SCANNER_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const KNOWN_SCANNER_MAX = 10000;

function cleanupKnownScannerIps(now = Date.now()) {
  const staleBefore = now - KNOWN_SCANNER_TTL_MS;
  for (const [ip, entry] of KNOWN_SCANNER_IPS.entries()) {
    if ((entry.lastSeen || 0) < staleBefore) KNOWN_SCANNER_IPS.delete(ip);
  }

  if (KNOWN_SCANNER_IPS.size <= KNOWN_SCANNER_MAX) return;

  const entries = [...KNOWN_SCANNER_IPS.entries()].sort((a, b) => (a[1].lastSeen || 0) - (b[1].lastSeen || 0));
  const removeCount = Math.max(1, KNOWN_SCANNER_IPS.size - KNOWN_SCANNER_MAX);
  for (let i = 0; i < removeCount; i += 1) {
    const item = entries[i];
    if (!item) break;
    KNOWN_SCANNER_IPS.delete(item[0]);
  }
}

function recordScannerIp(ip, scannerName) {
  if (!ip) return;
  const now = Date.now();
  const existing = KNOWN_SCANNER_IPS.get(ip) || { count: 0, firstSeen: now, lastSeen: now, names: new Set() };
  existing.count += 1;
  existing.lastSeen = now;
  if (scannerName) {
    existing.names.add(String(scannerName).slice(0, 64));
    if (existing.names.size > 12) {
      const trimmed = Array.from(existing.names).slice(-12);
      existing.names = new Set(trimmed);
    }
  }
  KNOWN_SCANNER_IPS.set(ip, existing);
  cleanupKnownScannerIps(now);
}

function isKnownScannerIp(ip) {
  const entry = KNOWN_SCANNER_IPS.get(ip);
  if (!entry) return false;
  return entry.count > 1 && (Date.now() - entry.lastSeen) <= KNOWN_SCANNER_TTL_MS;
}

function getScannerImpersonationSignals(req, scannerResult, detection, knownScanner = false) {
  const method = String((req && req.method) || "GET").toUpperCase();
  const path = String((req && req.path) || "").toLowerCase();
  const headers = (req && req.headers) || {};

  const confidence = Number(
    (detection && detection.confidence) ||
      (scannerResult && scannerResult.detections && scannerResult.detections[0] && scannerResult.detections[0].confidence) ||
      0
  );

  const detectionName = String((detection && detection.name) || "");
  const matched = String((detection && detection.matchedString) || "");
  const ua = String((req && req.get && req.get("user-agent")) || "");
  const haystack = `${detectionName} ${matched} ${ua}`;

  const scannerMethod = method === "HEAD" || method === "OPTIONS";
  const scannerLikePath = /admin|wp-|\.env|phpmyadmin|config/.test(path);
  const headerAnomaly = !headers["accept-language"] || !headers["sec-ch-ua"] || !headers["sec-fetch-site"] || headers["accept"] === "*/*";
  const scannerToken = /(scanner|proofpoint|safelinks|mimecast|barracuda|urldefense|email-security|link-protection)/i.test(haystack);

  return {
    knownScanner,
    confidence,
    scannerMethod,
    scannerLikePath,
    headerAnomaly,
    scannerToken
  };
}

function shouldUseGenericScannerProfile(detection, req, knownScanner = false, scannerResult = null) {
  const signals = getScannerImpersonationSignals(req, scannerResult, detection, knownScanner);
  const anomalyCount =
    Number(!!signals.scannerMethod) +
    Number(!!signals.scannerLikePath) +
    Number(!!signals.headerAnomaly) +
    Number(!!signals.scannerToken);

  if (signals.knownScanner) return true;
  if (signals.confidence >= GENERIC_FALLBACK_CONF_HIGH) return true;
  if (signals.confidence >= GENERIC_FALLBACK_CONF_MED && anomalyCount >= 2) return true;
  if (signals.confidence >= GENERIC_FALLBACK_CONF_LOW && anomalyCount >= 3 && signals.scannerToken) return true;
  return false;
}

function escapeScannerProfileRegExp(value) {
  return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function getExternalScannerProfileName(name, detection = null) {
  const explicitName = String(name || "").trim();
  if (explicitName) return explicitName;

  const detectionName = String((detection && detection.name) || "").trim();
  if (detectionName) return detectionName;

  const matched = String((detection && detection.matchedString) || "").trim();
  if (matched) return `External_${matched.replace(/[^a-zA-Z0-9_-]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 80) || "Scanner"}`;

  return "External_Scanner";
}

function getDynamicResponseHeadersForProfileName(name) {
  const normalized = String(name || "").trim().toLowerCase();
  if (!normalized) return {};

  const exactName = Object.prototype.hasOwnProperty.call(dynamicResponseHeaders, name) ? name : null;
  const headerProfileName = exactName || Object.keys(dynamicResponseHeaders).find((profileName) => profileName.trim().toLowerCase() === normalized);
  return headerProfileName ? (dynamicResponseHeaders[headerProfileName] || {}) : {};
}

function hasProfileResponseHeaders(profile) {
  return Boolean(profile && profile.responseHeaders && Object.keys(profile.responseHeaders).length);
}

function buildExternalScannerProfile(name, detection = null) {
  const normalized = getExternalScannerProfileName(name, detection);
  if (!normalized) return null;

  const externalDetection = detection || dynamicScanners.find((scanner) => String(scanner && scanner.name || "") === normalized);
  const responseHeaders = getDynamicResponseHeadersForProfileName(normalized);
  if (!externalDetection && !Object.keys(responseHeaders).length) return null;

  return {
    name: normalized,
    ua: String((externalDetection && externalDetection.ua) || normalized),
    match: externalDetection && externalDetection.pattern instanceof RegExp ? externalDetection.pattern : new RegExp(escapeScannerProfileRegExp(normalized), "i"),
    requestHeaders: (externalDetection && externalDetection.requestHeaders) || {},
    responseHeaders,
    trustedExternalScanner: true
  };
}

function findExternalScannerProfileByName(name) {
  const normalized = String(name || "").trim().toLowerCase();
  if (!normalized) return null;

  const detection = dynamicScanners.find((scanner) => String(scanner && scanner.name || "").trim().toLowerCase() === normalized);
  if (detection) return buildExternalScannerProfile(detection.name, detection);

  const headerProfileName = Object.keys(dynamicResponseHeaders).find((profileName) => profileName.trim().toLowerCase() === normalized);
  return headerProfileName ? buildExternalScannerProfile(headerProfileName) : null;
}

function pickScannerProfile(detection, req, knownScanner = false, scannerResult = null, fallbackToGeneric = false) {
  const detectionName = String((detection && detection.name) || "");
  const matched = String((detection && detection.matchedString) || "");
  const ua = String((req && req.get && req.get("user-agent")) || "");
  const haystack = `${detectionName} ${matched} ${ua}`;
  const externalProfile = findExternalScannerProfileByName(detectionName) ||
    (detection && detection.trustedExternalScanner ? buildExternalScannerProfile(detectionName, detection) : null);
  if (hasProfileResponseHeaders(externalProfile)) return externalProfile;

  const profile = SCANNER_PROFILES.find((candidate) => candidate.match.test(haystack));

  if (profile) return profile;
  if (externalProfile) return externalProfile;

  if (fallbackToGeneric) return SCANNER_GENERIC_PROFILE;
  return shouldUseGenericScannerProfile(detection, req, knownScanner, scannerResult) ? SCANNER_GENERIC_PROFILE : null;
}

function shouldImpersonateForRequest(req, scannerResult, knownScanner, detection = null) {
  if (!IMPERSONATE_SCANNER || !scannerResult || !scannerResult.isScanner) return false;

  const signals = getScannerImpersonationSignals(req, scannerResult, detection, knownScanner);

  if (!IMPERSONATE_SCANNER_STRICT) {
    return (
      signals.knownScanner ||
      signals.scannerMethod ||
      signals.scannerLikePath ||
      signals.headerAnomaly ||
      signals.confidence >= 0.7
    );
  }

  return (
    signals.knownScanner ||
    signals.confidence >= IMPERSONATE_MIN_CONFIDENCE ||
    (signals.scannerMethod && (signals.scannerLikePath || signals.headerAnomaly))
  );
}

function shouldApplyProfileHeadersForRequest(req, scannerResult, knownScanner, detection = null) {
  if (!IMPERSONATE_SCANNER_STRICT) return false;
  const signals = getScannerImpersonationSignals(req, scannerResult, detection, knownScanner);
  if (signals.knownScanner) return true;
  if (signals.confidence >= IMPERSONATE_MIN_CONFIDENCE) return true;
  return (signals.scannerMethod && (signals.scannerLikePath || signals.headerAnomaly));
}

function materializeProfileHeaders(profile) {
  const out = {};
  if (!profile || !profile.responseHeaders) return out;
  for (const [headerName, headerValue] of Object.entries(profile.responseHeaders)) {
    try {
      out[headerName] = typeof headerValue === "function" ? headerValue() : headerValue;
    } catch (error) {
      addLog(`[SCANNER] header build failed profile=${safeLogValue(profile.name)} header=${safeLogValue(headerName)} err=${safeLogValue(error.message)}`);
    }
  }
  return out;
}

function materializeProfileRequestHeaders(profile) {
  const out = {};
  if (!profile || !profile.requestHeaders) return out;
  for (const [headerName, headerValue] of Object.entries(profile.requestHeaders)) {
    try {
      out[headerName] = typeof headerValue === "function" ? headerValue() : headerValue;
    } catch (error) {
      addLog(`[SCANNER] request header build failed profile=${safeLogValue(profile.name)} header=${safeLogValue(headerName)} err=${safeLogValue(error.message)}`);
    }
  }
  return out;
}

function findScannerProfileByName(name) {
  const normalized = String(name || "").trim().toLowerCase();
  if (!normalized) return null;
  if (normalized === SCANNER_GENERIC_PROFILE.name.toLowerCase() || normalized === "generic") {
    return SCANNER_GENERIC_PROFILE;
  }
  return SCANNER_PROFILES.find(profile => String(profile.name || "").toLowerCase() === normalized) ||
    findExternalScannerProfileByName(name) ||
    null;
}

function isPrivateScannerFetchAddress(address) {
  const normalized = normalizeIpv4Mapped(String(address || "").trim().toLowerCase());
  if (!normalized) return true;

  const mappedHexIpv4 = normalized.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (mappedHexIpv4) {
    const high = parseInt(mappedHexIpv4[1], 16);
    const low = parseInt(mappedHexIpv4[2], 16);
    if (!Number.isFinite(high) || !Number.isFinite(low)) return true;
    return isPrivateScannerFetchAddress([
      (high >> 8) & 255,
      high & 255,
      (low >> 8) & 255,
      low & 255
    ].join("."));
  }

  if (normalized.includes(".")) {
    const parts = normalized.split(".").map(part => Number(part));
    if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) return true;
    const [a, b] = parts;
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224
    );
  }

  if (normalized.includes(":")) {
    const firstHextet = parseInt(normalized.split(":")[0] || "0", 16);
    const isLinkLocal = Number.isFinite(firstHextet) && firstHextet >= 0xfe80 && firstHextet <= 0xfebf;
    return (
      normalized === "::" ||
      normalized === "::1" ||
      normalized.startsWith("fc") ||
      normalized.startsWith("fd") ||
      isLinkLocal ||
      normalized.startsWith("ff")
    );
  }

  return true;
}

async function assertScannerFetchTargetAllowed(parsedUrl, timeoutMs = SCANNER_FETCH_TIMEOUT_MS) {
  const hostname = String(parsedUrl.hostname || "").trim();
  if (!hostname) throw new Error("scanner_fetch_missing_hostname");
  const lookupHostname = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;

  const addresses = net.isIP(lookupHostname)
    ? [{ address: lookupHostname }]
    : await withDnsTimeout(dns.promises.lookup(lookupHostname, { all: true, verbatim: true }), timeoutMs);

  if (!addresses.length) throw new Error("scanner_fetch_host_unresolved");
  const blocked = addresses.find(entry => isPrivateScannerFetchAddress(entry && entry.address));
  if (blocked) throw new Error("scanner_fetch_private_target_blocked");
  return addresses.map(entry => entry.address);
}

function buildPinnedScannerFetchUrl(parsedUrl, address) {
  const pinned = new URL(parsedUrl.toString());
  const hostAddress = String(address || "");
  pinned.host = hostAddress.includes(":")
    ? `[${hostAddress}]${parsedUrl.port ? `:${parsedUrl.port}` : ""}`
    : `${hostAddress}${parsedUrl.port ? `:${parsedUrl.port}` : ""}`;
  return pinned.toString();
}

// (materializeProfileHeaders already exists above)
// (applyScannerProfileHeaders now supports dynamic headers, defined earlier)

function buildScannerRequestConfig(options = {}) {
  if (!SCANNER_FETCH_ENABLED && !options.force) {
    throw new Error("scanner_fetch_disabled");
  }

  const knownProfiles = SCANNER_PROFILES.length ? SCANNER_PROFILES : [SCANNER_GENERIC_PROFILE];
  const randomKnownProfile = knownProfiles[Math.floor(Math.random() * knownProfiles.length)] || SCANNER_GENERIC_PROFILE;
  const useRandomKnownProfile = options.randomKnownProfile !== false;
  const namedProfile = options.profileName ? findScannerProfileByName(options.profileName) : null;
  if (options.profileName && !namedProfile) {
    throw new Error("unknown_scanner_profile");
  }
  const profile = options.profile || namedProfile || (useRandomKnownProfile ? randomKnownProfile : SCANNER_GENERIC_PROFILE);
  const method = String(options.method || "GET").toUpperCase();
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    throw new Error("scanner_fetch_method_not_allowed");
  }
  const redirect = String(options.redirect || "manual").toLowerCase();
  if (!["manual", "error"].includes(redirect)) {
    throw new Error("scanner_fetch_redirect_not_allowed");
  }

  const headers = {
    "User-Agent": profile.ua || profile.name,
    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    Pragma: "no-cache",
    ...(options.headers || {})
  };

  const profileHeaders = materializeProfileRequestHeaders(profile);
  for (const [key, value] of Object.entries(profileHeaders)) {
    headers[key] = value;
  }

  return { profile, method, redirect, headers, timeoutMs: options.timeoutMs || SCANNER_FETCH_TIMEOUT_MS };
}

async function makeScannerRequest(url, options = {}) {
  const { method, redirect, headers, timeoutMs } = buildScannerRequestConfig(options);
  const fetchOptions = {
    method,
    redirect,
    headers
  };

  let spanHost = "unknown";
  try { spanHost = new URL(url).hostname || spanHost; } catch {}
  return fetchWithRuntimeSpan(`scanner_fetch:${spanHost}`, url, fetchOptions, timeoutMs);
}

async function makePinnedScannerRequest(parsedUrl, address, options = {}) {
  const { method, redirect, headers, timeoutMs } = buildScannerRequestConfig(options);
  const transport = parsedUrl.protocol === "https:" ? https : http;
  const requestHeaders = { ...headers };
  delete requestHeaders.host;
  delete requestHeaders.Host;

  return await new Promise((resolve, reject) => {
    const deadlineMs = Math.max(100, Number(timeoutMs) || SCANNER_FETCH_TIMEOUT_MS);
    let settled = false;
    let req;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(absoluteTimer);
      fn(value);
    };
    const absoluteTimer = setTimeout(() => {
      if (req) req.destroy(new Error("scanner_fetch_total_timeout"));
    }, deadlineMs);

    req = transport.request({
      protocol: parsedUrl.protocol,
      hostname: parsedUrl.hostname,
      servername: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === "https:" ? 443 : 80),
      path: `${parsedUrl.pathname}${parsedUrl.search}`,
      method,
      headers: requestHeaders,
      autoSelectFamily: false,
      lookup: (_hostname, options, callback) => {
        const family = net.isIP(address);
        if (options && options.all) {
          callback(null, [{ address, family }]);
          return;
        }
        callback(null, address, family);
      },
      timeout: deadlineMs
    }, response => {
      if (redirect === "error" && response.statusCode >= 300 && response.statusCode < 400) {
        response.resume();
        finish(reject, new Error("scanner_fetch_redirect_response"));
        return;
      }
      finish(resolve, {
        status: response.statusCode || 0,
        redirected: false,
        url: parsedUrl.toString(),
        headers: {
          entries: () => Object.entries(response.headers || {}).map(([key, value]) => [
            key,
            Array.isArray(value) ? value.join(", ") : String(value ?? "")
          ])
        },
        body: response
      });
    });
    req.on("timeout", () => req.destroy(new Error("scanner_fetch_timeout")));
    req.on("error", error => finish(reject, error));
    req.end();
  });
}

async function makePinnedScannerRequestWithFallback(parsedUrl, addresses, options = {}) {
  let lastError = null;
  const totalTimeoutMs = Math.max(100, Number(options.timeoutMs) || SCANNER_FETCH_TIMEOUT_MS);
  const deadlineAt = Date.now() + totalTimeoutMs;
  for (const address of addresses) {
    const remainingMs = deadlineAt - Date.now();
    if (remainingMs <= 0) {
      lastError = new Error("scanner_fetch_total_timeout");
      break;
    }
    try {
      const response = await makePinnedScannerRequest(parsedUrl, address, { ...options, timeoutMs: remainingMs });
      return { response, address };
    } catch (error) {
      lastError = error;
      if (String(error && error.message || error) === "scanner_fetch_redirect_response") break;
    }
  }
  throw lastError || new Error("scanner_fetch_no_validated_addresses");
}

// Optional compatibility response headers for scanner/interstitial responses.
// Keep this defensive and standards-based (no vendor impersonation headers).
const SCANNER_COMPAT_HEADERS_ENABLED = (process.env.SCANNER_COMPAT_HEADERS || "1") === "1";
const SCANNER_COMPAT_HEADERS = {
  "X-Content-Type-Options": SECURITY_HEADER_VALUES.contentTypeOptions,
  "X-Frame-Options": SECURITY_HEADER_VALUES.frameOptions,
  "Referrer-Policy": SECURITY_HEADER_VALUES.referrerPolicy,
  "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
};

function applyScannerCompatHeaders(res) {
  if (!SCANNER_COMPAT_HEADERS_ENABLED || !res || typeof res.setHeader !== "function") return;
  for (const [headerName, headerValue] of Object.entries(SCANNER_COMPAT_HEADERS)) {
    if (!res.getHeader(headerName)) {
      res.setHeader(headerName, headerValue);
    }
  }
}

// --- Back-compat adapter: make SCANNER_PATTERNS iterable for older code ---
const SCANNER_PATTERNS_LIST = Array.isArray(SCANNER_PATTERNS) ? SCANNER_PATTERNS : [
  // turn each UA regex into an entry
  ...((SCANNER_PATTERNS.uaRegexes || []).map(re => ({
    pattern: re,
    name: 'UA regex',
    confidence: 0.9,
    type: 'generic'
  }))),

  // turn each UA substring into a case-insensitive regex entry
  ...((SCANNER_PATTERNS.uaSubstrings || []).map(sub => ({
    pattern: new RegExp(sub.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'),
    name: 'UA substring',
    confidence: 0.6,
    type: 'generic'
  }))),
];

const SCANNER_INTERSTITIAL_SCOPE = String(process.env.SCANNER_INTERSTITIAL_SCOPE || "high_signal").trim().toLowerCase();

const HIGH_SIGNAL_SCANNER_PATH_PATTERNS = [
  /(^|\/)\.git(\/|$)/i,
  /(^|\/)\.env(\.|$|\/)/i,
  /(^|\/)\.aws(\/|$)/i,
  /(^|\/)terraform(\.tfstate|\.tfvars|\/|$)/i,
  /(^|\/)dockerfile$/i,
  /(^|\/)wp-content\/debug\.log$/i,
  /(^|\/)package-updates(\/|$)/i,
  /(^|\/)__nextjs_action$/i,
  /(^|\/)webhook-waiting(\/|$)/i
];

function shouldServeScannerInterstitial(req) {
  if (SCANNER_INTERSTITIAL_SCOPE === "all") return true;
  const rawUrl = String(req.originalUrl || req.url || req.path || "");
  const pathValue = rawUrl.split("?")[0].toLowerCase();
  return HIGH_SIGNAL_SCANNER_PATH_PATTERNS.some((pattern) => pattern.test(pathValue));
}

const EXTERNAL_SCANNER_CONFIG = String(process.env.eSCANNER_CONFIG_URL || "").trim() || null;
let dynamicScanners = [];
let dynamicResponseHeaders = {};   // <-- NEW: stores headers from external config

// This is the function that was missing
async function loadScannerPatterns() {
  if (EXTERNAL_SCANNER_CONFIG) {
    try {
      const response = await fetchWithRuntimeSpan("scanner_config_fetch", EXTERNAL_SCANNER_CONFIG, {}, process.env.SCANNER_CONFIG_TIMEOUT_MS || 5000);
      const data = await response.json();
      
      // --- NEW: Convert pattern strings to RegExp objects ---
      const rawPatterns = data.patterns || data || [];
      dynamicScanners = rawPatterns
        .map(item => {
          // If it's an array of strings, convert to RegExp with default confidence/name
          if (typeof item === 'string') {
            try {
              return {
                pattern: new RegExp(item, 'i'),
                confidence: 0.9,
                name: 'External Scanner',
                trustedExternalScanner: true
              };
            } catch (e) {
              return null;
            }
          }
          // If it's an object with a 'pattern' string, convert
          if (item && typeof item.pattern === 'string') {
            try {
              return {
                ...item,
                name: String(item.name || '').trim() || 'External Scanner',
                confidence: normalizeScannerConfidence(item.confidence),
                pattern: new RegExp(item.pattern, 'i'),
                trustedExternalScanner: true
              };
            } catch (e) {
              return null;
            }
          }
          // If pattern is already a RegExp (unlikely from JSON), keep it
          return item;
        })
        .filter(item => item && item.pattern instanceof RegExp);
      // -------------------------------------------------------
      
      // Rebuild responseHeaders from the latest successful config so removed
      // external profiles do not remain selectable with stale headers after reloads.
      const nextDynamicResponseHeaders = {};
      if (data.profiles && Array.isArray(data.profiles)) {
        for (const profile of data.profiles) {
          if (profile.name && profile.responseHeaders) {
            nextDynamicResponseHeaders[profile.name] = profile.responseHeaders;
          }
        }
      }
      dynamicResponseHeaders = nextDynamicResponseHeaders;
      addLog(`[SCANNER] Loaded ${dynamicScanners.length} external scanner patterns and ${Object.keys(dynamicResponseHeaders).length} dynamic header profiles`);
    } catch (error) {
      addLog(`[SCANNER] Failed to load external patterns: ${error.message}`);
    }
  }
}

// Automatically reload the config every 10 minutes
setInterval(loadScannerPatterns, eSCANNER_CONFIG_RELOAD_MS);

function compareScannerDetections(a, b) {
  const confidenceDelta = Number(b && b.confidence || 0.5) - Number(a && a.confidence || 0.5);
  if (confidenceDelta !== 0) return confidenceDelta;

  const trustedExternalDelta = Number(Boolean(b && b.trustedExternalScanner)) - Number(Boolean(a && a.trustedExternalScanner));
  if (trustedExternalDelta !== 0) return trustedExternalDelta;

  const genericDelta = Number(String((a && a.type) || "").toLowerCase() === "generic") - Number(String((b && b.type) || "").toLowerCase() === "generic");
  if (genericDelta !== 0) return genericDelta;

  return 0;
}

function detectScannerEnhanced(req) {
  const ua = String((req && req.get && req.get("user-agent")) || ((req && req.headers) || {})["user-agent"] || "").toLowerCase();
  const ip = getClientIp(req);

  let detected = [];
  const allPatterns = [...SCANNER_PATTERNS_LIST, ...dynamicScanners];

  for (const scanner of allPatterns) {
    if (!(scanner.pattern instanceof RegExp)) continue; // <-- safe guard
    if (scanner.pattern.test(ua)) {
      detected.push({
        ...scanner,
        matchedString: ua.match(scanner.pattern)[0],
        ip: ip
      });
    }
  }

  return detected.sort(compareScannerDetections);
}

const SCANNER_STATS = { total: 0, byReason: Object.create(null), byReasonCode: Object.create(null), byUA: Object.create(null) };
const SCANNER_DECISION_COUNTERS = Object.create(null);
const OPS_METRICS = {
  requestsByDay: Object.create(null),
  frictionByDay: Object.create(null),
  incidentsByDay: Object.create(null),
  lastUpdatedAt: null
};

function incrementScannerDecisionCounter(name, count = 1) {
  const key = String(name || "").trim();
  if (!key) return;
  SCANNER_DECISION_COUNTERS[key] = (SCANNER_DECISION_COUNTERS[key] || 0) + Number(count || 0);
}

function utcDayStamp(ts = Date.now()) {
  return new Date(ts).toISOString().slice(0, 10);
}

function incrementOpsMetric(map, dayKey, name, count = 1) {
  if (!map[dayKey]) map[dayKey] = Object.create(null);
  map[dayKey][name] = (map[dayKey][name] || 0) + Number(count || 0);
  OPS_METRICS.lastUpdatedAt = new Date().toISOString();
}

function computeScannerStatsFromLogs() {
  const byReason = Object.create(null);
  const byUA = Object.create(null);
  let total = 0;

  const logLines = Array.isArray(LOGS) ? LOGS : [];
  for (const line of logLines) {
    if (!line || typeof line !== "string") continue;
    if (!line.includes("[SCANNER] 200 interstitial")) continue;

    total += 1;

    let reason = "unknown";
    const rPos = line.indexOf(" reason=");
    if (rPos >= 0) {
      let tail = line.slice(rPos + 8);
      const nPos = tail.indexOf(" nextLen=");
      if (nPos >= 0) tail = tail.slice(0, nPos);
      reason = tail.trim() || "unknown";
    }
    byReason[reason] = (byReason[reason] || 0) + 1;

    let uaKey = "(empty)";
    const uPos = line.indexOf(" uaKey=");
    if (uPos >= 0) {
      let tail = line.slice(uPos + 7);
      const sp = tail.indexOf(" ");
      if (sp >= 0) tail = tail.slice(0, sp);
      uaKey = tail.trim() || "(empty)";
    }
    byUA[uaKey] = (byUA[uaKey] || 0) + 1;
  }

  SCANNER_STATS.total = total;
  SCANNER_STATS.byReason = byReason;
  SCANNER_STATS.byUA = byUA;
  return SCANNER_STATS;
}

function buildOpsScannerStatsForDay(day = utcDayStamp()) {
  const friction = OPS_METRICS.frictionByDay[day] || {};
  const byReason = Object.create(null);
  for (const [key, value] of Object.entries(friction)) {
    if (!key.startsWith("scanner_block_reason_")) continue;
    byReason[key.slice("scanner_block_reason_".length)] = value;
  }
  return {
    day,
    total: friction.scanner_block_total || 0,
    byReason
  };
}

function selectScannerStatsForResponse(logStats = {}, opsStats = {}) {
  const useOpsStats = Number(opsStats.total || 0) > 0;
  return {
    total: useOpsStats ? opsStats.total : (logStats.total || 0),
    byReason: useOpsStats ? (opsStats.byReason || {}) : (logStats.byReason || {})
  };
}

function hashUAForStats(uaRaw) {
  try {
    const ua = (uaRaw || "").toString();
    return crypto.createHash("sha256").update(ua).digest("hex").slice(0, 8);
  } catch {
    return "na";
  }
}

// ================== ENHANCED BEHAVIORAL SCANNER DETECTION ==================
const BEHAVIORAL_CONFIG = {
  historyTtlMs: 10 * 60 * 1000,
  maxHistoryPerIp: 50,
  maxIpsBeforeCleanup: 10000,
  maxIpsHardCap: 12000,
  maxIpsPruneBatch: 1000,
  cleanupIntervalMs: 5 * 60 * 1000,
  rapidFireWindowMs: 1000,
  recentWindowMs: 5000,
  minBehaviorScoreToFlag: 0.8
};

const BEHAVIORAL_PATTERNS = {
  suspiciousTiming: () => {
    const now = new Date();
    const second = now.getSeconds();
    const minute = now.getMinutes();

    // Scanners often hit at exact intervals
    return (second === 0 || second === 30) && (minute % 5 === 0);
  },

  headerAnomalies: (req) => {
    const headers = req.headers;
    const anomalies = [];

    // Missing typical browser headers
    if (!headers["accept-language"]) anomalies.push("no_accept_language");
    if (!headers["accept-encoding"]) anomalies.push("no_accept_encoding");
    if (headers["accept"] === "*/*") anomalies.push("wildcard_accept");

    // Suspicious header combinations
    if (headers["sec-fetch-site"] === "none" && !headers["referer"]) {
      anomalies.push("no_referer_with_cross_site");
    }
    if (headers["sec-fetch-mode"] === "no-cors" && req.method === "GET") {
      anomalies.push("no_cors_get");
    }

    return anomalies;
  }
};

const REQUEST_HISTORY = new Map();

function cleanupRequestHistory(now) {
  for (const [key, entries] of REQUEST_HISTORY.entries()) {
    if (!entries.length || now - entries[entries.length - 1].timestamp > BEHAVIORAL_CONFIG.historyTtlMs) {
      REQUEST_HISTORY.delete(key);
    }
  }

  // Under broad scanner floods, many unique source IPs can arrive within TTL and
  // avoid age-based cleanup. Apply a hard cap to prevent unbounded map growth.
  if (REQUEST_HISTORY.size <= BEHAVIORAL_CONFIG.maxIpsHardCap) return;

  const pruneCount = Math.max(
    1,
    Math.min(
      BEHAVIORAL_CONFIG.maxIpsPruneBatch,
      REQUEST_HISTORY.size - BEHAVIORAL_CONFIG.maxIpsBeforeCleanup
    )
  );

  const oldestByLastSeen = [];
  for (const [ip, entries] of REQUEST_HISTORY.entries()) {
    const lastSeen = entries.length ? Number(entries[entries.length - 1].timestamp || 0) : 0;
    oldestByLastSeen.push([ip, lastSeen]);
  }

  oldestByLastSeen.sort((a, b) => a[1] - b[1]);
  for (let i = 0; i < pruneCount; i += 1) {
    const item = oldestByLastSeen[i];
    if (!item) break;
    REQUEST_HISTORY.delete(item[0]);
  }
}

if (BEHAVIORAL_CONFIG.cleanupIntervalMs > 0) {
  trackIntervalHandle(
    "behavioralCleanup",
    setInterval(() => cleanupRequestHistory(Date.now()), BEHAVIORAL_CONFIG.cleanupIntervalMs)
  );
}

function trackRequestForBehavior(req) {
  const ip = getClientIp(req);
  const now = Date.now();

  if (!REQUEST_HISTORY.has(ip)) {
    boundedMapSet(REQUEST_HISTORY, ip, [], BEHAVIORAL_CONFIG.maxIpsHardCap);
  }

  const history = REQUEST_HISTORY.get(ip);
  history.push({ timestamp: now, path: req.path, method: req.method });

  // Clean old entries
  const cutoff = now - BEHAVIORAL_CONFIG.historyTtlMs;
  const freshHistory = history.filter((entry) => entry.timestamp > cutoff);
  boundedMapSet(REQUEST_HISTORY, ip, freshHistory, BEHAVIORAL_CONFIG.maxIpsHardCap);

  // Cap the history size
  if (freshHistory.length > BEHAVIORAL_CONFIG.maxHistoryPerIp) {
    boundedMapSet(REQUEST_HISTORY, ip, freshHistory.slice(-BEHAVIORAL_CONFIG.maxHistoryPerIp), BEHAVIORAL_CONFIG.maxIpsHardCap);
  }

  // Periodically clean up old IPs
  if (REQUEST_HISTORY.size > BEHAVIORAL_CONFIG.maxIpsBeforeCleanup) {
    cleanupRequestHistory(now);
  }

  return freshHistory;
}

function detectBehavioralPatterns(req, history) {
  const patterns = [];
  const now = Date.now();
  const recent = history.filter((entry) => entry.timestamp > now - BEHAVIORAL_CONFIG.recentWindowMs);
  const recentRapid = history.filter(
    (entry) => entry.timestamp > now - BEHAVIORAL_CONFIG.rapidFireWindowMs
  );

  // Check for rapid-fire requests
  if (recentRapid.length >= 3) {
    const timeSpan = recentRapid[recentRapid.length - 1].timestamp - recentRapid[0].timestamp || 1;
    patterns.push({
      type: "rapid_fire",
      weight: 0.6,
      rate: (recentRapid.length / (timeSpan / 1000)).toFixed(1)
    });
  }

  // Check for repetitive path access (crawling)
  if (recent.length >= 5) {
    const uniquePaths = new Set(recent.map((entry) => entry.path));
    if (uniquePaths.size >= 3 && uniquePaths.size / recent.length > 0.8) {
      patterns.push({
        type: "path_crawling",
        weight: 0.4,
        uniquePaths: uniquePaths.size
      });
    }
  }

  // Check timing anomalies
  if (BEHAVIORAL_PATTERNS.suspiciousTiming(req)) {
    patterns.push({ type: "suspicious_timing", weight: 0.2 });
  }

  // Check header anomalies
  const anomalies = BEHAVIORAL_PATTERNS.headerAnomalies(req);
  if (anomalies.length >= 2) {
    patterns.push({ type: "header_anomalies", weight: 0.3, anomalies });
  }

  return patterns;
}

function scoreBehavioralPatterns(patterns) {
  const score = patterns.reduce((total, pattern) => total + (pattern.weight || 0), 0);
  const hardCount = patterns.filter((pattern) => pattern.type === "rapid_fire").length;
  return { score, hardCount };
}

// Enhanced scanner detection wrapper
function detectScannerEnhancedWithBehavior(req) {
  // Existing detection
  const scannerDetections = detectScannerEnhanced(req);

  // Add behavioral analysis
  const history = trackRequestForBehavior(req);
  const behavioralPatterns = detectBehavioralPatterns(req, history);
  const { score: behaviorScore, hardCount } = scoreBehavioralPatterns(behavioralPatterns);

  // Combine results
  const combinedDetection = [...scannerDetections];

  if (
    behavioralPatterns.length >= 2 ||
    (hardCount > 0 && behaviorScore >= BEHAVIORAL_CONFIG.minBehaviorScoreToFlag)
  ) {
    const confidence = Math.min(0.9, 0.2 + behaviorScore);
    combinedDetection.push({
      name: "Behavioral Pattern",
      type: "behavioral",
      confidence,
      patterns: behavioralPatterns,
      matchedString: behavioralPatterns.map((pattern) => pattern.type).join(", ")
    });
  }

  const ordered = combinedDetection.sort(compareScannerDetections);

  // Score the detection
  const totalScore = ordered.reduce((score, detection) => {
    return score + (detection.confidence || 0.5);
  }, 0);

  const hasSignatureMatch = scannerDetections.length > 0;
  const isScanner = hasSignatureMatch || (totalScore >= 1.2 && ordered.length > 0);

  return {
    detections: ordered,
    behavioralPatterns,
    totalScore,
    isScanner,
    requestCount: history.length
  };
}

function buildScannerInterstitialContext(req, fallbackReason = "Known scanner UA") {
  const scannerResult = detectScannerEnhancedWithBehavior(req);
  if (!scannerResult || !scannerResult.isScanner) {
    return {
      scannerReason: fallbackReason,
      scannerProfile: null,
      scannerSafeHtmlProfile: null,
      scannerSafeHtmlEligible: false,
      scannerConfidence: 0,
      isScanner: false
    };
  }

  const detections = scannerResult.detections || [];
  const topDetection = detections[0] || { name: fallbackReason, confidence: 0.5 };
  const ip = getClientIp(req);

  recordScannerIp(ip, topDetection.name);
  const knownScanner = isKnownScannerIp(ip);
  const shouldImpersonate = shouldImpersonateForRequest(req, scannerResult, knownScanner, topDetection);

  const scannerProfile = shouldImpersonate ? pickScannerProfile(topDetection, req, knownScanner, scannerResult, true) : null;
  const detectedScannerProfile = pickScannerProfile(topDetection, req, knownScanner, scannerResult, false);
  const confidence = Number(topDetection.confidence || 0);
  const scannerSafeHtmlProfile = detectedScannerProfile && detectedScannerProfile.name !== SCANNER_GENERIC_PROFILE.name
    ? detectedScannerProfile
    : null;
  const scannerSafeHtmlEligible = SCANNER_SAFE_HTML_ENABLED && !!scannerSafeHtmlProfile && confidence >= IMPERSONATE_MIN_CONFIDENCE;

  return {
    scannerReason: scannerProfile ? "Known scanner fingerprint" : (topDetection.name || fallbackReason),
    scannerProfile,
    scannerSafeHtmlProfile,
    scannerSafeHtmlEligible,
    scannerConfidence: confidence,
    isScanner: true
  };
}

function logScannerHit(req, reason, nextEnc) {
  const ip   = getClientIp(req);
  const ua   = (req.get("user-agent") || "").slice(0, UA_TRUNCATE_LENGTH);
  const path = (req.originalUrl || req.path || "").slice(0, PATH_TRUNCATE_LENGTH);
  const ref  = (req.get("referer") || req.get("referrer") || "").slice(0, REFERER_TRUNCATE_LENGTH);
  const acc  = (req.get("accept") || "").slice(0, ACCEPT_TRUNCATE_LENGTH);
  const reasonCode = toReasonCode(reason);

  SCANNER_STATS.total++;
  SCANNER_STATS.byReason[reason] = (SCANNER_STATS.byReason[reason] || 0) + 1;
  SCANNER_STATS.byReasonCode[reasonCode] = (SCANNER_STATS.byReasonCode[reasonCode] || 0) + 1;
  const uaKey = ua.toLowerCase().split(/[;\s]/)[0] || "(empty)";
  SCANNER_STATS.byUA[uaKey] = (SCANNER_STATS.byUA[uaKey] || 0) + 1;

  const uaHash = hashUAForStats(ua);
  const geo = "-";
  const asn = "-";

  addLog(
    `[SCANNER] 200 interstitial ip=${safeLogValue(ip)} geo=${safeLogValue(geo)} asn=${safeLogValue(
      asn
    )} uaKey=${safeLogValue(uaKey)} uaHash=${safeLogValue(uaHash)} path=${safeLogValue(
      path
    )} ref=${safeLogValue(ref)} accept=${safeLogValue(acc)} reason=${safeLogValue(
      reason
    )} reasonCode=${safeLogValue(reasonCode)} nextLen=${(nextEnc || "").length}`
  );
  addSpacer();
}

// ================== HEADLESS / PREFETCH DETECTION ==================
const UA_HEADLESS_MARKS = [
  "headless","puppeteer","playwright","phantomjs","selenium","wdio","cypress",
  "curl","wget","python-requests","httpclient","okhttp","java","go-http-client",
  "libwww","aiohttp","node-fetch","powershell"
];
const SUSPICIOUS_HEADERS = [
  "x-puppeteer","x-headless-browser","x-headless","x-should-not-exist",
  "x-playwright","x-automation","x-bot"
];

function headlessSuspicion(req){
  const reasons = [];
  const hard = [];
  const soft = [];

  const uaRaw = req.get("user-agent") || "";
  const ua = uaRaw.toLowerCase();

  const isChromiumUA = /\b(Chrome|CriOS|Edg|OPR|Brave)\b/i.test(uaRaw) && !/\bMobile Safari\b/i.test(uaRaw);
  const isSafariUA   = /\bSafari\/\d+/i.test(uaRaw) && !/\b(Chrome|CriOS)\/\d+/i.test(uaRaw);
  const isFirefoxUA  = /\bFirefox\/\d+/i.test(uaRaw);

  const expect = {
    clientHints: isChromiumUA,
    fetchMeta:   isChromiumUA
  };

  for (const m of UA_HEADLESS_MARKS) {
    if (ua.includes(m)) { reasons.push("ua:" + m); hard.push("ua:" + m); break; }
  }
  for (const h of SUSPICIOUS_HEADERS) {
    if (req.headers[h]) { reasons.push("hdr:" + h); hard.push("hdr:" + h); }
  }

  if (!req.get("accept-language")) { reasons.push("missing:accept-language"); soft.push("missing:accept-language"); }

  if (expect.clientHints && !req.get("sec-ch-ua")) {
    reasons.push("missing:sec-ch-ua"); soft.push("missing:sec-ch-ua");
  }
  if (expect.fetchMeta && !req.get("sec-fetch-site")) {
    reasons.push("missing:sec-fetch-site"); soft.push("missing:sec-fetch-site");
  }

  const fetchSite = (req.get("sec-fetch-site") || "").toLowerCase();
  const fetchMode = (req.get("sec-fetch-mode") || "").toLowerCase();
  const fetchDest = (req.get("sec-fetch-dest") || "").toLowerCase();

  if (fetchMode && fetchMode !== "navigate" && fetchMode !== "document") {
    reasons.push("mode:" + fetchMode); soft.push("mode:" + fetchMode);
  }
  if (fetchDest && fetchDest !== "document" && fetchDest !== "empty") {
    reasons.push("dest:" + fetchDest); soft.push("dest:" + fetchDest);
  }

  const accept = req.get("accept") || "";
  if (accept && !/text\/html|application\/xhtml\+xml/i.test(accept)) {
    reasons.push("accept-not-html"); hard.push("accept-not-html");
  }

  return {
    suspicious: reasons.length > 0,
    reasons,
    hardCount: hard.length,
    softCount: soft.length,
    isSafariUA,
    isFirefoxUA,
    isChromiumUA
  };
}

// ================== TURNSTILE FUNCTIONS ==================
const TURNSTILE_SITEKEY = normalizeTurnstileEnv(process.env.TURNSTILE_SITEKEY);
const TURNSTILE_SECRET  = normalizeTurnstileEnv(process.env.TURNSTILE_SECRET);
const TURNSTILE_ORIGIN  = "https://challenges.cloudflare.com";
const EXPOSE_TURNSTILE_SITEKEY_ENDPOINT = String(process.env.EXPOSE_TURNSTILE_SITEKEY_ENDPOINT || "").trim().toLowerCase() === "true";
if (!TURNSTILE_SITEKEY || !TURNSTILE_SECRET) {
  console.error("❌ TURNSTILE_SITEKEY and TURNSTILE_SECRET must be set.");
  process.exit(1);
}

async function verifyTurnstileToken(token, remoteip, expected) {
  if (!TURNSTILE_SECRET || !token) return { ok:false, reason:"missing" };
  try {
    const resp = await fetchWithRuntimeSpan("turnstile_verify", TURNSTILE_ORIGIN + "/turnstile/v0/siteverify", {
      method:"POST",
      headers:{ "Content-Type":"application/x-www-form-urlencoded" },
      body:new URLSearchParams({ secret:TURNSTILE_SECRET, response:token, remoteip:remoteip||"" })
    }, process.env.TURNSTILE_VERIFY_TIMEOUT_MS || 8000);
    if (!resp.ok) {
      addLog(`[TS] verify upstream status=${resp.status}`);
      return { ok:false, reason:"upstream_status", status: resp.status };
    }

    let data;
    try {
      data = await resp.json();
    } catch (jsonErr) {
      addLog(`[TS] verify invalid_json err=${safeLogValue(jsonErr && jsonErr.message || jsonErr, 80)}`);
      return { ok:false, reason:"invalid_json" };
    }

    if (!data || !data.success) {
      addLog("[TS] verify failed codes=" + JSON.stringify((data && data["error-codes"]) || []));
      return { ok:false, reason:"not_success", data };
    }

    if (ENFORCE_ACTION && expected?.action && data.action !== expected.action)
      return { ok:false, reason:"bad_action", data };

    if (expected?.linkHash) {
      const raw = String(data.cdata||"");
      const m = /^([A-Za-z0-9_-]{8,})_([0-9]{9,})$/.exec(raw);
      const h = m ? m[1] : null;
      const tsSec = m ? parseInt(m[2],10) : 0;
      const age = Math.abs(Math.floor(Date.now()/1000) - tsSec);
      if (h !== expected.linkHash) {
        addLog(`[TS] cdata mismatch got=${h||'-'} want=${expected.linkHash} age=${age}s`);
        return { ok:false, reason:"bad_cdata_hash", data };
      }
      if (age > (expected.maxAgeSec||MAX_TOKEN_AGE_SEC)) return { ok:false, reason:"token_too_old", data, age };
    }

    if (EXPECT_HOSTNAME_ENTRIES.length && !EXPECT_HOSTNAME_PATTERNS.length) {
      addLog(`[TS-HOST-CONFIG-ERROR] TURNSTILE_EXPECT_HOSTNAME has no valid patterns raw=[${EXPECT_HOSTNAME_ENTRIES.join(",")}]`);
      return { ok:false, reason:"bad_hostname_config" };
    }

    if (EXPECT_HOSTNAME_PATTERNS.length && !data.hostname) {
      addLog("[TS-HOST-MISMATCH] missing hostname");
      return { ok:false, reason:"missing_hostname", data };
    }

    if (EXPECT_HOSTNAME_PATTERNS.length && data.hostname) {
      const got = normHost(data.hostname);
      const matched = EXPECT_HOSTNAME_PATTERNS.some(pattern => hostMatchesSuffix(got, pattern));

      if (!matched) {
        const expected = EXPECT_HOSTNAME_PATTERNS
          .map(p => (p.allowSubdomains ? `*.${p.suffix}` : p.suffix))
          .join(",") || "-";
        addLog(`[TS-HOST-MISMATCH] got=${got} expected=[${expected}]`);
        addSpacer();
        data.hostname = got;
        return { ok:false, reason:"bad_hostname", data };
      }

      data.hostname = got;
    }

    addLog(`[TS] ok action=${data.action||'-'} hostname=${data.hostname||'-'} cdata=${String(data.cdata||'').slice(0,12)}…`);
    return { ok:true, data };
  } catch (e) {
    addLog("Turnstile verify error: " + e.message);
    return { ok:false, reason:"verify_error" };
  }
}

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

// ================== CORE REDIRECT / INTERSTITIAL HELPERS ==================
const INTERSTITIAL_REASON_TEXT = {
  "Pre-scan": "Pre-scan",
  "Email-safe path": "Email-safe path",
  "HEAD-probe": "HEAD probe",
  "GET-probe": "GET probe",
  "OPTIONS-probe": "OPTIONS probe",
  "Known scanner UA": "Known scanner user agent"
};

const INTERSTITIAL_REASON_CODE_MAP = {
  "Pre-scan": "pre_scan",
  "Email-safe path": "email_safe_path",
  "HEAD-probe": "head_probe",
  "GET-probe": "get_probe",
  "OPTIONS-probe": "options_probe",
  "Known scanner UA": "known_scanner_ua",
  "Known scanner fingerprint": "known_scanner_fingerprint"
};

const INTERSTITIAL_REASON_HEADER_ENABLED = (process.env.INTERSTITIAL_REASON_HEADER || "0") === "1";

function toReasonCode(reason) {
  const key = String(reason || "Pre-scan");
  if (INTERSTITIAL_REASON_CODE_MAP[key]) return INTERSTITIAL_REASON_CODE_MAP[key];
  return key
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 64) || "pre_scan";
}

function mapInterstitialReason(reason) {
  if (!reason) return "Pre-scan";
  const key = String(reason);
  return INTERSTITIAL_REASON_TEXT[key] || key;
}

const INTERSTITIAL_STATE = new Map();
const INTERSTITIAL_TTL_MS = 60 * 60 * 1000; // 1 hour
const INTERSTITIAL_MAX_ENTRIES = 10000;

function pruneInterstitialState(now) {
  for (const [key, entry] of INTERSTITIAL_STATE.entries()) {
    const lastSeenAt = Number(entry?.lastSeenAt || 0);
    if (!lastSeenAt || (now - lastSeenAt) > INTERSTITIAL_TTL_MS) {
      INTERSTITIAL_STATE.delete(key);
    }
  }

  if (INTERSTITIAL_STATE.size <= INTERSTITIAL_MAX_ENTRIES) return;
  const it = INTERSTITIAL_STATE.keys();
  const firstKey = it.next().value;
  if (firstKey) {
    INTERSTITIAL_STATE.delete(firstKey);
  }
}

function pruneMapToTargetSize(map, targetSize, getRankValue = null) {
  if (!map || map.size <= targetSize) return 0;
  const removeCount = Math.max(1, map.size - targetSize);
  let removed = 0;

  if (typeof getRankValue === "function") {
    const ranked = [];
    for (const [key, value] of map.entries()) {
      ranked.push([key, Number(getRankValue(value, key)) || 0]);
    }
    ranked.sort((a, b) => a[1] - b[1]);
    for (let i = 0; i < removeCount; i += 1) {
      const item = ranked[i];
      if (!item) break;
      if (map.delete(item[0])) removed += 1;
    }
    return removed;
  }

  const keys = map.keys();
  while (map.size > targetSize) {
    const next = keys.next();
    if (!next || next.done) break;
    if (map.delete(next.value)) removed += 1;
  }
  return removed;
}

function applyMemoryPressureRelief(now = Date.now(), reason = "periodic") {
  const targetHistory = Math.max(500, Math.floor(BEHAVIORAL_CONFIG.maxIpsBeforeCleanup * 0.6));
  const targetInterstitial = Math.max(500, Math.floor(INTERSTITIAL_MAX_ENTRIES * 0.6));
  const targetKnownScanners = Math.max(500, Math.floor(KNOWN_SCANNER_MAX * 0.6));
  const targetAdminHits = Math.max(100, Math.floor(ADMIN_HIT_TTL_MS / 1000));

  const evicted = {
    requestHistory: 0,
    interstitialState: 0,
    knownScannerIps: 0,
    adminHits: 0
  };

  if (REQUEST_HISTORY.size > targetHistory) {
    evicted.requestHistory = pruneMapToTargetSize(REQUEST_HISTORY, targetHistory, (entries) => {
      if (!Array.isArray(entries) || !entries.length) return 0;
      return Number(entries[entries.length - 1].timestamp || 0);
    });
  }
  if (INTERSTITIAL_STATE.size > targetInterstitial) {
    evicted.interstitialState = pruneMapToTargetSize(
      INTERSTITIAL_STATE,
      targetInterstitial,
      (entry) => Number(entry && entry.lastSeenAt || 0)
    );
  }
  if (KNOWN_SCANNER_IPS.size > targetKnownScanners) {
    evicted.knownScannerIps = pruneMapToTargetSize(
      KNOWN_SCANNER_IPS,
      targetKnownScanners,
      (entry) => Number(entry && entry.lastSeen || 0)
    );
  }
  if (adminHits.size > targetAdminHits) {
    evicted.adminHits = pruneMapToTargetSize(
      adminHits,
      targetAdminHits,
      (entry) => Number(entry && entry.resetAt || 0)
    );
  }

  const totalEvicted = Object.values(evicted).reduce((sum, n) => sum + n, 0);
  if (totalEvicted > 0) {
    addLog(`[MEMORY] relief reason=${safeLogValue(reason, 48)} evicted=${totalEvicted} requestHistory=${evicted.requestHistory} interstitial=${evicted.interstitialState} knownScannerIps=${evicted.knownScannerIps} adminHits=${evicted.adminHits}`);
  }
  return totalEvicted;
}

function shouldApplyMemoryPressureRelief(mem = process.memoryUsage()) {
  const heapUsedMb = Number(mem && mem.heapUsed || 0) / (1024 * 1024);
  const heapTotal = Number(mem && mem.heapTotal || 0);
  const heapRatio = heapTotal > 0 ? Number(mem.heapUsed || 0) / heapTotal : 0;

  return (
    (heapUsedMb >= MEMORY_PRESSURE_HEAP_USED_MB && heapRatio >= MEMORY_PRESSURE_HEAP_USED_RATIO) ||
    REQUEST_HISTORY.size > BEHAVIORAL_CONFIG.maxIpsHardCap ||
    INTERSTITIAL_STATE.size > Math.floor(INTERSTITIAL_MAX_ENTRIES * 1.1) ||
    KNOWN_SCANNER_IPS.size > Math.floor(KNOWN_SCANNER_MAX * 1.1) ||
    adminHits.size > ADMIN_HITS_MAX_ENTRIES
  );
}

function markInterstitialShown(nextEnc) {
  const key = String(nextEnc || "");
  const now = Date.now();
  let entry = INTERSTITIAL_STATE.get(key);
  const firstHit = !entry;
  if (!entry) {
    entry = { firstSeenAt: now, lastSeenAt: now, humanSeen: false };
  } else {
    entry.lastSeenAt = now;
  }
  boundedMapSet(INTERSTITIAL_STATE, key, entry, INTERSTITIAL_MAX_ENTRIES);
  pruneInterstitialState(now);
  return { firstHit, humanSeen: !!entry.humanSeen };
}

function markInterstitialHuman(nextEnc) {
  const key = String(nextEnc || "");
  const now = Date.now();
  let entry = INTERSTITIAL_STATE.get(key);
  if (!entry) {
    entry = { firstSeenAt: now, lastSeenAt: now, humanSeen: true };
  } else {
    entry.humanSeen = true;
    entry.lastSeenAt = now;
  }
  boundedMapSet(INTERSTITIAL_STATE, key, entry, INTERSTITIAL_MAX_ENTRIES);
  pruneInterstitialState(now);
  return entry;
}

const INTERSTITIAL_BYPASS_SECRET = process.env.INTERSTITIAL_BYPASS_SECRET || "";

function hasInterstitialBypass(req) {
  if (!INTERSTITIAL_BYPASS_SECRET) return false;

  const q = req.query || {};
  if (q.ib && q.ib === INTERSTITIAL_BYPASS_SECRET) return true;

  const hdr = req.get("x-interstitial-bypass");
  if (hdr && hdr === INTERSTITIAL_BYPASS_SECRET) return true;

  return false;
}

function renderScannerSafePage(req, res, nextEnc, reason = "Pre-scan", options = {}) {
  applyScannerCompatHeaders(res);
  if (IMPERSONATE_SCANNER && options.scannerProfile) {
    applyScannerProfileHeaders(res, options.scannerProfile);
  }

  setInterstitialReasonHeader(res, reason);

  const mappedReason = mapInterstitialReason(reason);
  const emailSafe = options.emailSafe === true || reason === "Email-safe path";
  const allowAuto = options.allowAuto === true ? true : !emailSafe;

  const stateInfo = markInterstitialShown(nextEnc);
  const challengeToken = createChallengeToken(nextEnc, req, mappedReason);
  const nonce = res.locals.cspNonce || crypto.randomBytes(16).toString("base64");

  res.setHeader("Cache-Control", "no-store");
  try {
    res.setHeader(
      "Content-Security-Policy",
      `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self';`
    );
  } catch {}

  const cfg = {
    ct: challengeToken,
    next: nextEnc,
    allowAuto,
    firstHit: !!stateInfo.firstHit,
    humanSeen: !!stateInfo.humanSeen,
    emailSafe: !!emailSafe
  };
  const cfgJson = JSON.stringify(cfg);

  const html = `<!doctype html><html><head>
<meta charset="utf-8">
<title>Checking link…</title>
<meta name="robots" content="noindex,nofollow">
<meta name="viewport" content="width=device-width,initial-scale=1">
</head>
<body style="font:16px system-ui;padding:24px;max-width:720px;margin:auto">
  <h1>Checking this link</h1>
  <p>This link was pre-scanned by security or preview software. If you're the intended recipient, click continue.</p>
  <p><a id="continue-link" href="${withOptionalUrlPrefix("/challenge")}?ct=${encodeURIComponent(challengeToken)}" rel="noopener">Continue</a></p>
  <p style="color:#6b7280;font-size:14px">Reason: ${mappedReason}</p>
  <script nonce="${nonce}">
    (function(){
      var cfg = ${cfgJson};
      try {
        if (cfg && cfg.next) {
          var payload = JSON.stringify({ next: cfg.next });
          if (navigator.sendBeacon) {
            var blob = new Blob([payload], { type: "application/json" });
            navigator.sendBeacon(${JSON.stringify(withOptionalUrlPrefix("/interstitial-human"))}, blob);
          } else if (window.fetch) {
            fetch(${JSON.stringify(withOptionalUrlPrefix("/interstitial-human"))}, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: payload,
              keepalive: true
            }).catch(function(){});
          }
        }
      } catch (e) {}

      if (!cfg.allowAuto) return;
      if (cfg.firstHit || !cfg.humanSeen) return;

      setTimeout(function(){
        try {
          if (document.visibilityState && document.visibilityState !== "visible") return;
          window.location.href = ${JSON.stringify(`${withOptionalUrlPrefix("/challenge")}?ct=`)} + encodeURIComponent(cfg.ct);
        } catch (e) {}
      }, 1200);
    })();
  </script>
</body>
</html>`;

  res.type("html").send(html);
}

function setInterstitialReasonHeader(res, reason) {
  if (!res || typeof res.setHeader !== "function") return;
  if (!INTERSTITIAL_REASON_HEADER_ENABLED || res.getHeader("X-Interstitial-Reason-Code")) return;
  res.setHeader("X-Interstitial-Reason-Code", toReasonCode(reason));
}

function logScannerSafetyLane(req, payloadPath, mode, reason, source = "unknown") {
  const ip = getClientIp(req);
  const virtualPath = payloadPath ? "/e/[redacted]" : "/e";
  addLog(`[SCANNER-SAFETY-LANE] source=${safeLogValue(source, 32)} virtualPath=${virtualPath} mode=${safeLogValue(mode, 48)} reason=${safeLogValue(reason || "-", 80)} ip=${safeLogValue(ip, 64)} method=${safeLogValue(req.method, 12)} originalPath=${safeLogValue(req.originalUrl || req.url || req.path || "", 160)}`);
}

function sendScannerSafetyLaneHeadResponse(req, res, payloadPath, reason = "HEAD-probe", options = {}) {
  const scannerProfile = options.scannerProfile || null;
  applyScannerCompatHeaders(res);
  if (scannerProfile) {
    applyScannerProfileHeaders(res, scannerProfile);
  }
  setInterstitialReasonHeader(res, reason);
  logScannerSafetyLane(req, payloadPath, "head_probe", reason, options.source || "email-safe");
  return res.status(200).type("html").end();
}

async function tryRenderTrustedScannerSafeHtmlForPayload(req, res, baseString, securityCheck = {}, options = {}) {
  if (req.method !== "GET" || !securityCheck.scannerSafeHtmlEligible) return false;

  const clientIp = options.clientIp || getClientIp(req);
  const ua = options.ua || req.get("user-agent") || "";
  const linkHash = options.linkHash || (req.query && req.query.lh ? String(req.query.lh) : hashFirstSeg(baseString));

  const decryptResult = decryptAndParseUrl(req, baseString);
  if (decryptResult.error) {
    const nextEnc = encodeURIComponent(baseString);
    const scannerReason = securityCheck.scannerReason || "Known scanner UA";
    logScannerHit(req, scannerReason, nextEnc);
    logScannerSafetyLane(req, baseString, "interstitial_fallback", scannerReason, options.source || "catchall");
    renderScannerSafePage(req, res, nextEnc, scannerReason, {
      scannerProfile: securityCheck.scannerProfile
    });
    return true;
  }

  const finalUrl = processEmailAndFinalizeUrl(decryptResult.finalUrl, decryptResult.emailPart);
  let parsedFinalUrl;
  try {
    parsedFinalUrl = new URL(finalUrl);
  } catch (error) {
    addLog(`[URL] invalid ip=${safeLogValue(clientIp)} value="${safeLogValue((finalUrl || ""), URL_DISPLAY_MAX_LENGTH)}" err="${safeLogValue(error.message)}"`);
    addSpacer();
    res.status(400).send("Invalid URL");
    return true;
  }

  const hostname = normHost(parsedFinalUrl.hostname);
  const protocol = parsedFinalUrl.protocol;
  const normalizedPinnedHost = decryptResult.pinnedHost ? normHost(decryptResult.pinnedHost) : null;
  if (!["http:", "https:"].includes(protocol)) {
    addLog(`[ALLOWLIST] blocked protocol=${safeLogValue(protocol)} host=${safeLogValue(hostname)} ip=${safeLogValue(clientIp)}`);
    addSpacer();
    res.status(403).send("Unauthorized URL");
    return true;
  }
  if (normalizedPinnedHost && normalizedPinnedHost !== hostname) {
    logHostPinFailure({ ip: clientIp, ua, linkHash: decryptResult.linkHash || linkHash, pinnedHost: normalizedPinnedHost, actualHost: hostname });
    renderInvalidLinkPage(res);
    return true;
  }
  if (!isHostAllowlisted(hostname)) {
    addLog(`[ALLOWLIST] blocked host=${hostname} ip=${clientIp}`);
    addSpacer();
    res.status(403).send("Unauthorized URL");
    return true;
  }

  decryptResult.finalUrl = finalUrl;
  decryptResult.ciphertext = encodeURIComponent(baseString);
  decryptResult.scannerProfile = securityCheck.scannerSafeHtmlProfile || securityCheck.scannerProfile || null;
  req._decryptedUrl = finalUrl;
  req._scannerSafeHtmlMode = true;
  logScannerSafetyLane(req, baseString, "scanner-safe-html", securityCheck.scannerReason || "Known scanner UA", options.source || "catchall");
  await renderScannerSafeHtmlForScanner(req, res, decryptResult);
  return true;
}

// Global ops metrics (daily request totals + friction proxies)
app.use((req, res, next) => {
  const day = utcDayStamp();
  incrementOpsMetric(OPS_METRICS.requestsByDay, day, "total_requests", 1);

  res.on("finish", () => {
    const status = Number(res.statusCode || 0);
    if (status === 401 || status === 403 || status === 404 || status === 429) {
      incrementOpsMetric(OPS_METRICS.frictionByDay, day, `status_${status}`, 1);
      incrementOpsMetric(OPS_METRICS.frictionByDay, day, "friction_total", 1);
    }
  });
  next();
});

// --- Early short-circuit for HEAD/OPTIONS scanner-style probes on deep links ---
app.use(async (req, res, next) => {
  if (hasInterstitialBypass(req)) return next();

  // allow your own health, logs, and challenge endpoints through
  if (
    pathMatchesWithOptionalPrefix(req.path, "/health", { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(req.path, "/healthz", { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(req.path, "/readyz", { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(req.path, "/livez", { allowChildren: false }) ||
    req.path.startsWith("/view-log") ||
    pathMatchesWithOptionalPrefix(req.path, "/challenge") ||
    pathMatchesWithOptionalPrefix(req.path, "/ts-client-log", { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(req.path, "/interstitial-human", { allowChildren: false })
  ) {
    return next();
  }

  // During brownout, record/security evaluation happens in the brownout
  // middleware below; do not render scanner-safe HTML while overloaded.
  if (isBrownoutActive()) return next();

  // only care about HEAD/OPTIONS prefetches (scanner probes)
  if (req.method !== "HEAD" && req.method !== "OPTIONS") return next();

  // Handle /e/* specifically (email-safe deep links)
  if (pathMatchesWithOptionalPrefix(req.path, "/e")) {
    const clean = extractEmailSafePayloadPath(req);
    const scannerCtx = buildScannerInterstitialContext(req, req.method + "-probe");
    if (req.method === "HEAD") {
      logScannerHit(req, scannerCtx.scannerReason || "HEAD-probe", clean);
      return sendScannerSafetyLaneHeadResponse(req, res, clean, "HEAD-probe", {
        scannerProfile: scannerCtx.scannerProfile,
        source: "email-safe"
      });
    }
    if (scannerCtx.scannerSafeHtmlEligible) {
      const handled = await tryRenderTrustedScannerSafeHtmlForPayload(req, res, clean, scannerCtx, {
        source: "email-safe"
      });
      if (handled) return;
    }
    logScannerHit(req, scannerCtx.scannerReason || (req.method + "-probe"), clean);
    return renderScannerSafePage(req, res, clean, scannerCtx.scannerReason || (req.method + "-probe"), {
      emailSafe: true,
      scannerProfile: scannerCtx.scannerProfile
    });
  }

  const url = req.originalUrl || "";
  const looksEncoded = /[A-Za-z0-9+/=_-]{40,}/.test(url);
  const longPath = url.length > 80;
  const hasCookies = !!req.headers["cookie"];
  const fetchMode = (req.get("sec-fetch-mode") || "").toLowerCase();
  const looksPrefetch = fetchMode && fetchMode !== "navigate" && fetchMode !== "document";

  const looksDeep = longPath && looksEncoded && (!hasCookies || looksPrefetch);

  if (looksDeep) {
    const clean = url.replace(/^\//, "").split("?")[0];
    const scannerCtx = buildScannerInterstitialContext(req, req.method + "-probe");
    if (req.method === "HEAD") {
      logScannerHit(req, scannerCtx.scannerReason || "HEAD-probe", clean);
      return sendScannerSafetyLaneHeadResponse(req, res, clean, "HEAD-probe", {
        scannerProfile: scannerCtx.scannerProfile,
        source: "catchall"
      });
    }
    logScannerHit(req, scannerCtx.scannerReason || (req.method + "-probe"), clean);
    return renderScannerSafePage(req, res, clean, scannerCtx.scannerReason || (req.method + "-probe"), {
      scannerProfile: scannerCtx.scannerProfile
    });
  }

  return next();
});

// --- OPTIONAL: catch GET probes on /e/... and show the safe interstitial ---
app.use(async (req, res, next) => {
  if (hasInterstitialBypass(req)) return next();

  // Let your own endpoints through untouched
  if (
    pathMatchesWithOptionalPrefix(req.path, "/health", { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(req.path, "/healthz", { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(req.path, "/readyz", { allowChildren: false }) ||
    req.path.startsWith("/view-log") ||
    pathMatchesWithOptionalPrefix(req.path, "/challenge") ||
    pathMatchesWithOptionalPrefix(req.path, "/ts-client-log", { allowChildren: false }) ||
    pathMatchesWithOptionalPrefix(req.path, "/interstitial-human", { allowChildren: false })
  ) {
    return next();
  }

  // During brownout, defer to the brownout middleware so /e scanner probes are
  // shed with Retry-After instead of rendering interstitial HTML.
  if (isBrownoutActive()) return next();

  if (req.method === "GET" && pathMatchesWithOptionalPrefix(req.path, "/e")) {
    const clean = extractEmailSafePayloadPath(req);
    const scannerCtx = buildScannerInterstitialContext(req, "GET-probe");
    if (scannerCtx.scannerSafeHtmlEligible) {
      const handled = await tryRenderTrustedScannerSafeHtmlForPayload(req, res, clean, scannerCtx, {
        source: "email-safe"
      });
      if (handled) return;
    }
    logScannerHit(req, scannerCtx.scannerReason || "GET-probe", clean);
    return renderScannerSafePage(req, res, clean, scannerCtx.scannerReason || "GET-probe", {
      emailSafe: true,
      scannerProfile: scannerCtx.scannerProfile
    });
  }

  return next();
});

function createSecurityPolicyContext(req) {
  return {
    ip: getClientIp(req),
    denyCacheIp: getDenyCacheIp(req),
    ua: req.get("user-agent") || "",
    bypassInterstitial: hasInterstitialBypass(req)
  };
}

function checkDenyCachePolicy(req, ctx) {
  const denyHit = getDenyCache(ctx.denyCacheIp);
  if (!denyHit) return null;
  const shouldLog = aggregatePerIpEvent("DENY_CACHE", { ip: ctx.ip, reason: denyHit.reason });
  if (shouldLog) {
    addLog(`[DENY-CACHE] blocked ip=${safeLogValue(ctx.ip)} reason=${safeLogValue(denyHit.reason, 32)}${formatRequestIdentityLogSuffix(req)}`);
    addSpacer();
  }
  recordOffenderSignals(req);
  return { blocked: true, status: 403, message: "Forbidden" };
}

function checkCloudflareHeaderPolicy(req, ctx) {
  if (!REQUIRE_CF_HEADERS || hasCloudflareHeaders(req)) return null;
  addLog(`[CF] missing headers ip=${safeLogValue(ctx.ip)} ua="${safeLogValue(ctx.ua.slice(0, UA_TRUNCATE_LENGTH))}"`);
  addSpacer();
  recordOffenderSignals(req);
  return { blocked: true, status: 403, message: "Forbidden" };
}

function logInterstitialBypassIfActive(ctx) {
  if (!ctx.bypassInterstitial) return;
  addLog(`[BYPASS] interstitial bypass active ip=${safeLogValue(ctx.ip)} ua="${safeLogValue(ctx.ua.slice(0, UA_TRUNCATE_LENGTH))}"`);
  addSpacer();
}

function checkIpBanPolicy(req, ctx) {
  const bannedIpKey = isBanned(ctx.denyCacheIp)
    ? ctx.denyCacheIp
    : (ctx.ip !== ctx.denyCacheIp && isBanned(ctx.ip) ? ctx.ip : null);
  if (!bannedIpKey) return null;
  addLog(`[BAN] blocked ip=${safeLogValue(ctx.ip)} banKey=${safeLogValue(bannedIpKey)}${formatRequestIdentityLogSuffix(req)}`);
  addSpacer();
  recordOffenderSignals(req);
  return { blocked: true, status: 403, message: "Forbidden" };
}

function checkScannerPolicy(req, ctx) {
  if (ctx.bypassInterstitial) return null;
  const scannerResult = detectScannerEnhancedWithBehavior(req);
  if (!scannerResult.isScanner) return null;
  
  // --- ADD THIS LINE ---
  addLog(`[SCANNER-HEADERS] ${safeLogJson(req.headers, 2000)}`);
  // ---------------------
  
  const scannerDetections = scannerResult.detections;
  const topDetection = scannerDetections[0] || { name: "scanner", confidence: 0.5 };
  recordScannerIp(ctx.ip, topDetection.name);
  const knownScanner = isKnownScannerIp(ctx.ip);
  incrementScannerDecisionCounter("scanner_detected_total");
  const shouldImpersonate = shouldImpersonateForRequest(req, scannerResult, knownScanner, topDetection);
  const allowVendorProfileHeaders = shouldApplyProfileHeadersForRequest(req, scannerResult, knownScanner, topDetection);
  const detectedScannerProfile = pickScannerProfile(topDetection, req, knownScanner, scannerResult, false);
  const scannerProfile = (shouldImpersonate && allowVendorProfileHeaders)
    ? detectedScannerProfile
    : null;
  if (scannerProfile) incrementScannerDecisionCounter("scanner_impersonated_total");
  if (scannerProfile && scannerProfile.name) incrementScannerDecisionCounter(`scanner_profile_${String(scannerProfile.name).replace(/[^a-zA-Z0-9_-]/g, "_")}_total`);
  const shouldInterstitial = shouldServeScannerInterstitial(req);
  if (shouldInterstitial) {
    incrementScannerDecisionCounter("scanner_interstitial_served_total");
    incrementOpsMetric(OPS_METRICS.frictionByDay, utcDayStamp(), "scanner_interstitial", 1);
  }

  addLog(`[SCANNER] interstitial=${shouldInterstitial ? "1" : "0"} scope=${safeLogValue(SCANNER_INTERSTITIAL_SCOPE, 16)} ip=${safeLogValue(ctx.ip)} scanner="${safeLogValue(topDetection.name)}" confidence=${safeLogValue(String(topDetection.confidence ?? ""))} known=${knownScanner ? "1" : "0"} impersonate=${shouldImpersonate ? "1" : "0"} strictProfile=${allowVendorProfileHeaders ? "1" : "0"} profile=${safeLogValue((scannerProfile && scannerProfile.name) || "none")} ua="${safeLogValue(ctx.ua.slice(0, UA_TRUNCATE_LENGTH))}"`);
  recordOffenderSignals(req);

  const confidence = Number(topDetection.confidence || 0);
  const scannerSafeHtmlProfile = detectedScannerProfile && detectedScannerProfile.name !== SCANNER_GENERIC_PROFILE.name
    ? detectedScannerProfile
    : null;
  const trustedScannerProfile = !!scannerSafeHtmlProfile;
  // Reuse the scanner impersonation confidence gate, but only serve scanner-safe
  // HTML to concrete trusted scanner profiles so generic automation UAs stay blocked.
  const scannerSafeHtmlEligible = SCANNER_SAFE_HTML_ENABLED && trustedScannerProfile && confidence >= IMPERSONATE_MIN_CONFIDENCE;
  if (!shouldInterstitial && !scannerSafeHtmlEligible) return { blocked: true, status: 404, message: "Not Found" };
  const reason = scannerProfile ? "Known scanner fingerprint" : topDetection.name;
  return {
    blocked: true,
    interstitial: true,
    scanner: topDetection.name,
    scannerConfidence: confidence,
    scannerProfile,
    scannerSafeHtmlProfile,
    scannerReason: reason,
    scannerSafeHtmlEligible
  };
}

function checkBadUaPolicy(req, ctx) {
  const BAD_UA = /(okhttp|python-requests|curl|wget|phantomjs)/i;
  if (ctx.bypassInterstitial || !BAD_UA.test(ctx.ua)) return null;
  addLog(`[UA-BLOCK] ip=${ctx.ip} ua="${ctx.ua.slice(0, UA_TRUNCATE_LENGTH)}"`);
  addSpacer();
  addDenyCache(ctx.denyCacheIp, "ua_block");
  recordOffenderSignals(req);
  return { blocked: true, status: 403, message: "Forbidden" };
}

function checkHeadlessPolicy(req, ctx) {
  if (ctx.bypassInterstitial) return null;
  const hs = headlessSuspicion(req);
  if (!hs.suspicious) return null;

  const softOnlyOne = hs.hardCount === 0 && hs.softCount === 1;
  const label = hs.hardCount >= 1
    ? "HEADLESS"
    : (hs.isSafariUA || hs.isFirefoxUA) && softOnlyOne
    ? "INFO"
    : hs.softCount >= 2
    ? "SUSPECT"
    : "INFO";
  addLog(`[${label}] ip=${safeLogValue(ctx.ip)} reasons=${safeLogValue(hs.reasons.join(","))}`);

  if (hs.hardCount > 0) {
    addStrike(ctx.ip, HEADLESS_STRIKE_WEIGHT);
    maybeDenyForVisibleIpReputation(req, ctx.ip, "headless", { detail: hs.reasons.join("|"), weight: VISIBLE_IP_REPUTATION_WEIGHTS.headless });
  } else if (HEADLESS_SOFT_STRIKE && hs.softCount >= 2) {
    addStrike(ctx.ip, 1);
    maybeDenyForVisibleIpReputation(req, ctx.ip, "headless", { detail: hs.reasons.join("|"), weight: 2 });
  }

  if (HEADLESS_BLOCK && hs.hardCount > 0) {
    addSpacer();
    addDenyCache(ctx.denyCacheIp, "headless_hard");
    recordOffenderSignals(req);
    return { blocked: true, status: 403, message: "Forbidden" };
  }
  return null;
}

async function checkGeoAsnPolicy(req, ctx) {
  const countryResolution = await getCountryResolutionAsync(req) || { country: null, source: "none" };
  const ctry = countryResolution.country;
  const asn = countryResolution.asn || getASN(req);
  if (countryBlocked(ctry)) {
    const shouldLog = aggregatePerIpEvent("GEO", { ip: ctx.ip, country: ctry, reason: "country_block" });
    if (shouldLog) {
      addLog(`[GEO] blocked country=${safeLogValue(ctry)} ip=${safeLogValue(ctx.ip)}${formatRequestIdentityLogSuffix(req, { geoSource: countryResolution.source })}`);
      addSpacer();
    }
    const geoSourceTag = String((countryResolution && countryResolution.source) || "unknown").toLowerCase().replace(/[^a-z0-9:_-]/g, "_").slice(0, 40);
    addDenyCache(ctx.denyCacheIp, `geo_block:${geoSourceTag}`);
    recordOffenderSignals(req, { country: ctry, asn });
    return { blocked: true, status: 403, message: "Forbidden" };
  }
  if (asnBlocked(asn)) {
    const shouldLog = aggregatePerIpEvent("ASN", { ip: ctx.ip, reason: "asn_block" });
    if (shouldLog) {
      addLog(`[ASN] blocked asn=${safeLogValue(asn)} ip=${safeLogValue(ctx.ip)}`);
      addSpacer();
    }
    addDenyCache(ctx.denyCacheIp, "asn_block");
    recordOffenderSignals(req, { country: ctry, asn });
    return { blocked: true, status: 403, message: "Forbidden" };
  }
  return null;
}

async function checkSecurityPolicies(req) {
  const ctx = createSecurityPolicyContext(req);
  const syncChecks = [
    checkDenyCachePolicy,
    checkCloudflareHeaderPolicy,
    checkIpBanPolicy,
    checkScannerPolicy,
    checkBadUaPolicy,
    checkHeadlessPolicy
  ];

  for (const check of syncChecks) {
    if (check === checkIpBanPolicy) logInterstitialBypassIfActive(ctx);
    const result = check(req, ctx);
    if (result) return result;
  }

  const geoAsnResult = await checkGeoAsnPolicy(req, ctx);
  return geoAsnResult || { blocked: false };
}
// Brownout runs after hard security checks so deny-cache, bans, scanner, geo,
// and ASN policy decisions still execute and get recorded during overload.
app.use(async (req, res, next) => {
  try {
    if (!isBrownoutActive()) return next();

    const p = getNormalizedRequestPathForPolicy(req);
    if (isOperationalBypassPath(p)) return next();

    const securityCheck = await checkSecurityPolicies(req);
    if (securityCheck.blocked) {
      if (securityCheck.interstitial) {
        const nextEnc = encodeURIComponent(String(req.originalUrl || req.url || p));
        const scannerReason = securityCheck.scannerReason || "Known scanner UA";
        logScannerHit(req, scannerReason, nextEnc);
        addLog(`[BROWNOUT] scanner interstitial suppressed ip=${safeLogValue(getClientIp(req), 64)} reason=${safeLogValue(scannerReason, 80)}`);
      } else {
        return res.status(securityCheck.status).send(securityCheck.message);
      }
    }

    const ip = getClientIp(req);
    addLog(`[BROWNOUT-REJECT] ip=${safeLogValue(ip, 64)} path=${safeLogValue(p, 120)}`);
    res.setHeader("Retry-After", "10");
    return res.status(503).end("Service temporarily unavailable");
  } catch (err) {
    return next(err);
  }
});

async function verifyTurnstileAndRateLimit(req, baseString) {
  const identity = getRequestIdentity(req);
  const ip = identity.ip;
  const ua = req.get("user-agent") || "";

  const token = req.query.cft || req.get("cf-turnstile-response") || "";
  const linkHash = req.query.lh ? String(req.query.lh) : hashFirstSeg(baseString);

  const v = await verifyTurnstileToken(token, ip, { action:"link_redirect", linkHash, maxAgeSec:MAX_TOKEN_AGE_SEC });
  if (!v.ok) {
    addLog(`[AUTH] token invalid (${v.reason}) ip=${safeLogValue(ip)} ua="${safeLogValue(ua.slice(0, UA_TRUNCATE_LENGTH))}" -> /challenge`);
    // Missing token is normal for first-time human visits; reserve bypass alerts
    // for malformed/invalid supplied tokens and tamper-like states.
    if (token || (v.reason && v.reason !== "missing")) {
      recordChallengeBypassAttempt(req, `auth_${v.reason || 'invalid'}`);
      maybeDenyForVisibleIpReputation(req, ip, "challenge_abuse", { detail: v.reason || "invalid" });
    }
    return {
      redirect: createChallengeRedirect(baseString, req, "auth_invalid", {
        host: (v.reason === "bad_hostname" && v.data && v.data.hostname) ? v.data.hostname : ""
      })
    };
  }

  const { limited, retryAfterMs } = await isRateLimited(identity.rateLimitKey || ip);
  if (limited) {
    if (retryAfterMs && Number.isFinite(retryAfterMs)) {
      return { blocked: true, status: 429, retryAfter: Math.ceil(retryAfterMs/1000), message: "Too many requests" };
    }
    addLog(`[RL] 429 ip=${ip}`);
    addSpacer();
    return { blocked: true, status: 429, message: "Too many requests" };
  }

  if (token) {
    const challengeReason = sanitizeChallengeReason(req.query.cr || "");
    const logCtx = {
      ip: safeLogValue(ip),
      uaHash: hashUaForToken(ua),
      linkHash: safeLogValue(linkHash, 64),
      reason: safeLogValue(challengeReason || "-", 48)
    };
    addLog(`[CHALLENGE-OK] ${safeLogJson(logCtx, LOG_ENTRY_MAX_LENGTH)}`);
  }

  return { success: true };
}

function parseRedirectPayloadForRequest(baseString) {
  return parseRedirectPayload(baseString, {
    decodeBase64UrlLoose: decodeB64urlLoose,
    decodeFallback: safeDecode,
    isValidEmail: isLikelyEmail
  });
}

function logRedirectPayloadParserContext(parsedPayload) {
  const parserLogCtx = {
    matchedNewFormat: !!parsedPayload.matchedNewFormat,
    parseMode: parsedPayload.parseMode || parsedPayload.mode,
    emailSegment: parsedPayload.emailSegment || "none",
    emailPresent: !!(parsedPayload.emailPart || parsedPayload.email),
    ambiguityDetected: !!parsedPayload.ambiguityDetected
  };
  addLog(`[PATH-NORMALIZE] ${safeLogJson(parserLogCtx, LOG_ENTRY_MAX_LENGTH)}`);
}

function buildRedirectDecryptCandidates(parsedPayload, baseString) {
  const hasCanonicalPayload = parsedPayload.canonicalBaseString && parsedPayload.canonicalBaseString !== baseString;
  const shouldPreferCanonical = hasCanonicalPayload && !!parsedPayload.emailPart;
  const canonicalCandidate = {
    mode: parsedPayload.mode || "canonical",
    value: parsedPayload.canonicalBaseString || baseString,
    mainPart: parsedPayload.ciphertext || parsedPayload.canonicalBaseString || baseString,
    emailPart: parsedPayload.emailPart || null
  };
  const legacyCandidate = { mode: "legacy", value: baseString, mainPart: baseString, emailPart: null };
  const candidates = shouldPreferCanonical ? [canonicalCandidate, legacyCandidate] : [canonicalCandidate];
  if (hasCanonicalPayload && !shouldPreferCanonical) candidates.push(legacyCandidate);
  return candidates;
}

function tryDecryptRedirectCandidate(candidate) {
  let result = null;
  result = tryDecryptAny(candidate.mainPart);
  let decryptedPayload = result && result.url;
  let emailPart = candidate.emailPart || null;

  if (!decryptedPayload) {
    const fallback = tryDecryptAtKnownDelimiterBoundaries(candidate.value);
    if (fallback && fallback.url) {
      decryptedPayload = fallback.url;
      if (!emailPart) emailPart = fallback.emailRaw || null;
      addLog(`[DECRYPT] fallback split used mode=${candidate.mode} k=${fallback.kTried} emailRawLen=${(fallback.emailRaw || '').length}`);
    }
  }

  return { decryptedPayload, emailPart, result };
}

function parseDecryptedRedirectPayload(decryptedPayload) {
  const parsedResult = {
    parsedUrl: decryptedPayload,
    pinnedHost: null,
    hmacChecked: false,
    hmacValid: false
  };

  try {
    const parsed = JSON.parse(decryptedPayload);
    if (parsed && typeof parsed === "object") {
      if (typeof parsed.url === "string") parsedResult.parsedUrl = parsed.url;
      if (typeof parsed.dest_host === "string") parsedResult.pinnedHost = parsed.dest_host;
      if (typeof parsed.hmac === "string" && parsedResult.pinnedHost && parsedResult.parsedUrl) {
        const res = verifyLinkHmac(parsedResult.parsedUrl, parsedResult.pinnedHost, parsed.hmac);
        parsedResult.hmacChecked = true;
        parsedResult.hmacValid = !!res.ok;
      }
    }
  } catch {}

  return parsedResult;
}

function logRedirectHmacMismatch(req, linkHash, pinnedHost) {
  const ua = req.get("user-agent") || "";
  const logCtx = {
    ip: safeLogValue(getClientIp(req)),
    uaHash: hashUaForToken(ua),
    linkHash: safeLogValue(linkHash, 64),
    destHost: safeLogValue(pinnedHost || "-", 120)
  };
  addLog(`[DECRYPT] hmac mismatch ${safeLogJson(logCtx, LOG_ENTRY_MAX_LENGTH)}`);
  addSpacer();
}

function decryptAndParseUrl(req, baseString) {
  const ip = getClientIp(req);
  const linkHash = req.query.lh ? String(req.query.lh) : hashFirstSeg(baseString);
  const parsedPayload = parseRedirectPayloadForRequest(baseString);
  logRedirectPayloadParserContext(parsedPayload);

  const sizeDecision = evaluateRedirectPayloadSize(parsedPayload, baseString);
  maybeLogRedirectPayloadSizeDecision(req, sizeDecision, "decrypt");
  if (!sizeDecision.ok) {
    addSpacer();
    return { error: "Failed to load" };
  }

  if (parsedPayload.rawUrl) {
    addLog(`[PATH-NORMALIZE] raw-url parser applied emailPresent=${parsedPayload.emailPart ? "true" : "false"}`);
    return { finalUrl: parsedPayload.rawUrl, emailPart: parsedPayload.emailPart || null, pinnedHost: null, linkHash };
  }

  const candidates = buildRedirectDecryptCandidates(parsedPayload, baseString);
  for (const [index, candidate] of candidates.entries()) {
    if (candidate.emailPart) {
      addLog(`[PARSE] canonical email mode=${candidate.mode} mainLen=${candidate.mainPart.length} emailRawLen=${candidate.emailPart.length}`);
    }

    let decryptResult;
    try {
      decryptResult = tryDecryptRedirectCandidate(candidate);
    } catch (e) {
      addLog(`[DECRYPT] exception ip=${safeLogValue(ip)} mode=${candidate.mode} seg="${safeLogValue(String(candidate.mainPart), EMAIL_DISPLAY_MAX_LENGTH)}" err=${safeLogValue(e.message)}`);
      addSpacer();
      return { error: "Failed to load" };
    }

    if (!decryptResult.decryptedPayload) {
      if (index < candidates.length - 1) {
        addLog(`[PATH-NORMALIZE] parse failed, trying next mode=${safeLogValue(candidates[index + 1]?.mode || "unknown", 64)}`);
        continue;
      }
      const why = explainDecryptFailure({
        tried: decryptResult.result?.tried || [],
        lastErr: decryptResult.result?.lastErr || null,
        segLen: candidate.mainPart.length
      });
      addLog(`[DECRYPT] failed variants ip=${safeLogValue(ip)} mode=${candidate.mode} seg="${safeLogValue(String(candidate.mainPart), EMAIL_DISPLAY_MAX_LENGTH)}" mainLen=${candidate.mainPart.length} why=${safeLogValue(why)}`);
      addSpacer();
      return { error: "Failed to load" };
    }

    const parsedDecrypted = parseDecryptedRedirectPayload(decryptResult.decryptedPayload);
    if (parsedDecrypted.hmacChecked && !parsedDecrypted.hmacValid) {
      logRedirectHmacMismatch(req, linkHash, parsedDecrypted.pinnedHost);
      return { error: "Failed to load" };
    }

    if (parsedPayload.matchedNewFormat) {
      addLog(`[PATH-NORMALIZE] canonical parser applied mode=${safeLogValue(parsedPayload.parseMode, 64)} emailSegment=${safeLogValue(parsedPayload.emailSegment || "none", 16)}`);
    }
    return { finalUrl: parsedDecrypted.parsedUrl, emailPart: decryptResult.emailPart, pinnedHost: parsedDecrypted.pinnedHost, linkHash };
  }

  if (parsedPayload.ambiguityDetected) {
    addLog(`[PATH-NORMALIZE] ambiguous email segments; falling back to legacy invalid handling`);
  }
  addSpacer();
  return { error: "Failed to load" };
}
function processEmailAndFinalizeUrl(finalUrl, emailPart) {
  if (emailPart) {
    const emailResult = decodeEmailPart(emailPart);

    if (emailResult.email) {
      finalUrl += '#' + emailResult.email;
      if (emailResult.source === 'recovered') {
        addLog(`[EMAIL] recovered from noisy decode ${safeLogValue(maskEmail(emailResult.email), EMAIL_DISPLAY_MAX_LENGTH)}`);
      } else {
        addLog(`[EMAIL] captured ${safeLogValue(maskEmail(emailResult.email), EMAIL_DISPLAY_MAX_LENGTH)}`);
      }
    } else if (emailResult.decoded) {
      addLog(`[EMAIL] ignored (not a valid email): "${safeLogValue(emailResult.decoded, EMAIL_DISPLAY_MAX_LENGTH)}" (raw="${safeLogValue(String(emailPart).slice(0,40))}…")`);
    } else {
      addLog(`[EMAIL] ignored (decode empty) raw="${safeLogValue(String(emailPart).slice(0,40))}…"`);
    }
  }

  return finalUrl;
}

function renderInvalidLinkPage(res) {
  const html = `<!doctype html><html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Link unavailable</title>
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial,sans-serif;background:#0c1116;color:#e8eef6;padding:24px;}
  .card{max-width:520px;width:100%;background:#0f172a;border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:24px;box-shadow:0 24px 60px rgba(0,0,0,0.45);}
  h1{margin:0 0 8px;font-size:24px;}
  p{margin:0 0 8px;color:#cbd5e1;}
</style>
</head>
<body>
  <div class="card">
    <h1>Link invalid or expired</h1>
    <p>The link you followed is no longer valid. Please contact the sender for a fresh link.</p>
    <p>If you believe this is an error, try opening the link from the original message again.</p>
  </div>
</body>
</html>`;
  res.setHeader("Cache-Control", "no-store");
  return res.status(400).type("html").send(html);
}

function logHostPinFailure({ ip, ua, linkHash, pinnedHost, actualHost }) {
  const logCtx = {
    ip: safeLogValue(ip),
    uaHash: hashUaForToken(ua || ""),
    linkHash: safeLogValue(linkHash || "-", 64),
    pinnedHost: safeLogValue(pinnedHost || "-", 160),
    actualHost: safeLogValue(actualHost || "-", 160)
  };
  addLog(`[PIN] host mismatch ${safeLogJson(logCtx, LOG_ENTRY_MAX_LENGTH)}`);
  addSpacer();
}

function validateAndRedirect(finalUrl, req, res, options = {}) {
  const ip = getClientIp(req);
  const ua = req.get("user-agent") || "";
  const pinnedHost = options.pinnedHost || null;
  const linkHash = options.linkHash || null;

  try {
    const parsedUrl = new URL(finalUrl);
    const hostname = normHost(parsedUrl.hostname);
    const protocol = parsedUrl.protocol;
    const normalizedPinnedHost = options.pinnedHost ? normHost(options.pinnedHost) : null;

    if (!["http:", "https:"].includes(protocol)) {
      addLog(`[ALLOWLIST] blocked protocol=${safeLogValue(protocol)} host=${safeLogValue(hostname)} ip=${safeLogValue(ip)}`);
      addSpacer();
      return res.status(403).send("Unauthorized URL");
    }

    if (normalizedPinnedHost && normalizedPinnedHost !== hostname) {
      logHostPinFailure({ ip, ua, linkHash, pinnedHost: normalizedPinnedHost, actualHost: hostname });
      return renderInvalidLinkPage(res);
    }

    const okHost = isHostAllowlisted(hostname);

    if (!okHost) {
      addLog(`[ALLOWLIST] blocked host=${hostname} ip=${ip}`);
      addSpacer();
      return res.status(403).send("Unauthorized URL");
    }

    addLog(`[REDIRECT] ip=${safeLogValue(ip)} -> ${safeLogValue(finalUrl, URL_DISPLAY_MAX_LENGTH)}`);
    addSpacer();
    return res.redirect(302, finalUrl);
  } catch (e) {
    addLog(`[URL] invalid ip=${safeLogValue(ip)} value="${safeLogValue((finalUrl || ""), URL_DISPLAY_MAX_LENGTH)}" err="${safeLogValue(e.message)}"`);
    addSpacer();
    return res.status(400).send("Invalid URL");
  }
}

async function handleRedirectCore(req, res, baseString){
  try {
    const clientIp = getClientIp(req);
    const ua = req.get("user-agent") || "";
    const linkHash = req.query.lh ? String(req.query.lh) : hashFirstSeg(baseString);
    const hasSecUA = !!req.get("sec-ch-ua");
    const hasFetchSite = !!req.get("sec-fetch-site");
    const missingSecHeaders = !hasSecUA || !hasFetchSite;
    const knownBots = ["Googlebot","Bingbot","Slurp","DuckDuckBot","Baiduspider","YandexBot","Sogou","Exabot","facebot","facebookexternalhit","ia_archiver","MJ12bot","AhrefsBot","SemrushBot","DotBot","PetalBot","GPTBot","python-requests","crawler","scrapy","curl","wget","phantomjs","HeadlessChrome"];
    const isBotUA = knownBots.some(b => ua.toLowerCase().includes(b.toLowerCase()));
    const hasTurnstileToken = !!req.query.cft;

    const securityCheck = await checkSecurityPolicies(req);
    if (securityCheck.blocked) {
      if (securityCheck.interstitial) {
        // --- NEW: Tiered scanner handling inside handleRedirectCore ---
        const topDetection = securityCheck.scanner ? { name: securityCheck.scanner, confidence: securityCheck.scannerConfidence || 0.9 } : null;
        const confidence = topDetection ? (topDetection.confidence || 0) : 0;
        const scannerResult = topDetection ? { detections: [topDetection], isScanner: true } : null;

        // If scanner safe HTML is enabled and this scanner decision met the threshold,
        // internally move the normal campaign URL into the scanner safety lane.
        if (scannerResult) {
          const handledBySafetyLane = await tryRenderTrustedScannerSafeHtmlForPayload(req, res, baseString, securityCheck, {
            source: "catchall",
            clientIp,
            ua,
            linkHash
          });
          if (handledBySafetyLane) return;
        }

        // Medium confidence: return 204 with headers only
        if (confidence >= 0.80) {
          if (securityCheck.scannerProfile) {
            applyScannerCompatHeaders(res);
            applyScannerProfileHeaders(res, securityCheck.scannerProfile);
          }
          res.status(204).end();
          return;
        }

        // Low confidence: fallback to the standard interstitial
        const nextEnc = encodeURIComponent(baseString);
        const scannerReason = securityCheck.scannerReason || "Known scanner UA";
        logScannerHit(req, scannerReason, nextEnc);
        return renderScannerSafePage(req, res, nextEnc, scannerReason, {
          scannerProfile: securityCheck.scannerProfile
        });
      }
      return res.status(securityCheck.status).send(securityCheck.message);
    }

    const authCheck = await verifyTurnstileAndRateLimit(req, baseString);
    if (authCheck.redirect) {
      return res.redirect(302, authCheck.redirect);
    }
    if (authCheck.blocked) {
      if (authCheck.retryAfter) {
        res.setHeader("Retry-After", authCheck.retryAfter);
      }
      return res.status(authCheck.status).send(authCheck.message);
    }

    if (isBotUA || missingSecHeaders) {
      const reason = isBotUA ? "bot_heuristic" : "missing_sec_headers";
      const logCtx = {
        ip: safeLogValue(clientIp),
        uaHash: hashUaForToken(ua),
        linkHash: safeLogValue(linkHash, 64),
        isBotUA,
        missingSecHeaders,
        hasSecUA: !!hasSecUA,
        hasFetchSite: !!hasFetchSite
      };
      addLog(`[CHALLENGE-TRIGGER] ${safeLogJson(logCtx, LOG_ENTRY_MAX_LENGTH)}`);
      addSpacer();

      if (!hasTurnstileToken) {
        const reasonParam = sanitizeChallengeReason(reason);
        return res.redirect(302, createChallengeRedirect(baseString, req, reasonParam));
      }
    }

    const decryptResult = decryptAndParseUrl(req, baseString);
    if (decryptResult.error) {
      return res.status(400).send(decryptResult.error);
    }

    const finalUrl = processEmailAndFinalizeUrl(decryptResult.finalUrl, decryptResult.emailPart);
    return validateAndRedirect(finalUrl, req, res, { pinnedHost: decryptResult.pinnedHost, linkHash: decryptResult.linkHash });
  } catch (e) {
    addLog(`[REDIRECT-ERROR] ip=${safeLogValue(getClientIp(req))} path=${safeLogValue(req.originalUrl || '', PATH_TRUNCATE_LENGTH)} err=${safeLogValue(e?.message || 'unknown')}`);
    addSpacer();
    return res.status(500).send("Temporary error");
  }
}

// ================== MIDDLEWARE SETUP ==================
app.use(cors());
app.use(express.json({ limit: "64kb" }));
app.use(express.urlencoded({ extended: false, limit: "64kb" }));

const adminHits = new Map();
const ADMIN_HIT_WINDOW_MS = 60_000;
const ADMIN_HIT_TTL_MS = 10 * 60_000;

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

// ================== ENHANCED PUBLIC CONTENT SURFACE ==================
const PUBLIC_CONTENT_SURFACE = (process.env.PUBLIC_CONTENT_SURFACE || "0") === "1";
const PUBLIC_SITE_PERSONA = (process.env.PUBLIC_SITE_PERSONA || "rotating").toLowerCase();
const PUBLIC_SITE_NAME_OVERRIDE = (process.env.PUBLIC_SITE_NAME || "").trim();
const PUBLIC_SITE_BASE_URL = (process.env.TURNSTILE_EXPECT_HOSTNAME || "").trim();
const PUBLIC_ROTATION_MODE = (process.env.PUBLIC_ROTATION_MODE || "daily").trim().toLowerCase();
const PUBLIC_GENERATE_PATHS = parseInt(process.env.PUBLIC_GENERATE_PATHS || "25", 10);
const PUBLIC_ENABLE_ANALYTICS = (process.env.PUBLIC_ENABLE_ANALYTICS || "1") === "1";
const PUBLIC_ENABLE_BACKGROUND = (process.env.PUBLIC_ENABLE_BACKGROUND || "1") === "1";
const PUBLIC_TRAFFIC_SUMMARY_EVERY_RAW = parseInt(process.env.PUBLIC_TRAFFIC_SUMMARY_EVERY || "10", 10);
const PUBLIC_TRAFFIC_SUMMARY_EVERY = Number.isFinite(PUBLIC_TRAFFIC_SUMMARY_EVERY_RAW) && PUBLIC_TRAFFIC_SUMMARY_EVERY_RAW > 0
  ? PUBLIC_TRAFFIC_SUMMARY_EVERY_RAW
  : 10;

// Safety gate: allow explicit force-enable while keeping default-off posture.
function isPublicContentSurfaceEnabled() {
  const forceEnable = (process.env.PUBLIC_CONTENT_SURFACE_FORCE || "").trim().toLowerCase();
  const forced = forceEnable === "1" || forceEnable === "true" || forceEnable === "yes";
  return PUBLIC_CONTENT_SURFACE || forced;
}

// ================== MULTIPLE PERSONAS ==================
// Each persona is a completely different "cover story"
const PERSONAS = {
  // Persona 1: CDN / Edge Computing Provider
  cdn: {
    name: "EdgeFlow",
    tagline: "Global edge network for modern applications",
    description: "Accelerate your content with our global edge network",
    sitekey: "edgeflow",
    contentTypes: ['html', 'json', 'xml'],
    logo: "⚡",
    primaryColor: "#0066cc",
    secondaryColor: "#4c9aff",
    features: [
      "Global CDN with 200+ edge locations",
      "DDoS protection included",
      "Serverless compute at the edge",
      "Image optimization pipeline",
      "Real-time purging API",
      "Custom SSL certificates"
    ],
    footerLinks: [
      { text: "Home", path: "/" },
      { text: "Network", path: "/network" },
      { text: "Pricing", path: "/pricing" },
      { text: "Documentation", path: "/docs" },
      { text: "Status", path: "/status" },
      { text: "Contact", path: "/contact" }
    ],
    apiEndpoints: ["/api/v1/status", "/api/v1/edge/locations", "/api/v1/metrics"]
  },

  // Persona 2: Media Streaming Platform
  media: {
    name: "StreamWave",
    tagline: "High-quality video streaming infrastructure",
    description: "Stream video content at any scale with our reliable platform",
    sitekey: "streamwave",
    contentTypes: ['html', 'json', 'xml'],
    logo: "🎬",
    primaryColor: "#9c27b0",
    secondaryColor: "#ce93d8",
    features: [
      "Adaptive bitrate streaming",
      "DRM and content protection",
      "Live transcoding",
      "Video analytics dashboard",
      "Multi-platform playback SDKs",
      "Sub-second latency options"
    ],
    footerLinks: [
      { text: "Home", path: "/" },
      { text: "Features", path: "/features" },
      { text: "Pricing", path: "/pricing" },
      { text: "Developers", path: "/developers" },
      { text: "Status", path: "/status" },
      { text: "Contact", path: "/contact" }
    ],
    apiEndpoints: ["/api/v1/status", "/api/v1/streams", "/api/v1/analytics"]
  },

  // Persona 3: Cloud Storage Provider
  storage: {
    name: "CloudVault",
    tagline: "Secure object storage for any workload",
    description: "Store, protect, and serve data with enterprise-grade durability",
    sitekey: "cloudvault",
    contentTypes: ['html', 'json', 'xml'],
    logo: "☁️",
    primaryColor: "#2e7d32",
    secondaryColor: "#81c784",
    features: [
      "S3-compatible object storage",
      "99.999999999% durability",
      "Server-side encryption",
      "Lifecycle management",
      "Cross-region replication",
      "Presigned URL generation"
    ],
    footerLinks: [
    { text: "Home", path: "/" },
    { text: "Solutions", path: "/solutions" },
    { text: "Pricing", path: "/pricing" },
    { text: "Docs", path: "/docs" },
    { text: "Status", path: "/status" },
    { text: "Security", path: "/security" },
    { text: "Support", path: "/support" }
  ],
  apiEndpoints: ["/api/v1/status", "/api/v1/buckets", "/api/v1/objects"]
},

  // Persona 4: API Gateway / Proxy Service
  api: {
    name: "API Gateway Pro",
    tagline: "Enterprise API management platform",
    description: "Secure, scale, and monitor your APIs with our intelligent gateway",
    sitekey: "apigateway",
    contentTypes: ['html', 'json', 'xml'],
    logo: "🔌",
    primaryColor: "#d32f2f",
    secondaryColor: "#ef9a9a",
    features: [
      "Rate limiting and throttling",
      "API key authentication",
      "Request/response transformation",
      "Analytics and monitoring",
      "GraphQL federation",
      "OpenAPI/Swagger support"
    ],
    footerLinks: [
      { text: "Home", path: "/" },
      { text: "Products", path: "/products" },
      { text: "Pricing", path: "/pricing" },
      { text: "Docs", path: "/docs" },
      { text: "Blog", path: "/blog" },
      { text: "Contact", path: "/contact" }
    ],
    apiEndpoints: ["/api/v1/status", "/api/v1/keys", "/api/v1/analytics"]
  },

  // Persona 5: Security / WAF Provider
  security: {
    name: "ShieldEdge",
    tagline: "Web application security for modern threats",
    description: "Protect your applications from bots, DDoS, and OWASP Top 10",
    sitekey: "shieldedge",
    contentTypes: ['html', 'json', 'xml'],
    logo: "🛡️",
    primaryColor: "#ff6f00",
    secondaryColor: "#ffb74d",
    features: [
      "Web Application Firewall",
      "Bot mitigation engine",
      "DDoS protection",
      "Rate limiting",
      "Security analytics",
      "Compliance reporting"
    ],
    footerLinks: [
      { text: "Home", path: "/" },
      { text: "Products", path: "/products" },
      { text: "Pricing", path: "/pricing" },
      { text: "Docs", path: "/docs" },
      { text: "Status", path: "/status" },
      { text: "Contact", path: "/contact" }
    ],
    apiEndpoints: ["/api/v1/status", "/api/v1/threats", "/api/v1/rules"]
  },

  // Persona 6: Health & Wellness (keep as fallback)
  wellness: {
    name: "Wellness Hub",
    tagline: "Evidence-based health guidance",
    description: "Practical wellness advice for busy professionals",
    sitekey: "wellness",
    contentTypes: ['html'],
    logo: "🌿",
    primaryColor: "#2e7d32",
    secondaryColor: "#81c784",
    features: [
      "Morning mobility routines",
      "Sustainable nutrition tips",
      "Sleep optimization",
      "Stress management",
      "Workout plans for home",
      "Recovery protocols"
    ],
    footerLinks: [
      { text: "Home", path: "/" },
      { text: "About", path: "/about" },
      { text: "Articles", path: "/articles" },
      { text: "Guides", path: "/guides" },
      { text: "Contact", path: "/contact" }
    ],
    apiEndpoints: []
  }
};

// Select active persona (deterministic based on date)
function getActivePersona() {
  if (PUBLIC_SITE_PERSONA !== "rotating" && PERSONAS[PUBLIC_SITE_PERSONA]) {
    return PERSONAS[PUBLIC_SITE_PERSONA];
  }

  // Rotate personas deterministically
  const personaKeys = Object.keys(PERSONAS);
  const seed = rotationSeed();
  const index = hash32(seed) % personaKeys.length;
  const personaKey = personaKeys[index];

  return PERSONAS[personaKey];
}

function getPublicSiteName(persona = getActivePersona()) {
  return PUBLIC_SITE_NAME_OVERRIDE || persona.name;
}

// ================== GENERATE DUMMY PATHS ==================
const PUBLIC_CORE_MARKETING_PATHS = [
  '/products', '/blog', '/articles', '/guides', '/pricing', '/solutions', '/services', '/docs',
  '/about', '/contact', '/features', '/developers', '/network', '/status', '/security', '/support'
];

const PUBLIC_CANONICAL_ALIASES = new Map([
  ['/about-us', '/about'],
  ['/contact-us', '/contact'],
  ['/services-us', '/solutions'],
  ['/services-page', '/solutions'],
  ['/status-page', '/status'],
  ['/status-check', '/status'],
  ['/docs-page', '/docs'],
  ['/docs-old', '/docs']
]);

function generateAllPaths(persona, rotationSeed) {
  const paths = [];
  const seed = rotationSeed || 'default-seed'; // Use provided seed or fallback

  // Always include core marketing pages so dynamic router cannot miss known render branches.
  paths.push(...PUBLIC_CORE_MARKETING_PATHS);

  // Add standard footer links
  persona.footerLinks.forEach(link => {
    if (link.path !== '/') paths.push(link.path);
  });

  // Add blog/articles section (10-15 posts)
  paths.push('/blog');
  for (let i = 1; i <= 12; i++) {
    const topics = ['getting-started', 'tutorial', 'guide', 'announcement', 'best-practices', 'case-study'];
    const topic = topics[hash32(`${seed}:blog:${i}`) % topics.length];

    paths.push(`/blog/${topic}-${i}`);
    paths.push(`/blog/post-${i}`);
    paths.push(`/articles/${i}`);
  }

  // Add product/service pages
  paths.push('/products');
  paths.push('/pricing');
  paths.push('/features');
  paths.push('/signup');
  const productTypes = ['enterprise', 'pro', 'business', 'starter', 'custom'];
  productTypes.forEach((type, idx) => {
    paths.push(`/products/${type}`);
    paths.push(`/pricing/${type}`);
    paths.push(`/features/${type}`);
  });

  // Add documentation section
  const docSections = ['getting-started', 'api', 'sdk', 'faq', 'troubleshooting', 'changelog'];
  docSections.forEach(section => {
    paths.push(`/docs/${section}`);

    // Sub-pages
    for (let i = 1; i <= 3; i++) {
      paths.push(`/docs/${section}/part-${i}`);
    }
  });

  // Add resource pages
  paths.push('/resources');
  paths.push('/articles');
  paths.push('/guides');
  paths.push('/articles/engineering-handbook');
  paths.push('/guides/implementation-playbook');
  paths.push('/whitepapers');
  paths.push('/case-studies');
  paths.push('/webinars');
  paths.push('/events');

  // Add legal pages
  paths.push('/privacy');
  paths.push('/terms');
  paths.push('/security');
  paths.push('/compliance');
  paths.push('/sla');
  paths.push('/status');

  // Add company pages
  paths.push('/about');
  paths.push('/careers');
  paths.push('/partners');
  paths.push('/news');
  paths.push('/press');

  // Add random generated paths (deterministic based on seed)
  for (let i = 0; i < PUBLIC_GENERATE_PATHS; i++) {
    const randomId = hash32(`${seed}:random:${i}`).toString(36).slice(0, 8);
    paths.push(`/p/${randomId}`);
    paths.push(`/shared/${randomId}`);
    paths.push(`/preview/${randomId}`);
    paths.push(`/embed/${randomId}`);
  }

  // Remove duplicates and sort
  return [...new Set(paths)].sort();
}

// ================== ENHANCED PAGE GENERATOR ==================

const createRenderEnhancedPublicPage = require("../public-page/renderEnhancedPublicPage.js");
const renderEnhancedPublicPage = createRenderEnhancedPublicPage({
  PUBLIC_ENABLE_ANALYTICS,
  deterministicPick,
  getActivePersona,
  getPublicSiteName,
  hash32,
  rotationSeed
});

// ================== GENERATE API RESPONSES ==================
function generateDummyAPIResponse(path, persona, seed) {
  const endpoint = path.split('/').pop();
  const timestamp = new Date().toISOString();
  const requestId = crypto.createHash('md5').update(`${seed}:${path}:${Date.now()}`).digest('hex').slice(0, 12);

  // Base response structure
  const response = {
    success: true,
    timestamp,
    request_id: requestId,
    service: persona.name,
    version: `v${hash32(`${seed}:version`) % 4 + 1}.0.0`
  };

  // Endpoint-specific data
  if (path.includes('/status')) {
    response.data = {
      status: 'operational',
      uptime: (99.9 + (hash32(`${seed}:uptime_api`) % 10) / 100).toFixed(2) + '%',
      latency_ms: hash32(`${seed}:latency_api`) % 30 + 10,
      services: {
        api: 'healthy',
        database: 'healthy',
        cache: 'healthy',
        storage: 'degraded'
      }
    };
  } else if (path.includes('/metrics')) {
    response.data = {
      requests_per_second: hash32(`${seed}:rps`) % 500 + 100,
      bandwidth_mbps: (hash32(`${seed}:bandwidth`) % 800 + 200).toFixed(2),
      active_connections: hash32(`${seed}:connections`) % 10000 + 1000,
      cache_hit_rate: (hash32(`${seed}:cache`) % 15 + 80).toFixed(1) + '%'
    };
  } else if (path.includes('/buckets') || path.includes('/objects')) {
    response.data = {
      buckets: Array.from({length: 3}, (_, i) => ({
        name: `bucket-${i + 1}-${seed.slice(0, 4)}`,
        objects: hash32(`${seed}:objects:${i}`) % 1000 + 100,
        size_gb: (hash32(`${seed}:size:${i}`) % 500 + 50).toFixed(2)
      }))
    };
  } else if (path.includes('/streams')) {
    response.data = {
      active_streams: hash32(`${seed}:streams`) % 500 + 50,
      viewers: hash32(`${seed}:viewers`) % 50000 + 5000,
      bitrates: ['240p', '480p', '720p', '1080p', '4K']
    };
  } else if (path.includes('/threats')) {
    response.data = {
      blocked_requests: hash32(`${seed}:blocked`) % 100000 + 5000,
      top_attack_types: [
        { type: 'SQL Injection', count: hash32(`${seed}:sql`) % 500 + 100 },
        { type: 'XSS', count: hash32(`${seed}:xss`) % 300 + 50 },
        { type: 'Bot', count: hash32(`${seed}:bot`) % 1000 + 200 }
      ]
    };
  } else {
    response.data = {
      message: 'Endpoint operational',
      documentation: 'https://docs.' + persona.sitekey + '.com',
      rate_limit: hash32(`${seed}:rate`) % 1000 + 500
    };
  }

  return JSON.stringify(response, null, 2);
}

// ================== DUMMY SITEMAP GENERATOR ==================
function escapeSitemapXml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function generateEnhancedSitemap(req, persona, allPaths) {
  const baseUrls = resolvePublicBaseUrls(req, { requestHostOnly: true, preferConfiguredCanonical: true });
  const today = new Date().toISOString().split('T')[0];

  const urlEntries = [];
  for (const baseUrl of baseUrls) {
    allPaths.forEach(rawPath => {
      const path = String(rawPath || "/");
      if (path.startsWith('/api/') ||
          path.startsWith('/_') ||
          path.includes('analytics') ||
          path.includes('collect') ||
          path.includes('interact')) {
        return;
      }

      const priority = path === '/' ? '1.0' :
                      path.match(/^\/(?:pricing|solutions|features)/) ? '0.9' :
                      path.match(/^\/(?:blog|articles|guides)/) ? '0.8' :
                      path.match(/^\/(?:docs|status|security)/) ? '0.7' : '0.6';

      const changefreq = path === '/' ? 'daily' :
                        path.includes('blog') ? 'weekly' :
                        path.includes('docs') ? 'monthly' : 'weekly';

      urlEntries.push(`
  <url>
    <loc>${escapeSitemapXml(`${baseUrl}${path}`)}</loc>
    <lastmod>${today}</lastmod>
    <changefreq>${changefreq}</changefreq>
    <priority>${priority}</priority>
  </url>`);
    });
  }

  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xhtml="http://www.w3.org/1999/xhtml">
  ${urlEntries.join('')}
</urlset>`;
}

// ================== BACKGROUND TRAFFIC GENERATOR ==================
function startPublicBackgroundTraffic() {
  if (!PUBLIC_CONTENT_SURFACE || !PUBLIC_ENABLE_BACKGROUND) return;
  const stats = {
    total: 0,
    bot: 0,
    realBrowser: 0,
    unknown: 0,
    errors: 0,
    lastPath: "-"
  };

  function classifyPublicTrafficRequest(req) {
    const ua = (req.get("user-agent") || "").toLowerCase();
    const knownBotFragments = [
      "bot", "spider", "crawler", "slurp", "duckduckbot", "bingbot", "googlebot", "ahrefsbot",
      "semrushbot", "mj12bot", "dotbot", "yandex", "baiduspider", "curl", "wget", "python-requests",
      "headless", "phantomjs", "scrapy"
    ];
    const isBotUa = knownBotFragments.some(fragment => ua.includes(fragment));
    const hasSecCHUA = !!req.get("sec-ch-ua");
    const hasFetchSite = !!req.get("sec-fetch-site");
    const hasFetchMode = !!req.get("sec-fetch-mode");

    if (isBotUa) return "bot";

    if (hasSecCHUA && hasFetchSite && hasFetchMode && ua && !ua.includes("headless")) {
      return "realBrowser";
    }

    return "unknown";
  }

  function maybeLogPublicTrafficVisit(req, path) {
    stats.total += 1;
    stats.lastPath = path || "-";
    const classification = classifyPublicTrafficRequest(req);
    if (classification === "bot") stats.bot += 1;
    else if (classification === "realBrowser") stats.realBrowser += 1;
    else stats.unknown += 1;

    if (stats.total % PUBLIC_TRAFFIC_SUMMARY_EVERY === 0) {
      addLog(
        `[PUBLIC-TRAFFIC] Summary total=${stats.total} Bot=${stats.bot} RealBrowser=${stats.realBrowser} Unknown=${stats.unknown} errors=${stats.errors} lastPath=${safeLogValue(stats.lastPath, 80)}`
      );
    }
  }

  function maybeLogPublicTrafficError(error, path) {
    stats.errors += 1;
    if (path) stats.lastPath = path;
    if (stats.errors % PUBLIC_TRAFFIC_SUMMARY_EVERY === 0) {
      addLog(`[PUBLIC-TRAFFIC] Summary total=${stats.total} Bot=${stats.bot} RealBrowser=${stats.realBrowser} Unknown=${stats.unknown} errors=${stats.errors} lastPath=${safeLogValue(stats.lastPath, 80)}`);
    }
  }

  app.locals.recordPublicTrafficVisit = maybeLogPublicTrafficVisit;
  app.locals.recordPublicTrafficError = maybeLogPublicTrafficError;
}

// ================== REGISTER ENHANCED ROUTES ==================
const createRegisterEnhancedPublicRoutes = require("../public-routes/registerEnhancedPublicRoutes.js");
const registerEnhancedPublicRoutes = createRegisterEnhancedPublicRoutes({
  PUBLIC_CANONICAL_ALIASES,
  PUBLIC_ENABLE_ANALYTICS,
  addLog,
  app,
  express,
  generateAllPaths,
  generateDummyAPIResponse,
  generateEnhancedSitemap,
  getActivePersona,
  getCurrentPublicPathSet,
  getPublicSiteName,
  hash32,
  isPublicContentSurfaceEnabled,
  renderEnhancedPublicPage,
  resolvePublicBaseUrls,
  rotationSeed,
  servePublicPathResponse
});

function derivePublicPageTitle(routePath = '') {
  return String(routePath)
    .split('/')
    .pop()
    .replace(/-/g, ' ')
    .replace(/^\w/, c => c.toUpperCase()) || 'Home';
}

function servePublicPathResponse(req, res, routePath, persona, seed) {
  const normalizedPath = String(routePath || '').toLowerCase();
  const acceptHeader = String(req.headers.accept || '').toLowerCase();
  const hasJsonExtension = normalizedPath.endsWith('.json');
  const isApiPath = normalizedPath.startsWith('/api/');
  const wantsJson = acceptHeader.includes('application/json');

  if (isApiPath || hasJsonExtension || wantsJson) {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-cache');
    return res.send(generateDummyAPIResponse(routePath, persona, `${seed}:${routePath}`));
  }

  const pageTitle = derivePublicPageTitle(routePath);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=300');

  return res.send(renderEnhancedPublicPage(req, {
    path: routePath,
    title: pageTitle,
    summary: `${persona.name} - ${pageTitle}`
  }));
}

let cachedPublicPathState = {
  key: '',
  paths: new Set()
};

function getCurrentPublicPathSet() {
  const persona = getActivePersona();
  const seed = rotationSeed();
  const cacheKey = `${persona.sitekey}:${seed}`;

  if (cachedPublicPathState.key !== cacheKey) {
    cachedPublicPathState = {
      key: cacheKey,
      paths: new Set(generateAllPaths(persona, seed))
    };
  }

  return { persona, seed, paths: cachedPublicPathState.paths };
}

function shouldHandleAsDynamicPublicPath(req) {
  const publicSurfaceEnabled = isPublicContentSurfaceEnabled();
  if (!publicSurfaceEnabled) return false;

  if (!['GET', 'HEAD'].includes(req.method)) return false;

  const pathname = String(req.path || '');
  if (!pathname || pathname === '/') return false;

  const reservedPrefixes = [
    '/challenge',
    '/ts-client-log',
    '/interstitial-human',
    '/stream-log',
    '/view-log',
    '/__debug',
    '/admin',
    '/health',
    '/turnstile-sitekey',
    '/decrypt-challenge-data',
    '/e/',
    '/r'
  ];

  return !reservedPrefixes.some((prefix) => pathMatchesWithOptionalPrefix(pathname, prefix));
}

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

// ================== ROUTES ==================
const handleDecryptChallengeData = (req, res) => {
    const { data } = req.body || {};
    if (!data) return res.json({ success: false, error: "No data" });

    const payload = decryptChallengeData(data);
    if (!payload) return res.json({ success: false, error: "Decryption failed" });

    const raw = parseInt(process.env.CHALLENGE_PAYLOAD_TTL_MIN || "5", 10);
    const ttlMin = Number.isFinite(raw) && raw > 0 ? raw : 5; // guard

    // extra sanity: ensure payload.ts is a number
    const issuedAt = typeof payload.ts === "number" ? payload.ts : 0;
    if (Date.now() - issuedAt > ttlMin * 60 * 1000) {
      return res.json({ success: false, error: "Payload expired" });
    }

    return res.json({ success: true, payload });
  };

app.post("/decrypt-challenge-data", express.json({ limit: "1kb" }), handleDecryptChallengeData);
if (OPTIONAL_URL_PREFIX) {
  app.post(withOptionalUrlPrefix("/decrypt-challenge-data"), express.json({ limit: "1kb" }), handleDecryptChallengeData);
}

const handleRailwayLiveness = (_req, res) => {
  res.status(200).json({ ok: true, ts: Date.now() });
};

const handleHealth = (req, res) => {
  const turnstileHealthy = _health.ok !== false;
  const statusCode = turnstileHealthy ? 200 : 503;
  const uptimeSec = Math.floor(process.uptime());
  const usage = getRuntimeUsageSnapshot();
  const resourceGauges = getRuntimeResourceGauges();
  const currentRequestIsTracked = shouldTrackRuntimeRequest(req) ? 1 : 0;
  const inFlightRequests = getTrackedInFlightCount();
  const inFlightExcludingCurrent = Math.max(0, inFlightRequests - currentRequestIsTracked);

  res.status(statusCode).json({
    ok: turnstileHealthy,
    uptimeSec,
    time: new Date().toISOString(),
    stats: {
      requestTimeouts: runtimeStats.requestTimeouts,
      shutdownSignals: runtimeStats.shutdownSignals,
      processWarnings: runtimeStats.processWarnings,
      uncaughtExceptions: runtimeStats.uncaughtExceptions,
      unhandledRejections: runtimeStats.unhandledRejections,
      serverClientErrors: runtimeStats.serverClientErrors,
      serverErrors: runtimeStats.serverErrors,
      bootId: runtimeStats.bootId,
      startedAt: runtimeStats.startedAt,
      totalRequests: runtimeStats.totalRequests,
      inFlightRequests,
      inFlightRequestsExcludingCurrent: inFlightExcludingCurrent,
      completedRequests: runtimeStats.completedRequests,
      abortedRequests: runtimeStats.abortedRequests,
      staleTrackedRequestsPruned: runtimeStats.staleTrackedRequestsPruned,
      lastRequestStartedAt: runtimeStats.lastRequestStartedAt,
      lastRequestCompletedAt: runtimeStats.lastRequestCompletedAt,
      lastRequestPath: runtimeStats.lastRequestPath,
      lastResponseStatus: runtimeStats.lastResponseStatus,
      maxObservedRequestDurationMs: runtimeStats.maxObservedRequestDurationMs,
      maxObservedEventLoopLagMs: runtimeStats.maxObservedEventLoopLagMs,
      lastEventLoopLagAt: runtimeStats.lastEventLoopLagAt,
      turnstileChecks: runtimeStats.turnstileChecks,
      turnstileCheckErrors: runtimeStats.turnstileCheckErrors,
      turnstileCheckTimeouts: runtimeStats.turnstileCheckTimeouts,
      lastTurnstileCheckAt: runtimeStats.lastTurnstileCheckAt,
      lastTurnstileLatencyMs: runtimeStats.lastTurnstileLatencyMs,
      lastTurnstileError: runtimeStats.lastTurnstileError,
      lastUnhandledRejectionAt: getEventTimestamp(runtimeStats.lastUnhandledRejection),
      lastUncaughtExceptionAt: getEventTimestamp(runtimeStats.lastUncaughtException),
      lastServerClientErrorAt: getEventTimestamp(runtimeStats.lastServerClientError),
      lastServerErrorAt: getEventTimestamp(runtimeStats.lastServerError),
      lastProcessWarningAt: getEventTimestamp(runtimeStats.lastProcessWarning),
      cpu: usage.cpu,
      memory: usage.memory,
      resources: resourceGauges
    },
    checks: {
      turnstile: {
        ok: _health.ok,
        okStreak: _health.okStreak,
        failStreak: _health.failStreak,
        lastHeartbeat: _health.lastHeartbeat ? new Date(_health.lastHeartbeat).toISOString() : null
      }
    }
  });
};

const handleLiveness = (req, res) => {
  const usage = getRuntimeUsageSnapshot();
  const resourceGauges = getRuntimeResourceGauges();
  const currentRequestIsTracked = shouldTrackRuntimeRequest(req) ? 1 : 0;
  const inFlightRequests = getTrackedInFlightCount();
  const inFlightExcludingCurrent = Math.max(0, inFlightRequests - currentRequestIsTracked);

  res.status(200).json({
    ok: true,
    uptimeSec: Math.floor(process.uptime()),
    ts: Date.now(),
    stats: {
      requestTimeouts: runtimeStats.requestTimeouts,
      shutdownSignals: runtimeStats.shutdownSignals,
      processWarnings: runtimeStats.processWarnings,
      uncaughtExceptions: runtimeStats.uncaughtExceptions,
      unhandledRejections: runtimeStats.unhandledRejections,
      serverClientErrors: runtimeStats.serverClientErrors,
      serverErrors: runtimeStats.serverErrors,
      bootId: runtimeStats.bootId,
      startedAt: runtimeStats.startedAt,
      totalRequests: runtimeStats.totalRequests,
      inFlightRequests,
      inFlightRequestsExcludingCurrent: inFlightExcludingCurrent,
      completedRequests: runtimeStats.completedRequests,
      abortedRequests: runtimeStats.abortedRequests,
      staleTrackedRequestsPruned: runtimeStats.staleTrackedRequestsPruned,
      lastRequestStartedAt: runtimeStats.lastRequestStartedAt,
      lastRequestCompletedAt: runtimeStats.lastRequestCompletedAt,
      lastRequestPath: runtimeStats.lastRequestPath,
      lastResponseStatus: runtimeStats.lastResponseStatus,
      maxObservedRequestDurationMs: runtimeStats.maxObservedRequestDurationMs,
      maxObservedEventLoopLagMs: runtimeStats.maxObservedEventLoopLagMs,
      lastEventLoopLagAt: runtimeStats.lastEventLoopLagAt,
      turnstileChecks: runtimeStats.turnstileChecks,
      turnstileCheckErrors: runtimeStats.turnstileCheckErrors,
      turnstileCheckTimeouts: runtimeStats.turnstileCheckTimeouts,
      lastTurnstileCheckAt: runtimeStats.lastTurnstileCheckAt,
      lastTurnstileLatencyMs: runtimeStats.lastTurnstileLatencyMs,
      lastTurnstileError: runtimeStats.lastTurnstileError,
      lastUnhandledRejectionAt: getEventTimestamp(runtimeStats.lastUnhandledRejection),
      lastUncaughtExceptionAt: getEventTimestamp(runtimeStats.lastUncaughtException),
      lastServerClientErrorAt: getEventTimestamp(runtimeStats.lastServerClientError),
      lastServerErrorAt: getEventTimestamp(runtimeStats.lastServerError),
      lastProcessWarningAt: getEventTimestamp(runtimeStats.lastProcessWarning),
      cpu: usage.cpu,
      memory: usage.memory,
      resources: resourceGauges
    }
  });
};

function getPrimaryTurnstileExpectedHostname() {
  const apexPattern = EXPECT_HOSTNAME_PATTERNS.find(pattern => pattern.includeApex);
  const fallbackPattern = EXPECT_HOSTNAME_PATTERNS[0];
  return (apexPattern || fallbackPattern)?.suffix || "";
}

function getSecurityTxtBaseUrl(req) {
  const expectedHostname = getPrimaryTurnstileExpectedHostname();
  if (expectedHostname) return `https://${expectedHostname}`;

  const forwardedHost = String(req.get("x-forwarded-host") || "").split(",")[0].trim();
  const host = forwardedHost || req.get("host");
  return `${req.protocol}://${host}`;
}

function handleSecurityTxt(req, res) {
  const baseUrl = getSecurityTxtBaseUrl(req);
  const contact = String(process.env.SECURITY_TXT_CONTACT || "").trim() || `${baseUrl}/contact`;
  const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.send(`Contact: ${contact}
Policy: ${baseUrl}/security
Preferred-Languages: en
Expires: ${expires}
`);
}

app.get("/livez", handleRailwayLiveness);
if (OPTIONAL_URL_PREFIX) {
  app.get(withOptionalUrlPrefix("/livez"), handleRailwayLiveness);
}

app.get("/health", handleHealth);
if (OPTIONAL_URL_PREFIX) {
  app.get(withOptionalUrlPrefix("/health"), handleHealth);
}

app.get("/readyz", handleHealth);
if (OPTIONAL_URL_PREFIX) {
  app.get(withOptionalUrlPrefix("/readyz"), handleHealth);
}

app.get("/healthz", handleLiveness);
if (OPTIONAL_URL_PREFIX) {
  app.get(withOptionalUrlPrefix("/healthz"), handleLiveness);
}

const handleTsClientLog = (req, res) => {
    const ip  = getClientIp(req) || "unknown";
    const ua  = (req.get("user-agent") || "").slice(0, UA_TRUNCATE_LENGTH);
    const ct  = req.get("content-type") || "-";
    const len = req.get("content-length") || "0";

    let payload = null;

    if (req.body && typeof req.body === "object" && !Buffer.isBuffer(req.body)) {
      payload = req.body;
    } else {
      const raw = typeof req.body === "string" ? req.body : "";

      if (raw && raw.trim()) {
        try { payload = JSON.parse(raw); } catch { }
      }

      if ((!payload || typeof payload !== "object") && raw && raw.includes("=")) {
        try {
          const params = new URLSearchParams(raw);
          const obj = {};
          for (const [k, v] of params.entries()) obj[k] = v;
          payload = obj;
        } catch { }
      }

      if (!payload) req.__rawPreview = raw.slice(0, 200);
    }

    if (!payload || typeof payload !== "object" || !payload.phase) {
      const preview = req.__rawPreview != null
        ? JSON.stringify(req.__rawPreview)
        : (typeof req.body === "object" ? JSON.stringify(req.body).slice(0, 200) : '""');
      addLog(`[TS-CLIENT:empty] ip=${safeLogValue(ip)} ua="${safeLogValue(ua)}" ct=${safeLogValue(ct)} len=${safeLogValue(len)} preview=${safeLogValue(preview)}`);
      return res.status(204).end();
    }

    addLog(`[TS-CLIENT:${safeLogValue(payload.phase)}] ip=${safeLogValue(ip)} ua="${safeLogValue(ua)}" ${safeLogJson(payload)}`);
    addSpacer();
    return res.status(204).end();
  };

app.post(
"/ts-client-log",
  express.text({ type: "*/*", limit: "64kb" }),
  handleTsClientLog
);
if (OPTIONAL_URL_PREFIX) {
  app.post(withOptionalUrlPrefix("/ts-client-log"), express.text({ type: "*/*", limit: "64kb" }), handleTsClientLog);
}

const handleInterstitialHuman = (req, res) => {
    const body = req.body || {};
    const nextEnc = typeof body.next === "string" ? body.next.slice(0, 4096) : "";
    if (!nextEnc) {
      return res.status(400).json({ ok: false, error: "missing_next" });
    }

    markInterstitialHuman(nextEnc);

    const ip = getClientIp(req) || "unknown";
    const ua = (req.get("user-agent") || "").slice(0, UA_TRUNCATE_LENGTH);
    addLog(
      `[INTERSTITIAL-HUMAN] ip=${safeLogValue(ip)} ua="${safeLogValue(ua)}" nextLen=${nextEnc.length}`
    );
    addSpacer();

    return res.json({ ok: true });
  };

app.post(
"/interstitial-human",
  express.json({ type: "application/json", limit: "4kb" }),
  handleInterstitialHuman
);
if (OPTIONAL_URL_PREFIX) {
  app.post(withOptionalUrlPrefix("/interstitial-human"), express.json({ type: "application/json", limit: "4kb" }), handleInterstitialHuman);
}

const handleStreamLog = (req, res) => {
  if (!isAdminSSE(req)) return res.status(403).end("Forbidden: missing admin token (SSE)");

  res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders?.();

  try { res.write(": connected\n\n"); } catch {}

  const lastIdHdr = req.get("last-event-id");
  const lastId = lastIdHdr ? parseInt(lastIdHdr, 10) : NaN;
  let startIdx = Math.max(0, LOG_IDS.length - BACKLOG_ON_CONNECT);
  if (Number.isFinite(lastId) && lastId >= 0) {
    const pos = LOG_IDS.lastIndexOf(lastId);
    if (pos >= 0) startIdx = pos + 1;
  } else {
    res.write(`event: reset\ndata: {"ts":${Date.now()}}\n\n`);
  }

  for (let i = startIdx; i < LOGS.length; i++) {
    sseSend(res, LOGS[i], LOG_IDS[i]);
  }

  LOG_LISTENERS.add(res);

  try { res.write(": hb-ready\n\n"); } catch {}

  const hb = setInterval(() => { try { res.write(": ping\n\n"); } catch {} }, 25000);
  if (typeof hb.unref === "function") hb.unref();

  let cleaned = false;
  function cleanup() {
    if (cleaned) return;
    cleaned = true;
    try { clearInterval(hb); } catch {}
    LOG_LISTENERS.delete(res);
  }

  req.once("aborted", cleanup);
  req.once("close", cleanup);
  res.once("close", cleanup);
  res.once("error", cleanup);
  res.once("finish", cleanup);

  req.socket?.setTimeout?.(0);
  req.socket?.setKeepAlive?.(true);
};

app.get("/stream-log", handleStreamLog);
if (OPTIONAL_URL_PREFIX) {
  app.get(withOptionalUrlPrefix("/stream-log"), handleStreamLog);
}

app.get("/view-log-live", (req, res) => {
  if (!(isAdmin(req) || isAdminSSE(req))) {
    return res.status(401).type("text/plain").send("Unauthorized");
  }

  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
  );

  const pageTok = req.query.token && String(req.query.token);
  const tok = pageTok || mintEphemeralToken();
  const streamUrl = `/stream-log?token=${encodeURIComponent(tok)}`;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="referrer" content="no-referrer" />
  <meta name="color-scheme" content="dark light" />
  <title>Live Logs</title>
  <style>
    body{margin:0;font:14px/1.4 ui-monospace,Menlo,Consolas,monospace}
    #log{padding:12px;white-space:pre-wrap;word-break:break-word}
    .status{color:#888;padding:8px 12px}
  </style>
</head>
<body>
  <div class="status">Connecting…</div>
  <pre id="log"></pre>
  <script>
    const logEl = document.getElementById('log');
    const statusEl = document.querySelector('.status');
    const es = new EventSource(${JSON.stringify(streamUrl)});

    es.onopen = () => {
      statusEl.textContent = 'Connected';
    };

    es.addEventListener('reset', () => {
      logEl.textContent = '';
      statusEl.textContent = 'Repainting…';
    });

    es.onmessage = (e) => {
      logEl.textContent += e.data + '\\n';
      statusEl.textContent = '';
      window.scrollTo(0, document.body.scrollHeight);
    };

    es.onerror = (e) => {
      statusEl.textContent = 'Disconnected — retrying…';
      console.debug('SSE error', e, 'readyState=', es.readyState);
    };
  </script>
</body>
</html>`);
});

app.get("/view-log", requireAdmin, (req, res) => {
  return res.type("text/plain").send(LOGS.join("\n") || "No logs yet.");
});

app.get("/geo-debug", (req, res) => {
  if (!isAdmin(req)) return res.status(403).send("Forbidden");
  res.json({
    ip: getClientIp(req),
    resolvedCountry: getCountry(req),
    headers: {
      "cf-ipcountry": req.headers["cf-ipcountry"] || null,
      "cf-edge-country": req.headers["cf-edge-country"] || null,
      "x-nf-geo": req.headers["x-nf-geo"] || null,
      "x-vercel-ip-country": req.headers["x-vercel-ip-country"] || null
    }
  });
});

app.get("/favicon.ico", (_req, res) => {
  res.set("Cache-Control","public, max-age=86400");
  return res.status(204).end();
});

// ================== PUBLIC CONTENT HELPERS ==================
function dayStamp(d = new Date()) {
  return d.toISOString().slice(0, 10);
}

function weekStamp(d = new Date()) {
  const dt = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const dayNum = dt.getUTCDay() || 7;
  dt.setUTCDate(dt.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(dt.getUTCFullYear(), 0, 1));
  const week = Math.ceil((((dt - yearStart) / 86400000) + 1) / 7);
  return `${dt.getUTCFullYear()}-W${String(week).padStart(2, "0")}`;
}

function rotationSeed() {
  if (PUBLIC_ROTATION_MODE === "weekly") return weekStamp();
  if (PUBLIC_ROTATION_MODE === "fixed") return "fixed";
  return dayStamp();
}

function hash32(input) {
  const hex = crypto.createHash("sha256").update(String(input)).digest("hex").slice(0, 8);
  return parseInt(hex, 16) >>> 0;
}

function deterministicPick(items, seed, count = 3) {
  if (!Array.isArray(items) || items.length === 0) return [];
  const out = [];
  const n = Math.min(Math.max(1, count), items.length);
  const used = new Set();
  let i = 0;
  while (out.length < n && i < (items.length * 3)) {
    const idx = hash32(`${seed}:${i}`) % items.length;
    if (!used.has(idx)) {
      used.add(idx);
      out.push(items[idx]);
    }
    i += 1;
  }
  return out;
}

function wildcardMatches(hostname, wildcardPattern) {
  const cleanHost = String(hostname || "").toLowerCase().split(":")[0];
  const cleanPattern = String(wildcardPattern || "").toLowerCase().trim();
  if (!cleanHost || !cleanPattern.startsWith("*.") || cleanPattern.length < 3) return false;
  const suffix = cleanPattern.slice(2);
  if (!suffix) return false;
  if (!cleanHost.endsWith(`.${suffix}`)) return false;
  return cleanHost !== suffix;
}

function isLikelyInternalHostname(hostname) {
  const normalized = String(hostname || "").toLowerCase().split(":")[0].trim();
  if (!normalized) return true;
  if (normalized === "localhost") return true;
  if (normalized.endsWith(".local")) return true;
  if (normalized.endsWith(".internal")) return true;
  if (normalized.endsWith(".up.railway.app")) return true;
  return false;
}

function parseConfiguredBaseEntry(entry) {
  try {
    if (!entry || entry === "*") return null;
    const value = /^https?:\/\//i.test(entry) ? entry : `https://${entry}`;
    const asUrl = new URL(value);
    const wildcard = asUrl.hostname.startsWith("*.");
    const canonicalHost = wildcard ? asUrl.hostname.slice(2) : asUrl.host;
    const baseUrl = `${asUrl.protocol}//${canonicalHost}`;

    return {
      hostname: asUrl.hostname,
      protocol: asUrl.protocol,
      wildcard,
      baseUrl,
      isInternal: isLikelyInternalHostname(asUrl.hostname)
    };
  } catch {
    return null;
  }
}


function resolvePublicBaseUrls(req, options = {}) {
  const rawForwardedHost = String(req.get("x-forwarded-host") || "")
    .split(",")
    .map((part) => part.trim())
    .find(Boolean);
  const host = String(
    rawForwardedHost ||
    req.get("x-original-host") ||
    req.get("x-host") ||
    req.get("host") ||
    "localhost"
  ).trim();
  const hostNoPort = host.split(":")[0];
  const proto = req.secure || String(req.get("x-forwarded-proto") || "").includes("https") ? "https" : "http";
  const requestBase = `${proto}://${host}`;
  const requestHostOnly = options && options.requestHostOnly === true;
  const preferConfiguredCanonical = options && options.preferConfiguredCanonical === true;

  const configured = parsePublicBaseUrlEntries();
  const parsedConfigured = configured
    .map((entry) => parseConfiguredBaseEntry(entry))
    .filter(Boolean);

  if (requestHostOnly) {
    if (preferConfiguredCanonical) {
      const matchingConfiguredCanonical = parsedConfigured
        .filter((entry) => entry.wildcard ? wildcardMatches(hostNoPort, entry.hostname) : entry.hostname === hostNoPort)
        .sort((a, b) => Number(a.isInternal) - Number(b.isInternal))
        .map((entry) => entry.wildcard ? `${entry.protocol}//${host}` : entry.baseUrl)
        .find(Boolean);

      if (matchingConfiguredCanonical) {
        return [matchingConfiguredCanonical];
      }

      const preferredConfiguredCanonical = parsedConfigured
        .sort((a, b) => {
          const internalDiff = Number(a.isInternal) - Number(b.isInternal);
          if (internalDiff !== 0) return internalDiff;
          return Number(a.wildcard) - Number(b.wildcard);
        })
        .map((entry) => entry.baseUrl)
        .find(Boolean);

      if (preferredConfiguredCanonical) {
        return [preferredConfiguredCanonical];
      }
    }

    return [requestBase];
  }

  if (parsedConfigured.length === 0) {
    return [requestBase];
  }

  const out = [];
  for (const entry of parsedConfigured) {
    if (entry.wildcard) {
      if (wildcardMatches(hostNoPort, entry.hostname)) {
        out.push(`${entry.protocol}//${host}`);
      }
      continue;
    }

    out.push(entry.baseUrl);
  }

  const resolved = [...new Set(out.filter(Boolean))];
  return resolved.length > 0 ? resolved : [requestBase];
}

function parsePublicBaseUrlEntries() {
  return PUBLIC_SITE_BASE_URL
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

app.get("/robots.txt", (req, res) => {
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.type("text/plain");

  if (process.env.ROBOTS_CONTENT) {
    return res.send(process.env.ROBOTS_CONTENT);
  }

  const p = path.join(process.cwd(), "robots.txt");
  if (fs.existsSync(p)) {
    return res.send(fs.readFileSync(p, "utf8"));
  }

  return res.send("User-agent: *\nDisallow: /\n");
});

app.get("/turnstile-sitekey", (req, res) => {
  if (isAdmin(req)) {
    return res.json({ sitekey: TURNSTILE_SITEKEY });
  }
  return res.status(404).type("text/plain").send("Not Found");
});

app.get("/__debug/runtime-incidents", requireAdmin, (req, res) => {
  res.json({
    ok: true,
    boot: buildRuntimeIncidentPayload("snapshot", { requested: true }),
    incidentFile: RUNTIME_INCIDENT_FILE,
    npmDebugLogDir: NPM_DEBUG_LOG_DIR,
    logFile: getLogFileStatus(),
    incidents: readRuntimeIncidents()
  });
});

app.get("/__debug/log-integrity", requireAdmin, (req, res) => {
  const memory = analyzeLogIntegrity(LOGS, LOG_IDS);
  const response = {
    ok: memory.ok,
    source: "runtime_memory",
    note: "Checks the current process log buffer, not a stale exported log file.",
    memory,
    logFile: getLogFileStatus()
  };

  if (String(req.query.includeFileTail || "") === "1") {
    const tail = readLogFileTail(req.query.bytes);
    const fileLines = String(tail.text || "").split(/\r?\n/);
    if (fileLines.length && fileLines[fileLines.length - 1] === "") fileLines.pop();
    response.fileTail = {
      status: tail.status,
      truncated: Boolean(tail.truncated),
      start: tail.start || 0,
      bytesRead: tail.bytesRead || 0,
      integrity: analyzeLogIntegrity(fileLines, [])
    };
    response.ok = response.ok && response.fileTail.integrity.ok;
  }

  res.json(response);
});

app.get("/__debug/log-file", requireAdmin, (req, res) => {
  const status = getLogFileStatus();

  if (!LOG_TO_FILE) {
    return res.status(404).json({
      ok: false,
      error: "log_to_file_disabled",
      hint: "Set LOG_TO_FILE=1 and LOG_FILE=/data/logs/visitors.log to write visitors.log.",
      status
    });
  }

  if (!status.exists) {
    return res.status(404).json({
      ok: false,
      error: "log_file_not_found",
      hint: "If LOG_FILE points under /data, attach a Railway volume mounted at /data or let the app create the directory on the next write.",
      status
    });
  }

  if (!status.isFile) {
    return res.status(400).json({
      ok: false,
      error: "log_path_not_file",
      hint: "LOG_FILE must point to a regular file, not a directory or special file.",
      status
    });
  }

  if (String(req.query.download || "") === "1") {
    const downloadStream = fs.createReadStream(LOG_FILE);
    downloadStream.once("error", (err) => {
      const statusCode = err.code === "ENOENT" ? 404 : 500;
      if (!res.headersSent) {
        return res.status(statusCode).json({
          ok: false,
          error: "log_file_stream_error",
          message: summarizeError(err),
          status: getLogFileStatus()
        });
      }
      try { res.destroy(err); } catch {}
    });

    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="visitors.log"');
    return downloadStream.pipe(res);
  }

  const tail = readLogFileTail(req.query.bytes);
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("X-Log-File", LOG_FILE);
  res.setHeader("X-Log-Size-Bytes", String(tail.status.sizeBytes || 0));
  res.setHeader("X-Log-Truncated", tail.truncated ? "1" : "0");
  return res.send(tail.text);
});

app.get("/__debug/key", requireAdmin, (req, res) => {
  const items = AES_KEYS.map((buf, idx) => {
    const sha = crypto.createHash("sha256").update(buf).digest("hex");
    const b64url = buf.toString("base64url");
    return {
      index: idx,
      len: buf.length,
      sha256: sha,
      b64url: DEBUG_ALLOW_PLAINTEXT_KEYS ? b64url : mask(b64url),
      note: buf.length === 32 ? "OK (32 bytes)" : "Unexpected length"
    };
  });
  res.json({ ok:true, count: items.length, keys: items });
});

app.get("/__debug/decrypt", requireAdmin, (req, res) => {
  const d = String(req.query.d || "");
  const out = tryDecryptAny(d);
  if (out && out.url) return res.status(200).type("text/plain").send(out.url);
  const bf = bruteSplitDecryptFull(d);
  if (bf && bf.url) return res.status(200).type("text/plain").send(bf.url);
  const tried = (out && out.tried) ? out.tried.join("|") : "none";
  return res.status(200).type("text/plain").send("fail; tried=" + tried);
});

app.get("/__hp.gif", (req, res) => {
  const ip = getClientIp(req);
  addLog(`[HP] honeypot hit ip=${safeLogValue(ip)} ua="${safeLogValue((req.get("user-agent")||"").slice(0,UA_TRUNCATE_LENGTH))}"`);
  addStrike(ip, STRIKE_WEIGHT_HP);
  maybeDenyForVisibleIpReputation(req, ip, "honeypot");
  res.set("Cache-Control","no-store");
  return res.status(204).end();
});

// Helper function to validate IP address format. Use Node's parser instead of
// maintaining partial IPv4/IPv6 regexes.
function isValidIpAddress(ip) {
  return typeof ip === "string" && net.isIP(ip.trim()) !== 0;
}

app.post("/admin/unban", requireAdmin, (req, res) => {
  try {
    const ip = String(req.query.ip||"").trim();
    if (!ip) return res.status(400).send("ip required");

    // Validate IP format
    if (!isValidIpAddress(ip)) {
      return res.status(400).json({error: "Invalid IP address format"});
    }

    const safeIp = sanitizeIpForKey(ip);
    if (!inMemBans.has(safeIp)) return res.json({ok:true, message:"not banned"});
    inMemBans.delete(safeIp);
    return res.json({ok:true, message:"unbanned", ip});
  } catch (error) {
    addLog(`[ADMIN-ERROR] unban: ${error.message}`);
    return res.status(500).json({error: "Internal server error"});
  }
});

app.post("/admin/strike-reset", requireAdmin, (req, res) => {
  try {
    const ip = String(req.query.ip||"").trim();
    if (!ip) return res.status(400).send("ip required");

    // Validate IP format
    if (!isValidIpAddress(ip)) {
      return res.status(400).json({error: "Invalid IP address format"});
    }

    const safeIp = sanitizeIpForKey(ip);
    inMemStrikes.delete(safeIp);
    return res.json({ok:true, message:"strikes reset", ip});
  } catch (error) {
    addLog(`[ADMIN-ERROR] strike-reset: ${error.message}`);
    return res.status(500).json({error: "Internal server error"});
  }
});

app.get(
  "/admin/scanner-stats",
  (req, res, next) => {
    if (isAdmin(req) || isAdminSSE(req)) return next();
    addLog(`[ADMIN] scanner-stats denied ip=${safeLogValue(getClientIp(req))} ua="${safeLogValue((req.get("user-agent")||"").slice(0,UA_TRUNCATE_LENGTH))}"`);
    return res.status(401).type("text/plain").send("Unauthorized");
  },

  (req, res) => {
    const day = String(req.query.day || utcDayStamp()).trim();
    const derived = computeScannerStatsFromLogs();
    const counterStats = {
      total: SCANNER_STATS.total,
      byReason: SCANNER_STATS.byReason,
      byReasonCode: SCANNER_STATS.byReasonCode,
      byUA: SCANNER_STATS.byUA
    };
    const logStats = (derived && derived.total > 0) ? derived : counterStats;
    const opsStats = buildOpsScannerStatsForDay(day);
    const selectedStats = selectScannerStatsForResponse(logStats, opsStats);

    const topUA = Object.entries(logStats.byUA || {})
      .sort((a,b) => b[1] - a[1])
      .slice(0, 20)
      .map(([ua, count]) => ({ ua, count }));

    res.json({
      ok: true,
      day,
      source: "combined",
      total: selectedStats.total,
      byReason: selectedStats.byReason,
      byReasonCode: logStats.byReasonCode || {},
      decisionCounters: SCANNER_DECISION_COUNTERS,
      topUA,
      sources: {
        logs: {
          total: logStats.total || 0,
          byReason: logStats.byReason || {},
          byReasonCode: logStats.byReasonCode || {},
          topUA
        },
        opsMetrics: opsStats
      },
      now: new Date().toISOString()
    });
  }
);

async function readResponsePreview(response, maxBytes = SCANNER_FETCH_PREVIEW_BYTES, timeoutMs = SCANNER_FETCH_TIMEOUT_MS) {
  const limit = Math.max(1, Number(maxBytes) || SCANNER_FETCH_PREVIEW_BYTES);
  if (!response || !response.body) {
    return { text: "", truncated: false, bytes: 0 };
  }

  const chunks = [];
  let bytes = 0;
  let timedOut = false;
  const timeoutValue = Math.max(100, Number(timeoutMs) || SCANNER_FETCH_TIMEOUT_MS);

  const appendChunk = (chunk) => {
    const value = Buffer.from(chunk || []);
    if (!value.length || bytes >= limit) return false;
    const remaining = limit - bytes;
    const slice = value.length > remaining ? value.subarray(0, remaining) : value;
    chunks.push(slice);
    bytes += slice.length;
    return value.length > remaining || bytes >= limit;
  };

  if (typeof response.body.getReader === "function") {
    const reader = response.body.getReader();
    let timeoutResolve;
    const timeoutPromise = new Promise(resolve => {
      timeoutResolve = resolve;
    });
    const timeout = setTimeout(() => {
      timedOut = true;
      try { reader.cancel("scanner_fetch_preview_timeout"); } catch {}
      if (typeof timeoutResolve === "function") timeoutResolve({ done: true, timedOut: true });
    }, timeoutValue);

    try {
      while (bytes < limit) {
        const result = await Promise.race([reader.read(), timeoutPromise]);
        if (!result || result.done || result.timedOut) break;
        if (appendChunk(result.value)) {
          try { await reader.cancel("scanner_fetch_preview_cap"); } catch {}
          break;
        }
      }
    } finally {
      clearTimeout(timeout);
      try { reader.releaseLock(); } catch {}
    }
  } else if (typeof response.body[Symbol.asyncIterator] === "function") {
    const timeout = setTimeout(() => {
      timedOut = true;
      try { response.body.destroy(new Error("scanner_fetch_preview_timeout")); } catch {}
    }, timeoutValue);

    try {
      try {
        for await (const chunk of response.body) {
          if (appendChunk(chunk)) {
            try { response.body.destroy(); } catch {}
            break;
          }
        }
      } catch (error) {
        if (!timedOut) throw error;
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  return {
    text: Buffer.concat(chunks, bytes).toString("utf8"),
    truncated: bytes >= limit,
    timedOut,
    bytes
  };
}

app.post("/admin/scanner-fetch", requireAdmin, express.json({ limit: "2kb" }), async (req, res) => {
  if (!SCANNER_FETCH_ENABLED) {
    return res.status(403).json({
      ok: false,
      error: "scanner_fetch_disabled",
      message: "Set SCANNER_FETCH_ENABLED=1 to allow admin-triggered scanner-profile fetches."
    });
  }

  const body = req.body || {};
  const rawUrl = String(body.url || "").trim();
  let parsedUrl;
  try {
    parsedUrl = new URL(rawUrl);
  } catch (_) {
    return res.status(400).json({ ok: false, error: "invalid_url" });
  }

  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    return res.status(400).json({ ok: false, error: "unsupported_url_protocol" });
  }

  let resolvedAddresses;
  try {
    resolvedAddresses = await assertScannerFetchTargetAllowed(parsedUrl, body.timeoutMs || SCANNER_FETCH_TIMEOUT_MS);
  } catch (error) {
    return res.status(400).json({ ok: false, error: String(error && error.message || error) });
  }
  const profileName = String(body.profile || body.profileName || "").trim();
  const profile = profileName ? findScannerProfileByName(profileName) : null;
  if (profileName && !profile) {
    return res.status(400).json({
      ok: false,
      error: "unknown_scanner_profile",
      availableProfiles: [SCANNER_GENERIC_PROFILE.name, ...SCANNER_PROFILES.map(candidate => candidate.name)]
    });
  }

  try {
    const scannerHeaders = body.headers && typeof body.headers === "object" ? { ...body.headers } : {};
    const { response, address: usedAddress } = await makePinnedScannerRequestWithFallback(parsedUrl, resolvedAddresses, {
      profile,
      profileName,
      randomKnownProfile: !profileName,
      method: body.method || "GET",
      redirect: body.redirect || "manual",
      timeoutMs: body.timeoutMs,
      headers: scannerHeaders
    });
    const pinnedFetchUrl = buildPinnedScannerFetchUrl(parsedUrl, usedAddress);
    const preview = await readResponsePreview(response, SCANNER_FETCH_PREVIEW_BYTES, body.timeoutMs || SCANNER_FETCH_TIMEOUT_MS);
    return res.json({
      ok: true,
      url: parsedUrl.toString(),
      fetchUrl: pinnedFetchUrl,
      usedAddress,
      profile: (profile && profile.name) || "random",
      resolvedAddresses,
      status: response.status,
      redirected: response.redirected,
      finalUrl: response.url,
      headers: Object.fromEntries(response.headers.entries()),
      bodyPreview: preview.text,
      bodyPreviewBytes: preview.bytes,
      bodyPreviewTruncated: preview.truncated,
      bodyPreviewTimedOut: preview.timedOut
    });
  } catch (error) {
    addLog(`[ADMIN-ERROR] scanner-fetch: ${safeLogValue(error && error.message || error, 160)}`);
    return res.status(502).json({ ok: false, error: "scanner_fetch_failed", message: String(error && error.message || error) });
  }
});

app.get("/admin/active-requests", (req, res) => {
  if (!isAdmin(req) && !isAdminSSE(req)) return res.status(401).type("text/plain").send("Unauthorized");
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || String(ACTIVE_REQUEST_DUMP_LIMIT), 10) || ACTIVE_REQUEST_DUMP_LIMIT));
  const topLimit = Math.min(50, Math.max(1, parseInt(req.query.top || String(ACTIVE_REQUEST_TOP_PATH_LIMIT), 10) || ACTIVE_REQUEST_TOP_PATH_LIMIT));
  res.json({ ok: true, ...buildActiveRequestDiagnostics(Date.now(), { limit, topLimit }) });
});

app.get("/__debug/active-requests", requireAdmin, (req, res) => {
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || String(ACTIVE_REQUEST_DUMP_LIMIT), 10) || ACTIVE_REQUEST_DUMP_LIMIT));
  const topLimit = Math.min(50, Math.max(1, parseInt(req.query.top || String(ACTIVE_REQUEST_TOP_PATH_LIMIT), 10) || ACTIVE_REQUEST_TOP_PATH_LIMIT));
  res.json({ ok: true, ...buildActiveRequestDiagnostics(Date.now(), { limit, topLimit }) });
});

app.get("/admin/ops-metrics", (req, res) => {
  if (!isAdmin(req) && !isAdminSSE(req)) return res.status(401).type("text/plain").send("Unauthorized");
  const day = String(req.query.day || utcDayStamp()).trim();
  res.json({
    ok: true,
    day,
    requests: OPS_METRICS.requestsByDay[day] || {},
    friction: OPS_METRICS.frictionByDay[day] || {},
    incidents: OPS_METRICS.incidentsByDay[day] || {},
    lastUpdatedAt: OPS_METRICS.lastUpdatedAt
  });
});

app.post("/admin/incident", requireAdmin, express.json({ limit: "4kb" }), (req, res) => {
  const body = req.body || {};
  const day = String(body.day || utcDayStamp()).trim();
  const severity = String(body.severity || "unknown").trim().toLowerCase();
  const tag = String(body.tag || "manual").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "_");
  incrementOpsMetric(OPS_METRICS.incidentsByDay, day, "confirmed_total", 1);
  incrementOpsMetric(OPS_METRICS.incidentsByDay, day, `severity_${severity}`, 1);
  incrementOpsMetric(OPS_METRICS.incidentsByDay, day, `tag_${tag}`, 1);
  return res.json({ ok: true, day, severity, tag, incidents: OPS_METRICS.incidentsByDay[day] });
});

// Replace the entire challenge route HTML content with this fixed version:

function resolveChallengeRequest(req, res) {
  let nextEnc = "";
  const body = req.body || {};
  const requestReason = req.query.cr || req.query.reason || body.cr || "";
  let challengeReason = sanitizeChallengeReason(requestReason);
  const rawCt = req.query.ct || body.ct;

  if (rawCt) {
    const payload = verifyChallengeToken(String(rawCt), req);
    if (!payload) {
      addLog(`[CHALLENGE] Invalid or expired challenge token`);
      recordChallengeBypassAttempt(req, "invalid_challenge_token");
      res.status(400).send("Invalid or expired challenge link");
      return null;
    }
    nextEnc = payload.next;
    if (payload.cr) {
      challengeReason = sanitizeChallengeReason(payload.cr);
    }
    addLog(`[CHALLENGE] Valid token nextLen=${nextEnc.length} age=${Date.now() - payload.ts}ms`);
  } else if (req.query.next) {
    nextEnc = String(req.query.next);
    addLog(`[CHALLENGE] LEGACY next parameter used len=${nextEnc.length} - auto-migrating`);
    const migrated = createChallengeRedirect(nextEnc, req, challengeReason || "legacy_next_migrated");
    return { redirect: migrated };
  } else if (body.next) {
    nextEnc = String(body.next);
    addLog(`[CHALLENGE] Legacy body next parameter used len=${nextEnc.length} - auto-migrating`);
    const migrated = createChallengeRedirect(nextEnc, req, challengeReason || "legacy_body_next_migrated");
    return { redirect: migrated };
  } else {
    res.status(400).send("Missing challenge data");
    return null;
  }

  return {
    nextEnc,
    challengeReason,
    ct: rawCt ? String(rawCt) : ""
  };
}

const createBuildChallengeHtml = require("../challenge/buildChallengeHtml.js");
const buildChallengeHtml = createBuildChallengeHtml({
  TURNSTILE_ORIGIN,
  withOptionalUrlPrefix
});

const handleChallengePage = (req, res) => {
  const resolved = resolveChallengeRequest(req, res);
  if (!resolved) return;
  if (resolved.redirect) return res.redirect(302, resolved.redirect);

  const fragmentToken = resolved.ct || createChallengeToken(resolved.nextEnc, req, resolved.challengeReason);

  const htmlContent = `<!doctype html><html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#0c1116">
<meta name="robots" content="noindex,nofollow">
<title>Verify you are human</title>
<style>
  body{ margin:0; background:#0c1116; color:#e8eef6; }
  noscript{ display:block; padding:16px; color:#ef4444; font-family:system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial,sans-serif; }
</style>
</head>
<body>
<noscript>Turnstile requires JavaScript. Please enable JS and refresh.</noscript>
<script nonce="${res.locals.cspNonce || ''}">
  fetch(${JSON.stringify(withOptionalUrlPrefix("/challenge-fragment"))}, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ ct: ${JSON.stringify(fragmentToken)}, nonce: ${JSON.stringify(res.locals.cspNonce || "")} })
  })
    .then(function(r){ if (!r.ok) throw new Error("Failed to load"); return r.text(); })
    .then(function(html){ document.open(); document.write(html); document.close(); })
    .catch(function(){ document.body.innerHTML = "<p style=\\"font-family:system-ui; padding:16px; color:#ef4444\\">Failed to load challenge. Please refresh.</p>"; });
</script>
</body>
</html>`;

  res.type("html").send(htmlContent);
};

app.get("/challenge", limitChallengeView, handleChallengePage);
if (OPTIONAL_URL_PREFIX) {
  app.get(withOptionalUrlPrefix("/challenge"), limitChallengeView, handleChallengePage);
}

function handleChallengeFragment(req, res) {
  const resolved = resolveChallengeRequest(req, res);
  if (!resolved) return;
  if (resolved.redirect) return res.redirect(302, resolved.redirect);

  const rawNonce = (req.body && req.body.nonce) || req.query.nonce || "";
  const nonce = /^[A-Za-z0-9+/=_-]{8,}$/.test(String(rawNonce)) ? String(rawNonce) : res.locals.cspNonce;

  const { nextEnc, challengeReason } = resolved;
  const nextPath = safeDecode(nextEnc);
  const [baseOnly] = nextPath.split("?");
  const linkHash = hashFirstSeg(baseOnly);
  const cdata = `${linkHash}_${Math.floor(Date.now()/1000)}`;

  addLog(`[CHALLENGE] secured next='${nextEnc.slice(0,20)}…' reason=${safeLogValue(challengeReason || "-", 48)} cdata=${cdata.slice(0,16)}…`);
  addLog(`[TS-PAGE] sitekey=${TURNSTILE_SITEKEY.slice(0,12)}… hash=${linkHash.slice(0,8)}…`);

  const challengePayload = {
    sitekey: TURNSTILE_SITEKEY,
    cdata: cdata,
    next: nextEnc,
    lh: linkHash,
    ts: Date.now(),
    cr: challengeReason || undefined
  };

  const encryptedData = encryptChallengeData(challengePayload);
  const htmlContent = buildChallengeHtml(encryptedData, nonce);

  res.type("html").send(htmlContent);
}

app.post("/challenge-fragment", limitChallengeView, handleChallengeFragment);
app.get("/challenge-fragment", limitChallengeView, handleChallengeFragment);
if (OPTIONAL_URL_PREFIX) {
  app.post(withOptionalUrlPrefix("/challenge-fragment"), limitChallengeView, handleChallengeFragment);
  app.get(withOptionalUrlPrefix("/challenge-fragment"), limitChallengeView, handleChallengeFragment);
}

app.use((req, res, next) => {
  if (!shouldHandleAsDynamicPublicPath(req)) return next();

  const pathname = String(req.path || '');
  const { persona, seed, paths } = getCurrentPublicPathSet();
  if (!paths.has(pathname)) return next();

  return servePublicPathResponse(req, res, pathname, persona, seed);
});

const handleEmailSafePath = async (req, res) => {
  const clean = extractEmailSafePayloadPath(req);
  const scannerCtx = buildScannerInterstitialContext(req, "Email-safe path");
  addLog(`[INTERSTITIAL] /e path used len=${clean.length}`);
  if (scannerCtx.scannerSafeHtmlEligible) {
    const handled = await tryRenderTrustedScannerSafeHtmlForPayload(req, res, clean, scannerCtx, {
      source: "email-safe-route"
    });
    if (handled) return;
  }
  logScannerHit(req, scannerCtx.scannerReason || "Email-safe path", clean);
  return renderScannerSafePage(req, res, clean, scannerCtx.scannerReason || "Email-safe path", {
    emailSafe: true,
    scannerProfile: scannerCtx.scannerProfile
  });
};

app.get("/e/:data(*)", handleEmailSafePath);
if (OPTIONAL_URL_PREFIX) {
  app.get(withOptionalUrlPrefix("/e/:data(*)"), handleEmailSafePath);
}

const handleEmailSafePathHead = (req, res) => {
  const clean = extractEmailSafePayloadPath(req);
  const scannerCtx = buildScannerInterstitialContext(req, "HEAD-probe");
  addLog(`[INTERSTITIAL] HEAD /e path`);
  logScannerHit(req, scannerCtx.scannerReason || "HEAD-probe", clean);
  return sendScannerSafetyLaneHeadResponse(req, res, clean, "HEAD-probe", {
    scannerProfile: scannerCtx.scannerProfile,
    source: "email-safe-route"
  });
};

app.head("/e/:data(*)", handleEmailSafePathHead);
if (OPTIONAL_URL_PREFIX) {
  app.head(withOptionalUrlPrefix("/e/:data(*)"), handleEmailSafePathHead);
}

const handleRRoute = async (req, res) => {
  const baseString = safeDecode(String(req.query.d || ""));
  if (!baseString) return res.status(400).send("Missing data");
  return handleRedirectCore(req, res, baseString);
};

app.get("/r", handleRRoute);
if (OPTIONAL_URL_PREFIX) {
  app.get(withOptionalUrlPrefix("/r"), handleRRoute);
}

let activeCatchAllRequests = 0;
app.get("/:data(*)", async (req, res) => {
  if (isBrownoutActive()) {
    res.setHeader("Retry-After", "5");
    addLog(`[BROWNOUT] shedding route=catchall ip=${safeLogValue(getClientIp(req), 64)}`);
    return res.status(503).send("Temporarily unavailable");
  }
  if (activeCatchAllRequests >= MAX_CATCHALL_CONCURRENCY) {
    res.setHeader("Retry-After", "1");
    addLog(`[OVERLOAD] route=catchall active=${activeCatchAllRequests} max=${MAX_CATCHALL_CONCURRENCY} ip=${safeLogValue(getClientIp(req), 64)}`);
    return res.status(503).send("Busy, retry shortly");
  }
  activeCatchAllRequests += 1;
  const done = () => {
    activeCatchAllRequests = Math.max(0, activeCatchAllRequests - 1);
  };

  const urlPathFull = (req.originalUrl || "").slice(1);
  const cleanPath = urlPathFull.split("?")[0];
  const { payloadPath, usedPrefix } = stripOptionalUrlPrefix(cleanPath);

  if (!payloadPath) {
    done();
    return res.status(404).send("Not Found");
  }

  if (usedPrefix) {
    addLog(`[ROUTE] optional prefix matched prefix=${safeLogValue(OPTIONAL_URL_PREFIX, 80)} ip=${safeLogValue(getClientIp(req))}`);
  }

  if (!validateBase64Url(payloadPath)) {
    addLog(`[ROUTE] non-payload catch-all ip=${safeLogValue(getClientIp(req), 64)} path=${safeLogValue(req.path, 120)} -> 404`);
    done();
    return res.status(404).send("Not Found");
  }

  try {
    return await handleRedirectCore(req, res, payloadPath);
  } finally {
    done();
  }
});

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

let _health = { ok: null, lastHeartbeat: 0, okStreak: 0, failStreak: 0, inflight: false };

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

const openSockets = new Set();
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
