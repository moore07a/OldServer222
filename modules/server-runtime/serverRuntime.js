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
  RE_B64URL_SEGMENT, SCANNER_AGG_ALERT_THRESHOLD, TRUST_CLOUDFLARE_XFF_CHAIN,
  TRUST_UPSTREAM_GEO_HEADERS, VISIBLE_IP_REPUTATION_WEIGHTS, boundedMapSet, clampMs,
  formatLocal, fs, getConfiguredEmailDelimiters, lookupIpinfoLite, maybeEnrichGeoAsync,
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
  crypto
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
