module.exports = function createRequestRuntime(dependencies) {
  const {
    ARCHIVE_PROBE_NAME_REGEX, ARCHIVE_PROBE_SUFFIX_REGEX, CLIENT_ERROR_RAW_PACKET_PREVIEW_BYTES, REQUEST_TIMEOUT_MS,
    SCANNER_PROBE_EXACT_PATHS, SCANNER_PROBE_PREFIXES, addLog, classifyScannerProbeCandidate, crypto,
    decodePathForScannerMatching,
    decodeB64urlLoose, express, formatRequestIdentityLogSuffix, getClientIp,
    getConfiguredEmailDelimiters, getRequestIdentity, isLikelyEmail, markTimeoutAndMaybeBrownout,
    isScannerExactProbePath, normalizeScannerProbeCandidate, os,
    parseRedirectPayload, pathMatchesWithOptionalPrefix, readPositiveIntEnv,
    safeDecode, safeLogValue, stripOptionalUrlPrefix
  } = dependencies;
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

  return {
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
  };
};
