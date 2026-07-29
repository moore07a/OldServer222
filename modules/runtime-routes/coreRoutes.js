"use strict";

function createCoreRoutes(dependencies) {
  const {
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
  } = dependencies;

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

const createOperationalRoutes = require("../runtime-routes/operationalRoutes.js");
createOperationalRoutes({
  ACTIVE_REQUEST_DUMP_LIMIT,
  ACTIVE_REQUEST_TOP_PATH_LIMIT,
  AES_KEYS,
  DEBUG_ALLOW_PLAINTEXT_KEYS,
  LOGS,
  LOG_FILE,
  LOG_IDS,
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
  addLog,
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
  encryptChallengeData,
  express,
  extractEmailSafePayloadPath,
  findScannerProfileByName,
  fs,
  getClientIp,
  getCurrentPublicPathSet,
  getLogFileStatus,
  handleRedirectCore,
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
  mask,
  maybeDenyForVisibleIpReputation,
  net,
  path,
  readLogFileTail,
  readRuntimeIncidents,
  recordChallengeBypassAttempt,
  renderScannerSafePage,
  require,
  requireAdmin,
  safeDecode,
  safeLogValue,
  sanitizeChallengeReason,
  sanitizeIpForKey,
  selectScannerStatsForResponse,
  sendScannerSafetyLaneHeadResponse,
  servePublicPathResponse,
  shouldHandleAsDynamicPublicPath,
  stripOptionalUrlPrefix,
  summarizeError,
  tryDecryptAny,
  tryRenderTrustedScannerSafeHtmlForPayload,
  utcDayStamp,
  validateBase64Url,
  verifyChallengeToken,
  withOptionalUrlPrefix,
  rotationSeed,
  hash32,
  deterministicPick,
  resolvePublicBaseUrls
});

  return {
    handleSecurityTxt
  };
}

module.exports = createCoreRoutes;
