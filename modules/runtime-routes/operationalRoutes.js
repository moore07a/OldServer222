"use strict";

function createOperationalRoutes(dependencies) {
  const {
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
  } = dependencies;

// ================== PUBLIC CONTENT HELPERS ==================












function isLikelyInternalHostname(hostname) {
  const normalized = String(hostname || "").toLowerCase().split(":")[0].trim();
  if (!normalized) return true;
  if (normalized === "localhost") return true;
  if (normalized.endsWith(".local")) return true;
  if (normalized.endsWith(".internal")) return true;
  if (normalized.endsWith(".up.railway.app")) return true;
  return false;
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


  return {
  };
}

module.exports = createOperationalRoutes;
