"use strict";

function createBehavioralDetection(dependencies) {
  const {
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
    toReasonCode,
    trackIntervalHandle
  } = dependencies;

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
  const scannerResult = getRequestScannerDetection(req);
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

function getRequestScannerDetection(req) {
  if (req && req._scannerBehaviorDetectionResult) return req._scannerBehaviorDetectionResult;
  const result = detectScannerEnhancedWithBehavior(req);
  if (req) req._scannerBehaviorDetectionResult = result;
  return result;
}

function logScannerHit(req, reason, nextEnc) {
  const ip   = getClientIp(req);
  const ua   = (req.get("user-agent") || "").slice(0, UA_TRUNCATE_LENGTH);
  const requestPath = String(req.path || req.originalUrl || "");
  const path = nextEnc
    ? (/^\/e(?:\/|$)/.test(requestPath) ? "/e/[redacted]" : "/[redacted]")
    : requestPath.slice(0, PATH_TRUNCATE_LENGTH);
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


  return {
    BEHAVIORAL_CONFIG,
    REQUEST_HISTORY,
    cleanupRequestHistory,
    detectScannerEnhancedWithBehavior,
    getRequestScannerDetection,
    buildScannerInterstitialContext,
    logScannerHit
  };
}

module.exports = createBehavioralDetection;
