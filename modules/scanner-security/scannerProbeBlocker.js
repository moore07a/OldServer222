"use strict";

function createScannerProbeBlocker(getDependencies) {
  return (req, res, next) => {
  const {
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
  } = getDependencies();
  const rawPathOriginal = String(req.path || req.url || "/").split("?")[0];
  const originalPathOriginal = String(req.originalUrl || req.url || "/").split("?")[0];
  const rawPath = rawPathOriginal.toLowerCase();
  const originalPath = originalPathOriginal.toLowerCase();

  // Ultra-fast short-circuit for common scanner spam before any decode work.
  // Frequent in production logs: POST / and POST // probes.
  if (req.method === "POST" && (rawPath === "/" || rawPath === "//" || originalPath === "//")) {
    return res.status(404).end("Not Found");
  }

  const decodedPathOriginal = decodePathForScannerMatching(rawPathOriginal);
  const decodedPath = decodedPathOriginal.toLowerCase();
  const decodedOriginalPath = decodePathForScannerMatching(originalPath).toLowerCase();
  // Strip leading slash for prefix matching
  const candidateOriginal = rawPathOriginal.startsWith("/") ? rawPathOriginal.slice(1) : rawPathOriginal;
  const candidate = rawPath.startsWith("/") ? rawPath.slice(1) : rawPath;
  const decodedCandidateOriginal = decodedPathOriginal.startsWith("/") ? decodedPathOriginal.slice(1) : decodedPathOriginal;
  const decodedCandidate = decodedPath.startsWith("/") ? decodedPath.slice(1) : decodedPath;
  const rawUrlPayloadCandidate = isLikelyRawUrlRedirectPayload(candidate, decodedCandidate);
  const probeCandidate = normalizeScannerProbeCandidate(candidate);
  const decodedProbeCandidate = normalizeScannerProbeCandidate(decodedCandidate);
  const emailSafeProbeCandidate = isEmailSafePathCandidate(probeCandidate) || isEmailSafePathCandidate(decodedProbeCandidate);
  const flexibleRedirectProbeCandidate =
    isLikelyFlexibleRedirectPayloadCandidate(candidateOriginal) ||
    isLikelyFlexibleRedirectPayloadCandidate(decodedCandidateOriginal);

  const normalizedPath = `/${probeCandidate || candidate}`;
  const normalizedDecodedPath = `/${decodedProbeCandidate || decodedCandidate}`;
  const isDoubleSlashPostProbe = req.method === "POST" && (
    normalizedPath.includes("//") ||
    normalizedDecodedPath.includes("//") ||
    originalPath.includes("//") ||
    decodedOriginalPath.includes("//")
  );
  const isCommonNoisePath =
    normalizedPath === "/sitemap.txt" ||
    normalizedDecodedPath === "/sitemap.txt" ||
    normalizedPath === "/sitemap.xml.gz" ||
    normalizedDecodedPath === "/sitemap.xml.gz" ||
    normalizedPath === "/th1s_1s_a_4o4.html" ||
    normalizedDecodedPath === "/th1s_1s_a_4o4.html";


  const isProbe =
    !rawUrlPayloadCandidate && (
    isDoubleSlashPostProbe ||
    isCommonNoisePath ||
    probeCandidate.includes("..") ||
    (!rawUrlPayloadCandidate && decodedProbeCandidate.includes("..")) ||
    (!emailSafeProbeCandidate && (
      probeCandidate.includes(".php") ||
      probeCandidate.includes(".asp") ||
      probeCandidate.includes(".jsp") ||
      (!flexibleRedirectProbeCandidate && (
        NESTED_SCANNER_SUBSTRINGS.some(fragment => probeCandidate.includes(fragment) || decodedProbeCandidate.includes(fragment)) ||
        isLikelyArchiveProbePath(probeCandidate) ||
        isLikelyArchiveProbePath(decodedProbeCandidate) ||
        isLikelySensitiveConfigProbePath(probeCandidate) ||
        isLikelySensitiveConfigProbePath(decodedProbeCandidate) ||
        isScannerExactProbePath(probeCandidate) ||
        isScannerExactProbePath(decodedProbeCandidate) ||
        SCANNER_PROBE_PREFIXES.some(p => probeCandidate.startsWith(p) || decodedProbeCandidate.startsWith(p))
      ))
    ))
    );

  if (isProbe) {
    const identity = getRequestIdentity(req);
    const ip = identity.ip;
    const knownScannerDenyKey = getKnownScannerDenyKey(identity);
    const day = utcDayStamp();
    const category = chooseScannerProbeCategory(probeCandidate, decodedProbeCandidate) || "scanner_probe";
    incrementOpsMetric(OPS_METRICS.frictionByDay, day, "scanner_block_total", 1);
    incrementOpsMetric(OPS_METRICS.frictionByDay, day, `scanner_block_reason_${category}`, 1);
    if (knownScannerDenyKey) {
      const burst = recordKnownScannerProbeBurst(knownScannerDenyKey);
      if (burst.shouldDeny) {
        addDenyCache(knownScannerDenyKey, "known_scanner", KNOWN_SCANNER_DENY_TTL_SECONDS);
      }
    }
    if (ip && ip !== knownScannerDenyKey && shouldTrackVisibleIpKnownScannerBurst(category)) {
      const visibleBurst = recordKnownScannerVisibleIpBurst(ip);
      if (visibleBurst.shouldDeny && canDenyCacheVisibleIp(identity, ip)) {
        addDenyCache(ip, "known_scanner_visible", KNOWN_SCANNER_VISIBLE_IP_DENY_TTL_SECONDS);
      }
    }
    if (shouldTrackVisibleIpKnownScannerBurst(category)) {
      maybeDenyForVisibleIpReputation(req, ip, "scanner_probe", { detail: category });
    }
    const shouldLog = aggregatePerIpEvent("SCANNER-BLOCK", {
      ip,
      reason: category,
      suppressFirst: true
    });
    if (shouldLog) {
      addLog(`[SCANNER-BLOCK] ip=${safeLogValue(ip, 64)} method=${safeLogValue(req.method, 12)} blockedPath=${safeLogValue(rawPath, 120)} originalPath=${safeLogValue(originalPath, 120)} reason=${safeLogValue(category, 64)}`);
    }
    return res.status(404).end("Not Found");
  }
  next();
};
}

module.exports = createScannerProbeBlocker;
