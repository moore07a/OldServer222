"use strict";

module.exports = function createStartupSummary(dependencies) {
  const {
    AES_KEYS, ALLOWED_COUNTRIES, ALLOWLIST_DOMAINS, BAN_AFTER_STRIKES, BAN_TTL_SEC,
    BLOCKED_ASNS, BLOCKED_COUNTRIES, CRAWLER_PUBLIC_WALK_COOLDOWN_SECONDS,
    CRAWLER_PUBLIC_WALK_MAX_PATHS, CRAWLER_PUBLIC_WALK_SEARCH_MAX_PATHS,
    CRAWLER_PUBLIC_WALK_THROTTLE_ENABLED, CRAWLER_PUBLIC_WALK_WINDOW_SECONDS,
    ENFORCE_ACTION, EVENT_LOOP_FATAL_CONSECUTIVE, EVENT_LOOP_FATAL_MS,
    EVENT_LOOP_LAG_SAMPLE_MS, EVENT_LOOP_LAG_WARN_MS, EXPECT_HOSTNAME_PATTERNS,
    HEADLESS_BLOCK, HEADLESS_SOFT_STRIKE, HEADLESS_STRIKE_WEIGHT, HEALTH_HEARTBEAT_MS,
    HEALTH_INTERVAL_MS, IMPERSONATE_MIN_CONFIDENCE, IMPERSONATE_SCANNER,
    IMPERSONATE_SCANNER_STRICT, INTERSTITIAL_BYPASS_SECRET,
    INTERSTITIAL_REASON_HEADER_ENABLED, IPINFO_LITE_ENABLED, KNOWN_SCANNER_DENY_THRESHOLD,
    KNOWN_SCANNER_DENY_TTL_SECONDS, KNOWN_SCANNER_VISIBLE_IP_DENY_TTL_SECONDS,
    KNOWN_SCANNER_VISIBLE_IP_THRESHOLD, LOG_FILE, LOG_FILE_MAX_BYTES, LOG_FILE_MAX_FILES,
    LOG_TO_FILE, MAX_BRUTE_SPLIT_PAYLOAD_LENGTH, MAX_REDIRECT_PAYLOAD_LENGTH,
    MAX_REDIRECT_URL_PATH_LENGTH, MAX_TOKEN_AGE_SEC, NPM_DEBUG_LOG_DIR,
    OPTIONAL_URL_PREFIX, PORT, RATE_CAPACITY, RATE_LIMIT_MAX_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS, RATE_WINDOW_SECONDS, REDIRECT_PAYLOAD_OVERSIZE_MODE,
    REQUEST_TIMEOUT_MS, REQUIRE_CF_HEADERS, RUNTIME_INCIDENT_FILE,
    SCANNER_COMPAT_HEADERS_ENABLED, SERVER_HEADERS_TIMEOUT_MS, SERVER_KEEP_ALIVE_TIMEOUT_MS,
    SERVER_MAX_REQUESTS_PER_SOCKET, STRIKE_WEIGHT_HP, TRUST_UPSTREAM_GEO_HEADERS,
    TURNSTILE_SECRET, TURNSTILE_SITEKEY, UNKNOWN_SCANNER_DENY_TTL_SECONDS,
    UNKNOWN_SCANNER_MAX_HISTORY_PER_IP, UNKNOWN_SCANNER_RAPID_UNIQUE_PATHS,
    UNKNOWN_SCANNER_RAPID_WINDOW_SECONDS, UNKNOWN_SCANNER_SHIELD_ENABLED,
    UNKNOWN_SCANNER_UNIQUE_PATHS, UNKNOWN_SCANNER_WINDOW_SECONDS,
    VISIBLE_IP_PUBLIC_WALK_RAPID_UNIQUE_PATHS, VISIBLE_IP_PUBLIC_WALK_UNIQUE_PATHS,
    VISIBLE_IP_REPUTATION_DENY_THRESHOLD, VISIBLE_IP_REPUTATION_DENY_TTL_SECONDS,
    VISIBLE_IP_REPUTATION_ENABLED, VISIBLE_IP_REPUTATION_MIN_CATEGORIES,
    VISIBLE_IP_REPUTATION_WINDOW_SECONDS, crypto, fmtDurMH, formatRailwayRuntimeLine,
    getGeoIpFreshnessLines, ipinfoLiteStatusLine, mask, publicContentStartupSummaryLines,
    runtimeStats, trustProxyEffective, zoneLabel
  } = dependencies;

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

  return { startupSummary };
};
