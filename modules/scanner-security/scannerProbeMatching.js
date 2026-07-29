module.exports = function createScannerProbeMatching(dependencies) {
  const {
    NESTED_SCANNER_SUBSTRINGS, OPTIONAL_URL_PREFIX, SCANNER_PROBE_EXACT_PATHS,
    SCANNER_PROBE_PREFIXES, isLikelyArchiveProbePath, isLikelyEmail,
    looksLikeHttpUrl, parseRedirectPayload, safeDecode, decodeB64urlLoose,
    validateBase64Url
  } = dependencies;
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


  return {
    decodePathForScannerMatching,
    SENSITIVE_CONFIG_PROBE_BASENAME_REGEX,
    SENSITIVE_CONFIG_PROBE_PATH_REGEX,
    API_CONFIG_PROBE_PATH_REGEX,
    normalizeScannerProbeCandidate,
    stripOptionalScannerPrefixPreserveCase,
    isEmailSafePathCandidate,
    FLEXIBLE_REDIRECT_PAYLOAD_MIN_SEGMENT_LENGTH,
    REDIRECT_PAYLOAD_SEGMENT_REGEX,
    getScannerConfiguredEmailDelimiters,
    hasScannerConfiguredEmailDelimiter,
    isLikelyRedirectPayloadPathCandidate,
    isLikelyIgnoredPrefixRedirectPayloadCandidate,
    isLikelyFlexibleRedirectPayloadCandidate,
    isScannerExactProbePath,
    isLikelyApiConfigProbePath,
    isLikelySensitiveConfigProbePath,
    stripOptionalUrlPrefixForScannerPayload,
    isLikelyRawUrlRedirectPayload,
    classifyScannerProbeCandidate,
    chooseScannerProbeCategory,
    pathMatchesUnknownScannerSkipPrefix,
  };
};
