module.exports = function createRedirectPayload(dependencies) {
  const {
    MAX_BRUTE_SPLIT_PAYLOAD_LENGTH,
    MAX_REDIRECT_PAYLOAD_LENGTH,
    MAX_REDIRECT_URL_PATH_LENGTH,
    REDIRECT_PAYLOAD_OVERSIZE_MODE,
    RE_B64URL_PAYLOAD,
    RE_CONTROL_CHARS,
    SANITIZATION_MAX_LENGTH,
    SCANNER_PROBE_PREFIXES,
    VISIBLE_IP_REPUTATION_WEIGHTS,
    addLog,
    addStrike,
    aggregatePerIpEvent,
    decodeB64urlLoose,
    getClientIp,
    hasInterstitialBypass,
    isLikelyCrawlerProbePath,
    isLikelyEmail,
    isLikelyLocaleOnlyProbePath,
    isLikelyScannerProbePath,
    maybeDenyForVisibleIpReputation,
    tryBase64UrlToUtf8,
    tryDecryptAny,
    validationFailureLimiter
  } = dependencies;
  const ALLOWLIST_DOMAINS = {
    some(callback) {
      return dependencies.getAllowlistDomains().some(callback);
    }
  };

function mask(s){ if (!s) return ""; return s.length<=6 ? "*".repeat(s.length) : s.slice(0,4)+"…"+s.slice(-2); }

function safeZone(tz) {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz }).format();
    return tz;
  } catch {
    return 'UTC';
  }
}

const TIMEZONE = safeZone(process.env.TIMEZONE || 'UTC');

function formatLocal(ts, tz = TIMEZONE) {
  const d = ts instanceof Date ? ts : new Date(ts);
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: tz,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: true
  }).formatToParts(d);
  const p = Object.fromEntries(parts.map(x => [x.type, x.value]));
  return `${p.month}-${p.day}-${p.year} - ${p.hour}:${p.minute}:${p.second} ${p.dayPeriod}`;
}

function zoneLabel(tz = TIMEZONE) {
  const now = new Date();
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      timeZoneName: 'shortOffset'
    }).formatToParts(now);

    const name = parts.find(p => p.type === 'timeZoneName')?.value || '';
    const utc = name.replace(/^GMT/, 'UTC');

    const m = utc.match(/^UTC([+-])(\d{1,2})(?::?(\d{2}))?$/);
    if (m) {
      const sign = m[1];
      const hh = String(m[2]).padStart(2, '0');
      const mm = String(m[3] || '00').padStart(2, '0');
      return `${tz} (UTC${sign}${hh}:${mm})`;
    }
    return `${tz} (${utc || 'UTC'})`;
  } catch {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      timeZoneName: 'short'
    }).formatToParts(now);
    const abbr = parts.find(p => p.type === 'timeZoneName')?.value || tz;
    return `${tz} (${abbr})`;
  }
}

// Enhanced log sanitization function (Critical Fix 5)
function safeLogValue(value, maxLength = 100) {
  return String(value || '')
    .replace(/\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g, '') // Strip ANSI/CSI escape sequences
    .replace(/[\x00-\x1F\x7F-\x9F]/g, '')  // Remove all control characters
    .replace(/[ \t]{2,}/g, ' ')            // Collapse multiple spaces/tabs
    .replace(/[\r\n]/g, ' ')               // Replace newlines with spaces
    .trim()
    .substring(0, maxLength);
}


function parseEmailDelimiterEnvValue(rawValue) {
  return String(rawValue || '')
    .split(',')
    .map(value => value.trim())
    .filter(Boolean);
}

function getConfiguredEmailDelimiters() {
  const envDelimiters = parseEmailDelimiterEnvValue(
    process.env.REDIRECT_EMAIL_DELIMITERS || process.env.DELIMITER || process.env.Delimiter
  );
  const configured = envDelimiters.length ? envDelimiters : ['//', '__', '--', '~~'];
  return Array.from(new Set(configured)).sort((a, b) => b.length - a.length);
}

function findPreviousEmailDelimiter(value, beforeIndex) {
  const source = String(value || '');
  const limit = beforeIndex == null ? source.length : beforeIndex;
  let best = null;
  for (const delimiter of getConfiguredEmailDelimiters()) {
    let index = source.lastIndexOf(delimiter, limit - 1);
    while (index >= 0) {
      if (delimiter === '//' && index > 0 && source[index - 1] === ':') {
        index = source.lastIndexOf(delimiter, index - 1);
        continue;
      }
      const end = index + delimiter.length;
      const bestEnd = best ? best.index + best.delimiter.length : -1;
      if (!best || end > bestEnd || (end === bestEnd && delimiter.length > best.delimiter.length)) {
        best = { index, delimiter };
      }
      break;
    }
  }
  return best;
}

function findNextEmailDelimiter(value, fromIndex = 0) {
  const source = String(value || '');
  let best = null;
  for (const delimiter of getConfiguredEmailDelimiters()) {
    let index = source.indexOf(delimiter, fromIndex);
    while (index >= 0) {
      if (delimiter === '//' && index > 0 && source[index - 1] === ':') {
        index = source.indexOf(delimiter, index + delimiter.length);
        continue;
      }
      if (!best || index < best.index || (index === best.index && delimiter.length > best.delimiter.length)) {
        best = { index, delimiter };
      }
      break;
    }
  }
  return best;
}

// Enhanced JSON logging with proper length handling
function safeLogJson(payload, maxLength = 500) {
  try {
    const jsonString = JSON.stringify(payload);
    return safeLogValue(jsonString, maxLength);
  } catch (e) {
    return safeLogValue(`[JSON-Error: ${e.message}] ${String(payload)}`, maxLength);
  }
}

// Enhanced sanitizeOneLine with additional protection
function sanitizeOneLine(s) {
  return safeLogValue(s, SANITIZATION_MAX_LENGTH);
}

const sanitizeLogLine = sanitizeOneLine;

// Keep all your existing functions as they are...
function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

function parseOptionalUrlPrefix(rawPrefix) {
  const normalized = String(rawPrefix || "")
    .trim()
    .replace(/^\/+|\/+$/g, "");

  if (!normalized) return [];

  // Express string routes are compiled by path-to-regexp, so characters like
  // ?, +, *, (), [] can be interpreted as pattern tokens and crash route setup.
  // Restrict the optional prefix to URL-safe literal segment characters only.
  const SAFE_PREFIX_SEGMENT_RE = /^[A-Za-z0-9._~-]+$/;
  const rawSegments = normalized
    .split("/")
    .map((part) => part.trim())
    .filter(Boolean);

  const safeSegments = rawSegments.filter((segment) => SAFE_PREFIX_SEGMENT_RE.test(segment));

  if (safeSegments.length !== rawSegments.length) {
    console.warn(`[CONFIG] OPTIONAL_URL_PREFIX contains unsupported characters and has been sanitized. raw='${normalized}' safe='${safeSegments.join("/")}'`);
  }

  return safeSegments;
}

const OPTIONAL_URL_PREFIX_SEGMENTS = parseOptionalUrlPrefix(process.env.OPTIONAL_URL_PREFIX || "");
const OPTIONAL_URL_PREFIX = OPTIONAL_URL_PREFIX_SEGMENTS.join("/");

function getOptionalUrlPrefixPath() {
  return OPTIONAL_URL_PREFIX ? `/${OPTIONAL_URL_PREFIX}` : "";
}

function withOptionalUrlPrefix(pathValue) {
  const normalizedPath = `/${String(pathValue || "").replace(/^\/+/, "")}`;
  const optionalPrefixPath = getOptionalUrlPrefixPath();
  if (!optionalPrefixPath) return normalizedPath;
  return `${optionalPrefixPath}${normalizedPath}`;
}

function pathMatchesWithOptionalPrefix(pathname, basePath, { allowChildren = true } = {}) {
  const cleanPath = String(pathname || "");
  const normalizedBase = `/${String(basePath || "").replace(/^\/+/, "")}`;

  if (cleanPath === normalizedBase) return true;
  if (allowChildren && cleanPath.startsWith(`${normalizedBase}/`)) return true;

  const optionalPrefixPath = getOptionalUrlPrefixPath();
  if (!optionalPrefixPath) return false;

  const prefixedBase = `${optionalPrefixPath}${normalizedBase}`;
  if (cleanPath === prefixedBase) return true;
  if (allowChildren && cleanPath.startsWith(`${prefixedBase}/`)) return true;

  return false;
}

function pathMatchesExactRoute(pathname, basePath, { allowOptionalPrefix = false } = {}) {
  const cleanPath = String(pathname || "");
  const normalizedBase = `/${String(basePath || "").replace(/^\/+/, "")}`;
  const baseWithTrailingSlash = normalizedBase === "/" ? normalizedBase : `${normalizedBase}/`;

  if (cleanPath === normalizedBase || cleanPath === baseWithTrailingSlash) return true;

  if (!allowOptionalPrefix) return false;

  const optionalPrefixPath = getOptionalUrlPrefixPath();
  if (!optionalPrefixPath) return false;

  const prefixedBase = `${optionalPrefixPath}${normalizedBase}`;
  const prefixedWithTrailingSlash = prefixedBase === "/" ? prefixedBase : `${prefixedBase}/`;
  return cleanPath === prefixedBase || cleanPath === prefixedWithTrailingSlash;
}

function stripOptionalUrlPrefix(pathValue) {
  const clean = safeDecode(String(pathValue || "")).replace(/^\/+|\/+$/g, "");
  if (!clean) {
    return { payloadPath: "", usedPrefix: false };
  }

  if (!OPTIONAL_URL_PREFIX) {
    return { payloadPath: clean, usedPrefix: false };
  }

  if (clean === OPTIONAL_URL_PREFIX) {
    return { payloadPath: "", usedPrefix: true };
  }

  const prefixWithSlash = `${OPTIONAL_URL_PREFIX}/`;
  if (clean.startsWith(prefixWithSlash)) {
    return { payloadPath: clean.slice(prefixWithSlash.length), usedPrefix: true };
  }

  return { payloadPath: clean, usedPrefix: false };
}

function extractEmailSafePayloadPath(req) {
  if (req && req.params && typeof req.params.data === "string") {
    return String(req.params.data);
  }

  const candidateRaw = String((req?.originalUrl || "").slice(1).split("?")[0] || "");
  const { payloadPath } = stripOptionalUrlPrefix(candidateRaw);
  if (!payloadPath) return "";
  if (payloadPath.startsWith("e/")) return payloadPath.slice(2);
  return payloadPath;
}

function looksLikeHttpUrl(value) {
  const raw = String(value || "").trim();
  if (!/^https?:\/\//i.test(raw)) return false;
  try {
    const u = new URL(raw);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function detectEncodedEmailSegment(segment, decodeBase64UrlLoose, decodeFallback, isValidEmail) {
  const raw = String(segment || '').trim();
  if (!raw) return { isEmail: false, raw: '', decoded: '' };

  const b64Decoded = String(decodeBase64UrlLoose(raw) || '').trim();
  if (b64Decoded && isValidEmail(b64Decoded)) {
    return { isEmail: true, raw, decoded: b64Decoded, source: 'b64url' };
  }

  const fallbackDecoded = String(decodeFallback(raw) || '').trim();
  if (fallbackDecoded && fallbackDecoded !== raw && isValidEmail(fallbackDecoded)) {
    return { isEmail: true, raw, decoded: fallbackDecoded, source: 'fallback' };
  }

  if (isValidEmail(raw)) {
    return { isEmail: true, raw, decoded: raw, source: 'raw' };
  }

  return { isEmail: false, raw, decoded: '' };
}

function createRedirectPayloadResult(input) {
  const clean = String(input || '').replace(/^\/+/, '').split('?')[0].replace(/\/+$/g, '');
  return {
    matched: false,
    mode: 'invalid',
    input: clean,
    ciphertext: null,
    canonicalBaseString: null,
    email: null,
    emailPart: null,
    emailSegment: null,
    ignored: null,
    rawUrl: null,
    ambiguityDetected: false,
    matchedNewFormat: false,
    parseMode: 'invalid',
    ignoredSegment: null,
    normalizedBaseString: null
  };
}

function setRedirectPayloadMode(result, mode) {
  result.matched = true;
  result.mode = mode;
  result.parseMode = mode;
  return result;
}

function setRedirectPayloadIgnored(result, ignored) {
  result.ignored = String(ignored || '').replace(/^\/+|\/+$/g, '') || null;
  result.ignoredSegment = result.ignored;
  return result;
}

function setRedirectPayloadCanonical(result, ciphertext, emailPart, helpers) {
  result.ciphertext = ciphertext || null;
  result.emailPart = emailPart || null;
  if (result.emailPart) {
    const emailCandidate = detectEncodedEmailSegment(result.emailPart, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
    result.email = emailCandidate.isEmail ? emailCandidate.decoded : null;
    result.canonicalBaseString = result.ciphertext ? `${result.ciphertext}/${result.emailPart}` : null;
  } else {
    result.email = null;
    result.canonicalBaseString = result.ciphertext || null;
  }
  result.normalizedBaseString = result.canonicalBaseString;
  return result;
}

function finishFlexibleRedirectPayload(result, mode, ciphertext, emailPart, ignored, emailSegment, helpers) {
  setRedirectPayloadMode(result, mode);
  result.matchedNewFormat = true;
  result.emailSegment = emailSegment;
  setRedirectPayloadIgnored(result, ignored);
  setRedirectPayloadCanonical(result, ciphertext, emailPart, helpers);
  return result;
}

function joinCollapsedUrlParts(left, right) {
  const combined = `${String(left || '').trim()}/${String(right || '').trim()}`;
  const raw = combined.startsWith('url=') ? combined.slice(4) : combined;
  return /^https?:\/[^/]/i.test(raw) ? combined : '';
}

function joinCollapsedUrlSegments(parts) {
  const list = Array.isArray(parts) ? parts.filter(Boolean) : [];
  if (list.length < 2) return '';
  const head = joinCollapsedUrlParts(list[0], list[1]);
  if (!head) return '';
  return list.length === 2 ? head : `${head}/${list.slice(2).join('/')}`;
}


function looksLikeCiphertextSegment(segment) {
  const raw = String(segment || '').trim();
  if (raw.length < 40) return false;
  const base64UrlRegex = typeof RE_B64URL_PAYLOAD !== "undefined"
    ? RE_B64URL_PAYLOAD
    : /^[A-Za-z0-9_-]+(?:={0,2})?$/;
  return base64UrlRegex.test(raw);
}

function looksLikeRedirectPayloadSegment(segment, helpers) {
  if (looksLikeCiphertextSegment(segment)) return true;
  const decoded = String(helpers.decodeBase64UrlLoose(segment) || helpers.decodeFallback(segment) || '').trim();
  return looksLikeHttpUrl(decoded);
}

const createParseIgnoredUrlCipherPayload = require("../ignored-cipher/parseIgnoredUrlCipherPayload.js");
const parseIgnoredUrlCipherPayload = createParseIgnoredUrlCipherPayload({
  detectEncodedEmailSegment,
  findPreviousEmailDelimiter,
  finishFlexibleRedirectPayload,
  isPartialRawEmailDelimiterSplit,
  looksLikeCiphertextSegment,
  looksLikeHttpUrl,
  looksLikeRedirectPayloadSegment
});

function parseEmailFirstCipherPayload(result, clean, helpers) {
  const source = String(clean || '').replace(/^\/+|\/+$/g, '');
  const firstSlash = source.indexOf('/');
  if (firstSlash <= 0) return false;

  const emailRaw = source.slice(0, firstSlash);
  const ciphertext = source.slice(firstSlash + 1);
  if (!emailRaw || !ciphertext || ciphertext.includes('/')) return false;
  if (!looksLikeRedirectPayloadSegment(ciphertext, helpers)) return false;

  const emailCandidate = detectEncodedEmailSegment(emailRaw, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
  if (!emailCandidate.isEmail) return false;

  finishFlexibleRedirectPayload(
    result,
    'email_payload',
    ciphertext,
    emailCandidate.raw,
    null,
    'segment1',
    helpers
  );
  return true;
}


function isUnambiguousRawUrlEmailSuffix(rawUrlCandidate, wasEncodedPrefix = false, emailCandidate = null, delimiter = '') {
  if (!looksLikeHttpUrl(rawUrlCandidate)) return false;
  if (wasEncodedPrefix) {
    if (/[?#]/.test(rawUrlCandidate) && emailCandidate && emailCandidate.source === 'fallback' && getConfiguredEmailDelimiters().includes(delimiter)) return false;
    return true;
  }
  if (/[?#]/.test(rawUrlCandidate)) return false;
  try {
    const parsed = new URL(rawUrlCandidate);
    const origin = `${parsed.protocol}//${parsed.host}`;
    return rawUrlCandidate === origin || rawUrlCandidate.endsWith('/');
  } catch {
    return false;
  }
}

function isPartialRawEmailDelimiterSplit(source, delimiterMatch, emailRaw, helpers, options = {}) {
  if (!delimiterMatch || !emailRaw) return false;
  const previousDelimiter = findPreviousEmailDelimiter(source, delimiterMatch.index);
  if (!previousDelimiter) return false;
  const possibleLocalPrefix = String(source || '').slice(previousDelimiter.index + previousDelimiter.delimiter.length, delimiterMatch.index);
  if (!possibleLocalPrefix && (!options.allowEmptyLocalPrefix || delimiterMatch.delimiter === '//')) return false;
  if (/[/?#]/.test(possibleLocalPrefix)) return false;
  const combinedEmailRaw = `${possibleLocalPrefix}${delimiterMatch.delimiter}${emailRaw}`;
  const combinedEmail = detectEncodedEmailSegment(combinedEmailRaw, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
  return combinedEmail.isEmail;
}

function findRawUrlEmailSuffixSplit(source, helpers) {
  const input = String(source || '');
  let delimiterSearchEnd = input.length;
  while (delimiterSearchEnd > 0) {
    const delimiterSuffix = findPreviousEmailDelimiter(input, delimiterSearchEnd);
    if (!delimiterSuffix) break;
    const rawUrlCandidateRaw = input.slice(0, delimiterSuffix.index);
    const decodedRawUrlCandidate = String(helpers.decodeFallback(rawUrlCandidateRaw) || '').trim();
    const rawUrlCandidateWasDecoded = !!(decodedRawUrlCandidate && decodedRawUrlCandidate !== rawUrlCandidateRaw && !rawUrlCandidateRaw.includes('/'));
    const rawUrlCandidate = rawUrlCandidateWasDecoded
      ? decodedRawUrlCandidate
      : rawUrlCandidateRaw;
    const emailAndTail = input.slice(delimiterSuffix.index + delimiterSuffix.delimiter.length);
    const tailSlash = emailAndTail.indexOf('/');
    const emailCandidateRaw = tailSlash >= 0 ? emailAndTail.slice(0, tailSlash) : emailAndTail;
    const ignoredTail = tailSlash >= 0 ? emailAndTail.slice(tailSlash + 1) : '';
    const emailCandidate = detectEncodedEmailSegment(emailCandidateRaw, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
    if (emailCandidate.isEmail && isPartialRawEmailDelimiterSplit(input, delimiterSuffix, emailCandidateRaw, helpers)) {
      delimiterSearchEnd = delimiterSuffix.index;
      continue;
    }
    if (isUnambiguousRawUrlEmailSuffix(rawUrlCandidate, rawUrlCandidateWasDecoded, emailCandidate, delimiterSuffix.delimiter) && emailCandidate.isEmail) {
      return {
        rawUrl: rawUrlCandidate,
        remainder: `${delimiterSuffix.delimiter}${emailCandidate.raw}${ignoredTail ? `/${ignoredTail}` : ''}`
      };
    }
    delimiterSearchEnd = delimiterSuffix.index;
  }
  return null;
}

function splitRawUrlPayload(rawClean, helpers) {
  const decodedWhole = String(helpers.decodeFallback(rawClean) || '').trim();
  const rawSuffixSplit = findRawUrlEmailSuffixSplit(rawClean, helpers);
  if (rawSuffixSplit) return rawSuffixSplit;

  const normalizedInput =
    rawClean.indexOf('/') < 0 && decodedWhole && decodedWhole !== rawClean && looksLikeHttpUrl(decodedWhole)
      ? decodedWhole
      : rawClean;

  if (normalizedInput !== rawClean) {
    const normalizedSuffixSplit = findRawUrlEmailSuffixSplit(normalizedInput, helpers);
    if (normalizedSuffixSplit) return normalizedSuffixSplit;
  }

  let rawUrl = '';
  let remainder = '';
  const firstSlash = normalizedInput.indexOf('/');
  if (firstSlash > 0) {
    const firstSeg = normalizedInput.slice(0, firstSlash);
    const decodedFirst = String(helpers.decodeFallback(firstSeg) || '').trim();
    if (looksLikeHttpUrl(decodedFirst)) {
      rawUrl = decodedFirst;
      remainder = normalizedInput.slice(firstSlash + 1);
      if (normalizedInput[firstSlash + 1] === '/') remainder = `/${remainder}`;
    }
  }

  if (!rawUrl && /^https?:\/\//i.test(normalizedInput)) {
    const from = normalizedInput.startsWith('https://') ? 8 : 7;
    const markerScope = normalizedInput.split(/[?#]/, 1)[0];
    const idxHttps = markerScope.indexOf('/https://', from);
    const idxHttp = markerScope.indexOf('/http://', from);
    const splitIdx = [idxHttps, idxHttp].filter(i => i > 0).sort((a, b) => a - b)[0] || -1;

    if (splitIdx > 0) {
      rawUrl = normalizedInput.slice(0, splitIdx);
      remainder = normalizedInput.slice(splitIdx + 1);
    } else {
      try {
        const u = new URL(normalizedInput);
        const origin = `${u.protocol}//${u.host}`;
        const tail = `${u.pathname || ''}${u.search || ''}${u.hash || ''}`;
        if (getConfiguredEmailDelimiters().includes('//') && tail.startsWith('//')) {
          rawUrl = origin;
          remainder = tail;
        } else if (/^\/https?:/i.test(tail)) {
          rawUrl = origin;
          remainder = tail.replace(/^\/+/, '');
        } else {
          rawUrl = normalizedInput;
          remainder = '';
        }
      } catch {
        rawUrl = normalizedInput;
        remainder = '';
      }
    }
  }

  return rawUrl && looksLikeHttpUrl(rawUrl) ? { rawUrl, remainder } : null;
}

function splitRawUrlRemainder(remainder, helpers) {
  const rawRemainder = String(remainder || '');
  let emailPart = '';
  let ignored = '';

  const firstDelimiter = findNextEmailDelimiter(rawRemainder, 0);
  if (firstDelimiter && firstDelimiter.index === 0) {
    const afterDelimiter = rawRemainder.slice(firstDelimiter.delimiter.length);
    const slash = afterDelimiter.indexOf('/');
    const emailRaw = slash >= 0 ? afterDelimiter.slice(0, slash) : afterDelimiter;
    const trailingIgnored = slash >= 0 ? afterDelimiter.slice(slash + 1) : '';
    const emailCandidate = detectEncodedEmailSegment(emailRaw, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
    if (emailCandidate.isEmail) {
      return { emailPart: emailCandidate.raw, ignored: trailingIgnored };
    }
    return { emailPart: '', ignored: rawRemainder };
  }

  let searchEnd = rawRemainder.length;
  while (searchEnd > 0) {
    const match = findPreviousEmailDelimiter(rawRemainder, searchEnd);
    if (!match || match.index <= 0) break;
    const candidateEmail = rawRemainder.slice(match.index + match.delimiter.length);
    if (!candidateEmail || candidateEmail.includes('/')) { searchEnd = match.index; continue; }
    const emailCandidate = detectEncodedEmailSegment(candidateEmail, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
    if (!emailCandidate.isEmail) { searchEnd = match.index; continue; }
    emailPart = emailCandidate.raw;
    ignored = rawRemainder.slice(0, match.index);
    break;
  }
  if (!emailPart) ignored = rawRemainder;
  return { emailPart, ignored };
}

function parseRawUrlRedirectPayload(result, rawClean, helpers) {
  const split = splitRawUrlPayload(rawClean, helpers);
  if (!split) return false;
  const suffix = splitRawUrlRemainder(split.remainder, helpers);
  setRedirectPayloadMode(result, 'raw_url');
  result.rawUrl = split.rawUrl;
  result.emailPart = suffix.emailPart || null;
  if (result.emailPart) {
    result.email = detectEncodedEmailSegment(result.emailPart, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail).decoded || null;
  }
  setRedirectPayloadIgnored(result, suffix.ignored);
  return true;
}

function parseDelimitedCipherEmailPayload(result, clean, helpers) {
  const rhsDecodesToEmail = (rhs) => detectEncodedEmailSegment(rhs, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
  let delimiterSearchEnd = clean.length;
  while (delimiterSearchEnd > 0) {
    const match = findPreviousEmailDelimiter(clean, delimiterSearchEnd);
    if (!match) break;
    const lhs = clean.slice(0, match.index);
    const rhs = clean.slice(match.index + match.delimiter.length);
    const emailCandidate = rhsDecodesToEmail(rhs);
    if (emailCandidate.isEmail && !lhs.includes('/')) {
      const previousDelimiter = findPreviousEmailDelimiter(clean, match.index);
      const delimiterBeforePrevious = previousDelimiter ? findPreviousEmailDelimiter(clean, previousDelimiter.index) : null;
      const possibleLocalPrefix = previousDelimiter
        ? clean.slice(previousDelimiter.index + previousDelimiter.delimiter.length, match.index)
        : '';
      const rawEmailDelimiterIsLeading = previousDelimiter && match.index === previousDelimiter.index + previousDelimiter.delimiter.length;
      const rawEmailRepeatedDelimiterLooksNested =
        previousDelimiter &&
        previousDelimiter.delimiter === match.delimiter &&
        delimiterBeforePrevious &&
        delimiterBeforePrevious.delimiter !== match.delimiter;
      const rawEmailDifferentDelimiterLooksNested =
        previousDelimiter &&
        previousDelimiter.delimiter !== match.delimiter &&
        (
          rawEmailDelimiterIsLeading ||
          match.delimiter === '--' ||
          match.delimiter === '~~' ||
          (previousDelimiter.delimiter.length >= 2 && /[a-z.]/.test(possibleLocalPrefix))
        );
      const rawEmailDelimiterLooksNested = previousDelimiter && (
        rawEmailRepeatedDelimiterLooksNested ||
        rawEmailDifferentDelimiterLooksNested
      );
      const shouldCheckPartialEmailSplit =
        rawEmailDelimiterLooksNested &&
        (emailCandidate.source === 'fallback' || emailCandidate.source === 'raw');
      if (shouldCheckPartialEmailSplit && isPartialRawEmailDelimiterSplit(clean, match, rhs, helpers, { allowEmptyLocalPrefix: rawEmailDelimiterIsLeading })) {
        delimiterSearchEnd = match.index;
        continue;
      }
      setRedirectPayloadMode(result, 'delimited');
      setRedirectPayloadCanonical(result, lhs, rhs, helpers);
      return true;
    }
    delimiterSearchEnd = match.index;
  }

  const j = clean.lastIndexOf('/');
  if (j > 0) {
    const lhs = clean.slice(0, j);
    const rhs = clean.slice(j + 1);
    const emailCandidate = rhsDecodesToEmail(rhs);
    if (emailCandidate.isEmail && !lhs.includes('/')) {
      setRedirectPayloadMode(result, 'delimited');
      setRedirectPayloadCanonical(result, lhs, rhs, helpers);
      return true;
    }
  }
  return false;
}

const createParseFlexibleRedirectPayload = require("../flexible-redirect/parseFlexibleRedirectPayload.js");
const parseFlexibleRedirectPayload = createParseFlexibleRedirectPayload({
  detectEncodedEmailSegment,
  findNextEmailDelimiter,
  findPreviousEmailDelimiter,
  finishFlexibleRedirectPayload,
  isPartialRawEmailDelimiterSplit,
  joinCollapsedUrlSegments,
  looksLikeRedirectPayloadSegment,
  setRedirectPayloadMode
});

function normalizeRedirectPayloadHelpers(helpers = {}) {
  return {
    decodeBase64UrlLoose: helpers.decodeBase64UrlLoose || (() => ''),
    decodeFallback: helpers.decodeFallback || (() => ''),
    isValidEmail: helpers.isValidEmail || (() => false)
  };
}


function hasConfiguredEmailDelimiter(value) {
  return !!findNextEmailDelimiter(value, 0);
}

function hasValidIgnoredPrefixEmailDelimiter(clean, helpers) {
  const source = String(clean || '');
  let searchFrom = 0;
  while (searchFrom < source.length) {
    const match = findNextEmailDelimiter(source, searchFrom);
    if (!match) break;
    const i = match.index;
    const delimiter = match.delimiter;

    const lhs = source.slice(0, i);
    const rhs = source.slice(i + delimiter.length);
    const suffixPayloadSlash = lhs.lastIndexOf('/');
    if (suffixPayloadSlash > 0) {
      const payloadPart = lhs.slice(suffixPayloadSlash + 1);
      const suffixEmail = detectEncodedEmailSegment(rhs, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
      if (!rhs.includes('/') && suffixEmail.isEmail && looksLikeRedirectPayloadSegment(payloadPart, helpers)) return true;
    }

    const firstRhsSlash = rhs.indexOf('/');
    if (firstRhsSlash > 0) {
      const emailRaw = rhs.slice(0, firstRhsSlash);
      const payloadPart = rhs.slice(firstRhsSlash + 1);
      const firstEmail = detectEncodedEmailSegment(emailRaw, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
      if (!payloadPart.includes('/') && firstEmail.isEmail && looksLikeRedirectPayloadSegment(payloadPart, helpers)) return true;
    }
    searchFrom = i + delimiter.length;
  }
  return false;
}

function rawUrlHostIsAllowlistedDestination(raw) {
  if (typeof ALLOWLIST_DOMAINS === "undefined" || typeof isHostAllowlisted !== "function") return false;
  try {
    const parsed = new URL(String(raw || ""));
    return isHostAllowlisted(parsed.hostname);
  } catch {
    return false;
  }
}

function redirectPayloadSegmentDecrypts(segment) {
  if (typeof tryDecryptAny !== "function") return false;
  try {
    const decrypted = tryDecryptAny(segment);
    return !!(decrypted && decrypted.url);
  } catch {
    return false;
  }
}

function parseDecryptableIgnoredUrlPrefixPayload(result, clean, helpers) {
  const source = String(clean || "");
  const candidates = [source];
  const addCandidate = (candidate) => {
    if (candidate && !candidates.includes(candidate)) candidates.push(candidate);
  };
  if (/^https?:\/\//i.test(source)) {
    const hashIndex = source.indexOf("#");
    if (hashIndex >= 0) addCandidate(source.slice(0, hashIndex));
  } else {
    const firstSlash = source.indexOf("/");
    if (firstSlash > 0) {
      const firstSegment = source.slice(0, firstSlash);
      const decodedFirst = String(helpers.decodeFallback(firstSegment) || "").trim();
      if (looksLikeHttpUrl(decodedFirst)) {
        const suffix = source.slice(firstSlash + 1);
        const encodedHashIndex = suffix.search(/%23/i);
        if (encodedHashIndex >= 0) addCandidate(source.slice(0, firstSlash + 1 + encodedHashIndex));
        const rawHashIndex = suffix.indexOf("#");
        if (rawHashIndex >= 0) addCandidate(source.slice(0, firstSlash + 1 + rawHashIndex));
      }
    }
  }

  for (const candidateSource of candidates) {
    const candidate = createRedirectPayloadResult(candidateSource);
    if (!parseIgnoredUrlCipherPayload(candidate, candidate.input, helpers)) continue;
    const parseMode = String(candidate.parseMode || "");
    if (!parseMode.startsWith("ignored_url_")) continue;
    if (!redirectPayloadSegmentDecrypts(candidate.ciphertext)) continue;
    Object.assign(result, candidate);
    return true;
  }
  return false;
}

function shouldPreserveRawHttpUrlBeforeIgnoredPrefix(clean, helpers) {
  const raw = String(clean || '');
  if (!/^https?:\/\//i.test(raw)) return false;
  try {
    const parsed = new URL(raw);
    if (parsed.search) return true;
    const pathSegments = String(parsed.pathname || '').split('/').filter(Boolean);
    const lastSegment = pathSegments[pathSegments.length - 1] || '';
    if (pathSegments.length >= 1 && lastSegment.length >= 48 && looksLikeRedirectPayloadSegment(lastSegment, helpers)) {
      if (redirectPayloadSegmentDecrypts(lastSegment)) return false;
      return rawUrlHostIsAllowlistedDestination(raw);
    }
  } catch {}
  return !hasConfiguredEmailDelimiter(raw) || !hasValidIgnoredPrefixEmailDelimiter(raw, helpers);
}

function shouldPreserveEncodedRawUrlBeforeIgnoredPrefix(clean, helpers) {
  const raw = String(clean || '');
  const firstSlash = raw.indexOf('/');
  if (firstSlash <= 0) return false;
  const decodedFirst = String(helpers.decodeFallback(raw.slice(0, firstSlash)) || '').trim();
  return looksLikeHttpUrl(decodedFirst);
}

function parseRedirectPayload(input, helpers = {}) {
  const normalizedHelpers = normalizeRedirectPayloadHelpers(helpers);
  const rawInput = String(input || '');
  const rawClean = rawInput.replace(/^\/+/, '');
  const result = createRedirectPayloadResult(input);
  const clean = result.input;

  if (!clean) return result;
  if (parseEmailFirstCipherPayload(result, clean, normalizedHelpers)) return result;
  if (parseDecryptableIgnoredUrlPrefixPayload(result, clean, normalizedHelpers)) return result;
  if (rawClean !== clean && /^https?:\/\//i.test(rawClean)) {
    try {
      const parsedRaw = new URL(rawClean);
      const rawPathSegments = String(parsedRaw.pathname || '').split('/').filter(Boolean);
      const lastRawSegment = rawPathSegments[rawPathSegments.length - 1] || '';
      if (parsedRaw.search && !redirectPayloadSegmentDecrypts(lastRawSegment) && parseRawUrlRedirectPayload(result, rawClean, normalizedHelpers)) return result;
    } catch {}
  }
  if (shouldPreserveRawHttpUrlBeforeIgnoredPrefix(clean, normalizedHelpers) && parseRawUrlRedirectPayload(result, rawClean, normalizedHelpers)) return result;
  if (shouldPreserveEncodedRawUrlBeforeIgnoredPrefix(clean, normalizedHelpers) && parseRawUrlRedirectPayload(result, rawClean, normalizedHelpers)) return result;
  if (parseIgnoredUrlCipherPayload(result, clean, normalizedHelpers)) return result;
  if (parseRawUrlRedirectPayload(result, rawClean, normalizedHelpers)) return result;
  if (parseDelimitedCipherEmailPayload(result, clean, normalizedHelpers)) return result;
  if (parseFlexibleRedirectPayload(result, clean, normalizedHelpers)) return result;

  setRedirectPayloadMode(result, 'ciphertext');
  setRedirectPayloadCanonical(result, clean, null, normalizedHelpers);
  return result;
}
// ================== REQUEST VALIDATION MIDDLEWARE ==================
function getRedirectPayloadLimit() {
  return typeof MAX_REDIRECT_PAYLOAD_LENGTH !== "undefined" ? MAX_REDIRECT_PAYLOAD_LENGTH : 8192;
}

function getRedirectTotalPathLimit() {
  return typeof MAX_REDIRECT_URL_PATH_LENGTH !== "undefined" ? MAX_REDIRECT_URL_PATH_LENGTH : 16384;
}

function getRedirectOversizeMode() {
  return typeof REDIRECT_PAYLOAD_OVERSIZE_MODE !== "undefined" ? REDIRECT_PAYLOAD_OVERSIZE_MODE : "log";
}

function getMaxBruteSplitPayloadLength() {
  return typeof MAX_BRUTE_SPLIT_PAYLOAD_LENGTH !== "undefined" ? MAX_BRUTE_SPLIT_PAYLOAD_LENGTH : getRedirectTotalPathLimit();
}

function shouldBlockOversizedRedirectPayload() {
  return ["block", "enforce", "reject", "1", "true"].includes(getRedirectOversizeMode());
}

function getRedirectPayloadMeasuredLength(parsedPayload, fallbackValue = "") {
  if (parsedPayload && typeof parsedPayload.ciphertext === "string" && parsedPayload.ciphertext) {
    return { length: parsedPayload.ciphertext.length, kind: "ciphertext" };
  }
  if (parsedPayload && typeof parsedPayload.rawUrl === "string" && parsedPayload.rawUrl) {
    return { length: parsedPayload.rawUrl.length, kind: "raw_url" };
  }
  if (parsedPayload && typeof parsedPayload.canonicalBaseString === "string" && parsedPayload.canonicalBaseString) {
    return { length: parsedPayload.canonicalBaseString.length, kind: "canonical" };
  }
  return { length: String(fallbackValue || "").length, kind: "path" };
}

function evaluateRedirectPayloadSize(parsedPayload, fallbackValue = "") {
  const totalPathLength = String(fallbackValue || "").length;
  const measured = getRedirectPayloadMeasuredLength(parsedPayload, fallbackValue);
  const payloadLimit = getRedirectPayloadLimit();
  const totalPathLimit = getRedirectTotalPathLimit();
  const overPayloadLimit = measured.length > payloadLimit;
  const overTotalPathLimit = totalPathLength > totalPathLimit;
  const shouldBlock = overTotalPathLimit || (overPayloadLimit && shouldBlockOversizedRedirectPayload());
  return {
    ok: !shouldBlock,
    shouldBlock,
    overPayloadLimit,
    overTotalPathLimit,
    measuredLength: measured.length,
    measuredKind: measured.kind,
    totalPathLength,
    payloadLimit,
    totalPathLimit,
    mode: getRedirectOversizeMode()
  };
}

function maybeLogRedirectPayloadSizeDecision(req, decision, context = "redirect") {
  if (!decision || (!decision.overPayloadLimit && !decision.overTotalPathLimit)) return;
  const ip = req ? getClientIp(req) : "unknown";
  const shouldLog = aggregatePerIpEvent("PAYLOAD-SIZE", {
    ip,
    reason: decision.shouldBlock ? "oversize_block" : "oversize_log",
    suppressFirst: false
  });
  if (!shouldLog) return;
  addLog(`[PAYLOAD-SIZE] action=${decision.shouldBlock ? "block" : "log"} context=${safeLogValue(context, 32)} ip=${safeLogValue(ip, 64)} kind=${safeLogValue(decision.measuredKind, 24)} len=${decision.measuredLength} totalPathLen=${decision.totalPathLength} limit=${decision.payloadLimit} totalLimit=${decision.totalPathLimit} mode=${safeLogValue(decision.mode, 16)}`);
}

function isValidRedirectPayloadInput(input) {
  if (!input || typeof input !== "string") return false;
  if (input.length > getRedirectTotalPathLimit()) return false;

  const clean = input.split("?")[0];
  if (clean.length > getRedirectTotalPathLimit()) return false;
  // Prefer canonical module-level regexes and only fall back to local literals
  // in isolated execution contexts (e.g., VM snippets).
  const base64UrlRegex = typeof RE_B64URL_PAYLOAD !== "undefined"
    ? RE_B64URL_PAYLOAD
    : /^[A-Za-z0-9_-]+(?:={0,2})?$/;
  const controlCharsRegex = typeof RE_CONTROL_CHARS !== "undefined"
    ? RE_CONTROL_CHARS
    : /[\x00-\x20\x7F]/;

  if (clean.length < 10) return false;
  if (controlCharsRegex.test(clean)) return false;

  const parsed = parseRedirectPayload(clean, {
    decodeBase64UrlLoose: decodeB64urlLoose,
    decodeFallback: safeDecode,
    isValidEmail: isLikelyEmail
  });

  const sizeDecision = evaluateRedirectPayloadSize(parsed, clean);
  if (!sizeDecision.ok) return false;

  if (parsed.rawUrl) return true;
  if (!parsed.ciphertext || !base64UrlRegex.test(parsed.ciphertext)) return false;
  if (parsed.ambiguityDetected) return false;
  if (!parsed.emailPart) return true;

  return !!parsed.email;
}

// Backward-compatible alias used by existing VM-based tests. New code should use
// isValidRedirectPayloadInput because raw URL payloads are also accepted.
const validateBase64Url = isValidRedirectPayloadInput;

function isObviouslyNotPayloadPath(candidate) {
  const candidateLower = String(candidate || "").toLowerCase().replace(/^\/+/, "");
  return candidateLower.includes(".php") ||
    candidateLower.includes(".asp") ||
    candidateLower.includes(".jsp") ||
    candidateLower.includes(".env") ||
    candidateLower.includes("..") ||
    SCANNER_PROBE_PREFIXES.some(p => candidateLower.startsWith(p));
}

function validateRRouteParams(req, errors) {
  const baseString = safeDecode(String(req.query.d || req.params.data || ""));

  if (!baseString) {
    errors.push("Missing required parameter: d");
  } else if (!isValidRedirectPayloadInput(baseString)) {
    errors.push("Invalid data format: must be valid base64url");

    if (baseString.length > 1000) {
      addLog(`[VALIDATION] Oversized payload ip=${safeLogValue(getClientIp(req))} len=${baseString.length}`);
    }
  }
}

function validateSuspiciousQueryParams(req, errors) {
  const suspiciousParams = ["javascript:", "data:", "vbscript:", "alert("];
  for (const [key, value] of Object.entries(req.query || {})) {
    if (typeof value !== "string") continue;
    for (const suspicious of suspiciousParams) {
      if (value.toLowerCase().includes(suspicious)) {
        errors.push(`Suspicious value in parameter ${key}`);
        break;
      }
    }
  }
}

function validateCatchAllRedirectPath(req, errors) {
  if (req.path === "/" || pathMatchesWithOptionalPrefix(req.path, "/r") || req.path.startsWith("/e/")) return;
  const candidateRaw = String((req.originalUrl || "").slice(1).split("?")[0] || "");
  const { payloadPath: candidate } = stripOptionalUrlPrefix(candidateRaw);

  if (!candidate || isObviouslyNotPayloadPath(candidate) || !isValidRedirectPayloadInput(candidate)) {
    errors.push("Invalid catch-all path: expected encoded redirect payload");
  }
}

function validateRedirectParams(req) {
  const errors = [];

  if (pathMatchesWithOptionalPrefix(req.path, "/r")) {
    validateRRouteParams(req, errors);
  }

  validateSuspiciousQueryParams(req, errors);
  validateCatchAllRedirectPath(req, errors);

  return errors;
}

function validateRedirectRequest(req, res, next) {
  const exactSkipPaths = [
    "/health", "/healthz", "/readyz", "/livez", "/geo-debug",
    "/favicon.ico", "/robots.txt", "/.well-known/security.txt", "/turnstile-sitekey", "/__hp.gif",
    "/decrypt-challenge-data", "/view-log-live",
    "/about", "/services", "/docs", "/status", "/contact",
    "/sitemap.xml", "/api/v1/status"
  ];
  const optionalExactSkipPaths = [
    "/health", "/healthz", "/readyz", "/livez", "/decrypt-challenge-data"
  ];
  const prefixedSkipPaths = [
    "/view-log", "/stream-log", "/admin", "/__debug", "/_debug",
    "/challenge", "/challenge-fragment", "/ts-client-log", "/interstitial-human"
  ];

  if (
    exactSkipPaths.some(path => pathMatchesExactRoute(req.path, path)) ||
    optionalExactSkipPaths.some(path => pathMatchesExactRoute(req.path, path, { allowOptionalPrefix: true })) ||
    prefixedSkipPaths.some(path => pathMatchesWithOptionalPrefix(req.path, path))
  ) {
    return next();
  }

  if (hasInterstitialBypass(req)) {
    return next();
  }

  const errors = validateRedirectParams(req);
  if (errors.length > 0) {
    const ip = getClientIp(req);
    const ua = req.get("user-agent") || "";
    const onlyCatchAllValidationError =
      errors.length === 1 && errors[0] === "Invalid catch-all path: expected encoded redirect payload";

    if (onlyCatchAllValidationError) {
      const scannerLikeCatchAllPath = isLikelyScannerProbePath(req.path);
      const crawlerLikeCatchAllPath = isLikelyCrawlerProbePath(req.path) || isLikelyLocaleOnlyProbePath(req.path);
      maybeDenyForVisibleIpReputation(req, ip, scannerLikeCatchAllPath || crawlerLikeCatchAllPath ? "invalid_scanner_path" : "invalid_catch_all", {
        detail: safeLogValue(req.path, 80),
        weight: scannerLikeCatchAllPath || crawlerLikeCatchAllPath ? VISIBLE_IP_REPUTATION_WEIGHTS.invalid_scanner_path : VISIBLE_IP_REPUTATION_WEIGHTS.invalid_catch_all
      });
      // Expected behavior for noisy scanner paths: suppress per-request logs
      // and rely on periodic [AGG:VALIDATION-FAILED] summary lines per IP.
      const shouldLog = aggregatePerIpEvent("VALIDATION-FAILED", {
        ip,
        reason: "invalid_catch_all_path",
        // Suppress first-hit logs for scanner-like catch-all probes only; keep
        // first-hit visibility for non-scanner client mistakes.
        suppressFirst: scannerLikeCatchAllPath || crawlerLikeCatchAllPath
      });

      if (shouldLog) {
        addLog(`[VALIDATION-FAILED] ip=${safeLogValue(ip)} path=${req.path} errors=${errors.join(", ")} ua="${safeLogValue(ua.slice(0, 100))}"`);
      }
    } else {
      addLog(`[VALIDATION-FAILED] ip=${safeLogValue(ip)} path=${req.path} errors=${errors.join(", ")} ua="${safeLogValue(ua.slice(0, 100))}"`);
    }

    if (errors.some(e => e.includes("Suspicious"))) {
      addStrike(ip, 2);
    }

    const sendValidationError = () => {
      if (pathMatchesWithOptionalPrefix(req.path, "/r", { allowChildren: false }) && !req.query.d) {
        return res.status(400).send("Missing required parameter: d");
      }
      if (errors.some(e => e.includes("Invalid catch-all path"))) {
        return res.status(404).send("Not Found");
      }
      return res.status(400).send("Invalid request");
    };

    if (pathMatchesWithOptionalPrefix(req.path, "/r")) {
      return validationFailureLimiter(req, res, sendValidationError);
    }

    return sendValidationError();
  }

  next();
}


  return {
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
  };
};
