'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');
const { createRequire } = require('node:module');
const path = require('node:path');

function loadFunctionsFromServer() {
  const source = fs.readFileSync('modules/server-runtime/serverRuntime.js', 'utf8');
  const start = source.indexOf('function safeLogValue(');
  const end = source.indexOf('// ================== LOGGING SYSTEM');
  if (start < 0 || end < 0 || end <= start) {
    throw new Error('Could not locate expected function region in server.js');
  }
  const sanitizeStart = source.indexOf('function sanitizeRequestPath(');
  const sanitizeEnd = source.indexOf('\nfunction getEventTimestamp(', sanitizeStart);
  if (sanitizeStart < 0 || sanitizeEnd < 0 || sanitizeEnd <= sanitizeStart) {
    throw new Error('Could not locate sanitizeRequestPath in server.js');
  }

  const testKeyHex = '0707070707070707070707070707070707070707070707070707070707070707';
  const snippet = `
    const SANITIZATION_MAX_LENGTH = 500;
    const AES_KEYS = [Buffer.from('${testKeyHex}', 'hex')];
    const BRUTE_FORCE_MIN_RATIO = 0.4;
    const MAX_REDIRECT_PAYLOAD_LENGTH = 8192;
    const MAX_REDIRECT_URL_PATH_LENGTH = 16384;
    const REDIRECT_PAYLOAD_OVERSIZE_MODE = 'log';
    const MAX_BRUTE_SPLIT_PAYLOAD_LENGTH = 16384;
    const RE_SCANNER_PATH = /^$/;
    const RE_B64URL_SEGMENT = /^[A-Za-z0-9_-]+=*$/;
    const ALLOWLIST_DOMAINS = [{ suffix: 'cdn.example.com', includeApex: true, allowSubdomains: false }];
    ${source.slice(sanitizeStart, sanitizeEnd)}
    ${source.slice(start, end)}
    this.__loaded = { parseRedirectPayload, validateBase64Url, safeLogValue, sanitizeRequestPath, decodeEmailPart, isLikelyEmail, extractSingleCleanEmailToken, bruteSplitDecryptFull, hasBruteSplitRecoverySuffix, getBruteSplitCandidatePrefixLengths, testKeyHex: '${testKeyHex}', vmProcess: process };
  `;
  const sandboxProcess = { ...process, env: {} };
  const serverRequire = createRequire(path.resolve('modules/server-runtime/serverRuntime.js'));
  const sandbox = { Buffer, URL, process: sandboxProcess, console, crypto, require: serverRequire };
  vm.createContext(sandbox);
  vm.runInContext(snippet, sandbox);

  if (!sandbox.__loaded || typeof sandbox.__loaded.parseRedirectPayload !== 'function' || typeof sandbox.__loaded.validateBase64Url !== 'function' || typeof sandbox.__loaded.safeLogValue !== 'function' || typeof sandbox.__loaded.sanitizeRequestPath !== 'function' || typeof sandbox.__loaded.decodeEmailPart !== 'function' || typeof sandbox.__loaded.isLikelyEmail !== 'function' || typeof sandbox.__loaded.extractSingleCleanEmailToken !== 'function' || typeof sandbox.__loaded.bruteSplitDecryptFull !== 'function') {
    throw new Error('Failed to load parser/validator functions from server.js');
  }

  return sandbox.__loaded;
}

const {
  parseRedirectPayload,
  validateBase64Url,
  safeLogValue,
  sanitizeRequestPath,
  decodeEmailPart,
  isLikelyEmail,
  extractSingleCleanEmailToken,
  bruteSplitDecryptFull,
  hasBruteSplitRecoverySuffix,
  getBruteSplitCandidatePrefixLengths,
  testKeyHex,
  vmProcess
} = loadFunctionsFromServer();

function decodeB64urlLoose(s) {
  try {
    let u = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
    while (u.length % 4) u += '=';
    return Buffer.from(u, 'base64').toString('utf8');
  } catch {
    return '';
  }
}

function safeDecode(s) {
  try {
    return decodeURIComponent(String(s || ''));
  } catch {
    return String(s || '');
  }
}

const helpers = {
  decodeBase64UrlLoose: decodeB64urlLoose,
  decodeFallback: safeDecode,
  isValidEmail: isLikelyEmail
};

const b64urlEmail = Buffer.from('alice@example.com', 'utf8').toString('base64url');
const b64stdEmail = Buffer.from('bob@example.com', 'utf8').toString('base64');
const payload = 'I8d-eh9OogUNRrosFLLESnDTLOGI_bDottmN-72JzwezfDqfiudRshnTmpYjXnOYYXNWVFR1SefJp_KfB8ZDyabpDBM';

test('supports /{payload}/{ignored}/{email}', () => {
  const parsed = parseRedirectPayload(`${payload}/test.com/${b64urlEmail}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'payload_ignored_email');
  assert.equal(parsed.emailSegment, 'segment3');
});

test('supports /{payload}/{email}/{ignored}', () => {
  const parsed = parseRedirectPayload(`${payload}/${b64urlEmail}/cosmetic`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'payload_email_ignored');
  assert.equal(parsed.emailSegment, 'segment2');
});

test('supports /{payload}/{ignored} with no email', () => {
  const parsed = parseRedirectPayload(`${payload}/test.com`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'payload_ignored');
  assert.equal(parsed.normalizedBaseString, payload);
});

test('supports URL-safe and standard base64 email', () => {
  const parsedUrl = parseRedirectPayload(`${payload}/${b64urlEmail}/ignored`, helpers);
  const parsedStd = parseRedirectPayload(`${payload}/${b64stdEmail}/ignored`, helpers);
  assert.equal(parsedUrl.emailSegment, 'segment2');
  assert.equal(parsedStd.emailSegment, 'segment2');
});

test('ambiguous both-email segments are flagged', () => {
  const another = Buffer.from('eve@example.org', 'utf8').toString('base64url');
  const parsed = parseRedirectPayload(`${payload}/${b64urlEmail}/${another}`, helpers);
  assert.equal(parsed.ambiguityDetected, true);
  assert.equal(parsed.normalizedBaseString, null);
});

test('validateBase64Url accepts payload//email/ignored', () => {
  assert.equal(validateBase64Url(`${payload}//${b64urlEmail}/test.com`), true);
});

test('validateBase64Url accepts payload/ignored//email', () => {
  assert.equal(validateBase64Url(`${payload}/test.com//${b64urlEmail}`), true);
});

test('validateBase64Url supports second payload sample with optional-prefix style paths', () => {
  const payload2 = 'LiW9YpsvCplyLIlP2nPTeZ5JsWE5TbC7LSECsbflC7Cc2gtL-7LHqm-FT1JBkL2eY8wUyFUoI1RgldgpR2W7kNVG7h-KADXS_Jk';
  const email2 = 'cmUzNDM2OTZAaG90bWFpbC5jb20=';
  assert.equal(validateBase64Url(`${payload2}/test.com//${email2}`), true);
  assert.equal(validateBase64Url(`${payload2}//${email2}/test.com`), true);
});

test('validateBase64Url accepts ignored full URL with email at end', () => {
  assert.equal(validateBase64Url(`${payload}/https://test.com//${b64urlEmail}`), true);
});

test('validateBase64Url accepts email first then ignored full URL', () => {
  assert.equal(validateBase64Url(`${payload}//${b64urlEmail}/https://test.com`), true);
});

test('validateBase64Url accepts ignored full URL without email', () => {
  assert.equal(validateBase64Url(`${payload}/https://test.com`), true);
});

test('validateBase64Url accepts platform-collapsed ignored URL before email', () => {
  assert.equal(validateBase64Url(`${payload}/url=https:/test.com/${b64urlEmail}`), true);
});

test('validateBase64Url accepts platform-collapsed ignored URL after email', () => {
  assert.equal(validateBase64Url(`${payload}/${b64urlEmail}/url=https:/test.com`), true);
});

test('validateBase64Url accepts email-first then full url= ignored segment', () => {
  assert.equal(validateBase64Url(`${payload}//${b64urlEmail}/url=https://test.com`), true);
});

test('validateBase64Url accepts email-first ignored URL with path segments', () => {
  assert.equal(validateBase64Url(`${payload}//${b64urlEmail}/https://test.com/path`), true);
});

test('validateBase64Url accepts ignored URL with path segments before email', () => {
  assert.equal(validateBase64Url(`${payload}/https://test.com/path//${b64urlEmail}`), true);
});

test('validateBase64Url accepts landing-page URL as payload (raw)', () => {
  assert.equal(
    validateBase64Url(`https://landingpage.com/https://test.com//${b64urlEmail}`),
    true
  );
});

test('validateBase64Url accepts landing-page URL as payload (url-encoded)', () => {
  assert.equal(
    validateBase64Url(`https%3A%2F%2Flandingpage.com/https://test.com//${b64urlEmail}`),
    true
  );
});

test('validateBase64Url accepts raw-url payload with email first then ignored segment', () => {
  assert.equal(
    validateBase64Url(`https://rawurl.com//${b64urlEmail}/https:test.com`),
    true
  );
});

test('validateBase64Url accepts raw-url payload with email and no ignored segment', () => {
  assert.equal(
    validateBase64Url(`https://rawurl.com//${b64urlEmail}`),
    true
  );
});

test('parseRedirectPayload keeps //email delimiter for encoded raw-url payload', () => {
  const parsed = parseRedirectPayload(`https%3A%2F%2Frawurl.com//${b64urlEmail}`, helpers);
  assert.equal(parsed.matched, true);
  assert.equal(parsed.rawUrl, 'https://rawurl.com');
  assert.equal(parsed.emailPart, b64urlEmail);
});

test('validateBase64Url accepts raw-url payload with ignored segment and no email', () => {
  assert.equal(
    validateBase64Url('https://rawurl.com/https:test.com'),
    true
  );
});

test('parseRedirectPayload keeps ignored tail separate in URL fallback path', () => {
  const parsed = parseRedirectPayload('https://rawurl.com/https:test.com', helpers);
  assert.equal(parsed.matched, true);
  assert.equal(parsed.rawUrl, 'https://rawurl.com');
  assert.equal(parsed.ignoredSegment, 'https:test.com');
});

test('parseRedirectPayload preserves full raw URL when no suffix segments are present', () => {
  const parsed = parseRedirectPayload('https://landingpage.com/pricing?utm=1#hero', helpers);
  assert.equal(parsed.matched, true);
  assert.equal(parsed.rawUrl, 'https://landingpage.com/pricing?utm=1#hero');
  assert.equal(parsed.ignoredSegment, null);
});

test('parseRedirectPayload preserves trailing slash in raw URL destination', () => {
  const parsed = parseRedirectPayload('https://landingpage.com/docs/', helpers);
  assert.equal(parsed.matched, true);
  assert.equal(parsed.rawUrl, 'https://landingpage.com/docs/');
});

test('parseRedirectPayload does not split on /https:// inside query string', () => {
  const parsed = parseRedirectPayload('https://landingpage.com/path?next=/https://foo.com', helpers);
  assert.equal(parsed.matched, true);
  assert.equal(parsed.rawUrl, 'https://landingpage.com/path?next=/https://foo.com');
  assert.equal(parsed.ignoredSegment, null);
});

test('validateBase64Url accepts fully URL-encoded raw URL with no extra segments', () => {
  assert.equal(validateBase64Url('https%3A%2F%2Flandingpage.com'), true);
});

test('parseRedirectPayload parses fully encoded raw URL with //email suffix', () => {
  const encoded = encodeURIComponent(`https://rawurl.com//${b64urlEmail}`);
  const parsed = parseRedirectPayload(encoded, helpers);
  assert.equal(parsed.matched, true);
  assert.equal(parsed.rawUrl, 'https://rawurl.com');
  assert.equal(parsed.emailPart, b64urlEmail);
});

test('parseRedirectPayload parses fully encoded raw URL with ignored suffix', () => {
  const encoded = encodeURIComponent('https://rawurl.com/https:test.com');
  const parsed = parseRedirectPayload(encoded, helpers);
  assert.equal(parsed.matched, true);
  assert.equal(parsed.rawUrl, 'https://rawurl.com');
  assert.equal(parsed.ignoredSegment, 'https:test.com');
});

test('validateBase64Url accepts raw-url payload with ignored full URL and no email', () => {
  assert.equal(
    validateBase64Url('https://landingpage.com/https://test.com/path'),
    true
  );
});



test('parseRedirectPayload canonicalizes ignored URL before email', () => {
  const parsed = parseRedirectPayload(`${payload}/https://test.com/path//${b64urlEmail}`, helpers);
  assert.equal(parsed.mode, 'payload_ignored_email');
  assert.equal(parsed.ciphertext, payload);
  assert.equal(parsed.emailPart, b64urlEmail);
  assert.equal(parsed.ignored, 'https://test.com/path');
});


test('parseRedirectPayload honors configured suffix delimiters after ignored raw URL', () => {
  for (const delimiter of ['__', '--', '~~']) {
    const parsed = parseRedirectPayload(`https://www.123.com/${payload}${delimiter}${b64urlEmail}`, helpers);
    assert.equal(parsed.matchedNewFormat, true);
    assert.equal(parsed.parseMode, 'ignored_url_payload_email');
    assert.equal(parsed.ciphertext, payload);
    assert.equal(parsed.emailPart, b64urlEmail);
    assert.equal(parsed.email, 'alice@example.com');
    assert.equal(parsed.ignored, 'https://www.123.com');
  }
});

test('parseRedirectPayload honors configured email-first delimiters after ignored raw URL', () => {
  for (const delimiter of ['__', '--', '~~']) {
    const parsed = parseRedirectPayload(`https://www.123.com/${delimiter}${b64urlEmail}/${payload}`, helpers);
    assert.equal(parsed.matchedNewFormat, true);
    assert.equal(parsed.parseMode, 'ignored_url_email_payload');
    assert.equal(parsed.ciphertext, payload);
    assert.equal(parsed.emailPart, b64urlEmail);
    assert.equal(parsed.email, 'alice@example.com');
    assert.equal(parsed.ignored, 'https://www.123.com');
  }
});

test('parseRedirectPayload supports custom comma-separated delimiter env', () => {
  const previous = vmProcess.env.REDIRECT_EMAIL_DELIMITERS;
  vmProcess.env.REDIRECT_EMAIL_DELIMITERS = '%%,@@';
  try {
    const parsed = parseRedirectPayload(`https://www.123.com/${payload}%%${b64urlEmail}`, helpers);
    assert.equal(parsed.matchedNewFormat, true);
    assert.equal(parsed.parseMode, 'ignored_url_payload_email');
    assert.equal(parsed.email, 'alice@example.com');
  } finally {
    if (previous === undefined) delete vmProcess.env.REDIRECT_EMAIL_DELIMITERS;
    else vmProcess.env.REDIRECT_EMAIL_DELIMITERS = previous;
  }
});

test('parseRedirectPayload honors configured delimiters in payload-first flexible links', () => {
  for (const delimiter of ['__', '--', '~~']) {
    const emailFirst = parseRedirectPayload(`${payload}${delimiter}${b64urlEmail}/campaign`, helpers);
    assert.equal(emailFirst.matchedNewFormat, true);
    assert.equal(emailFirst.parseMode, 'payload_email_ignored');
    assert.equal(emailFirst.ciphertext, payload);
    assert.equal(emailFirst.emailPart, b64urlEmail);
    assert.equal(emailFirst.ignored, 'campaign');

    const emailSuffix = parseRedirectPayload(`${payload}/campaign${delimiter}${b64urlEmail}`, helpers);
    assert.equal(emailSuffix.matchedNewFormat, true);
    assert.equal(emailSuffix.parseMode, 'payload_ignored_email');
    assert.equal(emailSuffix.ciphertext, payload);
    assert.equal(emailSuffix.emailPart, b64urlEmail);
    assert.equal(emailSuffix.ignored, 'campaign');
  }
});

test('parseRedirectPayload keeps scanning payload delimiters when raw email contains another delimiter', () => {
  const rawEmail = 'john--doe%40example.com';
  const parsed = parseRedirectPayload(`${payload}__${rawEmail}/campaign`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'payload_email_ignored');
  assert.equal(parsed.ciphertext, payload);
  assert.equal(parsed.emailPart, rawEmail);
  assert.equal(parsed.email, 'john--doe@example.com');
  assert.equal(parsed.ignored, 'campaign');
});

test('parseRedirectPayload keeps scanning payload suffix delimiters when raw email contains another delimiter', () => {
  const rawEmail = 'john--doe%40example.com';
  const parsed = parseRedirectPayload(`${payload}/https:test.com__${rawEmail}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'payload_ignored_email');
  assert.equal(parsed.ciphertext, payload);
  assert.equal(parsed.emailPart, rawEmail);
  assert.equal(parsed.email, 'john--doe@example.com');
  assert.equal(parsed.ignored, 'https:test.com');
});

test('parseRedirectPayload honors custom delimiter env for raw URL email suffixes', () => {
  const previous = vmProcess.env.REDIRECT_EMAIL_DELIMITERS;
  vmProcess.env.REDIRECT_EMAIL_DELIMITERS = '@@';
  try {
    const parsed = parseRedirectPayload(`https://rawurl.com/path/@@${b64urlEmail}`, helpers);
    assert.equal(parsed.mode, 'raw_url');
    assert.equal(parsed.rawUrl, 'https://rawurl.com/path/');
    assert.equal(parsed.emailPart, b64urlEmail);
    assert.equal(parsed.email, 'alice@example.com');
  } finally {
    if (previous === undefined) delete vmProcess.env.REDIRECT_EMAIL_DELIMITERS;
    else vmProcess.env.REDIRECT_EMAIL_DELIMITERS = previous;
  }
});

test('parseRedirectPayload preserves double-slash raw URL paths when // delimiter is disabled', () => {
  const previous = vmProcess.env.REDIRECT_EMAIL_DELIMITERS;
  vmProcess.env.REDIRECT_EMAIL_DELIMITERS = '@@';
  try {
    const rawUrl = 'https://example.com//about';
    const parsed = parseRedirectPayload(rawUrl, helpers);
    assert.equal(parsed.mode, 'raw_url');
    assert.equal(parsed.rawUrl, rawUrl);
    assert.equal(parsed.ignoredSegment, null);
  } finally {
    if (previous === undefined) delete vmProcess.env.REDIRECT_EMAIL_DELIMITERS;
    else vmProcess.env.REDIRECT_EMAIL_DELIMITERS = previous;
  }
});

test('parseRedirectPayload preserves raw URLs with delimiter-like query values', () => {
  const rawUrl = 'https://example.com/landing?ref=foo--alice@example.com';
  const parsed = parseRedirectPayload(rawUrl, helpers);
  assert.equal(parsed.mode, 'raw_url');
  assert.equal(parsed.rawUrl, rawUrl);
  assert.equal(parsed.emailPart, null);
});

test('parseRedirectPayload preserves encoded raw URLs with delimiter-like query values', () => {
  const rawUrl = 'https://example.com/landing?ref=foo--alice@example.com';
  const parsed = parseRedirectPayload(encodeURIComponent(rawUrl), helpers);
  assert.equal(parsed.mode, 'raw_url');
  assert.equal(parsed.rawUrl, rawUrl);
  assert.equal(parsed.emailPart, null);
});

test('parseRedirectPayload splits raw-email suffixes after encoded query URLs', () => {
  const rawUrl = 'https://rawurl.com?x=1';
  const parsed = parseRedirectPayload(`${encodeURIComponent(rawUrl)}__alice@example.com`, helpers);
  assert.equal(parsed.mode, 'raw_url');
  assert.equal(parsed.rawUrl, rawUrl);
  assert.equal(parsed.emailPart, 'alice@example.com');
  assert.equal(parsed.email, 'alice@example.com');
});

test('parseRedirectPayload preserves percent-encoded delimiter-like query emails in encoded raw URLs', () => {
  for (const delimiter of ['__', '~~']) {
    const rawUrl = `https://example.com/landing?ref=foo${delimiter}alice@example.com`;
    const parsed = parseRedirectPayload(encodeURIComponent(rawUrl), helpers);
    assert.equal(parsed.mode, 'raw_url');
    assert.equal(parsed.rawUrl, rawUrl);
    assert.equal(parsed.emailPart, null);
  }
});

test('parseRedirectPayload decodes fully encoded raw URLs with delimiter-like path content', () => {
  const rawUrl = 'https://landingpage.com/foo--bar';
  const parsed = parseRedirectPayload(encodeURIComponent(rawUrl), helpers);
  assert.equal(parsed.mode, 'raw_url');
  assert.equal(parsed.rawUrl, rawUrl);
  assert.equal(parsed.emailPart, null);
  assert.equal(validateBase64Url(encodeURIComponent(rawUrl)), true);
});

test('parseRedirectPayload preserves raw URLs with double-slash email-looking path segments', () => {
  const rawUrl = 'https://example.com/profile//alice@example.com';
  const parsed = parseRedirectPayload(rawUrl, helpers);
  assert.equal(parsed.mode, 'raw_url');
  assert.equal(parsed.rawUrl, rawUrl);
  assert.equal(parsed.emailPart, null);
});


test('parseRedirectPayload keeps scanning when raw email contains another delimiter', () => {
  const rawEmail = 'john--doe%40example.com';
  const parsed = parseRedirectPayload(`https://rawurl.com__${rawEmail}/campaign`, helpers);
  assert.equal(parsed.mode, 'raw_url');
  assert.equal(parsed.rawUrl, 'https://rawurl.com');
  assert.equal(parsed.emailPart, rawEmail);
  assert.equal(parsed.email, 'john--doe@example.com');
  assert.equal(parsed.ignored, 'campaign');
});

test('parseRedirectPayload chooses the actual delimiter before percent-encoded raw email suffixes', () => {
  const rawEmail = 'john__doe%40example.com';
  const parsed = parseRedirectPayload(`${payload}--${rawEmail}`, helpers);
  assert.equal(parsed.matched, true);
  assert.equal(parsed.parseMode, 'delimited');
  assert.equal(parsed.ciphertext, payload);
  assert.equal(parsed.emailPart, rawEmail);
  assert.equal(parsed.email, 'john__doe@example.com');
});

test('parseRedirectPayload chooses the actual delimiter before raw email suffixes', () => {
  const rawEmail = 'john--doe@example.com';
  const parsed = parseRedirectPayload(`${payload}__${rawEmail}`, helpers);
  assert.equal(parsed.matched, true);
  assert.equal(parsed.parseMode, 'delimited');
  assert.equal(parsed.ciphertext, payload);
  assert.equal(parsed.emailPart, rawEmail);
  assert.equal(parsed.email, 'john--doe@example.com');
});

test('parseRedirectPayload chooses the actual delimiter before default and custom raw email delimiters', () => {
  const defaultParsed = parseRedirectPayload(`${payload}--john__doe@example.com`, helpers);
  assert.equal(defaultParsed.matched, true);
  assert.equal(defaultParsed.parseMode, 'delimited');
  assert.equal(defaultParsed.ciphertext, payload);
  assert.equal(defaultParsed.emailPart, 'john__doe@example.com');
  assert.equal(defaultParsed.email, 'john__doe@example.com');

  const previous = vmProcess.env.REDIRECT_EMAIL_DELIMITERS;
  vmProcess.env.REDIRECT_EMAIL_DELIMITERS = '__,++';
  try {
    const customParsed = parseRedirectPayload(`${payload}__john++doe@example.com`, helpers);
    assert.equal(customParsed.matched, true);
    assert.equal(customParsed.parseMode, 'delimited');
    assert.equal(customParsed.ciphertext, payload);
    assert.equal(customParsed.emailPart, 'john++doe@example.com');
    assert.equal(customParsed.email, 'john++doe@example.com');
  } finally {
    if (previous === undefined) delete vmProcess.env.REDIRECT_EMAIL_DELIMITERS;
    else vmProcess.env.REDIRECT_EMAIL_DELIMITERS = previous;
  }
});

test('parseRedirectPayload preserves ciphertext containing the separator delimiter', () => {
  const ciphertext = `${payload}__BBBBBBBBBB`;
  const parsed = parseRedirectPayload(`${ciphertext}__alice@example.com`, helpers);
  assert.equal(parsed.matched, true);
  assert.equal(parsed.parseMode, 'delimited');
  assert.equal(parsed.ciphertext, ciphertext);
  assert.equal(parsed.emailPart, 'alice@example.com');
  assert.equal(parsed.email, 'alice@example.com');
});

test('parseRedirectPayload prefers longer overlapping delimiters', () => {
  const previous = vmProcess.env.REDIRECT_EMAIL_DELIMITERS;
  vmProcess.env.REDIRECT_EMAIL_DELIMITERS = '__,_';
  try {
    const parsed = parseRedirectPayload(`${payload}__alice@example.com`, helpers);
    assert.equal(parsed.matched, true);
    assert.equal(parsed.parseMode, 'delimited');
    assert.equal(parsed.ciphertext, payload);
    assert.equal(parsed.emailPart, 'alice@example.com');
  } finally {
    if (previous === undefined) delete vmProcess.env.REDIRECT_EMAIL_DELIMITERS;
    else vmProcess.env.REDIRECT_EMAIL_DELIMITERS = previous;
  }
});

test('parseRedirectPayload preserves percent-encoded emails with overlapping delimiters', () => {
  const previous = vmProcess.env.REDIRECT_EMAIL_DELIMITERS;
  vmProcess.env.REDIRECT_EMAIL_DELIMITERS = '__,_';
  try {
    const parsed = parseRedirectPayload(`${payload}__alice%40example.com`, helpers);
    assert.equal(parsed.matched, true);
    assert.equal(parsed.parseMode, 'delimited');
    assert.equal(parsed.ciphertext, payload);
    assert.equal(parsed.emailPart, 'alice%40example.com');
    assert.equal(parsed.email, 'alice@example.com');
  } finally {
    if (previous === undefined) delete vmProcess.env.REDIRECT_EMAIL_DELIMITERS;
    else vmProcess.env.REDIRECT_EMAIL_DELIMITERS = previous;
  }
});

test('parseRedirectPayload preserves mixed-delimiter ciphertext before email split', () => {
  const ciphertext = `${payload}--BBBBBBBBBB`;
  const parsed = parseRedirectPayload(`${ciphertext}__alice@example.com`, helpers);
  assert.equal(parsed.matched, true);
  assert.equal(parsed.parseMode, 'delimited');
  assert.equal(parsed.ciphertext, ciphertext);
  assert.equal(parsed.emailPart, 'alice@example.com');
  assert.equal(parsed.email, 'alice@example.com');
});

test('parseRedirectPayload preserves short mixed-delimiter ciphertext suffixes', () => {
  const ciphertext = `${payload}--ABCD`;
  const parsed = parseRedirectPayload(`${ciphertext}__alice@example.com`, helpers);
  assert.equal(parsed.matched, true);
  assert.equal(parsed.parseMode, 'delimited');
  assert.equal(parsed.ciphertext, ciphertext);
  assert.equal(parsed.emailPart, 'alice@example.com');
  assert.equal(parsed.email, 'alice@example.com');
});

test('parseRedirectPayload preserves lowercase delimiter-like ciphertext suffixes', () => {
  const ciphertext = `${payload}__john`;
  const parsed = parseRedirectPayload(`${ciphertext}__alice@example.com`, helpers);
  assert.equal(parsed.matched, true);
  assert.equal(parsed.parseMode, 'delimited');
  assert.equal(parsed.ciphertext, ciphertext);
  assert.equal(parsed.emailPart, 'alice@example.com');
  assert.equal(parsed.email, 'alice@example.com');
});

test('parseRedirectPayload keeps scanning when uppercase percent-encoded raw email contains another delimiter', () => {
  const rawEmail = 'JOHN~~doe%40example.com';
  const parsed = parseRedirectPayload(`${payload}__${rawEmail}`, helpers);
  assert.equal(parsed.matched, true);
  assert.equal(parsed.parseMode, 'delimited');
  assert.equal(parsed.ciphertext, payload);
  assert.equal(parsed.emailPart, rawEmail);
  assert.equal(parsed.email, 'JOHN~~doe@example.com');
});

test('parseRedirectPayload keeps scanning repeated percent-encoded raw email delimiters', () => {
  const rawEmail = 'john--middle--doe%40example.com';
  const parsed = parseRedirectPayload(`${payload}__${rawEmail}`, helpers);
  assert.equal(parsed.matched, true);
  assert.equal(parsed.parseMode, 'delimited');
  assert.equal(parsed.ciphertext, payload);
  assert.equal(parsed.emailPart, rawEmail);
  assert.equal(parsed.email, 'john--middle--doe@example.com');
});

test('parseRedirectPayload keeps scanning repeated raw email delimiters', () => {
  const rawEmail = 'john--middle--doe@example.com';
  const parsed = parseRedirectPayload(`${payload}__${rawEmail}`, helpers);
  assert.equal(parsed.matched, true);
  assert.equal(parsed.parseMode, 'delimited');
  assert.equal(parsed.ciphertext, payload);
  assert.equal(parsed.emailPart, rawEmail);
  assert.equal(parsed.email, 'john--middle--doe@example.com');
});

test('parseRedirectPayload keeps scanning raw email local parts with leading delimiters', () => {
  for (const [delimiter, rawEmail] of [['__', '--john@example.com'], ['--', '__john@example.com']]) {
    const parsed = parseRedirectPayload(`${payload}${delimiter}${rawEmail}`, helpers);
    assert.equal(parsed.matched, true);
    assert.equal(parsed.parseMode, 'delimited');
    assert.equal(parsed.ciphertext, payload);
    assert.equal(parsed.emailPart, rawEmail);
    assert.equal(parsed.email, rawEmail);
  }
});

test('parseRedirectPayload keeps scanning ignored-prefix delimiters when raw email contains another delimiter', () => {
  const rawEmail = 'john--doe%40example.com';
  const suffix = parseRedirectPayload(`https://example.com/path/${payload}__${rawEmail}`, helpers);
  assert.equal(suffix.matchedNewFormat, true);
  assert.equal(suffix.parseMode, 'ignored_url_payload_email');
  assert.equal(suffix.ciphertext, payload);
  assert.equal(suffix.emailPart, rawEmail);
  assert.equal(suffix.email, 'john--doe@example.com');
  assert.equal(suffix.ignored, 'https://example.com/path');

  const emailFirst = parseRedirectPayload(`https://example.com/path__${rawEmail}/${payload}`, helpers);
  assert.equal(emailFirst.matchedNewFormat, true);
  assert.equal(emailFirst.parseMode, 'ignored_url_email_payload');
  assert.equal(emailFirst.ciphertext, payload);
  assert.equal(emailFirst.emailPart, rawEmail);
  assert.equal(emailFirst.email, 'john--doe@example.com');
  assert.equal(emailFirst.ignored, 'https://example.com/path');
});

test('parseRedirectPayload preserves ignored tails after configured raw URL email delimiters', () => {
  const defaultParsed = parseRedirectPayload(`https://rawurl.com__${b64urlEmail}/campaign`, helpers);
  assert.equal(defaultParsed.mode, 'raw_url');
  assert.equal(defaultParsed.rawUrl, 'https://rawurl.com');
  assert.equal(defaultParsed.emailPart, b64urlEmail);
  assert.equal(defaultParsed.email, 'alice@example.com');
  assert.equal(defaultParsed.ignored, 'campaign');

  const tailDelimiterParsed = parseRedirectPayload(`https://rawurl.com__${b64urlEmail}/campaign--summer`, helpers);
  assert.equal(tailDelimiterParsed.mode, 'raw_url');
  assert.equal(tailDelimiterParsed.rawUrl, 'https://rawurl.com');
  assert.equal(tailDelimiterParsed.emailPart, b64urlEmail);
  assert.equal(tailDelimiterParsed.ignored, 'campaign--summer');

  const encodedPrefixParsed = parseRedirectPayload(`${encodeURIComponent('https://rawurl.com')}__${b64urlEmail}/campaign`, helpers);
  assert.equal(encodedPrefixParsed.mode, 'raw_url');
  assert.equal(encodedPrefixParsed.rawUrl, 'https://rawurl.com');
  assert.equal(encodedPrefixParsed.emailPart, b64urlEmail);
  assert.equal(encodedPrefixParsed.ignored, 'campaign');

  const encodedQueryPrefixParsed = parseRedirectPayload(`${encodeURIComponent('https://rawurl.com?x=1')}__${b64urlEmail}`, helpers);
  assert.equal(encodedQueryPrefixParsed.mode, 'raw_url');
  assert.equal(encodedQueryPrefixParsed.rawUrl, 'https://rawurl.com?x=1');
  assert.equal(encodedQueryPrefixParsed.emailPart, b64urlEmail);

  const previous = vmProcess.env.REDIRECT_EMAIL_DELIMITERS;
  vmProcess.env.REDIRECT_EMAIL_DELIMITERS = '@@';
  try {
    const parsed = parseRedirectPayload(`https://rawurl.com/path/@@${b64urlEmail}/campaign`, helpers);
    assert.equal(parsed.mode, 'raw_url');
    assert.equal(parsed.rawUrl, 'https://rawurl.com/path/');
    assert.equal(parsed.emailPart, b64urlEmail);
    assert.equal(parsed.email, 'alice@example.com');
    assert.equal(parsed.ignored, 'campaign');
  } finally {
    if (previous === undefined) delete vmProcess.env.REDIRECT_EMAIL_DELIMITERS;
    else vmProcess.env.REDIRECT_EMAIL_DELIMITERS = previous;
  }
});

test('parseRedirectPayload preserves raw URL destinations', () => {
  const parsed = parseRedirectPayload(`https://rawurl.com//${b64urlEmail}`, helpers);
  assert.equal(parsed.mode, 'raw_url');
  assert.equal(parsed.rawUrl, 'https://rawurl.com');
  assert.equal(parsed.emailPart, b64urlEmail);
});

test('parseRedirectPayload parses slash email delimiters after trailing-slash raw URLs', () => {
  for (const emailRaw of ['alice@example.com', 'alice%40example.com']) {
    const parsed = parseRedirectPayload(`https://example.com/path///${emailRaw}`, helpers);
    assert.equal(parsed.mode, 'raw_url');
    assert.equal(parsed.rawUrl, 'https://example.com/path/');
    assert.equal(parsed.emailPart, emailRaw);
    assert.equal(parsed.email, 'alice@example.com');
  }
});

test('parseRedirectPayload preserves encoded raw URLs ending with delimiters before email suffixes', () => {
  const rawUrl = 'https://example.com/path__';
  const parsed = parseRedirectPayload(`${encodeURIComponent(rawUrl)}--alice@example.com`, helpers);
  assert.equal(parsed.mode, 'raw_url');
  assert.equal(parsed.rawUrl, rawUrl);
  assert.equal(parsed.emailPart, 'alice@example.com');
  assert.equal(parsed.email, 'alice@example.com');
});


test('parseRedirectPayload accepts raw email and decodeEmailPart preserves it', () => {
  const parsed = parseRedirectPayload(`${payload}/alice@example.com/ignored`, helpers);
  assert.equal(parsed.mode, 'payload_email_ignored');
  assert.equal(parsed.emailPart, 'alice@example.com');
  assert.equal(parsed.email, 'alice@example.com');
  const decoded = decodeEmailPart(parsed.emailPart);
  assert.equal(decoded.email, 'alice@example.com');
  assert.equal(decoded.decoded, 'alice@example.com');
  assert.equal(decoded.source, 'raw');
});

test('decodeEmailPart still decodes base64url email segments', () => {
  const decoded = decodeEmailPart(b64urlEmail);
  assert.equal(decoded.email, 'alice@example.com');
  assert.equal(decoded.decoded, 'alice@example.com');
  assert.equal(decoded.source, 'b64');
});

test('safeLogValue strips ANSI escape sequences', () => {
  assert.equal(safeLogValue('ok\u001b[31mred\u001b[0m'), 'okred');
});

test('sanitizeRequestPath redacts configured-delimiter links with ignored tails', () => {
  assert.equal(sanitizeRequestPath(`/${payload}__${b64urlEmail}/campaign`), '/[encoded-redacted]');
});

test('sanitizeRequestPath scans later delimiters before preserving paths', () => {
  const prefixedPayload = `AAAAAAAAAA__${payload}`;
  assert.equal(sanitizeRequestPath(`/${prefixedPayload}__${b64urlEmail}/campaign`), '/[encoded-redacted]');
});

test('sanitizeRequestPath redacts slash-delimited valid links when slash delimiter is disabled', () => {
  const previous = vmProcess.env.REDIRECT_EMAIL_DELIMITERS;
  vmProcess.env.REDIRECT_EMAIL_DELIMITERS = '@@';
  try {
    assert.equal(sanitizeRequestPath(`/${payload}//${b64urlEmail}/campaign`), '/[encoded-redacted]');
  } finally {
    if (previous === undefined) delete vmProcess.env.REDIRECT_EMAIL_DELIMITERS;
    else vmProcess.env.REDIRECT_EMAIL_DELIMITERS = previous;
  }
});

test('sanitizeRequestPath redacts email-first payload links', () => {
  assert.equal(sanitizeRequestPath(`/alice@example.com/${payload}`), '/[encoded-redacted]');
  assert.equal(sanitizeRequestPath(`/${b64urlEmail}/${payload}`), '/[encoded-redacted]');
});

test('sanitizeRequestPath redacts URL-prefix payload links', () => {
  assert.equal(sanitizeRequestPath(`/https://example.com/${payload}`), '/[encoded-redacted]');
});

test('isLikelyEmail rejects decoded ciphertext noise with email substring', () => {
  assert.equal(isLikelyEmail('�+B��?re343694@gmail.com'), false);
});

test('isLikelyEmail accepts plain ascii address', () => {
  assert.equal(isLikelyEmail('re343694@gmail.com'), true);
});


test('extractSingleCleanEmailToken recovers one email from noisy decoded text', () => {
  assert.equal(extractSingleCleanEmailToken('�+B��?re343694@gmail.com'), 're343694@gmail.com');
});

test('extractSingleCleanEmailToken does not recover when no binary noise is present', () => {
  assert.equal(extractSingleCleanEmailToken('prefix re343694@gmail.com'), '');
});

test('extractSingleCleanEmailToken rejects multiple embedded emails', () => {
  assert.equal(extractSingleCleanEmailToken('�alice@example.com and bob@example.com'), '');
});

test('extractSingleCleanEmailToken rejects end-of-string trailing ASCII noise in TLD', () => {
  assert.equal(extractSingleCleanEmailToken('�alice@example.comabc'), '');
});

test('validateBase64Url logs-but-allows payloads above soft cap and below hard path cap', () => {
  assert.equal(validateBase64Url('A'.repeat(9000)), true);
});

test('validateBase64Url rejects payloads above hard path cap', () => {
  assert.equal(validateBase64Url('A'.repeat(17000)), false);
});


function encryptForBruteSplitTest(plainUrl) {
  const keyBuf = Buffer.from(testKeyHex, 'hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuf, iv);
  const ct = Buffer.concat([cipher.update(plainUrl, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ct, tag]).toString('base64url');
}



test('validateBase64Url rejects over-limit raw URL query before query stripping', () => {
  const rawUrlWithHugeQuery = `https://example.com/path?${'a'.repeat(17000)}`;
  assert.equal(validateBase64Url(rawUrlWithHugeQuery), false);
});

test('bruteSplitDecryptFull skips long single-segment payloads without recovery suffix', () => {
  const invalidSingleSegment = 'A'.repeat(16000);
  assert.equal(hasBruteSplitRecoverySuffix(invalidSingleSegment), false);
  assert.equal(getBruteSplitCandidatePrefixLengths(invalidSingleSegment).length, 0);
  assert.equal(bruteSplitDecryptFull(invalidSingleSegment), null);
});

test('bruteSplitDecryptFull rejects empty trailing suffix and bounds slash candidates', () => {
  const trailingSlashOnly = `${'A'.repeat(16000)}/`;
  assert.equal(hasBruteSplitRecoverySuffix(trailingSlashOnly), false);
  assert.equal(getBruteSplitCandidatePrefixLengths(trailingSlashOnly).length, 0);
  assert.equal(bruteSplitDecryptFull(trailingSlashOnly), null);

  const oneSuffix = `${'A'.repeat(16000)}/x`;
  assert.equal(hasBruteSplitRecoverySuffix(oneSuffix), true);
  assert.deepEqual(Array.from(getBruteSplitCandidatePrefixLengths(oneSuffix)), [16000]);
  assert.equal(bruteSplitDecryptFull(oneSuffix), null);
});

test('bruteSplitDecryptFull recovers delimiterless payloads with long raw suffixes', () => {
  const destination = 'https://landing.example/path?campaign=summer';
  const encrypted = encryptForBruteSplitTest(destination);
  const suffix = `/${'ignored-segment-'.repeat(24)}long.raw-local-part.with.metadata.1234567890@example.com`;
  assert.ok(suffix.length > 256);

  const recovered = bruteSplitDecryptFull(`${encrypted}${suffix}`);
  assert.ok(recovered, 'expected delimiterless payload with long suffix to recover');
  assert.equal(recovered.url, destination);
  assert.equal(recovered.emailRaw, suffix.slice(1));
  assert.ok(`${encrypted}${suffix}`.length - recovered.kTried > 32);
});


test('bruteSplitDecryptFull follows hard path cap for log-mode oversized payloads', () => {
  const destination = `https://landing.example/path?blob=${'a'.repeat(6100)}`;
  const encrypted = encryptForBruteSplitTest(destination);
  const suffix = '/metadata@example.com';
  const combined = `${encrypted}${suffix}`;
  assert.ok(combined.length > 8192);
  assert.ok(combined.length < 16384);

  const recovered = bruteSplitDecryptFull(combined);
  assert.ok(recovered, 'expected log-mode oversized payload under hard path cap to recover');
  assert.equal(recovered.url, destination);
});

const requestedPayload = 'J2GrkvHZU4iMtYnBeVkksJC78kOx5U4mPG75xnqEvCCFcLGK45U6VofqPB-Zn_L1s8uVG74xePGAvuwHPDlkMIv5KWtsCcVT6FIR7oi2fNo5Ru3ioUiZZLYXP50dG1I';
const requestedEmail = 'YTRhbmdlbGVzQHltYWlsLmNvbQ==';

test('supports ignored full URL before payload with no email delimiter', () => {
  const parsed = parseRedirectPayload(`https://example.com/${requestedPayload}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'ignored_url_payload');
  assert.equal(parsed.ciphertext, requestedPayload);
  assert.equal(parsed.ignoredSegment, 'https://example.com');
  assert.equal(validateBase64Url(`https://example.com/${requestedPayload}`), true);
});

test('supports ignored full URL before shorter payload with no email delimiter', () => {
  const shortPayload = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdEfGhIj';
  const parsed = parseRedirectPayload(`https://example.com/${shortPayload}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'ignored_url_payload');
  assert.equal(parsed.ciphertext, shortPayload);
  assert.equal(parsed.ignoredSegment, 'https://example.com');
  assert.equal(validateBase64Url(`https://example.com/${shortPayload}`), true);
});

test('preserves queried raw URLs with long payload-shaped final path segments', () => {
  const token = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdEfGhIjKlMnOpQrStUvWxYz';
  const rawUrl = `https://files.example.com/blob/${token}?sig=abc123&expires=1783240100`;
  const parsed = parseRedirectPayload(rawUrl, helpers);
  assert.equal(parsed.mode, 'raw_url');
  assert.equal(parsed.rawUrl, rawUrl);
  assert.equal(validateBase64Url(rawUrl), true);
});

test('preserves allowlisted raw URLs with opaque payload-shaped final path segments', () => {
  const token = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdEfGhIjKlMnOpQrStUvWxYz';
  const rawUrl = `https://cdn.example.com/files/${token}`;
  const parsed = parseRedirectPayload(rawUrl, helpers);
  assert.equal(parsed.mode, 'raw_url');
  assert.equal(parsed.rawUrl, rawUrl);
  assert.equal(validateBase64Url(rawUrl), true);
});

test('supports allowlisted ignored full URL before decryptable payload', () => {
  const encrypted = encryptForBruteSplitTest('https://landingpage.com/welcome');
  const parsed = parseRedirectPayload(`https://cdn.example.com/${encrypted}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'ignored_url_payload');
  assert.equal(parsed.ciphertext, encrypted);
  assert.equal(parsed.ignoredSegment, 'https://cdn.example.com');
  assert.equal(validateBase64Url(`https://cdn.example.com/${encrypted}`), true);
});

test('supports queried allowlisted ignored full URL before decryptable payload', () => {
  const encrypted = encryptForBruteSplitTest('https://landingpage.com/welcome');
  const parsed = parseRedirectPayload(`https://cdn.example.com/${encrypted}?utm=x`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'ignored_url_payload');
  assert.equal(parsed.ciphertext, encrypted);
  assert.equal(parsed.ignoredSegment, 'https://cdn.example.com');
  assert.equal(validateBase64Url(`https://cdn.example.com/${encrypted}?utm=x`), true);
});

test('supports fragment-suffixed allowlisted ignored full URL before decryptable payload', () => {
  const encrypted = encryptForBruteSplitTest('https://landingpage.com/welcome');
  const parsed = parseRedirectPayload(`https://cdn.example.com/${encrypted}#frag`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'ignored_url_payload');
  assert.equal(parsed.ciphertext, encrypted);
  assert.equal(parsed.ignoredSegment, 'https://cdn.example.com');
  assert.equal(validateBase64Url(`https://cdn.example.com/${encrypted}#frag`), true);
});

test('supports encoded allowlisted ignored full URL before decryptable payload', () => {
  const encrypted = encryptForBruteSplitTest('https://landingpage.com/welcome');
  const encodedPrefix = encodeURIComponent('https://cdn.example.com');
  const parsed = parseRedirectPayload(`${encodedPrefix}/${encrypted}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'ignored_url_payload');
  assert.equal(parsed.ciphertext, encrypted);
  assert.equal(parsed.ignoredSegment, encodedPrefix);
  assert.equal(validateBase64Url(`${encodedPrefix}/${encrypted}`), true);
});

test('supports encoded allowlisted ignored full URL before fragment-suffixed decryptable payload', () => {
  const encrypted = encryptForBruteSplitTest('https://landingpage.com/welcome');
  const encodedPrefix = encodeURIComponent('https://cdn.example.com');
  const parsed = parseRedirectPayload(`${encodedPrefix}/${encrypted}%23frag`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'ignored_url_payload');
  assert.equal(parsed.ciphertext, encrypted);
  assert.equal(parsed.ignoredSegment, encodedPrefix);
  assert.equal(validateBase64Url(`${encodedPrefix}/${encrypted}%23frag`), true);
});

test('supports queried allowlisted ignored full URL before decryptable payload and email suffix', () => {
  const encrypted = encryptForBruteSplitTest('https://landingpage.com/welcome');
  const parsed = parseRedirectPayload(`https://cdn.example.com/${encrypted}//${requestedEmail}?utm=x`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'ignored_url_payload_email');
  assert.equal(parsed.ciphertext, encrypted);
  assert.equal(parsed.emailPart, requestedEmail);
  assert.equal(parsed.ignoredSegment, 'https://cdn.example.com');
  assert.equal(validateBase64Url(`https://cdn.example.com/${encrypted}//${requestedEmail}?utm=x`), true);
});

test('supports trailing-slash allowlisted ignored full URL before decryptable payload', () => {
  const encrypted = encryptForBruteSplitTest('https://landingpage.com/welcome');
  const parsed = parseRedirectPayload(`https://cdn.example.com/${encrypted}/`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'ignored_url_payload');
  assert.equal(parsed.ciphertext, encrypted);
  assert.equal(parsed.ignoredSegment, 'https://cdn.example.com');
  assert.equal(validateBase64Url(`https://cdn.example.com/${encrypted}/`), true);
});

test('supports ignored full URL before payload with email suffix', () => {
  const parsed = parseRedirectPayload(`https://example.com/${requestedPayload}//${requestedEmail}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'ignored_url_payload_email');
  assert.equal(parsed.emailSegment, 'segment3');
  assert.equal(parsed.ciphertext, requestedPayload);
  assert.equal(parsed.emailPart, requestedEmail);
  assert.equal(parsed.normalizedBaseString, `${requestedPayload}/${requestedEmail}`);
  assert.equal(validateBase64Url(`https://example.com/${requestedPayload}//${requestedEmail}`), true);
});

test('supports ignored full URL before email and payload', () => {
  const parsed = parseRedirectPayload(`https://example.com//${requestedEmail}/${requestedPayload}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'ignored_url_email_payload');
  assert.equal(parsed.emailSegment, 'segment2');
  assert.equal(parsed.ciphertext, requestedPayload);
  assert.equal(parsed.emailPart, requestedEmail);
  assert.equal(parsed.normalizedBaseString, `${requestedPayload}/${requestedEmail}`);
  assert.equal(validateBase64Url(`https://example.com//${requestedEmail}/${requestedPayload}`), true);
});

test('supports arbitrary ignored full URL hosts and paths before payload', () => {
  const ignoredUrl = 'https://tracking.vendor.net/campaign/segment';
  const parsed = parseRedirectPayload(`${ignoredUrl}/${requestedPayload}//${requestedEmail}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'ignored_url_payload_email');
  assert.equal(parsed.ciphertext, requestedPayload);
  assert.equal(parsed.emailPart, requestedEmail);
  assert.equal(parsed.ignoredSegment, ignoredUrl);
  assert.equal(validateBase64Url(`${ignoredUrl}/${requestedPayload}//${requestedEmail}`), true);
});

test('supports email-first payload links', () => {
  const parsed = parseRedirectPayload(`${requestedEmail}/${requestedPayload}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'email_payload');
  assert.equal(parsed.emailSegment, 'segment1');
  assert.equal(parsed.ciphertext, requestedPayload);
  assert.equal(parsed.emailPart, requestedEmail);
  assert.equal(parsed.normalizedBaseString, `${requestedPayload}/${requestedEmail}`);
  assert.equal(validateBase64Url(`${requestedEmail}/${requestedPayload}`), true);
});

test('supports email-first links with decryptable payloads without dropping email', () => {
  const encrypted = encryptForBruteSplitTest('https://landingpage.com/welcome');
  const parsed = parseRedirectPayload(`${requestedEmail}/${encrypted}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'email_payload');
  assert.equal(parsed.emailSegment, 'segment1');
  assert.equal(parsed.ciphertext, encrypted);
  assert.equal(parsed.emailPart, requestedEmail);
  assert.equal(parsed.normalizedBaseString, `${encrypted}/${requestedEmail}`);
  assert.equal(validateBase64Url(`${requestedEmail}/${encrypted}`), true);
});

test('supports email-first links with hash characters in email local part', () => {
  const encrypted = encryptForBruteSplitTest('https://landingpage.com/welcome');
  const email = 'alice#tag@example.com';
  const parsed = parseRedirectPayload(`${email}/${encrypted}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'email_payload');
  assert.equal(parsed.emailSegment, 'segment1');
  assert.equal(parsed.ciphertext, encrypted);
  assert.equal(parsed.emailPart, email);
  assert.equal(parsed.normalizedBaseString, `${encrypted}/${email}`);
  assert.equal(validateBase64Url(`${email}/${encrypted}`), true);
});

test('supports arbitrary non-url ignored prefixes before payload', () => {
  const parsedSimple = parseRedirectPayload(`nytimes/${requestedPayload}`, helpers);
  assert.equal(parsedSimple.matchedNewFormat, true);
  assert.equal(parsedSimple.parseMode, 'ignored_url_payload');
  assert.equal(parsedSimple.ciphertext, requestedPayload);
  assert.equal(parsedSimple.ignoredSegment, 'nytimes');
  assert.equal(validateBase64Url(`nytimes/${requestedPayload}`), true);

  const parsedDotted = parseRedirectPayload(`url.com/path/${requestedPayload}//${requestedEmail}`, helpers);
  assert.equal(parsedDotted.matchedNewFormat, true);
  assert.equal(parsedDotted.parseMode, 'ignored_url_payload_email');
  assert.equal(parsedDotted.ciphertext, requestedPayload);
  assert.equal(parsedDotted.emailPart, requestedEmail);
  assert.equal(parsedDotted.ignoredSegment, 'url.com/path');
  assert.equal(validateBase64Url(`url.com/path/${requestedPayload}//${requestedEmail}`), true);
});

test('supports arbitrary ignored prefixes before email and payload', () => {
  const parsed = parseRedirectPayload(`anything/goes//${requestedEmail}/${requestedPayload}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'ignored_url_email_payload');
  assert.equal(parsed.ciphertext, requestedPayload);
  assert.equal(parsed.emailPart, requestedEmail);
  assert.equal(parsed.ignoredSegment, 'anything/goes');
  assert.equal(validateBase64Url(`anything/goes//${requestedEmail}/${requestedPayload}`), true);
});

test('supports platform-collapsed ignored prefix payload/email paths', () => {
  const collapsedIgnored = 'https:/example.com';

  const suffix = parseRedirectPayload(`${collapsedIgnored}/${requestedPayload}/${requestedEmail}`, helpers);
  assert.equal(suffix.matchedNewFormat, true);
  assert.equal(suffix.parseMode, 'ignored_url_payload_email');
  assert.equal(suffix.emailSegment, 'segment3');
  assert.equal(suffix.ciphertext, requestedPayload);
  assert.equal(suffix.emailPart, requestedEmail);
  assert.equal(suffix.ignoredSegment, collapsedIgnored);
  assert.equal(validateBase64Url(`${collapsedIgnored}/${requestedPayload}/${requestedEmail}`), true);

  const first = parseRedirectPayload(`${collapsedIgnored}/${requestedEmail}/${requestedPayload}`, helpers);
  assert.equal(first.matchedNewFormat, true);
  assert.equal(first.parseMode, 'ignored_url_email_payload');
  assert.equal(first.emailSegment, 'segment2');
  assert.equal(first.ciphertext, requestedPayload);
  assert.equal(first.emailPart, requestedEmail);
  assert.equal(first.ignoredSegment, collapsedIgnored);
  assert.equal(validateBase64Url(`${collapsedIgnored}/${requestedEmail}/${requestedPayload}`), true);
});

test('accepts logged collapsed bare-domain ignored prefix payload/email path', () => {
  const loggedPayload = 'fag3d9O8s8fJBPh59at0ABJWN9BrOnQSamV2W2bII6sTtmrxcR82eCYW2yq-UVmEkKz7R6tsbTLcsWXcxyGu1IRd2qjbyD41Ees';
  const loggedPath = `example.com/${loggedPayload}/${requestedEmail}`;
  const parsed = parseRedirectPayload(loggedPath, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'ignored_url_payload_email');
  assert.equal(parsed.emailSegment, 'segment3');
  assert.equal(parsed.ciphertext, loggedPayload);
  assert.equal(parsed.emailPart, requestedEmail);
  assert.equal(parsed.ignoredSegment, 'example.com');
  assert.equal(validateBase64Url(loggedPath), true);
});

test('does not steal existing payload-first ignored links', () => {
  const tracking = 'campaign012345678901234567890123456789012345';
  const parsedNoEmail = parseRedirectPayload(`${payload}/${tracking}`, helpers);
  assert.notEqual(parsedNoEmail.parseMode, 'ignored_url_payload');
  assert.equal(parsedNoEmail.ciphertext, payload);

  const parsedWithEmail = parseRedirectPayload(`${payload}/${tracking}/${requestedEmail}`, helpers);
  assert.equal(parsedWithEmail.parseMode, 'payload_ignored_email');
  assert.equal(parsedWithEmail.ciphertext, payload);
  assert.equal(parsedWithEmail.emailPart, requestedEmail);
});

test('preserves raw URL destinations with payload-shaped slugs', () => {
  const parsed = parseRedirectPayload('https://landingpage.com/newsletter2026', helpers);
  assert.equal(parsed.mode, 'raw_url');
  assert.equal(parsed.rawUrl, 'https://landingpage.com/newsletter2026');
});


test('preserves long raw URL destinations before ignored-prefix parsing', () => {
  const longSlug = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const parsed = parseRedirectPayload(`https://landingpage.com/${longSlug}`, helpers);
  assert.equal(parsed.mode, 'raw_url');
  assert.equal(parsed.rawUrl, `https://landingpage.com/${longSlug}`);
  assert.equal(validateBase64Url(`https://landingpage.com/${longSlug}`), true);
});

test('preserves encoded raw URL prefixes before ignored-prefix parsing', () => {
  const longSlug = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
  const encodedRawUrl = encodeURIComponent('https://rawurl.com');
  const parsed = parseRedirectPayload(`${encodedRawUrl}/${longSlug}//${requestedEmail}`, helpers);
  assert.equal(parsed.mode, 'raw_url');
  assert.equal(parsed.rawUrl, 'https://rawurl.com');
  assert.equal(parsed.emailPart, requestedEmail);
  assert.equal(parsed.ignoredSegment, longSlug);
  assert.equal(validateBase64Url(`${encodedRawUrl}/${longSlug}//${requestedEmail}`), true);
});

test('preserves raw URLs with doubled path slashes when no email delimiter is present', () => {
  const longSlug = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const parsed = parseRedirectPayload(`https://landingpage.com/path//${longSlug}`, helpers);
  assert.equal(parsed.mode, 'raw_url');
  assert.equal(parsed.rawUrl, `https://landingpage.com/path//${longSlug}`);
  assert.equal(validateBase64Url(`https://landingpage.com/path//${longSlug}`), true);
});

test('does not steal short base64url raw-url payload-first links', () => {
  const rawUrlPayload = Buffer.from('https://a.co', 'utf8').toString('base64url');
  const tracking = 'campaign012345678901234567890123456789012345';
  const parsed = parseRedirectPayload(`${rawUrlPayload}/${tracking}`, helpers);
  assert.notEqual(parsed.parseMode, 'ignored_url_payload');
  assert.equal(parsed.ciphertext, rawUrlPayload);
});

test('supports ignored long campaign prefix before encrypted payload and email suffix', () => {
  const longCampaign = 'campaign012345678901234567890123456789012345';
  const parsed = parseRedirectPayload(`${longCampaign}/${requestedPayload}//${requestedEmail}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'ignored_url_payload_email');
  assert.equal(parsed.ciphertext, requestedPayload);
  assert.equal(parsed.emailPart, requestedEmail);
  assert.equal(parsed.ignoredSegment, longCampaign);
  assert.equal(validateBase64Url(`${longCampaign}/${requestedPayload}//${requestedEmail}`), true);
});

test('supports ignored prefix before short base64url raw-url payload', () => {
  const rawUrlPayload = Buffer.from('https://a.co', 'utf8').toString('base64url');
  const parsed = parseRedirectPayload(`campaign/${rawUrlPayload}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'ignored_url_payload');
  assert.equal(parsed.ciphertext, rawUrlPayload);
  assert.equal(parsed.ignoredSegment, 'campaign');
  assert.equal(validateBase64Url(`campaign/${rawUrlPayload}`), true);
});

test('supports collapsed email suffix after long ignored campaign prefix', () => {
  const longCampaign = 'campaign012345678901234567890123456789012345';
  const parsed = parseRedirectPayload(`${longCampaign}/${requestedPayload}/${requestedEmail}`, helpers);
  assert.equal(parsed.matchedNewFormat, true);
  assert.equal(parsed.parseMode, 'ignored_url_payload_email');
  assert.equal(parsed.emailSegment, 'segment3');
  assert.equal(parsed.ciphertext, requestedPayload);
  assert.equal(parsed.emailPart, requestedEmail);
  assert.equal(parsed.ignoredSegment, longCampaign);
  assert.equal(validateBase64Url(`${longCampaign}/${requestedPayload}/${requestedEmail}`), true);
});
