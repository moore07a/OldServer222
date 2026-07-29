"use strict";

function createParseIgnoredUrlCipherPayload(dependencies) {
  const {
    detectEncodedEmailSegment,
    findPreviousEmailDelimiter,
    finishFlexibleRedirectPayload,
    isPartialRawEmailDelimiterSplit,
    looksLikeCiphertextSegment,
    looksLikeHttpUrl,
    looksLikeRedirectPayloadSegment
  } = dependencies;

  return function parseIgnoredUrlCipherPayload(result, clean, helpers) {
  const source = String(clean || '').replace(/^\/+|\/+$/g, '');
  if (!source || !source.includes('/')) return false;

  const firstSlash = source.indexOf('/');
  const firstSegment = firstSlash > 0 ? source.slice(0, firstSlash) : source;
  const firstSegmentDecodedUrl = String(helpers.decodeBase64UrlLoose(firstSegment) || helpers.decodeFallback(firstSegment) || '').trim();
  const firstSegmentLooksPayload = looksLikeCiphertextSegment(firstSegment);
  if (looksLikeHttpUrl(firstSegmentDecodedUrl)) return false;

  const finish = (ciphertext, emailRaw, ignoredRaw, emailSegment) => {
    const ignored = String(ignoredRaw || '').replace(/^\/+|\/+$/g, '');
    if (!ignored || !looksLikeRedirectPayloadSegment(ciphertext, helpers)) return false;
    const ciphertextEmailCandidate = detectEncodedEmailSegment(ciphertext, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
    if (ciphertextEmailCandidate.isEmail) return false;
    finishFlexibleRedirectPayload(
      result,
      emailRaw ? (emailSegment === 'segment2' ? 'ignored_url_email_payload' : 'ignored_url_payload_email') : 'ignored_url_payload',
      ciphertext,
      emailRaw || null,
      ignored,
      emailSegment || null,
      helpers
    );
    return true;
  };

  const tryEmailFirst = () => {
    let searchEnd = source.length;
    while (searchEnd > 0) {
      const match = findPreviousEmailDelimiter(source, searchEnd);
      if (!match) break;
      const i = match.index;
      const delimiter = match.delimiter;

      const ignored = source.slice(0, i);
      const remainder = source.slice(i + delimiter.length);
      const slash = remainder.indexOf('/');
      if (!ignored || slash <= 0) { searchEnd = i; continue; }

      const emailRaw = remainder.slice(0, slash);
      const ciphertext = remainder.slice(slash + 1);
      if (!ciphertext || ciphertext.includes('/')) { searchEnd = i; continue; }

      const emailCandidate = detectEncodedEmailSegment(emailRaw, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
      if (emailCandidate.isEmail && isPartialRawEmailDelimiterSplit(source, match, emailRaw, helpers)) { searchEnd = i; continue; }
      if (emailCandidate.isEmail && finish(ciphertext, emailCandidate.raw, ignored, 'segment2')) return true;
      searchEnd = i;
    }
    return false;
  };

  const tryEmailSuffix = () => {
    let searchEnd = source.length;
    while (searchEnd > 0) {
      const match = findPreviousEmailDelimiter(source, searchEnd);
      if (!match) break;
      const i = match.index;
      const delimiter = match.delimiter;

      const lhs = source.slice(0, i);
      const emailRaw = source.slice(i + delimiter.length);
      if (!lhs || !emailRaw || emailRaw.includes('/')) { searchEnd = i; continue; }

      const payloadSlash = lhs.lastIndexOf('/');
      if (payloadSlash <= 0) { searchEnd = i; continue; }

      const ignored = lhs.slice(0, payloadSlash);
      const ciphertext = lhs.slice(payloadSlash + 1);
      const emailCandidate = detectEncodedEmailSegment(emailRaw, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
      if (emailCandidate.isEmail && isPartialRawEmailDelimiterSplit(source, match, emailRaw, helpers)) { searchEnd = i; continue; }
      if (emailCandidate.isEmail && finish(ciphertext, emailCandidate.raw, ignored, 'segment3')) return true;
      searchEnd = i;
    }
    return false;
  };

  const tryCollapsedEmailPair = () => {
    const segments = source.split('/').filter(Boolean);
    if (segments.length < 3) return false;

    const last = segments[segments.length - 1];
    const beforeLast = segments[segments.length - 2];
    const ignoredBeforePair = segments.slice(0, -2).join('/');
    const shouldDeferToPayloadFirst = (candidatePayload) => firstSegmentLooksPayload && String(candidatePayload || '').length < firstSegment.length;

    const suffixEmail = detectEncodedEmailSegment(last, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
    if (!shouldDeferToPayloadFirst(beforeLast) && suffixEmail.isEmail && finish(beforeLast, suffixEmail.raw, ignoredBeforePair, 'segment3')) return true;

    const middleEmail = detectEncodedEmailSegment(beforeLast, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
    if (!shouldDeferToPayloadFirst(last) && middleEmail.isEmail && finish(last, middleEmail.raw, ignoredBeforePair, 'segment2')) return true;

    return false;
  };

  if (tryEmailFirst()) return true;
  if (tryEmailSuffix()) return true;
  if (tryCollapsedEmailPair()) return true;

  if (firstSegmentLooksPayload) return false;

  const lastSlash = source.lastIndexOf('/');
  if (lastSlash <= 0) return false;

  const ignored = source.slice(0, lastSlash);
  const ciphertext = source.slice(lastSlash + 1);
  if (!ciphertext || ciphertext.includes('/')) return false;

  const emailCandidate = detectEncodedEmailSegment(ciphertext, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
  if (emailCandidate.isEmail) return false;

  return finish(ciphertext, null, ignored, null);
}
}

module.exports = createParseIgnoredUrlCipherPayload;
