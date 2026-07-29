"use strict";

function createParseFlexibleRedirectPayload(dependencies) {
  const {
    detectEncodedEmailSegment,
    findNextEmailDelimiter,
    findPreviousEmailDelimiter,
    finishFlexibleRedirectPayload,
    isPartialRawEmailDelimiterSplit,
    joinCollapsedUrlSegments,
    looksLikeRedirectPayloadSegment,
    setRedirectPayloadMode
  } = dependencies;

  return function parseFlexibleRedirectPayload(result, clean, helpers) {
  const firstSlash = clean.indexOf('/');
  if (firstSlash <= 0) return false;

  let payload = String(clean.slice(0, firstSlash) || '');
  let remainder = String(clean.slice(firstSlash + 1) || '');
  if (!payload || !remainder) return false;

  const finishWithEmail = (emailRaw, ignoredRaw, emailSegment, payloadOverride) => {
    finishFlexibleRedirectPayload(
      result,
      emailSegment === 'segment2' ? 'payload_email_ignored' : 'payload_ignored_email',
      payloadOverride || payload,
      emailRaw,
      ignoredRaw,
      emailSegment,
      helpers
    );
    return true;
  };

  let payloadDelimiterSearchEnd = payload.length;
  while (payloadDelimiterSearchEnd > 0) {
    const payloadDelimiter = findPreviousEmailDelimiter(payload, payloadDelimiterSearchEnd);
    if (!payloadDelimiter || payloadDelimiter.index <= 0) break;
    const payloadRaw = payload.slice(0, payloadDelimiter.index);
    const emailRaw = payload.slice(payloadDelimiter.index + payloadDelimiter.delimiter.length);
    const emailCandidate = detectEncodedEmailSegment(emailRaw, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
    if (emailCandidate.isEmail && isPartialRawEmailDelimiterSplit(payload, payloadDelimiter, emailRaw, helpers)) {
      payloadDelimiterSearchEnd = payloadDelimiter.index;
      continue;
    }
    if (emailCandidate.isEmail && looksLikeRedirectPayloadSegment(payloadRaw, helpers)) {
      return finishWithEmail(emailCandidate.raw, remainder, 'segment2', payloadRaw);
    }
    payloadDelimiterSearchEnd = payloadDelimiter.index;
  }

  const firstDelimiter = findNextEmailDelimiter(remainder, 0);
  if (firstDelimiter && firstDelimiter.index === 0) {
    const afterDelimiter = remainder.slice(firstDelimiter.delimiter.length);
    const slash = afterDelimiter.indexOf('/');
    if (slash > 0) {
      const emailRaw = afterDelimiter.slice(0, slash);
      const ignoredRaw = afterDelimiter.slice(slash + 1);
      const emailCandidate = detectEncodedEmailSegment(emailRaw, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
      if (emailCandidate.isEmail) return finishWithEmail(emailCandidate.raw, ignoredRaw, 'segment2');
    }
  }

  let remainderDelimiterSearchEnd = remainder.length;
  while (remainderDelimiterSearchEnd > 0) {
    const lastDelimiter = findPreviousEmailDelimiter(remainder, remainderDelimiterSearchEnd);
    if (!lastDelimiter || lastDelimiter.index <= 0) break;
    const ignoredRaw = remainder.slice(0, lastDelimiter.index);
    const emailRaw = remainder.slice(lastDelimiter.index + lastDelimiter.delimiter.length);
    const emailCandidate = detectEncodedEmailSegment(emailRaw, helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
    if (emailCandidate.isEmail && isPartialRawEmailDelimiterSplit(remainder, lastDelimiter, emailRaw, helpers)) {
      remainderDelimiterSearchEnd = lastDelimiter.index;
      continue;
    }
    if (emailCandidate.isEmail && !emailRaw.includes('/')) return finishWithEmail(emailCandidate.raw, ignoredRaw, 'segment3');
    remainderDelimiterSearchEnd = lastDelimiter.index;
  }

  const segments = remainder.split('/').filter(Boolean);
  if (segments.length >= 3) {
    const ignoredThenEmail = joinCollapsedUrlSegments(segments.slice(0, -1));
    if (ignoredThenEmail) {
      const emailCandidate = detectEncodedEmailSegment(segments[segments.length - 1], helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
      if (emailCandidate.isEmail) return finishWithEmail(emailCandidate.raw, ignoredThenEmail, 'segment3');
    }

    const emailThenIgnored = joinCollapsedUrlSegments(segments.slice(1));
    if (emailThenIgnored) {
      const emailCandidate = detectEncodedEmailSegment(segments[0], helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
      if (emailCandidate.isEmail) return finishWithEmail(emailCandidate.raw, emailThenIgnored, 'segment2');
    }
  }

  if (segments.length !== 1 && segments.length !== 2) {
    if (remainder.includes('://')) {
      finishFlexibleRedirectPayload(result, 'payload_ignored', payload, null, remainder, null, helpers);
      return true;
    }
    return false;
  }

  if (segments.length === 1) {
    finishFlexibleRedirectPayload(result, 'payload_ignored', payload, null, segments[0] || null, null, helpers);
    return true;
  }

  const candidate2 = detectEncodedEmailSegment(segments[0], helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
  const candidate3 = detectEncodedEmailSegment(segments[1], helpers.decodeBase64UrlLoose, helpers.decodeFallback, helpers.isValidEmail);
  if (candidate2.isEmail && candidate3.isEmail) {
    setRedirectPayloadMode(result, 'ambiguous_email_segments');
    result.matchedNewFormat = true;
    result.ambiguityDetected = true;
    result.ciphertext = payload;
    result.canonicalBaseString = null;
    result.normalizedBaseString = null;
    return true;
  }
  if (!candidate2.isEmail && !candidate3.isEmail) {
    finishFlexibleRedirectPayload(result, 'payload_ignored_no_email', payload, null, segments[0] || null, null, helpers);
    return true;
  }

  const emailCandidate = candidate2.isEmail ? candidate2 : candidate3;
  const ignoredSegment = candidate2.isEmail ? segments[1] : segments[0];
  const emailSegment = candidate2.isEmail ? 'segment2' : 'segment3';
  return finishWithEmail(emailCandidate.raw, ignoredSegment || null, emailSegment);
}
}

module.exports = createParseFlexibleRedirectPayload;
