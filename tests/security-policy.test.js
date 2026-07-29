'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const createSecurityPolicy = require('../modules/security-runtime/securityPolicy.js');

test('security policy uses injected country and ASN blocklists', () => {
  const previousSitekey = process.env.TURNSTILE_SITEKEY;
  const previousSecret = process.env.TURNSTILE_SECRET;
  process.env.TURNSTILE_SITEKEY = '12345678901234567890';
  process.env.TURNSTILE_SECRET = '12345678901234567890';

  try {
    const { countryBlocked, asnBlocked } = createSecurityPolicy({
      AES_KEYS: [Buffer.alloc(32, 7)],
      ADMIN_TOKEN: '1234567890123456',
      ALLOWED_COUNTRIES: ['US', 'CA'],
      ALLOWLIST_DOMAINS: [{ suffix: 'example.com', allowSubdomains: false }],
      BLOCKED_ASNS: ['AS64512'],
      BLOCKED_COUNTRIES: ['CA'],
      EXPECT_HOSTNAME_ENTRIES: [],
      EXPECT_HOSTNAME_INVALID_ENTRIES: [],
      EXPECT_HOSTNAME_PATTERNS: [],
      RATE_CAPACITY: 5,
      RATE_WINDOW_SECONDS: 600,
      safeZone: value => value
    });

    assert.equal(countryBlocked('US'), false);
    assert.equal(countryBlocked('CA'), true);
    assert.equal(countryBlocked('GB'), true);
    assert.equal(asnBlocked('AS64512'), true);
    assert.equal(asnBlocked('AS64513'), false);
  } finally {
    if (previousSitekey === undefined) delete process.env.TURNSTILE_SITEKEY;
    else process.env.TURNSTILE_SITEKEY = previousSitekey;
    if (previousSecret === undefined) delete process.env.TURNSTILE_SECRET;
    else process.env.TURNSTILE_SECRET = previousSecret;
  }
});
