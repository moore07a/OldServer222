'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function loadIpinfoHelpers() {
  const source = fs.readFileSync('server.js', 'utf8');
  const start = source.indexOf('function normalizeAsn(');
  const end = source.indexOf('\nfunction pruneIpinfoLiteCache', start);
  if (start < 0 || end < 0 || end <= start) {
    throw new Error('Could not locate IPinfo helper region in server.js');
  }

  const snippet = `
    ${source.slice(start, end)}
    this.__loaded = { normalizeAsn, normalizeIpinfoLitePayload };
  `;
  const sandbox = { String };
  vm.createContext(sandbox);
  vm.runInContext(snippet, sandbox);
  return sandbox.__loaded;
}

test('normalizes IPinfo ASN values to AS-prefixed strings', () => {
  const { normalizeAsn } = loadIpinfoHelpers();

  assert.equal(normalizeAsn('15169'), 'AS15169');
  assert.equal(normalizeAsn('AS15169'), 'AS15169');
  assert.equal(normalizeAsn('as 15169'), 'AS15169');
  assert.equal(normalizeAsn(''), null);
});

test('normalizes IPinfo Lite payload country and ASN fields', () => {
  const { normalizeIpinfoLitePayload } = loadIpinfoHelpers();

  assert.deepEqual(JSON.parse(JSON.stringify(normalizeIpinfoLitePayload({
    country_code: 'us',
    asn: '15169',
    as_name: 'Google LLC',
    as_domain: 'google.com'
  }))), {
    country: 'US',
    asn: 'AS15169',
    asName: 'Google LLC',
    asDomain: 'google.com',
    source: 'ipinfo-lite'
  });

  assert.equal(normalizeIpinfoLitePayload({}), null);
});
