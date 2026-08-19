'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function loadGeoHelpers(env = {}, options = {}) {
  const source = fs.readFileSync('modules/client-security/clientGeo.js', 'utf8');
  const start = source.indexOf('function parseIpAddress(');
  const end = source.indexOf('\nfunction getCountryResolution', start);
  if (start < 0 || end < 0 || end <= start) {
    throw new Error('Could not locate geo helper region in server.js');
  }

  const snippet = `
    const TRUST_UPSTREAM_GEO_HEADERS = false;
    const trustProxyEffective = ${JSON.stringify(options.trustProxyEffective === undefined ? 1 : options.trustProxyEffective)};
    const TRUST_CLOUDFLARE_XFF_CHAIN = process.env.TRUST_CLOUDFLARE_XFF_CHAIN === "1";
    const FORWARDER_AUTH_HEADER = "x-mds-forwarder-auth";
    const MDS_FORWARDER_AUTH_SECRET = String(
      process.env.MDS_FORWARDER_AUTH_SECRET || process.env.TRUSTED_FORWARDER_AUTH_SECRET || ""
    ).trim();
    ${source.slice(start, end)}
    this.__loaded = {
      isCloudflareEdgeIp,
      hasCloudflareGeoProvenance,
      canTrustGeoCountryHeader,
      getClientIp,
      getDenyCacheIp,
      getRequestIdentity
    };
  `;
  const sandbox = { process: { env }, BigInt, Number, String, Boolean, RegExp };
  vm.createContext(sandbox);
  vm.runInContext(snippet, sandbox);
  return sandbox.__loaded;
}

test('request identity keeps response-affecting keys on the direct peer when proxy headers are untrusted', () => {
  const { getRequestIdentity } = loadGeoHelpers({}, { trustProxyEffective: false });
  const req = makeReq('198.51.100.20', {
    'cf-ipcountry': undefined,
    'cf-connecting-ip': undefined,
    'cf-ray': undefined,
    'x-forwarded-for': '203.0.113.99'
  });

  const identity = getRequestIdentity(req);
  assert.equal(identity.displayIp, '203.0.113.99');
  assert.equal(identity.keyIp, '198.51.100.20');
});

function makeReq(remoteAddress, headers = {}) {
  return {
    ip: remoteAddress,
    socket: { remoteAddress },
    connection: { remoteAddress },
    headers: {
      'cf-ipcountry': 'US',
      'cf-connecting-ip': '203.0.113.10',
      'cf-ray': 'test-ray',
      ...headers
    }
  };
}

test('Cloudflare geo provenance trusts direct Cloudflare edge peers', () => {
  const { isCloudflareEdgeIp, hasCloudflareGeoProvenance, canTrustGeoCountryHeader } = loadGeoHelpers();

  assert.equal(isCloudflareEdgeIp('162.158.1.1'), true);
  assert.equal(hasCloudflareGeoProvenance(makeReq('162.158.1.1')), true);
  assert.equal(canTrustGeoCountryHeader(makeReq('162.158.1.1'), 'cf-ipcountry', 'cloudflare'), true);
});


test('Cloudflare geo provenance accepts cf-edge-country without cf-ipcountry', () => {
  const { hasCloudflareGeoProvenance, canTrustGeoCountryHeader } = loadGeoHelpers();
  const req = makeReq('162.158.1.1', {
    'cf-ipcountry': undefined,
    'cf-edge-country': 'US'
  });

  assert.equal(hasCloudflareGeoProvenance(req), true);
  assert.equal(canTrustGeoCountryHeader(req, 'cf-edge-country', 'cloudflare'), true);
});



test('Cloudflare geo provenance rejects managed-platform source headers as Cloudflare proof', () => {
  const { hasCloudflareGeoProvenance, canTrustGeoCountryHeader } = loadGeoHelpers({ RAILWAY: '1' });
  const req = makeReq('203.0.113.20', { 'x-railway-ip': '203.0.113.10' });

  assert.equal(hasCloudflareGeoProvenance(req), false);
  assert.equal(canTrustGeoCountryHeader(req, 'cf-ipcountry', 'cloudflare'), false);
});

test('Cloudflare geo provenance rejects managed-platform env without request proof', () => {
  const { hasCloudflareGeoProvenance, canTrustGeoCountryHeader } = loadGeoHelpers({ RAILWAY: '1' });
  const req = makeReq('203.0.113.20');

  assert.equal(hasCloudflareGeoProvenance(req), false);
  assert.equal(canTrustGeoCountryHeader(req, 'cf-ipcountry', 'cloudflare'), false);
});


test('Cloudflare geo provenance trusts authenticated forwarder on managed platforms', () => {
  const { hasCloudflareGeoProvenance, canTrustGeoCountryHeader } = loadGeoHelpers({
    RAILWAY: '1',
    MDS_FORWARDER_AUTH_SECRET: 'secret-123'
  });
  const req = makeReq('10.250.11.6', {
    'x-railway-ip': '166.88.2.99',
    'x-mds-forwarder-auth': 'secret-123'
  });

  assert.equal(hasCloudflareGeoProvenance(req), true);
  assert.equal(canTrustGeoCountryHeader(req, 'cf-ipcountry', 'cloudflare'), true);
});

test('Cloudflare geo provenance rejects wrong authenticated forwarder secret', () => {
  const { hasCloudflareGeoProvenance, canTrustGeoCountryHeader } = loadGeoHelpers({
    RAILWAY: '1',
    MDS_FORWARDER_AUTH_SECRET: 'secret-123'
  });
  const req = makeReq('10.250.11.6', {
    'x-railway-ip': '166.88.2.99',
    'x-mds-forwarder-auth': 'wrong-secret'
  });

  assert.equal(hasCloudflareGeoProvenance(req), false);
  assert.equal(canTrustGeoCountryHeader(req, 'cf-ipcountry', 'cloudflare'), false);
});

test('Cloudflare geo provenance rejects spoofed direct non-Cloudflare peers', () => {
  const { isCloudflareEdgeIp, hasCloudflareGeoProvenance, canTrustGeoCountryHeader } = loadGeoHelpers();

  assert.equal(isCloudflareEdgeIp('8.8.8.8'), false);
  assert.equal(hasCloudflareGeoProvenance(makeReq('8.8.8.8')), false);
  assert.equal(canTrustGeoCountryHeader(makeReq('8.8.8.8'), 'cf-ipcountry', 'cloudflare'), false);
});

test('Cloudflare edge detection includes IPv6 ranges', () => {
  const { isCloudflareEdgeIp } = loadGeoHelpers();

  assert.equal(isCloudflareEdgeIp('2606:4700::6810:85e5'), true);
  assert.equal(isCloudflareEdgeIp('2001:4860:4860::8888'), false);
});


test('client IP trusts cf-connecting-ip for direct Cloudflare edge peers only', () => {
  const { getClientIp } = loadGeoHelpers();

  assert.equal(getClientIp(makeReq('162.158.1.1')), '203.0.113.10');
  assert.equal(getClientIp(makeReq('8.8.8.8')), '8.8.8.8');
});


test('client IP prefers Cloudflare visitor IP when a local trusted proxy proves the Cloudflare edge', () => {
  const { getClientIp } = loadGeoHelpers({ TRUST_CLOUDFLARE_XFF_CHAIN: '1' });
  const req = makeReq('10.250.11.6', {
    'x-forwarded-for': '203.0.113.10, 162.158.1.1'
  });

  assert.equal(getClientIp(req), '203.0.113.10');
});

test('client IP rejects spoofed Cloudflare XFF chains through managed platforms', () => {
  const { getClientIp } = loadGeoHelpers({ RAILWAY: '1', TRUST_CLOUDFLARE_XFF_CHAIN: '1' });
  const req = makeReq('10.250.11.6', {
    'x-railway-ip': '166.88.2.99',
    'x-forwarded-for': '203.0.113.10, 162.158.1.1'
  });

  assert.equal(getClientIp(req), '166.88.2.99');
});

test('client IP accepts Cloudflare XFF through managed platforms with authenticated forwarder secret', () => {
  const { getClientIp, getDenyCacheIp } = loadGeoHelpers({
    RAILWAY: '1',
    TRUST_CLOUDFLARE_XFF_CHAIN: '1',
    MDS_FORWARDER_AUTH_SECRET: 'secret-123'
  });
  const req = makeReq('10.250.11.6', {
    'x-railway-ip': '166.88.2.99',
    'x-mds-forwarder-auth': 'secret-123',
    'x-forwarded-for': '203.0.113.10, 162.158.1.1'
  });

  assert.equal(getClientIp(req), '203.0.113.10');
  assert.equal(getDenyCacheIp(req), '203.0.113.10');
});

test('client IP accepts authenticated forwarder Cloudflare IP when XFF is platform-rewritten', () => {
  const { getClientIp, getDenyCacheIp } = loadGeoHelpers({
    RAILWAY: '1',
    TRUST_CLOUDFLARE_XFF_CHAIN: '1',
    MDS_FORWARDER_AUTH_SECRET: 'secret-123'
  });
  const req = makeReq('10.250.11.6', {
    'x-railway-ip': '166.88.2.99',
    'x-mds-forwarder-auth': 'secret-123',
    'x-forwarded-for': '166.88.2.99, 84.17.44.225'
  });

  assert.equal(getClientIp(req), '203.0.113.10');
  assert.equal(getDenyCacheIp(req), '203.0.113.10');
});

test('client IP rejects authenticated-forwarder attempts with the wrong secret', () => {
  const { getClientIp } = loadGeoHelpers({
    RAILWAY: '1',
    TRUST_CLOUDFLARE_XFF_CHAIN: '1',
    MDS_FORWARDER_AUTH_SECRET: 'secret-123'
  });
  const req = makeReq('10.250.11.6', {
    'x-railway-ip': '166.88.2.99',
    'x-mds-forwarder-auth': 'wrong-secret',
    'x-forwarded-for': '203.0.113.10, 162.158.1.1'
  });

  assert.equal(getClientIp(req), '166.88.2.99');
});

test('client IP keeps Railway source IP when forwarded chain trust is disabled', () => {
  const { getClientIp } = loadGeoHelpers();
  const req = makeReq('10.250.11.6', {
    'x-railway-ip': '166.88.2.99',
    'x-forwarded-for': '203.0.113.10, 162.158.1.1'
  });

  assert.equal(getClientIp(req), '166.88.2.99');
});


test('deny cache IP uses Cloudflare visitor even when Express trusted hop is edge', () => {
  const { getDenyCacheIp } = loadGeoHelpers({ TRUST_CLOUDFLARE_XFF_CHAIN: '1' });
  const req = makeReq('162.158.1.1', {
    'x-forwarded-for': '203.0.113.10, 162.158.1.1'
  });
  req.ip = '162.158.1.1';

  assert.equal(getDenyCacheIp(req), '203.0.113.10');
});


test('client IP keeps Railway source IP when trusted forwarded chain lacks Cloudflare edge proof', () => {
  const { getClientIp } = loadGeoHelpers({ TRUST_CLOUDFLARE_XFF_CHAIN: '1' });
  const req = makeReq('10.250.11.6', {
    'x-railway-ip': '166.88.2.99',
    'x-forwarded-for': '203.0.113.10, 198.51.100.9'
  });

  assert.equal(getClientIp(req), '166.88.2.99');
});
