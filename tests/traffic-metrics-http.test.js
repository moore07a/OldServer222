'use strict';

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const { once } = require('node:events');
const fs = require('node:fs/promises');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

async function availablePort() {
  const socket = net.createServer();
  socket.listen(0, '127.0.0.1');
  await once(socket, 'listening');
  const { port } = socket.address();
  await new Promise((resolve, reject) => socket.close(error => error ? reject(error) : resolve()));
  return port;
}

test('private traffic metrics include early responses and separate HTTP request kinds', { timeout: 30000 }, async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'traffic-metrics-http-'));
  const port = await availablePort();
  const adminToken = randomBytes(24).toString('base64url');
  const baseUrl = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, ['server.js'], {
    cwd: path.resolve(__dirname, '..'),
    env: {
      ...process.env,
      NODE_ENV: 'development',
      PORT: String(port),
      AES_KEY_HEX: randomBytes(32).toString('hex'),
      AES_KEY: '',
      AES_KEYS: '',
      AES_KEY_SHA256: '',
      ADMIN_TOKEN: adminToken,
      DEBUG_SHOW_KEYS_ON_START: '0',
      DEBUG_ALLOW_PLAINTEXT_KEYS: '0',
      TURNSTILE_SITEKEY: '1x00000000000000000000AA',
      TURNSTILE_SECRET: '1x0000000000000000000000000000000AA',
      TURNSTILE_EXPECT_HOSTNAME: '',
      ALLOWLIST_DOMAINS: 'example.com',
      REQUIRE_CF_HEADERS: 'false',
      OPTIONAL_URL_PREFIX: 'campaign',
      RATE_LIMIT_MAX_REQUESTS: '1000',
      LOG_TO_FILE: '0',
      RUNTIME_DIAG_DIR: directory,
      IPINFO_LITE_ENABLED: '0',
      REDIS_URL: '',
      REDIS_PRIVATE_URL: '',
      eSCANNER_CONFIG_URL: ''
    },
    stdio: ['ignore', 'ignore', 'ignore']
  });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit');
      child.kill('SIGTERM');
      await exited;
    }
    await fs.rm(directory, { recursive: true, force: true });
  });
  await once(child, 'spawn');

  async function request(route, options = {}) {
    const response = await fetch(baseUrl + route, {
      ...options,
      redirect: 'manual',
      signal: AbortSignal.timeout(5000)
    });
    const text = await response.text();
    return { response, text };
  }

  for (let attempt = 0; ; attempt++) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error('Server exited before becoming ready');
    try {
      if ((await request('/livez')).response.status === 200) break;
    } catch {}
    if (attempt === 79) throw new Error('Server did not start');
    await new Promise(resolve => setTimeout(resolve, 100));
  }

  for (const route of ['/admin/traffic-metrics', '/campaign/admin/traffic-metrics']) {
    assert.equal((await request(route)).response.status, 401, 'metrics require bearer authentication');
  }
  const authenticated = { headers: { authorization: `Bearer ${adminToken}` } };
  const beforeResult = await request('/admin/traffic-metrics', authenticated);
  assert.equal(beforeResult.response.status, 200);
  assert.match(beforeResult.response.headers.get('cache-control'), /no-store/);
  const before = JSON.parse(beforeResult.text);
  assert.equal(before.ok, true);
  assert.equal(before.scope, 'current_process');

  assert.equal((await request('/.git/config')).response.status, 404, 'early probe denial executes');
  assert.equal((await request('/r?tracking=private-value')).response.status, 400);
  await request('/r', { method: 'HEAD' });
  await request('/r', { headers: { 'sec-purpose': 'prefetch;prerender' } });
  await request('/r', { method: 'POST' });
  assert.equal((await request('/campaign/livez')).response.status, 200);

  const afterResult = await request('/campaign/admin/traffic-metrics', authenticated);
  assert.equal(afterResult.response.status, 200, 'optional prefix supports the same authenticated endpoint');
  const after = JSON.parse(afterResult.text);
  for (const [kind, count] of Object.entries({ get: 2, head: 1, prefetch: 1, other: 1, operational: 2 })) {
    assert.equal(after.byKind[kind].requests - before.byKind[kind].requests, count, kind);
  }
  assert.equal(after.byKind.get.completed - before.byKind.get.completed, 2);
  assert.equal(after.byKind.get.byStatusClass['4xx'] - before.byKind.get.byStatusClass['4xx'], 2);
  assert.equal(after.total.requests - before.total.requests, 7);
  assert.equal(after.byKind.get.inFlight, 0);
  assert.equal(after.byKind.get.aborted, 0);
  assert.ok(after.byKind.get.latencyMs.recent.sampleCount >= 2);
  assert.doesNotMatch(afterResult.text, /private-value|\.git\/config|tracking=/, 'aggregates do not retain request paths or parameters');
});
