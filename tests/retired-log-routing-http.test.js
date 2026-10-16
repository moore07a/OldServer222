'use strict';

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { randomBytes, createHmac } = require('node:crypto');
const { once } = require('node:events');
const fs = require('node:fs/promises');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

async function fixture(t, optionalPrefix) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'retired-log-routing-'));
  const socket = net.createServer();
  socket.listen(0, '127.0.0.1');
  await once(socket, 'listening');
  const { port } = socket.address();
  await new Promise((resolve, reject) => socket.close(error => error ? reject(error) : resolve()));
  const adminToken = randomBytes(32).toString('base64url');
  const child = spawn(process.execPath, ['server.js'], {
    cwd: path.resolve(__dirname, '..'),
    // Each fixture has generated credentials and no inherited Redis bindings.
    env: {
      PATH: process.env.PATH,
      NODE_ENV: 'development', PORT: String(port),
      AES_KEY_HEX: randomBytes(32).toString('hex'), ADMIN_TOKEN: adminToken,
      TURNSTILE_SITEKEY: '1x00000000000000000000AA',
      TURNSTILE_SECRET: '1x0000000000000000000000000000000AA',
      ALLOWLIST_DOMAINS: 'example.com', REQUIRE_CF_HEADERS: 'false',
      OPTIONAL_URL_PREFIX: optionalPrefix, RATE_LIMIT_MAX_REQUESTS: '1000',
      CHALLENGE_VIEW_CAPACITY: '100', DEBUG_SHOW_KEYS_ON_START: '0',
      DEBUG_ALLOW_PLAINTEXT_KEYS: '0', LOG_TO_FILE: '0',
      LOG_FILE: path.join(directory, 'visitors.log'),
      RUNTIME_DIAG_DIR: directory, NPM_CONFIG_LOGS_DIR: directory,
      PUBLIC_ENABLE_BACKGROUND: '0', IPINFO_LITE_ENABLED: '0',
      REDIS_URL: '', REDIS_PRIVATE_URL: '', TRAFFIC_METRICS_REDIS_URL: '',
      eSCANNER_CONFIG_URL: '', SHUTDOWN_GRACE_MS: '1000'
    },
    stdio: ['ignore', 'ignore', 'ignore']
  });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit');
      child.kill('SIGTERM');
      const deadline = setTimeout(() => child.kill('SIGKILL'), 5000);
      try { await exited; } finally { clearTimeout(deadline); }
    }
    await fs.rm(directory, { recursive: true, force: true });
  });
  await once(child, 'spawn');
  async function request(route, options = {}) {
    const response = await fetch(`http://127.0.0.1:${port}${route}`, {
      ...options, redirect: 'manual', signal: AbortSignal.timeout(5000)
    });
    return { response, text: await response.text() };
  }
  for (let attempt = 0; ; attempt++) {
    assert.equal(child.exitCode, null, 'fixture server exited during startup');
    assert.equal(child.signalCode, null, 'fixture server was signalled during startup');
    try { if ((await request('/livez')).response.status === 200) break; } catch {}
    if (attempt === 79) throw new Error('Fixture server did not become live');
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  const authenticated = { headers: { authorization: `Bearer ${adminToken}` } };
  async function metrics() {
    const result = await request('/admin/traffic-metrics', authenticated);
    assert.equal(result.response.status, 200);
    return JSON.parse(result.text);
  }
  return { request, authenticated, adminToken, metrics };
}

for (const optionalPrefix of ['', 'CaMpAiGn/Nested', 'view-log', 'View-Log/nested', 'stream-log', 'view-log-live']) {
  test(`retired log routing preserves active routes with prefix ${optionalPrefix || '(none)'}`, { timeout: 30000 }, async t => {
    const { request, authenticated, adminToken, metrics } = await fixture(t, optionalPrefix);
    const prefixPath = optionalPrefix ? `/${optionalPrefix}` : '';
    const activePrefixes = [...new Set(['', prefixPath])];

    for (const prefix of activePrefixes) {
      for (const healthPath of ['/health', '/readyz', '/healthz', '/livez']) {
        const result = await request(`${prefix}${healthPath}`);
        const readiness = healthPath === '/health' || healthPath === '/readyz';
        assert.ok((readiness ? [200, 503] : [200]).includes(result.response.status), `${prefix}${healthPath} remains available`);
        const body = JSON.parse(result.text);
        assert.equal(body.ok, result.response.status === 200);
        if (healthPath === '/livez') assert.equal(typeof body.ts, 'number');
        else {
          assert.equal(typeof body.stats.cpu.processPercent, 'number');
          assert.ok(body.stats.memory.rssMb > 0);
          if (readiness) assert.ok(Object.hasOwn(body.checks.turnstile, 'lastHeartbeat'));
        }
      }
      const panel = await request(`${prefix}/admin/traffic-panel`);
      assert.equal(panel.response.status, 200, 'active panel shell survives a retired-name prefix');
      assert.ok(panel.text.includes(`data-metrics-url="${prefixPath}/admin/traffic-metrics"`));
      const script = await request(`${prefix}/admin/traffic-panel.js`);
      assert.equal(script.response.status, 200);
      assert.match(script.response.headers.get('content-type') || '', /javascript/);
      assert.match(script.text, /function createTrafficPanelController/);

      const metricsPath = `${prefix}/admin/traffic-metrics`;
      assert.equal((await request(metricsPath)).response.status, 401);
      assert.equal((await request(`${metricsPath}?token=${encodeURIComponent(adminToken)}`)).response.status, 401, 'query credentials cannot authenticate metrics');
      assert.equal((await request(metricsPath, { headers: { authorization: 'Bearer invalid-token' } })).response.status, 401);
      const privateReport = await request(metricsPath, authenticated);
      assert.equal(privateReport.response.status, 200);
      assert.equal(JSON.parse(privateReport.text).ok, true);
    }

    const beforeRetired = await metrics();
    const retiredPaths = new Set();
    // Bare old names remain retired even when a configured namespace overlaps.
    for (const route of ['/VIEW-LOG', '/View-Log-Live', '/StReAm-LoG']) {
      retiredPaths.add(route);
      retiredPaths.add(`${route}/`);
    }
    const comparisonPrefixes = [...new Set([prefixPath, prefixPath.toLowerCase(), prefixPath.toUpperCase()])];
    for (const prefix of comparisonPrefixes) {
      for (const route of ['/VIEW-LOG', '/View-Log-Live', '/StReAm-LoG']) {
        for (const suffix of ['', '/', '/ChIlD']) retiredPaths.add(`${prefix}${route}${suffix}`);
      }
    }
    for (const retiredPath of retiredPaths) {
      for (const method of ['GET', 'HEAD', 'POST', 'OPTIONS']) {
        const headers = { origin: 'https://external.example' };
        if (method === 'POST') headers['content-type'] = 'application/json';
        const retired = await request(`${retiredPath}?token=retired-token-marker`, {
          method, headers, ...(method === 'POST' ? { body: '{' } : {})
        });
        assert.equal(retired.response.status, 404, `${method} ${retiredPath} is rejected before parsing and CORS`);
        assert.equal(retired.response.headers.get('location'), null);
        assert.equal(retired.response.headers.get('link'), null);
        assert.equal(retired.response.headers.get('access-control-allow-origin'), null);
        assert.doesNotMatch(retired.response.headers.get('content-type') || '', /event-stream/);
        assert.doesNotMatch(retired.text, /retired-token-marker|event-stream|traffic-panel/);
        if (method === 'HEAD') assert.equal(retired.text, '');
      }
    }
    const afterRetired = await metrics();
    for (const kind of ['get', 'head', 'prefetch', 'other']) {
      assert.deepEqual(afterRetired.byKind[kind], beforeRetired.byKind[kind], 'mixed-case retired requests remain operational');
    }
    assert.equal(afterRetired.byKind.operational.requests - beforeRetired.byKind.operational.requests, retiredPaths.size * 4 + 1);
    assert.deepEqual(afterRetired.challenges, beforeRetired.challenges);

    // An active route inside the configured namespace must retain visitor classification.
    const visitor = await request(`${prefixPath}/r`);
    assert.equal(visitor.response.status, 400, 'the active redirect route receives its normal missing-parameter response');
    const afterVisitor = await metrics();
    assert.equal(afterVisitor.byKind.get.requests, afterRetired.byKind.get.requests + 1);
    assert.equal(afterVisitor.byKind.get.completed, afterRetired.byKind.get.completed + 1);

    // Authentication of this opaque mixed-case token fails if routing lowercases the URL.
    const body = Buffer.from(JSON.stringify({ next: '/r?d=MiXeD-Destination', ts: Date.now(), exp: Date.now() + 60000 })).toString('base64url');
    const challengeToken = `${body}.${createHmac('sha256', adminToken).update(body).digest('base64url')}`;
    assert.match(challengeToken, /[A-Z]/);
    assert.match(challengeToken, /[a-z]/);
    for (const prefix of activePrefixes) {
      const challenge = await request(`${prefix}/challenge?ct=${encodeURIComponent(challengeToken)}`);
      assert.equal(challenge.response.status, 200, 'signed mixed-case challenge links survive route comparison');
      assert.ok(challenge.text.includes(challengeToken), 'the signed token reaches the challenge page unchanged');
    }
  });
}
