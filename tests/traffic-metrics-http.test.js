'use strict';

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { randomBytes, createHmac, createCipheriv } = require('node:crypto');
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
  const aesKey = randomBytes(32);
  const baseUrl = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, ['-e', `
    const originalCpuUsage = process.cpuUsage;
    let cpuUsageReads = 0;
    process.cpuUsage = (...args) => {
      cpuUsageReads += 1;
      return originalCpuUsage(...args);
    };
    process.on('message', message => {
      if (message === 'test:cpu-usage-reads') process.send({ cpuUsageReads });
    });
    require('./server.js');
  `], {
    cwd: path.resolve(__dirname, '..'),
    env: {
      ...process.env,
      NODE_ENV: 'development',
      PORT: String(port),
      AES_KEY_HEX: aesKey.toString('hex'),
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
      CHALLENGE_VIEW_CAPACITY: '100',
      LOG_TO_FILE: '0',
      RUNTIME_DIAG_DIR: directory,
      IPINFO_LITE_ENABLED: '0',
      REDIS_URL: '',
      REDIS_PRIVATE_URL: '',
      TRAFFIC_METRICS_REDIS_URL: '',
      eSCANNER_CONFIG_URL: ''
    },
    stdio: ['ignore', 'ignore', 'ignore', 'ipc']
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
  assert.equal(before.shared, null);
  assert.equal(before.storage.configured, false);
  assert.ok(Object.values(before.challenges).every(value => value === 0));

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

  for (const prefix of ['', '/campaign']) {
    for (const route of ['/ads.txt', '/.well-known/security.txt']) {
      const result = await request(`${prefix}${route}?source=metrics-review`);
      assert.equal(result.response.status, 200, `${prefix}${route} serves utility content`);
    }
  }
  const utilitiesResult = await request('/admin/traffic-metrics', authenticated);
  assert.equal(utilitiesResult.response.status, 200);
  const utilities = JSON.parse(utilitiesResult.text);
  for (const kind of ['get', 'head', 'prefetch', 'other']) {
    assert.deepEqual(utilities.byKind[kind], after.byKind[kind], `${kind} metrics exclude utility requests`);
  }
  // Four utility requests and this operational metrics request were started.
  assert.equal(utilities.byKind.operational.requests - after.byKind.operational.requests, 5);
  assert.equal(utilities.byKind.operational.completed - after.byKind.operational.completed, 5);

  const tokenBody = Buffer.from(JSON.stringify({ next: '/r?d=fixture', ts: Date.now(), exp: Date.now() + 60000 })).toString('base64url');
  const ct = `${tokenBody}.${createHmac('sha256', adminToken).update(tokenBody).digest('base64url')}`;
  const fragment = await request('/campaign/challenge-fragment', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ct })
  });
  assert.equal(fragment.response.status, 200);
  await request(`/challenge-fragment?ct=${encodeURIComponent(ct)}`, { method: 'HEAD' });
  assert.equal((await request('/challenge-fragment?ct=invalid')).response.status, 400);

  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', aesKey, iv);
  const expired = Buffer.concat([iv, cipher.update(JSON.stringify({ ts: Date.now() - 360000 }), 'utf8'), cipher.final(), cipher.getAuthTag()]).toString('base64url');
  const expiredResult = await request('/campaign/decrypt-challenge-data', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ data: expired })
  });
  assert.equal(JSON.parse(expiredResult.text).error, 'Payload expired');
  const beforeRetirementChecks = JSON.parse((await request('/admin/traffic-metrics', authenticated)).text);
  const outcomes = beforeRetirementChecks.challenges;
  assert.equal(outcomes.shown, 1, 'the fragment POST counts once; HEAD and rejected requests do not');
  assert.equal(outcomes.payloadExpired, 1);
  assert.equal(outcomes.passed, 0);
  assert.equal(outcomes.redirected, 0);

  for (const prefix of ['', '/campaign']) {
    const panel = await request(`${prefix}/admin/traffic-panel`);
    assert.equal(panel.response.status, 200, 'the panel login shell is available without exposing metrics');
    assert.match(panel.response.headers.get('cache-control'), /no-store/);
    assert.match(panel.text, /type="password"/);
    assert.match(panel.text, /data-metrics-url="\/campaign\/admin\/traffic-metrics"/);
    const nonce = panel.text.match(/<style nonce="([^"]+)"/)[1];
    const csp = panel.response.headers.get('content-security-policy');
    assert.ok(csp.includes(`style-src 'nonce-${nonce}'`));
    assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
    assert.doesNotMatch(panel.text, new RegExp(adminToken));

    const script = await request(`${prefix}/admin/traffic-panel.js`);
    assert.equal(script.response.status, 200);
    assert.match(script.response.headers.get('content-type'), /javascript/);
    assert.match(script.text, /function createTrafficPanelController/);
    assert.doesNotMatch(script.text, /EventSource|localStorage|sessionStorage/);

    for (const legacy of ['/view-log', '/view-log-live', '/stream-log']) {
      for (const suffix of ['', '/', '/child']) {
        for (const method of ['GET', 'HEAD', 'POST', 'OPTIONS']) {
          const route = `${prefix}${legacy}${suffix}?token=legacy-secret`;
          const headers = { origin: 'https://external.example' };
          if (method === 'POST') headers['content-type'] = 'application/json';
          const retired = await request(route, { method, headers, ...(method === 'POST' ? { body: '{' } : {}) });
          assert.equal(retired.response.status, 404, `${method} ${route} is retired before parsing or CORS`);
          assert.equal(retired.response.headers.get('location'), null);
          assert.equal(retired.response.headers.get('link'), null);
          assert.equal(retired.response.headers.get('access-control-allow-origin'), null);
          assert.doesNotMatch(retired.response.headers.get('content-type') || '', /event-stream/);
          assert.doesNotMatch(retired.text, /legacy-secret|event-stream|traffic-panel/);
          if (method === 'HEAD') assert.equal(retired.text, '');
        }
      }
    }
  }
  assert.equal((await request('/admin/traffic-metrics?token=legacy-secret')).response.status, 401);
  const afterRetirementChecks = JSON.parse((await request('/admin/traffic-metrics', authenticated)).text);
  for (const kind of ['get', 'head', 'prefetch', 'other']) {
    assert.deepEqual(afterRetirementChecks.byKind[kind], beforeRetirementChecks.byKind[kind], 'retired paths never count as visitor traffic');
  }
  assert.deepEqual(afterRetirementChecks.challenges, outcomes, 'retired paths never enter challenge or destination handling');
  const resources = afterRetirementChecks.runtime;
  assert.ok(resources.memory.rssMb > 0);
  assert.ok(resources.memory.heapUsedMb > 0);
  assert.equal(resources.resources.sseListeners, 0);

  async function cpuUsageReads() {
    const reply = once(child, 'message');
    child.send('test:cpu-usage-reads');
    return (await reply)[0].cpuUsageReads;
  }
  let cpuReads = await cpuUsageReads();
  for (const route of ['/admin/traffic-metrics', '/campaign/admin/traffic-metrics']) {
    const result = await request(route, authenticated);
    assert.equal(result.response.status, 200);
    const memory = JSON.parse(result.text).runtime.memory;
    assert.deepEqual(Object.keys(memory).sort(), ['arrayBuffersMb', 'externalMb', 'heapTotalMb', 'heapUsedMb', 'rssMb']);
    assert.equal(await cpuUsageReads(), cpuReads, 'panel memory reads must not advance health CPU sampling');
  }
  // Readiness may report 503 before the provider heartbeat succeeds; it still
  // samples CPU. Both liveness routes remain independent of provider availability.
  for (const prefix of ['', '/campaign']) {
    for (const healthPath of ['/health', '/readyz', '/healthz', '/livez']) {
      const route = `${prefix}${healthPath}`;
      const result = await request(route);
      const readiness = healthPath === '/health' || healthPath === '/readyz';
      assert.ok((readiness ? [200, 503] : [200]).includes(result.response.status), `${route} keeps its existing health status`);
      const body = JSON.parse(result.text);
      assert.equal(body.ok, result.response.status === 200);
      if (healthPath === '/livez') {
        assert.equal(typeof body.ts, 'number');
        assert.equal(await cpuUsageReads(), cpuReads, 'minimal liveness does not sample CPU');
      } else {
        assert.equal(typeof body.stats.cpu.processPercent, 'number');
        assert.ok(body.stats.memory.rssMb > 0);
        assert.equal(body.stats.resources.sseListeners, 0);
        assert.equal(typeof body.uptimeSec, 'number');
        if (readiness) {
          assert.equal(typeof body.checks.turnstile.okStreak, 'number');
          assert.ok(Object.hasOwn(body.checks.turnstile, 'lastHeartbeat'));
        } else assert.equal(typeof body.ts, 'number');
        assert.equal(await cpuUsageReads(), ++cpuReads, 'health checks must continue taking CPU samples');
      }
    }
  }
});
