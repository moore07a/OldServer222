#!/usr/bin/env node
'use strict';

/*
 * Starts an isolated real server and exercises HTTP polling alongside mixed
 * traffic, deliberate disconnects, and slow readers. No production URL or
 * credentials are accepted. This is a bounded local reliability check, not a
 * proof of long-term memory stability or production proxy behaviour.
 *
 * node tests/traffic-panel-soak.js --duration-sec 300 --rps 30 --panels 3 \
 *   --output /tmp/traffic-panel-soak.json
 * Optional shared store: set TRAFFIC_METRICS_TEST_REDIS_URL in the environment.
 * A supplied Redis URL is never included in output. Use a dedicated test DB.
 */

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { randomBytes, createHmac } = require('node:crypto');
const { once } = require('node:events');
const fs = require('node:fs/promises');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { performance } = require('node:perf_hooks');

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const round = value => Number(value.toFixed(3));
const boundedPush = (values, value, limit) => {
  if (values.length >= limit) values.shift();
  values.push(value);
};

function options(argv) {
  const out = { durationSec: 300, rps: 30, concurrency: 8, panels: 3, timeoutMs: 5000, redisOutageSec: 0, output: null, smoke: false };
  const keys = { '--duration-sec': 'durationSec', '--rps': 'rps', '--concurrency': 'concurrency', '--panels': 'panels', '--timeout-ms': 'timeoutMs', '--redis-outage-sec': 'redisOutageSec' };
  for (let index = 0; index < argv.length; index++) {
    const key = argv[index];
    if (key === '--smoke') { out.smoke = true; continue; }
    if (key === '--output') { out.output = path.resolve(argv[++index]); continue; }
    if (!keys[key]) throw new Error(`Unknown option: ${key}`);
    const value = Number(argv[++index]);
    if (!Number.isFinite(value) || value <= 0) throw new Error(`Invalid numeric option: ${key}`);
    out[keys[key]] = value;
  }
  for (const key of ['durationSec', 'rps', 'concurrency', 'panels', 'timeoutMs']) {
    out[key] = Math.floor(out[key]);
    if (out[key] < 1) throw new Error(`Option must be at least one: ${key}`);
  }
  if (out.durationSec < (out.smoke ? 1 : 180)) throw new Error('Use at least 180 seconds, or --smoke for a startup-only debugging run');
  if (out.concurrency > 128 || out.panels > 32 || out.rps > 1000 || out.durationSec > 86400) throw new Error('Requested load exceeds local safety limits');
  if (out.redisOutageSec && (out.redisOutageSec < 5 || out.redisOutageSec > out.durationSec / 3)) throw new Error('Redis outage must be 5 seconds or more and at most one third of the run');
  return out;
}

async function redisFaultProxy(redisUrl) {
  const target = new URL(redisUrl);
  if (target.protocol !== 'redis:' || !['127.0.0.1', 'localhost', '[::1]'].includes(target.hostname)) {
    throw new Error('Fault injection requires an isolated local Redis fixture');
  }
  const upstreamHost = target.hostname.replace(/^\[|\]$/g, '');
  const upstreamPort = Number(target.port || 6379);
  const sockets = new Set();
  let offline = false;
  const proxy = net.createServer(socket => {
    if (offline) { socket.destroy(); return; }
    const upstream = net.connect({ host: upstreamHost, port: upstreamPort });
    sockets.add(socket); sockets.add(upstream);
    socket.on('error', () => {}); upstream.on('error', () => {});
    socket.on('close', () => { sockets.delete(socket); upstream.destroy(); });
    upstream.on('close', () => { sockets.delete(upstream); socket.destroy(); });
    socket.pipe(upstream); upstream.pipe(socket);
  });
  proxy.listen(0, '127.0.0.1');
  await once(proxy, 'listening');
  target.hostname = '127.0.0.1'; target.port = String(proxy.address().port);
  return {
    url: target.href,
    disconnect() { offline = true; for (const socket of sockets) socket.destroy(); },
    reconnect() { offline = false; },
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => proxy.close(resolve));
    }
  };
}

async function availablePort() {
  const server = net.createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

function percentiles(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const percentile = p => sorted.length ? round(sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))]) : null;
  return { sampleCount: sorted.length, p50Ms: percentile(0.5), p95Ms: percentile(0.95), p99Ms: percentile(0.99), maxMs: sorted.length ? round(sorted[sorted.length - 1]) : null };
}

function memorySummary(samples) {
  if (!samples.length) return null;
  const latter = samples.slice(Math.floor(samples.length / 2));
  const first = samples.slice(0, Math.max(1, Math.floor(samples.length / 3)));
  const last = samples.slice(-Math.max(1, Math.floor(samples.length / 3)));
  const minimum = values => Math.min(...values.map(value => value.heapUsedMb));
  const meanX = latter.reduce((sum, value) => sum + value.elapsedSec / 60, 0) / latter.length;
  const meanY = latter.reduce((sum, value) => sum + value.heapUsedMb, 0) / latter.length;
  const numerator = latter.reduce((sum, value) => sum + (value.elapsedSec / 60 - meanX) * (value.heapUsedMb - meanY), 0);
  const denominator = latter.reduce((sum, value) => sum + (value.elapsedSec / 60 - meanX) ** 2, 0);
  return {
    samples: samples.length,
    maxRssMb: round(Math.max(...samples.map(value => value.rssMb))),
    maxHeapUsedMb: round(Math.max(...samples.map(value => value.heapUsedMb))),
    firstThirdHeapFloorMb: round(minimum(first)),
    lastThirdHeapFloorMb: round(minimum(last)),
    heapFloorGrowthMb: round(minimum(last) - minimum(first)),
    latterHalfHeapSlopeMbPerMinute: round(denominator ? numerator / denominator : 0),
    note: 'Natural GC samples over this run; no forced collection. These observations do not establish absence of a long-term leak.'
  };
}

async function main() {
  const cfg = options(process.argv.slice(2));
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'traffic-panel-soak-'));
  const port = await availablePort();
  const adminToken = randomBytes(32).toString('base64url');
  const tokenBody = Buffer.from(JSON.stringify({ next: '/r?d=local-soak-fixture', ts: Date.now(), exp: Date.now() + (cfg.durationSec + 600) * 1000 })).toString('base64url');
  const challengeBody = JSON.stringify({ ct: `${tokenBody}.${createHmac('sha256', adminToken).update(tokenBody).digest('base64url')}` });
  const redisUrl = process.env.TRAFFIC_METRICS_TEST_REDIS_URL || '';
  if (cfg.redisOutageSec && !redisUrl) throw new Error('Redis outage validation requires a test Redis URL');
  // The fault proxy belongs to this test. The supplied Redis service is never
  // stopped, paused, reconfigured, or otherwise modified by fault injection.
  const redisProxy = cfg.redisOutageSec ? await redisFaultProxy(redisUrl) : null;
  const outage = { enabled: Boolean(redisProxy), started: false, recovered: false, localReportsDuringOutage: 0, recoveredReports: 0, pendingPeak: 0 };
  const agent = new http.Agent({ keepAlive: true, maxSockets: cfg.concurrency + cfg.panels + 8, maxFreeSockets: 4 });
  const pending = new Set();
  const timers = new Set();
  let child;
  let shuttingDown = false;
  let started = 0;
  let loadIndex = 0;
  let loadInFlight = 0;
  let loadPeak = 0;
  let prematureExit = false;
  let metricsBefore;
  let metricsAfter;
  let finalHealth;
  let result;
  const samples = [];
  const latencies = [];
  const panelLatencies = [];
  const failures = [];
  const totals = { completeRequests: 0, expected4xx: 0, expectedValidationRateLimits: 0, unexpectedStatus: 0, server5xx: 0, networkErrors: 0, observed499: 0, panelPolls: 0, challengeFragments: 0, deliberateDisconnects: 0, slowReaders: 0, skippedLoadTicks: 0, healthSamples: 0, byStatus: {} };

  function fail(message) { if (!failures.includes(message) && failures.length < 30) failures.push(message); }

  function request(route, { authenticated = false, slow = false, method = 'GET', body } = {}) {
    return new Promise((resolve, reject) => {
      const requestStarted = performance.now();
      let settled = false;
      let response;
      const timer = setTimeout(() => {
        response?.destroy();
        req.destroy(new Error('Request deadline exceeded'));
      }, cfg.timeoutMs);
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        error ? reject(error) : resolve(value);
      };
      const headers = authenticated ? { authorization: `Bearer ${adminToken}` } : {};
      if (body) Object.assign(headers, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
      const req = http.request({ hostname: '127.0.0.1', port, path: route, method, agent, headers }, res => {
        response = res;
        let body = '';
        res.setEncoding('utf8');
        res.on('data', chunk => {
          if (body.length + chunk.length > 1024 * 1024) {
            req.destroy(new Error('Response exceeded bounded test buffer'));
            return;
          }
          body += chunk;
        });
        res.on('end', () => finish(null, { status: res.statusCode, body, elapsedMs: performance.now() - requestStarted }));
        res.on('error', error => finish(error));
        if (slow) { res.pause(); setTimeout(() => res.resume(), 200); }
      });
      req.on('error', error => finish(error));
      req.end(body);
    });
  }

  function track(promise) {
    pending.add(promise);
    promise.finally(() => pending.delete(promise)).catch(() => {});
    return promise;
  }

  async function checked(route, expected, args) {
    try {
      const response = await request(route, args);
      totals.completeRequests++;
      totals.byStatus[response.status] = (totals.byStatus[response.status] || 0) + 1;
      boundedPush(latencies, response.elapsedMs, 10000);
      if (response.status >= 500) totals.server5xx++;
      if (response.status === 499) totals.observed499++;
      if (route === '/challenge-fragment' && response.status === 200) totals.challengeFragments++;
      // Intentionally malformed /r requests activate the existing validation
      // limiter after ten failures; its 429 is expected defensive behaviour.
      const validationLimited = route === '/r' && expected === 400 && response.status === 429;
      const accepted = response.status === expected || validationLimited;
      if (validationLimited) totals.expectedValidationRateLimits++;
      if (response.status >= 400 && response.status < 500 && accepted) totals.expected4xx++;
      if (!accepted) {
        totals.unexpectedStatus++;
        fail(`Unexpected status on ${route}: expected ${expected}, received ${response.status}`);
      }
      return response;
    } catch {
      totals.networkErrors++;
      fail(`Unexpected request failure on ${route}`);
      return null;
    }
  }

  async function sampleHealth() {
    const response = await checked('/healthz', 200);
    if (!response) return;
    try {
      const { stats } = JSON.parse(response.body);
      const sample = { elapsedSec: round((Date.now() - started) / 1000), rssMb: stats.memory.rssMb, heapUsedMb: stats.memory.heapUsedMb, inFlightRequests: stats.inFlightRequestsExcludingCurrent, openSockets: stats.resources.openSockets, sseListeners: stats.resources.sseListeners, logQueueBytes: stats.resources.logFileQueueBytes, requestTimeouts: stats.requestTimeouts, maxEventLoopLagMs: stats.maxObservedEventLoopLagMs };
      assert.ok(Number.isFinite(sample.heapUsedMb) && Number.isFinite(sample.rssMb));
      boundedPush(samples, sample, 600);
      totals.healthSamples++;
      return stats;
    } catch { fail('Invalid health sample'); }
  }

  async function pollPanel() {
    const response = await checked('/admin/traffic-metrics', 200, { authenticated: true });
    if (!response) return;
    totals.panelPolls++;
    boundedPush(panelLatencies, response.elapsedMs, 3000);
    try {
      const metrics = JSON.parse(response.body);
      assert.equal(metrics.ok, true);
      assert.equal(metrics.scope, 'current_process');
      if (redisUrl) assert.equal(metrics.storage.configured, true);
      outage.pendingPeak = Math.max(outage.pendingPeak, metrics.storage?.pendingObservations || 0);
      if (outage.started && !outage.recovered && metrics.shared === null) outage.localReportsDuringOutage++;
      if (outage.recovered && metrics.shared && metrics.storage?.ready && !metrics.storage?.lastError) outage.recoveredReports++;
      return metrics;
    } catch { fail('Invalid panel metrics response'); }
  }

  function deliberateDisconnect() {
    return new Promise(resolve => {
      const socket = net.connect({ host: '127.0.0.1', port });
      const close = setTimeout(() => socket.destroy(), 150);
      socket.on('connect', () => {
        // Incomplete JSON body keeps the request open until the client leaves.
        socket.write('POST /decrypt-challenge-data HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 512\r\nConnection: close\r\n\r\n{"data":"');
        totals.deliberateDisconnects++;
      });
      socket.on('error', () => {}); // Intentional disconnect, separate from complete-request failures.
      socket.on('close', () => { clearTimeout(close); resolve(); });
    });
  }

  function interval(fn, ms) {
    const timer = setInterval(() => { track(Promise.resolve().then(fn)); }, ms);
    timers.add(timer);
  }

  const interrupt = () => { fail('Run interrupted'); for (const timer of timers) clearInterval(timer); child?.kill('SIGTERM'); };
  process.once('SIGINT', interrupt);
  process.once('SIGTERM', interrupt);

  try {
    child = spawn(process.execPath, ['--max-old-space-size=256', 'server.js'], {
      cwd: path.resolve(__dirname, '..'),
      env: {
        ...process.env, NODE_ENV: 'development', PORT: String(port),
        AES_KEY_HEX: randomBytes(32).toString('hex'), AES_KEY: '', AES_KEYS: '', AES_KEY_SHA256: '',
        ADMIN_TOKEN: adminToken, DEBUG_SHOW_KEYS_ON_START: '0', DEBUG_ALLOW_PLAINTEXT_KEYS: '0',
        TURNSTILE_SITEKEY: '1x00000000000000000000AA', TURNSTILE_SECRET: '1x0000000000000000000000000000000AA',
        TURNSTILE_EXPECT_HOSTNAME: '', ALLOWLIST_DOMAINS: 'example.com', REQUIRE_CF_HEADERS: 'false',
        OPTIONAL_URL_PREFIX: '', RATE_LIMIT_MAX_REQUESTS: '100000',
        CHALLENGE_VIEW_CAPACITY: '100000', CHALLENGE_CAPACITY: '100000', LOG_TO_FILE: '0',
        RUNTIME_DIAG_DIR: directory, RUNTIME_INCIDENT_FILE: path.join(directory, 'incidents.ndjson'),
        LOG_DIR: directory, LOG_FILE: path.join(directory, 'visitors.log'),
        NPM_CONFIG_LOGS_DIR: directory, IPINFO_LITE_ENABLED: '0',
        REDIS_URL: '', REDIS_PRIVATE_URL: '', TRAFFIC_METRICS_REDIS_URL: redisProxy ? redisProxy.url : redisUrl,
        TRAFFIC_METRICS_NAMESPACE: `panel-soak-${randomBytes(8).toString('hex')}`, eSCANNER_CONFIG_URL: ''
      },
      stdio: ['ignore', 'ignore', 'ignore']
    });
    child.once('exit', () => { if (!shuttingDown) prematureExit = true; });
    await once(child, 'spawn');
    let ready = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      if (prematureExit) throw new Error('Isolated server exited before startup');
      try { if ((await request('/livez')).status === 200) { ready = true; break; } } catch {}
      await sleep(100);
    }
    assert.ok(ready, 'Isolated server must become live');
    started = Date.now();
    await checked('/admin/traffic-panel', 200);
    await checked('/admin/traffic-panel.js', 200);
    await checked('/view-log?token=discard-this-test-value', 302);
    await checked('/view-log-live?token=discard-this-test-value', 302);
    await checked('/stream-log', 204, { authenticated: true });
    await checked('/stream-log', 204);
    await checked('/admin/traffic-metrics', 401);
    metricsBefore = await pollPanel();
    if (redisUrl) {
      for (let attempt = 0; attempt < 30 && !metricsBefore?.shared; attempt++) { await sleep(100); metricsBefore = await pollPanel(); }
      assert.ok(metricsBefore?.shared, 'Test Redis must be available before load');
    }
    await sampleHealth();
    const end = started + cfg.durationSec * 1000;
    const routes = [
      ['/robots.txt', 200], ['/r', 400], ['/ads.txt', 200],
      ['/admin/traffic-panel', 200, { authenticated: true }], ['/r', 400], ['/admin/traffic-panel.js', 200, { authenticated: true }],
      ['/challenge-fragment', 200, { method: 'POST', body: challengeBody }],
      ['/.well-known/security.txt', 200], ['/r', 400], ['/stream-log', 204]
    ];
    interval(async () => {
      if (Date.now() >= end) return;
      if (loadInFlight >= cfg.concurrency) { totals.skippedLoadTicks++; return; }
      loadInFlight++;
      loadPeak = Math.max(loadPeak, loadInFlight);
      const [route, status, args] = routes[loadIndex++ % routes.length];
      try { await checked(route, status, args); } finally { loadInFlight--; }
    }, Math.max(1, Math.round(1000 / cfg.rps)));
    interval(sampleHealth, 2000);
    interval(deliberateDisconnect, 1000);
    interval(async () => {
      await checked('/admin/traffic-panel', 200, { slow: true, authenticated: true });
      totals.slowReaders++;
    }, 1000);
    if (redisProxy) interval(() => {
      const elapsed = Date.now() - started;
      const beginAt = cfg.durationSec * 1000 / 3;
      if (!outage.started && elapsed >= beginAt) {
        outage.started = true;
        redisProxy.disconnect();
      } else if (outage.started && !outage.recovered && elapsed >= beginAt + cfg.redisOutageSec * 1000) {
        outage.recovered = true;
        redisProxy.reconnect();
      }
    }, 100);
    // Each simulated panel schedules its next poll only after the previous one
    // completes, matching the one-in-flight browser controller contract.
    for (let index = 0; index < cfg.panels; index++) {
      track((async () => {
        await sleep(index * Math.min(100, 5000 / cfg.panels));
        while (Date.now() < end && !prematureExit) {
          await pollPanel();
          await sleep(Math.min(5000, Math.max(0, end - Date.now())));
        }
      })());
    }
    console.log(`Panel soak started: ${cfg.durationSec}s, ${cfg.rps} requests/s target, ${cfg.panels} polling panels, Redis ${redisUrl ? 'enabled' : 'disabled'}.`);
    while (Date.now() < end && !prematureExit) await sleep(Math.min(1000, end - Date.now()));
    for (const timer of timers) clearInterval(timer);
    await Promise.allSettled([...pending]);
    // Remove test client keep-alive sockets and allow all deliberate aborted
    // requests to settle before checking server resource counts.
    agent.destroy();
    await sleep(1500);
    finalHealth = await sampleHealth();
    metricsAfter = await pollPanel();
    if (prematureExit) fail('Server exited during load');
    if (!finalHealth) fail('Server did not remain responsive after load');
    if (finalHealth) {
      for (const key of ['uncaughtExceptions', 'unhandledRejections', 'serverErrors', 'requestTimeouts']) if (finalHealth[key] !== 0) fail(`Server runtime counter ${key} is ${finalHealth[key]}`);
      if (finalHealth.inFlightRequestsExcludingCurrent !== 0) fail('Tracked requests did not drain after load');
      if (finalHealth.resources.sseListeners !== 0) fail('SSE listeners remained allocated');
      if (finalHealth.resources.openSockets > 3) fail('Connections did not drain after load');
      if (finalHealth.resources.logFileQueueBytes !== 0) fail('Log queue did not drain');
    }
    const memory = memorySummary(samples);
    if (memory?.maxHeapUsedMb > 256 || memory?.maxRssMb > 512) fail('Memory exceeded isolated run budget');
    if (memory?.heapFloorGrowthMb > 64 && memory?.latterHalfHeapSlopeMbPerMinute > 20) fail('Sustained heap growth requires investigation');
    const timing = percentiles(latencies);
    if (timing.p99Ms > cfg.timeoutMs * 0.8) fail('Completed-request p99 approached request deadline');
    if (!totals.deliberateDisconnects || !totals.slowReaders || !totals.panelPolls) fail('Expected workload did not execute');
    if (!totals.challengeFragments || (metricsAfter?.challenges?.shown - metricsBefore?.challenges?.shown) < totals.challengeFragments) fail('Challenge HTML rendering was not counted correctly');
    if (redisUrl && !metricsAfter?.storage.ready) fail('Configured Redis store was not ready at completion');
    if (redisProxy && (!outage.started || !outage.recovered || !outage.localReportsDuringOutage || !outage.recoveredReports)) fail('Redis outage and local fallback/recovery were not demonstrated');
    if (redisUrl && (!metricsAfter?.shared || metricsAfter.storage.lastError || metricsAfter.storage.pendingObservations)) fail('Redis writes did not recover and drain');
    if (redisUrl && metricsAfter?.shared && metricsAfter.shared.challenges.shown < metricsAfter.challenges.shown) fail('Shared challenge counters omitted observations after recovery');
    result = {
      passed: failures.length === 0, smokeOnly: cfg.smoke,
      config: { ...cfg, output: undefined, redisEnabled: Boolean(redisUrl), panelPollIntervalMs: 5000, serverHeapLimitMb: 256 },
      elapsedSec: round((Date.now() - started) / 1000), totals, loadPeak,
      latency: timing, panelLatency: percentiles(panelLatencies), memory,
      final: finalHealth ? { inFlightRequests: finalHealth.inFlightRequestsExcludingCurrent, abortedRequests: finalHealth.abortedRequests, requestTimeouts: finalHealth.requestTimeouts, uncaughtExceptions: finalHealth.uncaughtExceptions, unhandledRejections: finalHealth.unhandledRejections, serverErrors: finalHealth.serverErrors, processWarnings: finalHealth.processWarnings, openSockets: finalHealth.resources.openSockets, sseListeners: finalHealth.resources.sseListeners, logQueueBytes: finalHealth.resources.logFileQueueBytes, maxEventLoopLagMs: finalHealth.maxObservedEventLoopLagMs } : null,
      metrics: { startedRequests: metricsBefore?.total?.requests, endedRequests: metricsAfter?.total?.requests, sharedStorageReady: metricsAfter?.storage?.ready ?? false },
      outage,
      sampleTail: samples.slice(-8), failures,
      limitation: 'Local HTTP test; deliberate disconnects are counted separately. A production proxy may record those disconnects as 499. Browser behaviour is verified separately.'
    };
  } finally {
    for (const timer of timers) clearInterval(timer);
    agent.destroy();
    shuttingDown = true;
    if (child && child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit');
      child.kill('SIGTERM');
      const killTimer = setTimeout(() => child.kill('SIGKILL'), 10000);
      await exited;
      clearTimeout(killTimer);
    }
    if (redisProxy) await redisProxy.close();
    process.off('SIGINT', interrupt);
    process.off('SIGTERM', interrupt);
    await fs.rm(directory, { recursive: true, force: true });
  }
  if (cfg.output) await fs.writeFile(cfg.output, JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
  console.log(JSON.stringify(result, null, 2));
  if (!result.passed) process.exitCode = 2;
}

main().catch(() => {
  // Do not echo untrusted child output, credentials, or Redis connection URLs.
  console.error('Panel soak could not complete; verify options and isolated server startup.');
  process.exitCode = 1;
});
