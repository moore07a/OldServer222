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
  const out = { durationSec: 300, rps: 30, concurrency: 8, panels: 3, timeoutMs: 5000, redisOutageSec: 0, diskOutageSec: 0, disk: false, output: null, smoke: false };
  const keys = { '--duration-sec': 'durationSec', '--rps': 'rps', '--concurrency': 'concurrency', '--panels': 'panels', '--timeout-ms': 'timeoutMs', '--redis-outage-sec': 'redisOutageSec', '--disk-outage-sec': 'diskOutageSec' };
  for (let index = 0; index < argv.length; index++) {
    const key = argv[index];
    if (key === '--disk') { out.disk = true; continue; }
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
  if (out.diskOutageSec && (!out.disk || out.diskOutageSec < 5 || out.diskOutageSec > out.durationSec / 3)) throw new Error('Disk outage requires --disk and 5 seconds or more, at most one third of the run');
  if (out.disk && out.redisOutageSec) throw new Error('Choose disk or Redis fault injection');
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

async function diskFault(directory) {
  const backup = `${directory}.fault-backup-${randomBytes(8).toString('hex')}`;
  const blockerBackup = `${directory}.fault-marker-${randomBytes(8).toString('hex')}`;
  let original;
  let blocker;
  let moved = false;
  const absent = async target => {
    try { await fs.lstat(target); throw new Error('Owned fixture destination already exists'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  };
  const same = (left, right) => left.ino === right.ino && left.dev === right.dev;
  return {
    async disconnect() {
      original = await fs.lstat(directory);
      assert.ok(original.isDirectory() && !original.isSymbolicLink());
      await absent(backup);
      await fs.rename(directory, backup);
      moved = true;
      // The existing worker retains its flock inode inside the moved directory.
      // ENOTDIR on future writes forces an ordinary write_failed response.
      const handle = await fs.open(directory, 'wx', 0o600);
      try { await handle.writeFile('owned analytics outage fixture'); blocker = await handle.stat(); }
      finally { await handle.close(); }
    },
    async reconnect() {
      if (!moved) return;
      const saved = await fs.lstat(backup);
      assert.ok(saved.isDirectory() && same(saved, original));
      if (blocker) {
        const current = await fs.lstat(directory);
        assert.ok(current.isFile() && same(current, blocker));
        await absent(blockerBackup);
        await fs.rename(directory, blockerBackup);
      } else await absent(directory);
      // Only paths created by this unique temporary fixture can be restored.
      await absent(directory);
      await fs.rename(backup, directory);
      moved = false;
      if (blocker) { await fs.unlink(blockerBackup); blocker = null; }
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
  const redisUrl = cfg.disk ? '' : process.env.TRAFFIC_METRICS_TEST_REDIS_URL || '';
  const analyticsDirectory = path.join(directory, 'analytics');
  const fixtureNamespace = `panel-soak-${randomBytes(8).toString('hex')}`;
  const riskCampaignId = 'soak_campaign';
  // Ignore inherited risk credentials/provider switches/Redis endpoints entirely.
  const fixtureEnvironment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('RISK_')));
  if (cfg.redisOutageSec && !redisUrl) throw new Error('Redis outage validation requires a test Redis URL');
  // The fault proxy belongs to this test. The supplied Redis service is never
  // stopped, paused, reconfigured, or otherwise modified by fault injection.
  const redisProxy = cfg.redisOutageSec ? await redisFaultProxy(redisUrl) : null;
  const diskProxy = cfg.diskOutageSec ? await diskFault(analyticsDirectory) : null;
  const diskOutage = { enabled: Boolean(diskProxy), started: false, recovered: false, failedReports: 0, recoveredReports: 0 };
  const diskSummary = { samples: 0, saveAdvances: 0, pendingBytesPeak: 0, savedRequestsAtStart: null, savedRequestsAtEnd: null, lastSaveAt: null, files: 0, fileBytes: 0, checkpointRequests: 0 };
  const outage = { enabled: Boolean(redisProxy), started: false, recovered: false, localReportsDuringOutage: 0, recoveredReports: 0, pendingPeak: 0 };
  const riskScopes = new Set();
  const riskSummary = { samples: 0, observerErrors: 0, providerLookups: 0, cacheEntriesPeak: 0, cacheQueuePeak: 0, cacheActivePeak: 0, pendingOperationsPeak: 0, localReportsDuringOutage: 0, recoveredReports: 0 };
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
      const validationLimited = route.split('?', 1)[0] === '/r' && expected === 400 && response.status === 429;
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

  function inspectRisk(metrics) {
    const risk = metrics.risk;
    assert.equal(risk.mode, 'report_only');
    assert.equal(risk.classification, 'indicators_only');
    assert.equal(risk.observerErrors, 0);
    assert.equal(risk.intelligence.enabled, false);
    assert.equal(risk.intelligence.providerStatus.enabled, false);
    assert.equal(risk.intelligence.providerStatus.used, 0);
    assert.equal(risk.intelligence.capabilities.residentialProxy, false);
    assert.equal(risk.conversions.enabled, false);
    const cache = risk.intelligence.cache;
    assert.equal(cache.enabled, false);
    assert.equal(cache.lookups, 0);
    assert.ok(cache.cacheEntries >= 0 && cache.cacheEntries <= cache.limits.maxEntries && cache.limits.maxEntries <= 128);
    assert.ok(cache.queued >= 0 && cache.queued <= cache.limits.maxQueue && cache.limits.maxQueue <= 8);
    assert.ok(cache.active >= 0 && cache.active <= cache.limits.concurrency && cache.limits.concurrency <= 2);
    const window = risk.campaignWindow;
    assert.ok(['current_process', 'redis', 'disk', 'unavailable'].includes(window.scope));
    assert.equal(window.attribution, 'client_supplied');
    assert.equal(window.campaigns.length, 2);
    assert.ok(window.campaigns.every(row => [riskCampaignId, '__unattributed__'].includes(row.id)));
    assert.equal(window.storage.configured, Boolean(redisUrl || cfg.disk));
    assert.ok(Number.isInteger(window.storage.pendingOperations) && window.storage.pendingOperations >= 0 && window.storage.pendingOperations <= window.storage.queueLimit && window.storage.queueLimit <= 128);
    if (window.scope === 'unavailable') assert.equal(window.storage.fallbackScope, 'current_process');
    riskSummary.samples++;
    riskScopes.add(window.scope);
    riskSummary.observerErrors = Math.max(riskSummary.observerErrors, risk.observerErrors);
    riskSummary.providerLookups = Math.max(riskSummary.providerLookups, cache.lookups, risk.intelligence.providerStatus.used);
    riskSummary.cacheEntriesPeak = Math.max(riskSummary.cacheEntriesPeak, cache.cacheEntries);
    riskSummary.cacheQueuePeak = Math.max(riskSummary.cacheQueuePeak, cache.queued);
    riskSummary.cacheActivePeak = Math.max(riskSummary.cacheActivePeak, cache.active);
    riskSummary.pendingOperationsPeak = Math.max(riskSummary.pendingOperationsPeak, window.storage.pendingOperations);
    if (outage.started && !outage.recovered && window.scope === 'unavailable') riskSummary.localReportsDuringOutage++;
    if (outage.recovered && window.scope === 'redis' && window.storage.ready && !window.storage.lastError && window.storage.pendingOperations <= 1) riskSummary.recoveredReports++;
  }

  function inspectDisk(metrics) {
    const status = metrics.diskStorage;
    assert.equal(status.backend, 'disk');
    assert.equal(status.configured, true);
    assert.ok(Number.isInteger(status.maxBytes) && status.maxBytes > 0 && status.maxBytes <= 1024 * 1024);
    assert.ok(Number.isInteger(status.pendingBytes) && status.pendingBytes >= 0 && status.pendingBytes <= 2 * 1024 * 1024);
    assert.equal(metrics.persistent.scope, 'disk');
    assert.ok(Number.isSafeInteger(metrics.persistent.total.requests) && metrics.persistent.total.requests >= 0);
    assert.ok(Number.isFinite(Date.parse(status.lastSaveAt)));
    if (status.ready) assert.equal(metrics.risk.campaignWindow.scope, 'disk');
    else assert.equal(metrics.risk.campaignWindow.scope, 'unavailable');
    const requests = metrics.persistent.total.requests;
    if (diskSummary.savedRequestsAtStart === null) diskSummary.savedRequestsAtStart = requests;
    if (diskSummary.lastSaveAt !== null && diskSummary.lastSaveAt !== status.lastSaveAt) diskSummary.saveAdvances++;
    diskSummary.lastSaveAt = status.lastSaveAt;
    diskSummary.savedRequestsAtEnd = requests;
    diskSummary.samples++;
    diskSummary.pendingBytesPeak = Math.max(diskSummary.pendingBytesPeak, status.pendingBytes);
    if (diskOutage.started && !diskOutage.recovered && status.lastError === 'write_failed') diskOutage.failedReports++;
    if (diskOutage.recovered && status.ready && !status.lastError) diskOutage.recoveredReports++;
  }

  async function inspectCheckpointFiles(metrics) {
    const entries = await fs.readdir(analyticsDirectory, { withFileTypes: true });
    assert.ok(entries.length >= 2 && entries.length <= 4, 'Only a checkpoint, lock, and bounded interrupted-write temporaries may remain');
    let checkpoint;
    let totalBytes = 0;
    for (const entry of entries) {
      assert.ok(entry.isFile() && !entry.isSymbolicLink());
      assert.ok(entry.name === `${fixtureNamespace}.json` || entry.name === `${fixtureNamespace}.lock` || (entry.name.startsWith(`.${fixtureNamespace}.`) && entry.name.endsWith('.tmp')));
      const stat = await fs.lstat(path.join(analyticsDirectory, entry.name));
      assert.ok(stat.isFile() && stat.nlink === 1 && !(stat.mode & 0o077) && stat.size <= 1024 * 1024);
      totalBytes += stat.size;
      if (entry.name === `${fixtureNamespace}.json`) checkpoint = JSON.parse(await fs.readFile(path.join(analyticsDirectory, entry.name), 'utf8'));
    }
    assert.ok(totalBytes <= 2 * 1024 * 1024);
    assert.equal(checkpoint.namespace, fixtureNamespace);
    assert.equal(checkpoint.data.version, 1);
    assert.ok(checkpoint.data.http.total.requests >= metrics.persistent.total.requests);
    assert.ok(checkpoint.data.risk.totals.observedRequests > 0);
    assert.ok(checkpoint.data.campaigns.campaigns.length <= 33 && checkpoint.data.campaigns.dedupe.length <= 4096);
    diskSummary.files = entries.length;
    diskSummary.fileBytes = totalBytes;
    diskSummary.checkpointRequests = checkpoint.data.http.total.requests;
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
      inspectRisk(metrics);
      if (cfg.disk) inspectDisk(metrics);
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
    child = spawn(process.execPath, ['--max-old-space-size=256', '-e', `
      // This reliability fixture never makes upstream HTTP requests. Preserve
      // health checks with a deterministic successful Turnstile script probe.
      globalThis.fetch = async (input, options = {}) => {
        const url = String(input && input.url || input);
        if (url === 'https://challenges.cloudflare.com/turnstile/v0/api.js' && options.method === 'HEAD') return new Response(null, { status: 200 });
        throw new Error('soak fixture blocks upstream HTTP');
      };
      require('./server.js');
    `], {
      cwd: path.resolve(__dirname, '..'),
      env: {
        ...fixtureEnvironment, NODE_ENV: 'development', PORT: String(port),
        AES_KEY_HEX: randomBytes(32).toString('hex'), AES_KEY: '', AES_KEYS: '', AES_KEY_SHA256: '',
        ADMIN_TOKEN: adminToken, DEBUG_SHOW_KEYS_ON_START: '0', DEBUG_ALLOW_PLAINTEXT_KEYS: '0',
        TURNSTILE_SITEKEY: '1x00000000000000000000AA', TURNSTILE_SECRET: '1x0000000000000000000000000000000AA',
        TURNSTILE_EXPECT_HOSTNAME: '', ALLOWLIST_DOMAINS: 'example.com', REQUIRE_CF_HEADERS: 'false',
        OPTIONAL_URL_PREFIX: '', RATE_LIMIT_MAX_REQUESTS: '100000',
        CHALLENGE_VIEW_CAPACITY: '100000', CHALLENGE_CAPACITY: '100000', LOG_TO_FILE: '0',
        RUNTIME_DIAG_DIR: directory, RUNTIME_INCIDENT_FILE: path.join(directory, 'incidents.ndjson'),
        LOG_DIR: directory, LOG_FILE: path.join(directory, 'visitors.log'),
        NPM_CONFIG_LOGS_DIR: directory, IPINFO_LITE_ENABLED: '0',
        ANALYTICS_STORAGE_DIR: cfg.disk ? analyticsDirectory : '', RAILWAY_VOLUME_MOUNT_PATH: '',
        REDIS_URL: '', REDIS_PRIVATE_URL: '', TRAFFIC_METRICS_REDIS_URL: redisProxy ? redisProxy.url : redisUrl,
        TRAFFIC_METRICS_NAMESPACE: fixtureNamespace, eSCANNER_CONFIG_URL: '',
        RISK_REPORTING_ENABLED: '1', RISK_IP_INTELLIGENCE_ENABLED: '0', RISK_IP_DAILY_BUDGET: '0',
        RISK_CAMPAIGN_IDS: riskCampaignId, RISK_NAMESPACE: fixtureNamespace,
        RISK_HASH_SECRET: randomBytes(32).toString('hex'), RISK_CONVERSION_TOKEN: '',
        RISK_WINDOW_SECONDS: '300', RISK_IP_CACHE_MAX_ENTRIES: '128', RISK_IP_QUEUE_MAX: '8',
        RISK_REDIS_URL: redisProxy ? redisProxy.url : redisUrl
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
    await checked('/view-log?token=discard-this-test-value', 404);
    await checked('/view-log-live?token=discard-this-test-value', 404);
    await checked('/stream-log', 404, { authenticated: true });
    await checked('/stream-log', 404);
    await checked('/admin/traffic-metrics', 401);
    metricsBefore = await pollPanel();
    if (redisUrl) {
      for (let attempt = 0; attempt < 30 && (!metricsBefore?.shared || metricsBefore?.risk?.campaignWindow?.scope !== 'redis'); attempt++) { await sleep(100); metricsBefore = await pollPanel(); }
      assert.ok(metricsBefore?.shared, 'Test Redis must be available before load');
      assert.equal(metricsBefore?.risk?.campaignWindow?.scope, 'redis', 'Risk Redis must be available before load');
    }
    await sampleHealth();
    const end = started + cfg.durationSec * 1000;
    const routes = [
      ['/robots.txt', 200], [`/r?campaign_id=${riskCampaignId}`, 400], ['/ads.txt', 200],
      ['/admin/traffic-panel', 200, { authenticated: true }], [`/r?campaign_id=${riskCampaignId}`, 400], ['/admin/traffic-panel.js', 200, { authenticated: true }],
      ['/challenge-fragment', 200, { method: 'POST', body: challengeBody }],
      ['/.well-known/security.txt', 200], [`/r?campaign_id=${riskCampaignId}`, 400], ['/stream-log', 404]
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
    if (diskProxy) {
      let faultBusy = false;
      interval(async () => {
        if (faultBusy) return;
        faultBusy = true;
        try {
          const elapsed = Date.now() - started;
          const beginAt = cfg.durationSec * 1000 / 3;
          if (!diskOutage.started && elapsed >= beginAt) {
            await diskProxy.disconnect();
            diskOutage.started = true;
          } else if (diskOutage.started && !diskOutage.recovered && elapsed >= beginAt + cfg.diskOutageSec * 1000) {
            await diskProxy.reconnect();
            diskOutage.recovered = true;
          }
        } catch { fail('Owned disk fault fixture failed'); }
        finally { faultBusy = false; }
      }, 100);
    }
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
    const finalRisk = metricsAfter?.risk;
    const finalRiskWindow = finalRisk?.campaignWindow;
    if (!finalRisk || finalRisk.totals.observedRequests <= 0) fail('Report-only risk observations did not execute');
    if (redisProxy && (!riskSummary.localReportsDuringOutage || !riskSummary.recoveredReports)) fail('Risk Redis local fallback/recovery were not demonstrated');
    // A successful read is still the single active command when its status is
    // captured; <=1 here means all observation work drained before that read.
    if (redisUrl && (finalRiskWindow?.scope !== 'redis' || !finalRiskWindow.storage.ready || finalRiskWindow.storage.lastError || finalRiskWindow.storage.pendingOperations > 1)) fail('Risk Redis observations did not recover and drain');
    if (cfg.disk) {
      if (!metricsAfter?.diskStorage?.ready || metricsAfter.diskStorage.lastError || finalRiskWindow?.scope !== 'disk') fail('Disk checkpoint did not remain available or recover');
      if (diskSummary.savedRequestsAtEnd <= diskSummary.savedRequestsAtStart || !diskSummary.saveAdvances) fail('Saved disk aggregate did not advance during load');
      if (diskProxy && (!diskOutage.started || !diskOutage.recovered || !diskOutage.failedReports || !diskOutage.recoveredReports)) fail('Disk write failure and recovery were not demonstrated');
      try { await inspectCheckpointFiles(metricsAfter); } catch { fail('Disk checkpoint files or saved progress exceeded bounded expectations'); }
    }
    result = {
      passed: failures.length === 0, smokeOnly: cfg.smoke,
      config: { ...cfg, output: undefined, redisEnabled: Boolean(redisUrl), panelPollIntervalMs: 5000, serverHeapLimitMb: 256 },
      elapsedSec: round((Date.now() - started) / 1000), totals, loadPeak,
      latency: timing, panelLatency: percentiles(panelLatencies), memory,
      final: finalHealth ? { inFlightRequests: finalHealth.inFlightRequestsExcludingCurrent, abortedRequests: finalHealth.abortedRequests, requestTimeouts: finalHealth.requestTimeouts, uncaughtExceptions: finalHealth.uncaughtExceptions, unhandledRejections: finalHealth.unhandledRejections, serverErrors: finalHealth.serverErrors, processWarnings: finalHealth.processWarnings, openSockets: finalHealth.resources.openSockets, sseListeners: finalHealth.resources.sseListeners, logQueueBytes: finalHealth.resources.logFileQueueBytes, maxEventLoopLagMs: finalHealth.maxObservedEventLoopLagMs } : null,
      metrics: { startedRequests: metricsBefore?.total?.requests, endedRequests: metricsAfter?.total?.requests, sharedStorageReady: metricsAfter?.storage?.ready ?? false },
      outage,
      disk: cfg.disk ? { ...diskSummary, outage: diskOutage } : null,
      risk: { ...riskSummary, mode: finalRisk?.mode, scopes: [...riskScopes],
        observedRequests: finalRisk?.totals.observedRequests, campaignScope: finalRiskWindow?.scope,
        providerEnabled: finalRisk?.intelligence.enabled, pendingOperationsAtFinalRead: finalRiskWindow?.storage.pendingOperations,
        droppedObservations: finalRiskWindow?.storage.droppedObservations, uncertainObservations: finalRiskWindow?.storage.uncertainObservations,
        note: 'Provider disabled; no upstream lookups. Redis observations are bounded best effort and can be dropped during outage. Final pending slot may be the current snapshot read.' },
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
    if (diskProxy) await diskProxy.reconnect();
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
