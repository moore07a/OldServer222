#!/usr/bin/env node
'use strict';

// Optional real Chromium validation. This is deliberately outside *.test.js:
// ordinary npm test does not install or require a browser.
// Run: node tests/traffic-panel-browser.js --output /tmp/traffic-panel-browser.json
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const { once } = require('node:events');
const fs = require('node:fs/promises');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');

const repository = path.resolve(__dirname, '..');
const role = name => `[data-role="${name}"]`;
const value = name => `[data-value="${name}"]`;
const wait = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const secrets = [];
function safeText(text) {
  let safe = String(text);
  for (const secret of secrets) safe = safe.split(secret).join('[redacted]');
  return safe;
}
function options(argv) {
  const result = {
    output: null,
    screenshot: path.resolve(repository, '..', '.cloud-onboarding', 'OldServer222', 'traffic-panel.png'),
    chromium: process.env.CHROMIUM_EXECUTABLE_PATH || '/usr/bin/chromium'
  };
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (!['--output', '--screenshot', '--chromium'].includes(key) || !argv[index + 1]) {
      throw new Error('Arguments: [--output report.json] [--screenshot panel.png] [--chromium executable]');
    }
    result[key.slice(2)] = path.resolve(argv[++index]);
  }
  return result;
}

async function fixture() {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'traffic-panel-browser-'));
  const socket = net.createServer();
  socket.listen(0, '127.0.0.1');
  await once(socket, 'listening');
  const { port } = socket.address();
  await new Promise((resolve, reject) => socket.close(error => error ? reject(error) : resolve()));
  const adminToken = randomBytes(32).toString('base64url');
  const aesKey = randomBytes(32).toString('hex');
  secrets.push(adminToken, aesKey);
  const child = spawn(process.execPath, ['server.js'], {
    cwd: repository,
    // Do not accidentally use credentials or Redis connections from the host.
    env: {
      PATH: process.env.PATH,
      NODE_ENV: 'development', PORT: String(port),
      AES_KEY_HEX: aesKey, ADMIN_TOKEN: adminToken,
      DEBUG_SHOW_KEYS_ON_START: '0', DEBUG_ALLOW_PLAINTEXT_KEYS: '0',
      TURNSTILE_SITEKEY: '1x00000000000000000000AA',
      TURNSTILE_SECRET: '1x0000000000000000000000000000000AA',
      TURNSTILE_EXPECT_HOSTNAME: '', ALLOWLIST_DOMAINS: 'example.com',
      REQUIRE_CF_HEADERS: 'false', OPTIONAL_URL_PREFIX: 'campaign',
      RATE_LIMIT_MAX_REQUESTS: '10000', CHALLENGE_VIEW_CAPACITY: '100',
      LOG_TO_FILE: '0', LOG_FILE: path.join(directory, 'visitors.log'),
      RUNTIME_DIAG_DIR: directory, NPM_CONFIG_LOGS_DIR: directory,
      PUBLIC_ENABLE_BACKGROUND: '0', IPINFO_LITE_ENABLED: '0',
      REDIS_URL: '', REDIS_PRIVATE_URL: '', TRAFFIC_METRICS_REDIS_URL: '',
      ANALYTICS_STORAGE_DIR: path.join(directory, 'analytics'),
      RISK_REPORTING_ENABLED: '1', RISK_IP_INTELLIGENCE_ENABLED: '0',
      eSCANNER_CONFIG_URL: '', SHUTDOWN_GRACE_MS: '1000'
    },
    // Startup diagnostics may contain deployment details. Never echo them.
    stdio: ['ignore', 'ignore', 'ignore']
  });
  await once(child, 'spawn');
  const baseUrl = `http://127.0.0.1:${port}`;
  const close = async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit');
      child.kill('SIGTERM');
      const force = setTimeout(() => child.kill('SIGKILL'), 5000);
      await exited;
      clearTimeout(force);
    }
    await fs.rm(directory, { recursive: true, force: true });
  };
  try {
    for (let attempt = 0; ; attempt += 1) {
      assert.equal(child.exitCode, null, 'fixture server exited before startup');
      try {
        const response = await fetch(`${baseUrl}/livez`, { signal: AbortSignal.timeout(1000) });
        await response.arrayBuffer();
        if (response.status === 200) break;
      } catch {}
      if (attempt === 99) throw new Error('Fixture server did not become live');
      await wait(100);
    }
    return { baseUrl, adminToken, close };
  } catch (error) {
    await close();
    throw error;
  }
}

async function main() {
  const config = options(process.argv.slice(2));
  const server = await fixture();
  let browser;
  const checks = [];
  const result = { ok: false, checks, scope: 'Isolated local Chromium and Node server; no hosting proxy or production 499 assertion.' };
  try {
    browser = await chromium.launch({ executablePath: config.chromium, headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
    const context = await browser.newContext({ viewport: { width: 1360, height: 1200 } });
    // Pass-through timer accounting observes cleanup without changing delays.
    await context.addInitScript(() => {
      const pending = new Set();
      const nativeSet = window.setTimeout.bind(window);
      const nativeClear = window.clearTimeout.bind(window);
      window.setTimeout = (callback, delay, ...args) => {
        let id;
        id = nativeSet(() => { pending.delete(id); callback(...args); }, delay);
        pending.add(id);
        return id;
      };
      window.clearTimeout = id => { pending.delete(id); nativeClear(id); };
      Object.defineProperty(window, '__panelHarnessPendingTimers', { get: () => pending.size });
    });
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    const consoleErrors = [];
    const pageErrors = [];
    const requestedUrls = [];
    const pendingRequests = new Set();
    let metricsRequests = 0;
    let maximumConcurrent = 0;
    let injectedFailure = false;
    page.on('console', message => {
      if (message.type() !== 'error') return;
      // Chromium reports intentional fault-injection statuses as resource errors.
      if (injectedFailure && /Failed to load resource:.*(?:401|403|503|net::ERR_ABORTED)/.test(message.text())) return;
      consoleErrors.push(safeText(message.text()));
    });
    page.on('pageerror', error => pageErrors.push(safeText(error.message)));
    page.on('request', request => {
      requestedUrls.push(request.url());
      if (!new URL(request.url()).pathname.endsWith('/admin/traffic-metrics')) return;
      metricsRequests += 1;
      pendingRequests.add(request);
      maximumConcurrent = Math.max(maximumConcurrent, pendingRequests.size);
      assert.equal(request.method(), 'GET', 'panel metrics are read-only');
      assert.ok(request.headers().authorization === `Bearer ${server.adminToken}`, 'metrics use the fixture bearer credential');
    });
    page.on('requestfinished', request => pendingRequests.delete(request));
    page.on('requestfailed', request => pendingRequests.delete(request));
    const loaded = () => page.waitForFunction(() => document.querySelector('[data-role="status"]').textContent.startsWith('Live'));
    const login = async ({ simulateTyping = true } = {}) => {
      if (simulateTyping) {
        await page.locator(role('token')).fill(server.adminToken);
        await page.locator(role('connect')).click();
      } else {
        // Repeated Playwright fill() edits create native Chromium undo-history
        // nodes even on a bare password input without the panel. Stress the
        // same real form handler without adding editor-history allocations.
        await page.locator(role('token')).evaluate((element, credential) => {
          element.value = credential;
          element.form.requestSubmit();
        }, server.adminToken);
      }
      await loaded();
    };
    const timerCount = () => page.evaluate(() => window.__panelHarnessPendingTimers);
    const chartCount = () => page.locator(role('chart')).evaluate(element => element.getAttribute('points').trim().split(/\s+/).filter(Boolean).length);
    const blank = async () => assert.equal(await page.locator(value('requests')).textContent(), '—');
    const panelUrl = `${server.baseUrl}/campaign/admin/traffic-panel`;

    await page.goto(panelUrl, { waitUntil: 'networkidle' });
    assert.equal(metricsRequests, 0, 'locked panel makes no unauthenticated API requests');
    assert.equal(await timerCount(), 0, 'locked panel has no refresh timers');
    await blank();
    const firstMetricsResponse = page.waitForResponse(response => new URL(response.url()).pathname.endsWith('/admin/traffic-metrics') && response.status() === 200);
    await login();
    const firstReport = await (await firstMetricsResponse).json();
    assert.equal(metricsRequests, 1);
    assert.equal(await page.locator(role('token')).inputValue(), '', 'token input is cleared after submit');
    assert.ok(await page.locator(role('token')).isDisabled());
    assert.match(await page.locator(value('requests')).textContent(), /\d/);
    assert.match(await page.locator(value('memory.rss')).textContent(), /\d/);
    assert.equal(await timerCount(), 1, 'exactly one refresh timer after completion');
    const storage = await page.evaluate(() => ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage), cookies: document.cookie }));
    assert.deepEqual(storage, { local: [], session: [], cookies: '' }, 'credentials are not persisted in browser storage');
    assert.equal((await context.cookies()).length, 0);
    assert.ok(!(await page.content()).includes(server.adminToken), 'credential is absent from page HTML');
    assert.equal(consoleErrors.length, 0, 'normal rendering has no CSP or console errors');
    checks.push('Locked state, bearer login, cleared password input, empty URL/cookie/browser storage, CSP and runtime gauges');

    assert.equal(firstReport.diskStorage.configured, true, 'the fixture has isolated disk analytics');
    assert.equal(firstReport.diskStorage.ready, true);
    assert.equal(firstReport.persistent.scope, 'disk');
    await page.locator(role('scope')).selectOption('persistent');
    assert.equal(metricsRequests, 1, 'selecting disk scope uses the report already loaded');
    // Disk totals expose acknowledged checkpoints. The initial empty checkpoint
    // is valid; let the existing five-second save/poll cycle provide a saved
    // report with completed requests rather than forcing writes from the UI.
    let diskReport = firstReport;
    if (!diskReport.persistent.total.requests) {
      const savedResponse = await page.waitForResponse(async response => {
        if (!new URL(response.url()).pathname.endsWith('/admin/traffic-metrics') || response.status() !== 200) return false;
        return (await response.json()).persistent?.total.requests > 0;
      }, { timeout: 15000 });
      diskReport = await savedResponse.json();
      await page.waitForFunction(expected => document.querySelector('[data-value="requests"]').textContent === expected, diskReport.persistent.total.requests.toLocaleString());
    }
    assert.ok(diskReport.persistent.total.requests > 0);
    assert.equal(await page.locator(role('scope-heading')).textContent(), 'Persisted disk totals');
    assert.match(await page.locator(role('scope-note')).textContent(), /do not combine separate replica volumes/);
    assert.equal(await page.locator(value('storage.backends')).textContent(), 'Disk');
    assert.equal(await page.locator(value('disk.state')).textContent(), 'Ready');
    assert.equal(await page.locator(value('requests')).textContent(), diskReport.persistent.total.requests.toLocaleString());
    for (const key of ['mean', 'max']) {
      const expected = `${diskReport.persistent.total.latencyMs[key].toLocaleString(undefined, { maximumFractionDigits: 2 })} ms`;
      assert.equal(await page.locator(value(`latency.${key}`)).textContent(), expected);
    }
    for (const key of ['inFlight', 'latency.p50', 'latency.p95', 'latency.p99', 'latency.samples']) {
      assert.equal(await page.locator(value(key)).textContent(), '—', `disk scope does not imply persisted ${key}`);
    }
    assert.equal(await page.locator(value('memory.rss')).textContent(), diskReport.runtime.memory.rssMb.toLocaleString(undefined, { maximumFractionDigits: 1 }));
    assert.equal(await page.locator(value('runtime.inFlightRequests')).textContent(), diskReport.runtime.inFlightRequests.toLocaleString());
    assert.match(await page.locator(role('campaign-window')).textContent(), /Persisted disk window/);
    assert.match(await page.locator(role('campaign-storage')).textContent(), /Disk ready/);
    checks.push('Isolated disk storage: persisted totals, mean/max, disk status and campaign window; no persisted in-flight/percentile claims; resources remain current process');
    await fs.mkdir(path.dirname(config.screenshot), { recursive: true });
    await page.screenshot({ path: config.screenshot, fullPage: true });
    result.screenshot = config.screenshot;
    await page.locator(role('scope')).selectOption('shared');
    assert.match(await page.locator(role('scope-note')).textContent(), /unavailable/i);
    await blank();
    await page.locator(role('scope')).selectOption('current');
    assert.match(await page.locator(value('requests')).textContent(), /\d/);
    const beforePause = metricsRequests;
    await page.locator(role('pause')).click();
    assert.equal(await timerCount(), 0, 'pause removes polling timer');
    await wait(200);
    assert.equal(metricsRequests, beforePause);
    assert.equal(await page.locator(role('pause')).textContent(), 'Resume');
    await page.locator(role('pause')).click();
    await loaded();
    assert.equal(metricsRequests, beforePause + 1, 'resume refreshes once');
    // Chromium headless tabs are often all visible. Exercise the real browser
    // visibility handler with a synthetic visibilitychange and hidden getter.
    await page.evaluate(() => { Object.defineProperty(document, 'hidden', { configurable: true, get: () => true }); document.dispatchEvent(new Event('visibilitychange')); });
    assert.equal(await timerCount(), 0, 'hidden-tab handler cancels polling');
    assert.match(await page.locator(role('status')).textContent(), /hidden/);
    const beforeVisible = metricsRequests;
    await page.evaluate(() => { delete document.hidden; document.dispatchEvent(new Event('visibilitychange')); });
    await loaded();
    assert.equal(metricsRequests, beforeVisible + 1, 'visible-tab handler performs one refresh');
    checks.push('Scope switching, pause/resume, and browser visibility handler cleanup (synthetic visibility event)');

    for (let sample = 0; sample < 65; sample += 1) {
      const response = page.waitForResponse(response => new URL(response.url()).pathname.endsWith('/admin/traffic-metrics'));
      await page.locator(role('refresh')).click();
      await response;
      await loaded();
    }
    assert.equal(await chartCount(), 60, 'chart history is capped at sixty samples');
    assert.match(await page.locator(role('chart-note')).textContent(), /^60 samples/);
    assert.equal(await timerCount(), 1);
    checks.push('65 manual refreshes retain exactly 60 chart samples and one polling timer');

    await page.locator(role('disconnect')).click();
    await blank();
    assert.equal(await timerCount(), 0);
    await cdp.send('HeapProfiler.collectGarbage');
    const beforeCycles = await cdp.send('Memory.getDOMCounters');
    const heapBefore = await cdp.send('Runtime.getHeapUsage');
    const cycleStart = metricsRequests;
    for (let cycle = 0; cycle < 50; cycle += 1) {
      await login({ simulateTyping: false });
      assert.equal(await timerCount(), 1);
      await page.locator(role('disconnect')).click();
      assert.equal(await timerCount(), 0, 'disconnect removes all timers');
      await blank();
      assert.equal(await chartCount(), 0, 'disconnect clears samples');
    }
    assert.equal(metricsRequests - cycleStart, 50, 'each connect/disconnect cycle performs one bounded request');
    await cdp.send('HeapProfiler.collectGarbage');
    const afterCycles = await cdp.send('Memory.getDOMCounters');
    const heapAfter = await cdp.send('Runtime.getHeapUsage');
    assert.ok(afterCycles.nodes <= beforeCycles.nodes + 20, `DOM nodes remain bounded across reconnects: before=${beforeCycles.nodes}, after=${afterCycles.nodes}, listeners=${beforeCycles.jsEventListeners}/${afterCycles.jsEventListeners}, heap=${heapBefore.usedSize}/${heapAfter.usedSize}`);
    assert.ok(afterCycles.jsEventListeners <= beforeCycles.jsEventListeners + 2, 'event listeners do not accumulate');
    assert.ok(heapAfter.usedSize <= heapBefore.usedSize + 2 * 1024 * 1024, 'retained browser heap remains bounded over reconnects');
    result.reconnects = { count: 50, before: beforeCycles, after: afterCycles, heapBeforeBytes: heapBefore.usedSize, heapAfterBytes: heapAfter.usedSize };
    checks.push('50 connect/disconnect cycles: bounded DOM, listeners, retained heap, requests, samples and zero disconnected timers');

    injectedFailure = true;
    await login();
    const routePattern = '**/admin/traffic-metrics';
    const rejected = async route => route.fulfill({ status: 401, body: 'Unauthorized' });
    await page.route(routePattern, rejected);
    await page.locator(role('refresh')).click();
    await page.waitForFunction(() => document.querySelector('[data-role="status"]').textContent.includes('Authentication rejected'));
    await blank();
    assert.equal(await timerCount(), 0, '401 clears credential and stops automatic retries');
    assert.equal(await page.locator(role('token')).inputValue(), '');
    assert.ok(await page.locator(role('disconnect')).isDisabled());
    await page.unroute(routePattern, rejected);
    checks.push('Authentication rejection clears the session and stops all polling');

    // A deliberately stalled response tests real AbortController timeout and
    // failure backoff without changing production controller timings.
    await login();
    const previousCount = await page.locator(value('requests')).textContent();
    let releaseStall;
    const stalled = new Promise(resolve => { releaseStall = resolve; });
    const slow = async route => { await stalled; await route.fulfill({ status: 503, body: 'Injected unavailable response' }).catch(() => {}); };
    await page.route(routePattern, slow);
    const timeoutStart = Date.now();
    const beforeStall = metricsRequests;
    await page.locator(role('refresh')).click();
    await page.waitForFunction(() => document.querySelector('[data-role="status"]').textContent.includes('timed out after 8 seconds'), null, { timeout: 11000 });
    result.timeoutObservedMs = Date.now() - timeoutStart;
    assert.ok(result.timeoutObservedMs >= 7500 && result.timeoutObservedMs < 11000, '8-second timeout is enforced');
    assert.equal(metricsRequests, beforeStall + 1, 'slow response does not spawn overlapping requests');
    assert.equal(await page.locator(value('requests')).textContent(), previousCount, 'failure preserves the last report');
    assert.match(await page.locator(role('last-success')).textContent(), /stale/);
    assert.equal(await timerCount(), 1, 'backoff has exactly one retry timer');
    await wait(1000);
    assert.equal(metricsRequests, beforeStall + 1, 'failure does not retry immediately');
    releaseStall();
    await page.unroute(routePattern, slow);
    // The first automatic retry occurs ten seconds after failure.
    const retryResponse = page.waitForResponse(response => new URL(response.url()).pathname.endsWith('/admin/traffic-metrics'), { timeout: 12000 });
    await retryResponse;
    await loaded();
    assert.ok(Date.now() - timeoutStart >= 17000, 'automatic retry respects 10-second initial backoff');
    checks.push('Real 8-second fetch timeout, last-report staleness, one pending request and 10-second automatic retry backoff');

    let releaseLate;
    const late = new Promise(resolve => { releaseLate = resolve; });
    let lateStarted;
    const lateRequest = new Promise(resolve => { lateStarted = resolve; });
    const delayed = async route => {
      lateStarted();
      const response = await route.fetch();
      const body = await response.json();
      body.total.requests = 999999999;
      await late;
      await route.fulfill({ response, json: body }).catch(() => {});
    };
    await page.route(routePattern, delayed);
    await page.locator(role('refresh')).click();
    await lateRequest;
    await page.locator(role('disconnect')).click();
    releaseLate();
    await wait(250);
    await blank();
    assert.equal(await timerCount(), 0);
    await page.unroute(routePattern, delayed);
    checks.push('Disconnect aborts in-flight work and rejects late responses without stale rendering');

    await login();
    const beforeNavigation = metricsRequests;
    await page.goto('about:blank');
    await wait(5500);
    assert.equal(metricsRequests, beforeNavigation, 'navigation does not leave an orphaned polling request');
    assert.equal(maximumConcurrent, 1, 'the browser never issued overlapping metrics requests');
    assert.ok(requestedUrls.every(url => !url.includes(server.adminToken)), 'credential never appears in URLs');
    assert.equal(pageErrors.length, 0, 'no uncaught browser errors');
    assert.equal(consoleErrors.length, 0, `no unexpected browser console errors: ${consoleErrors.join('; ')}`);
    checks.push('Navigation cleanup, at most one metrics request in flight, no uncaught browser or CSP errors');
    result.totalMetricsRequests = metricsRequests;
    result.maximumConcurrent = maximumConcurrent;
    result.consoleErrors = consoleErrors.length;
    result.pageErrors = pageErrors.length;
    result.ok = true;
  } finally {
    if (browser) await browser.close();
    await server.close();
  }
  if (config.output) {
    await fs.mkdir(path.dirname(config.output), { recursive: true });
    await fs.writeFile(config.output, `${safeText(JSON.stringify(result, null, 2))}\n`);
  }
  process.stdout.write(`${safeText(JSON.stringify(result, null, 2))}\n`);
}

main().catch(error => {
  process.stderr.write(`${safeText(error.stack || error)}\n`);
  process.exitCode = 1;
});
