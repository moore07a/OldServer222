#!/usr/bin/env node
'use strict';

/*
  Scanner-pattern soak tester for local/staging verification.
  Usage:
    node tests/scanner-soak.js --url http://127.0.0.1:8080 --duration-sec 60 --concurrency 16 --rps 40
*/

const { performance } = require('node:perf_hooks');

const DEFAULT_SCANNER_PATHS = [
  '/.env', '/wp-admin/', '/wp-login.php', '/xmlrpc.php', '/phpinfo.php',
  '/config/aws.yml', '/application.properties', '/server/php', '/logs/email.log',
  '/tmp/sendgrid_debug.log', '/templates/emails/welcome.html', '/utils/sendgrid.py',
  '/.git/config', '/actuator/env', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
  '/admin/', '/controlpanel', '/firebase%2ejson', '/%2efirebaserc', '/dnscfg%2ecgi'
];

function parseArgs(argv) {
  const out = {
    url: process.env.SCANNER_SOAK_URL || 'http://127.0.0.1:8080',
    durationSec: Number(process.env.SCANNER_SOAK_DURATION_SEC || 60),
    concurrency: Number(process.env.SCANNER_SOAK_CONCURRENCY || 16),
    rps: Number(process.env.SCANNER_SOAK_RPS || 40),
    timeoutMs: Number(process.env.SCANNER_SOAK_TIMEOUT_MS || 5000)
  };

  for (let i = 2; i < argv.length; i += 1) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key || !key.startsWith('--')) continue;
    if (key === '--url') out.url = String(value || out.url);
    if (key === '--duration-sec') out.durationSec = Number(value || out.durationSec);
    if (key === '--concurrency') out.concurrency = Number(value || out.concurrency);
    if (key === '--rps') out.rps = Number(value || out.rps);
    if (key === '--timeout-ms') out.timeoutMs = Number(value || out.timeoutMs);
    i += 1;
  }

  out.durationSec = Math.max(1, out.durationSec);
  out.concurrency = Math.max(1, out.concurrency);
  out.rps = Math.max(1, out.rps);
  out.timeoutMs = Math.max(250, out.timeoutMs);
  out.url = out.url.replace(/\/+$/, '');
  return out;
}

function percentile(values, p) {
  if (!values.length) return 0;
  const index = Math.min(values.length - 1, Math.max(0, Math.floor((p / 100) * values.length)));
  return values[index];
}

async function fetchWithTimeout(url, timeoutMs, headers) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error(`timeout ${timeoutMs}ms`)), timeoutMs);
  try {
    return await fetch(url, { signal: controller.signal, headers });
  } finally {
    clearTimeout(timer);
  }
}

async function main() {
  const cfg = parseArgs(process.argv);
  const endAt = Date.now() + cfg.durationSec * 1000;
  const stats = {
    total: 0,
    status2xx: 0,
    status3xx: 0,
    status4xx: 0,
    status5xx: 0,
    networkErr: 0,
    byStatus: {},
    latencyMs: []
  };
  let inFlight = 0;
  let pathIndex = 0;

  const everyMs = Math.max(10, Math.floor(1000 / cfg.rps));
  const headers = {
    'user-agent': 'curl/8.7.1 scanner-soak',
    accept: '*/*'
  };

  async function runOne() {
    if (Date.now() >= endAt || inFlight >= cfg.concurrency) return;
    inFlight += 1;
    const path = `${DEFAULT_SCANNER_PATHS[pathIndex % DEFAULT_SCANNER_PATHS.length]}?soak=${Date.now()}-${pathIndex}`;
    pathIndex += 1;
    const started = performance.now();
    try {
      const response = await fetchWithTimeout(`${cfg.url}${path}`, cfg.timeoutMs, headers);
      const elapsed = performance.now() - started;
      stats.total += 1;
      stats.latencyMs.push(elapsed);
      stats.byStatus[response.status] = (stats.byStatus[response.status] || 0) + 1;
      if (response.status >= 200 && response.status < 300) stats.status2xx += 1;
      else if (response.status >= 300 && response.status < 400) stats.status3xx += 1;
      else if (response.status >= 400 && response.status < 500) stats.status4xx += 1;
      else if (response.status >= 500) stats.status5xx += 1;
      try { await response.arrayBuffer(); } catch {}
    } catch {
      stats.total += 1;
      stats.networkErr += 1;
    } finally {
      inFlight -= 1;
    }
  }

  const tick = setInterval(() => { void runOne(); }, everyMs);
  await new Promise(resolve => setTimeout(resolve, cfg.durationSec * 1000));
  clearInterval(tick);
  while (inFlight > 0) await new Promise(resolve => setTimeout(resolve, 25));

  const sorted = stats.latencyMs.sort((a, b) => a - b);
  const result = {
    config: cfg,
    totals: {
      total: stats.total,
      status2xx: stats.status2xx,
      status3xx: stats.status3xx,
      status4xx: stats.status4xx,
      status5xx: stats.status5xx,
      networkErr: stats.networkErr,
      byStatus: stats.byStatus,
      p50Ms: Number(percentile(sorted, 50).toFixed(2)),
      p95Ms: Number(percentile(sorted, 95).toFixed(2)),
      p99Ms: Number(percentile(sorted, 99).toFixed(2)),
      maxMs: Number((sorted[sorted.length - 1] || 0).toFixed(2))
    }
  };

  console.log(JSON.stringify(result, null, 2));
  if (result.totals.networkErr > 0 || result.totals.status5xx > 0 || result.totals.p99Ms > cfg.timeoutMs * 0.8) {
    process.exitCode = 2;
  }
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});
