#!/usr/bin/env node
/*
  Minimal synthetic soak tester for long-running stability checks.
  Usage:
    node tests/soak-test.js --url http://localhost:8080/health --duration-min 30 --concurrency 8 --rps 20
*/

const { performance } = require('perf_hooks');

function parseArgs(argv) {
  const out = {
    url: process.env.SOAK_URL || 'http://127.0.0.1:8080/health',
    durationMin: Number(process.env.SOAK_DURATION_MIN || 30),
    concurrency: Number(process.env.SOAK_CONCURRENCY || 8),
    rps: Number(process.env.SOAK_RPS || 20),
    timeoutMs: Number(process.env.SOAK_TIMEOUT_MS || 8000)
  };

  for (let i = 2; i < argv.length; i += 1) {
    const k = argv[i];
    const v = argv[i + 1];
    if (!k || !k.startsWith('--')) continue;
    if (k === '--url') out.url = String(v || out.url);
    if (k === '--duration-min') out.durationMin = Number(v || out.durationMin);
    if (k === '--concurrency') out.concurrency = Number(v || out.concurrency);
    if (k === '--rps') out.rps = Number(v || out.rps);
    if (k === '--timeout-ms') out.timeoutMs = Number(v || out.timeoutMs);
    i += 1;
  }
  return out;
}

function pct(arr, p) {
  if (!arr.length) return 0;
  const idx = Math.min(arr.length - 1, Math.max(0, Math.floor((p / 100) * arr.length)));
  return arr[idx];
}

async function fetchWithTimeout(url, timeoutMs) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(new Error(`timeout ${timeoutMs}ms`)), timeoutMs);
  try {
    return await fetch(url, { signal: ctl.signal });
  } finally {
    clearTimeout(t);
  }
}

async function main() {
  const cfg = parseArgs(process.argv);
  const durationMs = Math.max(60_000, cfg.durationMin * 60_000);
  const startAt = Date.now();
  const endAt = startAt + durationMs;

  const stats = {
    total: 0,
    ok2xx: 0,
    status4xx: 0,
    status5xx: 0,
    networkErr: 0,
    latency: [],
    sampleHealth: []
  };

  let inFlight = 0;
  const perSecond = Math.max(1, cfg.rps);
  const everyMs = Math.max(20, Math.floor(1000 / perSecond));

  async function runOne() {
    if (Date.now() > endAt) return;
    if (inFlight >= cfg.concurrency) return;
    inFlight += 1;
    const t0 = performance.now();
    try {
      const res = await fetchWithTimeout(cfg.url, cfg.timeoutMs);
      const dt = performance.now() - t0;
      stats.total += 1;
      stats.latency.push(dt);
      if (res.status >= 200 && res.status < 300) stats.ok2xx += 1;
      else if (res.status >= 500) stats.status5xx += 1;
      else if (res.status >= 400) stats.status4xx += 1;

      const ct = String(res.headers.get('content-type') || '').toLowerCase();
      if (ct.includes('application/json')) {
        try {
          const body = await res.json();
          if (body && body.stats && body.stats.memory && body.stats.resources) {
            stats.sampleHealth.push({
              at: new Date().toISOString(),
              rssMb: body.stats.memory.rssMb,
              heapUsedMb: body.stats.memory.heapUsedMb,
              openSockets: body.stats.resources.openSockets,
              sseListeners: body.stats.resources.sseListeners,
              logQueueBytes: body.stats.resources.logFileQueueBytes,
              droppedLogLines: body.stats.resources.logFileDroppedLines,
              inFlightRequests: body.stats.inFlightRequests
            });
            if (stats.sampleHealth.length > 500) stats.sampleHealth.shift();
          }
        } catch {}
      }
    } catch {
      stats.total += 1;
      stats.networkErr += 1;
    } finally {
      inFlight -= 1;
    }
  }

  const tick = setInterval(() => { void runOne(); }, everyMs);
  const reporter = setInterval(() => {
    const sorted = [...stats.latency].sort((a, b) => a - b);
    const p95 = pct(sorted, 95).toFixed(1);
    const p99 = pct(sorted, 99).toFixed(1);
    const errRate = stats.total ? (((stats.status5xx + stats.networkErr) / stats.total) * 100).toFixed(2) : '0.00';
    console.log(`[SOAK] total=${stats.total} 2xx=${stats.ok2xx} 4xx=${stats.status4xx} 5xx=${stats.status5xx} netErr=${stats.networkErr} errRate=${errRate}% p95=${p95}ms p99=${p99}ms inFlight=${inFlight}`);
  }, 60_000);

  await new Promise((resolve) => setTimeout(resolve, durationMs));
  clearInterval(tick);
  clearInterval(reporter);

  while (inFlight > 0) {
    await new Promise((r) => setTimeout(r, 25));
  }

  const sorted = [...stats.latency].sort((a, b) => a - b);
  const result = {
    config: cfg,
    totals: {
      ...stats,
      latency: undefined,
      sampleHealthCount: stats.sampleHealth.length,
      p50Ms: Number(pct(sorted, 50).toFixed(2)),
      p95Ms: Number(pct(sorted, 95).toFixed(2)),
      p99Ms: Number(pct(sorted, 99).toFixed(2)),
      errRatePct: Number((stats.total ? ((stats.status5xx + stats.networkErr) / stats.total) * 100 : 0).toFixed(3))
    },
    sampleHealthTail: stats.sampleHealth.slice(-10)
  };

  console.log(JSON.stringify(result, null, 2));

  // non-zero if significant failures seen
  if (result.totals.errRatePct >= 1) process.exitCode = 2;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
