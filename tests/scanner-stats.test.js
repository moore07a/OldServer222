'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function loadScannerStatsHelpers() {
  const source = fs.readFileSync('modules/server-runtime/serverRuntime.js', 'utf8');
  const start = source.indexOf('function buildOpsScannerStatsForDay(day = utcDayStamp())');
  const end = source.indexOf('\nfunction hashUAForStats', start);
  if (start < 0 || end < 0 || end <= start) {
    throw new Error('Could not locate scanner stats helper region in server.js');
  }

  const snippet = `
    const OPS_METRICS = { frictionByDay: Object.create(null) };
    function utcDayStamp() { return '2026-06-11'; }
    ${source.slice(start, end)}
    this.__loaded = { OPS_METRICS, buildOpsScannerStatsForDay, selectScannerStatsForResponse };
  `;
  const sandbox = { Object, Number };
  vm.createContext(sandbox);
  vm.runInContext(snippet, sandbox);
  return sandbox.__loaded;
}

test('scanner stats response uses ops reasons when ops total is selected', () => {
  const { selectScannerStatsForResponse } = loadScannerStatsHelpers();
  const logStats = {
    total: 2,
    byReason: { interstitial: 2 }
  };
  const opsStats = {
    total: 15,
    byReason: { nested_probe: 12, prefix_probe: 3 }
  };

  const selected = selectScannerStatsForResponse(logStats, opsStats);
  assert.equal(selected.total, 15);
  assert.deepEqual(Object.fromEntries(Object.entries(selected.byReason)), { nested_probe: 12, prefix_probe: 3 });
});

test('scanner stats response falls back to log reasons when ops total is empty', () => {
  const { selectScannerStatsForResponse } = loadScannerStatsHelpers();
  const logStats = {
    total: 2,
    byReason: { interstitial: 2 }
  };
  const opsStats = {
    total: 0,
    byReason: { nested_probe: 12 }
  };

  const selected = selectScannerStatsForResponse(logStats, opsStats);
  assert.equal(selected.total, 2);
  assert.deepEqual(Object.fromEntries(Object.entries(selected.byReason)), { interstitial: 2 });
});

test('ops scanner stats extracts scanner_block_reason counters', () => {
  const { OPS_METRICS, buildOpsScannerStatsForDay } = loadScannerStatsHelpers();
  OPS_METRICS.frictionByDay['2026-06-11'] = {
    scanner_block_total: 7,
    scanner_block_reason_prefix_probe: 4,
    scanner_block_reason_nested_probe: 3,
    status_404: 10
  };

  const stats = buildOpsScannerStatsForDay('2026-06-11');
  assert.equal(stats.total, 7);
  assert.deepEqual(Object.fromEntries(Object.entries(stats.byReason)), { prefix_probe: 4, nested_probe: 3 });
});
