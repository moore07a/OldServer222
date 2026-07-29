'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function loadLogFunctions(maxLogLines) {
  const source = fs.readFileSync('server.js', 'utf8');
  const start = source.indexOf('function appendInMemoryLog(');
  const end = source.indexOf('// ================== SECURITY & RATE LIMITING', start);
  if (start < 0 || end < 0 || end <= start) {
    throw new Error('Could not locate expected log function region in server.js');
  }

  const snippet = `
    const MAX_LOG_LINES = ${maxLogLines};
    const LOGS = [];
    const LOG_IDS = [];
    let LOG_SEQ = 0;
    const formatLocal = () => 'timestamp';
    const sanitizeOneLine = (value) => String(value);
    const broadcastLog = () => {};
    const appendLogFileLine = () => {};
    ${source.slice(start, end)}
    this.__loaded = { LOGS, LOG_IDS, addLog, addSpacer, analyzeLogIntegrity };
  `;
  const sandbox = { console: { log() {} } };
  vm.createContext(sandbox);
  vm.runInContext(snippet, sandbox);
  return sandbox.__loaded;
}

test('spacer logs obey the in-memory retention cap', () => {
  const { LOGS, LOG_IDS, addSpacer } = loadLogFunctions(3);

  for (let i = 0; i < 10; i += 1) addSpacer();

  assert.equal(LOGS.length, 3);
  assert.deepEqual([...LOGS], ['', '', '']);
  assert.deepEqual([...LOG_IDS], [8, 9, 10]);
});

test('normal and spacer logs share one aligned retention window', () => {
  const { LOGS, LOG_IDS, addLog, addSpacer } = loadLogFunctions(3);

  addLog('first\nsecond');
  addSpacer();
  addLog('third');

  assert.deepEqual([...LOGS], ['[timestamp] second', '', '[timestamp] third']);
  assert.deepEqual([...LOG_IDS], [2, 3, 4]);
});


test('log integrity analyzer detects concatenated and duplicate runtime entries', () => {
  const { analyzeLogIntegrity } = loadLogFunctions(10);

  const result = analyzeLogIntegrity([
    '[07-18-2026 - 01:00:00 AM] [REQ:finish] id=a status=200',
    '[07-18-2026 - 01:00:01 AM] [REQ:finish] id=b status=200[07-18-2026 - 01:00:01 AM] [DEP:finish] span=x status=200',
    '[07-18-2026 - 01:00:02 AM] [SCANNER] ok',
    '[07-18-2026 - 01:00:02 AM] [SCANNER] ok'
  ], [1, 2, 4, 5]);

  assert.equal(result.ok, false);
  assert.equal(result.multiTimestampLines, 1);
  assert.equal(result.multiMarkerLines, 1);
  assert.equal(result.adjacentExactDuplicates, 1);
  assert.equal(result.idGaps, 1);
});

test('log integrity analyzer treats spacer entries separately from corruption', () => {
  const { analyzeLogIntegrity } = loadLogFunctions(10);

  const result = analyzeLogIntegrity([
    '[07-18-2026 - 01:00:00 AM] [REQ:finish] id=a status=200',
    '',
    '[07-18-2026 - 01:00:01 AM] [DEP:finish] span=x status=200'
  ], [1, 2, 3]);

  assert.equal(result.ok, true);
  assert.equal(result.blankSpacerLines, 1);
});
