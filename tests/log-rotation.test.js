'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');

function loadRotationHelpers() {
  const source = fs.readFileSync('modules/server-runtime/serverRuntime.js', 'utf8');
  const start = source.indexOf('function pruneLogArchives(');
  const end = source.indexOf('\nfunction rotateLogFileStream(', start);
  if (start < 0 || end < 0 || end <= start) {
    throw new Error('Could not locate rotation helpers in server.js');
  }

  const sandbox = {
    Buffer,
    fs,
    path,
    LOG_FILE: 'visitors.log',
    LOG_FILE_MAX_BYTES: 100,
    LOG_FILE_MAX_FILES: 3,
    ensureParentDirectoryForFile(filePath) {
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      return true;
    }
  };
  vm.createContext(sandbox);
  vm.runInContext(`${source.slice(start, end)}\nthis.__loaded = { pruneLogArchives, rotateLogFiles, appendLogChunksSync };`, sandbox);
  return sandbox.__loaded;
}

const { rotateLogFiles, appendLogChunksSync } = loadRotationHelpers();

function withTempDir(run) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'log-rotation-'));
  try { return run(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

test('rotates the active log and retains only the configured archives', () => {
  withTempDir((dir) => {
    const file = path.join(dir, 'visitors.log');
    fs.writeFileSync(file, 'active');
    fs.writeFileSync(`${file}.1`, 'one');
    fs.writeFileSync(`${file}.2`, 'two');
    fs.writeFileSync(`${file}.3`, 'three');

    rotateLogFiles(file, 3);

    assert.equal(fs.existsSync(file), false);
    assert.equal(fs.readFileSync(`${file}.1`, 'utf8'), 'active');
    assert.equal(fs.readFileSync(`${file}.2`, 'utf8'), 'one');
    assert.equal(fs.readFileSync(`${file}.3`, 'utf8'), 'two');
    assert.equal(fs.existsSync(`${file}.4`), false);
  });
});

test('prunes archives above a reduced retention count', () => {
  withTempDir((dir) => {
    const file = path.join(dir, 'visitors.log');
    fs.writeFileSync(file, 'active');
    for (let index = 1; index <= 5; index += 1) {
      fs.writeFileSync(`${file}.${index}`, String(index));
    }

    rotateLogFiles(file, 3);

    assert.equal(fs.existsSync(`${file}.4`), false);
    assert.equal(fs.existsSync(`${file}.5`), false);
    assert.equal(fs.readFileSync(`${file}.3`, 'utf8'), '2');
  });
});

test('does nothing when there is no active log file', () => {
  withTempDir((dir) => {
    const file = path.join(dir, 'visitors.log');
    fs.writeFileSync(`${file}.1`, 'existing archive');

    rotateLogFiles(file, 3);

    assert.equal(fs.readFileSync(`${file}.1`, 'utf8'), 'existing archive');
  });
});

test('synchronous shutdown flush rotates instead of exceeding the size limit', () => {
  withTempDir((dir) => {
    const file = path.join(dir, 'visitors.log');
    fs.writeFileSync(file, '12345678');

    const activeSize = appendLogChunksSync(['abcd', 'efgh'], file, 10, 2);

    assert.equal(activeSize, 8);
    assert.equal(fs.readFileSync(`${file}.1`, 'utf8'), '12345678');
    assert.equal(fs.readFileSync(file, 'utf8'), 'abcdefgh');
    assert.ok(fs.statSync(file).size <= 10);
  });
});

function loadRotateLogFileStream() {
  const source = fs.readFileSync('modules/server-runtime/serverRuntime.js', 'utf8');
  const start = source.indexOf('function rotateLogFileStream(');
  const end = source.indexOf('\nfunction ensureLogFileStream(', start);
  const calls = [];
  const sandbox = {
    Date,
    LOG_TO_FILE: true,
    logFileWriterClosed: false,
    logFileRotationPending: false,
    logFileRotationPromise: null,
    logFileDrainPending: false,
    logFileStream: null,
    logFileBytes: 100,
    logFileRotations: 0,
    logFileRetryAt: 0,
    logFileLastError: null,
    LOG_FILE_RETRY_DELAY_MS: 1000,
    LOG_FILE: 'visitors.log',
    rotateLogFiles() { calls.push('rotate'); },
    flushLogFileQueue() { calls.push('flush'); },
    summarizeError(error) { return String(error); },
    safeLogValue(value) { return String(value); },
    console: { error() {} }
  };
  vm.createContext(sandbox);
  vm.runInContext(`${source.slice(start, end)}\nthis.__loaded = rotateLogFileStream;`, sandbox);
  return { rotateLogFileStream: sandbox.__loaded, calls };
}

test('waits for the stream close event before renaming the active log', async () => {
  const { rotateLogFileStream, calls } = loadRotateLogFileStream();
  const stream = new EventEmitter();
  stream.end = () => stream.emit('finish');

  const rotation = rotateLogFileStream(stream);
  assert.deepEqual(calls, []);

  stream.emit('close');
  await rotation;
  assert.deepEqual(calls, ['rotate', 'flush']);
});
