'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function loadClientErrorHelpers() {
  const source = fs.readFileSync('modules/request-runtime/requestRuntime.js', 'utf8');
  const start = source.indexOf('function summarizeError(error, maxLen = 220)');
  const end = source.indexOf('\nlet cpuSnapshot = {', start);
  if (start < 0 || end < 0 || end <= start) {
    throw new Error('Could not locate client error helper region in server.js');
  }

  const snippet = `
    const CLIENT_ERROR_RAW_PACKET_PREVIEW_BYTES = 16;
    function safeLogValue(value, maxLength = 100) {
      return String(value || '')
        .split(String.fromCharCode(13)).join(' ')
        .split(String.fromCharCode(10)).join(' ')
        .trim()
        .substring(0, maxLength);
    }
    ${source.slice(start, end)}
    this.__loaded = {
      summarizeClientError,
      getClientErrorStatusCode,
      getClientErrorStatusMessage,
      isNoisyClientAbortParseError,
      getClientErrorAggregateIp
    };
  `;
  const sandbox = { Buffer, String, Number, Math };
  vm.createContext(sandbox);
  vm.runInContext(snippet, sandbox);
  return sandbox.__loaded;
}

test('clientError diagnostics include parser, packet, and socket context', () => {
  const { summarizeClientError } = loadClientErrorHelpers();
  const error = new Error('Parse Error');
  error.code = 'HPE_INVALID_METHOD';
  error.reason = 'Invalid method encountered';
  error.bytesParsed = 4;
  error.rawPacket = Buffer.from('BAD / HTTP/1.1\r\nHost: example.com\r\n');
  const socket = {
    remoteAddress: '198.51.100.77',
    remotePort: 54231,
    localAddress: '10.0.0.5',
    localPort: 8080,
    bytesRead: 35,
    bytesWritten: 0,
    writable: true,
    destroyed: false
  };

  const summary = summarizeClientError(error, socket);
  assert.match(summary, /code=HPE_INVALID_METHOD/);
  assert.match(summary, /reason=Invalid method encountered/);
  assert.match(summary, /bytesParsed=4/);
  assert.match(summary, /rawLen=35/);
  assert.match(summary, /rawHex=/);
  assert.match(summary, /rawAscii=BAD \/ HTTP\/1\.1/);
  assert.match(summary, /remote=198\.51\.100\.77:54231/);
  assert.match(summary, /local=10\.0\.0\.5:8080/);
  assert.match(summary, /writable=1/);
  assert.match(summary, /destroyed=0/);
});

test('clientError response code maps header overflow to 431', () => {
  const { getClientErrorStatusCode, getClientErrorStatusMessage } = loadClientErrorHelpers();
  assert.equal(getClientErrorStatusCode({ code: 'HPE_HEADER_OVERFLOW' }), 431);
  assert.equal(getClientErrorStatusMessage(431), 'Request Header Fields Too Large');
  assert.equal(getClientErrorStatusCode({ code: 'HPE_INVALID_METHOD' }), 400);
  assert.equal(getClientErrorStatusMessage(400), 'Bad Request');
});


test('clientError helpers classify invalid EOF state as noisy aborts', () => {
  const { isNoisyClientAbortParseError, getClientErrorAggregateIp } = loadClientErrorHelpers();

  assert.equal(isNoisyClientAbortParseError({ code: 'HPE_INVALID_EOF_STATE' }), true);
  assert.equal(isNoisyClientAbortParseError({ code: 'HPE_INVALID_METHOD' }), false);
  assert.equal(getClientErrorAggregateIp({ remoteAddress: '::ffff:100.64.0.19' }), '::ffff:100.64.0.19');
  assert.equal(getClientErrorAggregateIp({}), 'unknown');
});
