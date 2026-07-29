'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function loadParseMinHourToMs() {
  return require('../modules/runtime-utils/parseMinHourToMs.js');
}

test('parseMinHourToMs accepts scanner reload seconds, minutes, hours, and milliseconds', () => {
  const parseMinHourToMs = loadParseMinHourToMs();
  const cases = [
    ['1000', 1000],
    ['1500ms', 1500],
    ['1s', 1000],
    ['5s', 5000],
    ['30s', 30000],
    ['1m', 60000],
    ['5m', 300000],
    ['30m', 1800000],
    ['1h', 3600000],
    ['2h', 7200000],
    ['3h', 10800000]
  ];

  for (const [value, expected] of cases) {
    assert.equal(parseMinHourToMs(value, 60000, 'ms'), expected);
  }
});

test('parseMinHourToMs keeps minute-default behavior for existing callers', () => {
  const parseMinHourToMs = loadParseMinHourToMs();
  assert.equal(parseMinHourToMs('5', 60000), 300000);
  assert.equal(parseMinHourToMs('2h', 60000), 7200000);
  assert.equal(parseMinHourToMs('abc', 60000), 60000);
});


test('scanner reload parser preserves the 10-minute default when unset or blank', () => {
  const parseMinHourToMs = loadParseMinHourToMs();
  assert.equal(parseMinHourToMs(undefined, 600000, 'ms'), 600000);
  assert.equal(parseMinHourToMs('', 600000, 'ms'), 600000);
});
