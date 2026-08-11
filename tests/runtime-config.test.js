"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const { DEFAULT_MAX_TIMER_MS, readMsEnv } = require("../modules/runtime-utils/runtimeConfig");

function withEnv(name, value, callback) {
  const previous = process.env[name];
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;

  try {
    return callback();
  } finally {
    if (previous === undefined) delete process.env[name];
    else process.env[name] = previous;
  }
}

test("readMsEnv preserves an operational minimum above a lower timer cap", () => {
  withEnv("TEST_MONITOR_INTERVAL_MS", "1", () => {
    assert.equal(readMsEnv("TEST_MONITOR_INTERVAL_MS", 1000, 250, 50), 250);
  });
});

test("readMsEnv never allows a minimum above the JavaScript timer ceiling", () => {
  withEnv("TEST_MONITOR_INTERVAL_MS", String(DEFAULT_MAX_TIMER_MS + 10_000), () => {
    assert.equal(
      readMsEnv(
        "TEST_MONITOR_INTERVAL_MS",
        DEFAULT_MAX_TIMER_MS,
        DEFAULT_MAX_TIMER_MS + 1,
        DEFAULT_MAX_TIMER_MS + 2
      ),
      DEFAULT_MAX_TIMER_MS
    );
  });
});
