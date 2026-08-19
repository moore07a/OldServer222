"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const createSharedHeadProbeStore = require("../modules/scanner-security/sharedHeadProbeStore.js");

test("shared HEAD probe store correlates identities through Redis TTL keys", async () => {
  const values = new Map();
  const client = {
    async set(key, value, mode, ttl) {
      values.set(key, { value, mode, ttl });
    },
    async exists(key) {
      return values.has(key) ? 1 : 0;
    }
  };
  const storeA = createSharedHeadProbeStore({ client, crypto, ttlMs: 120000, now: () => 1000 });
  const storeB = createSharedHeadProbeStore({ client, crypto, ttlMs: 120000, now: () => 1000 });

  assert.equal(await storeB.has("198.51.100.7"), false);
  assert.equal(await storeA.remember("198.51.100.7", 1000), true);
  assert.equal(await storeB.has("198.51.100.7"), true);
  assert.equal([...values.values()][0].mode, "PX");
  assert.equal([...values.values()][0].ttl, 120000);
  assert.doesNotMatch([...values.keys()][0], /198\.51\.100\.7/);
});

test("shared HEAD probe TTL ends exactly one window after the observed HEAD", async () => {
  let clock = 61000;
  let writtenTtl = 0;
  const client = {
    async set(_key, _value, _mode, ttl) { writtenTtl = ttl; },
    async exists() { return 0; }
  };
  const store = createSharedHeadProbeStore({ client, crypto, ttlMs: 120000, now: () => clock });

  assert.equal(await store.remember("198.51.100.7", 31000), true);
  assert.equal(writtenTtl, 90000);
  clock = 151001;
  assert.equal(await store.remember("198.51.100.7", 31000), false);
});

test("shared HEAD probe store degrades safely without Redis", async () => {
  const store = createSharedHeadProbeStore({ client: null, crypto, ttlMs: 120000 });
  assert.equal(store.enabled, false);
  assert.equal(await store.remember("198.51.100.7"), false);
  assert.equal(await store.has("198.51.100.7"), false);
});

test("shared HEAD probe store fails fast while ioredis is disconnected", async () => {
  let commands = 0;
  const client = {
    status: "reconnecting",
    async set() { commands += 1; },
    async exists() { commands += 1; return 1; }
  };
  const store = createSharedHeadProbeStore({ client, crypto, ttlMs: 120000 });

  assert.equal(store.isReady(), false);
  assert.equal(await store.remember("198.51.100.7"), false);
  assert.equal(await store.has("198.51.100.7"), false);
  assert.equal(commands, 0);
});
