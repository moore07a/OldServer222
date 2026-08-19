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
  const storeA = createSharedHeadProbeStore({ client, crypto, ttlMs: 120000 });
  const storeB = createSharedHeadProbeStore({ client, crypto, ttlMs: 120000 });

  assert.equal(await storeB.has("198.51.100.7"), false);
  assert.equal(await storeA.remember("198.51.100.7"), true);
  assert.equal(await storeB.has("198.51.100.7"), true);
  assert.equal([...values.values()][0].mode, "PX");
  assert.equal([...values.values()][0].ttl, 120000);
  assert.doesNotMatch([...values.keys()][0], /198\.51\.100\.7/);
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
