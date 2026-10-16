"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const createIpIntelligenceCache = require("../modules/risk-assessment/ipIntelligenceCache.js");

const FLAGS = { hosting: true, vpn: false, proxy: false, residentialProxy: null, source: "test-provider" };
const flush = async () => { for (let step = 0; step < 16; step++) await Promise.resolve(); };

function harness(options = {}) {
  let at = 1000;
  let serial = 0;
  const timers = new Map();
  const calls = [];
  const { lookup, ...configuration } = options;
  const cache = createIpIntelligenceCache({
    enabled: true, ...configuration, now: () => at,
    setTimeout(callback, delay) { const id = ++serial; timers.set(id, { callback, at: at + delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    lookup(ip, context) {
      const call = { ip, signal: context.signal, settled: false };
      calls.push(call);
      if (lookup) return lookup(ip, context);
      return new Promise((resolve, reject) => {
        call.resolve = value => { call.settled = true; resolve(value); };
        call.reject = error => { call.settled = true; reject(error); };
      });
    }
  });
  return {
    cache, calls, timers,
    async advance(milliseconds) {
      const until = at + milliseconds;
      while (true) {
        const next = [...timers].sort((a, b) => a[1].at - b[1].at)[0];
        if (!next || next[1].at > until) break;
        at = next[1].at;
        timers.delete(next[0]);
        next[1].callback();
        await flush();
      }
      at = until;
      await flush();
    },
    async resolve(index, value = FLAGS) { calls[index].resolve(value); await flush(); },
    async reject(index, error = new Error("provider outage")) { calls[index].reject(error); await flush(); }
  };
}

test("disabled or unconfigured intelligence never starts work", async () => {
  let calls = 0;
  for (const configuration of [{ enabled: false, lookup() { calls++; } }, { enabled: true }]) {
    const cache = createIpIntelligenceCache(configuration);
    assert.deepEqual(cache.observe("8.8.8.8"), { state: "disabled", hosting: null, vpn: null, proxy: null, residentialProxy: null, source: null });
    await flush();
    assert.equal(cache.getStatus().enabled, false);
    assert.equal(cache.getStatus().lookups, 0);
    cache.close();
  }
  assert.equal(calls, 0);
});

test("observe is synchronous and defers deduplicated lookups; only cached boolean flags are known", async t => {
  const h = harness();
  t.after(() => h.cache.close());
  assert.equal(h.cache.observe("8.8.8.8").state, "pending");
  assert.equal(h.cache.observe("::FFFF:8.8.8.8").state, "pending");
  assert.equal(h.cache.observe("::ffff:0808:0808").state, "pending");
  assert.equal(h.calls.length, 0, "lookup must not run inside observe");
  assert.equal(h.cache.getStatus().queued, 1);
  await flush();
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].ip, "8.8.8.8");
  await h.resolve(0, { ...FLAGS, residentialProxy: "false" });
  const result = h.cache.observe(" 8.8.8.8 ");
  assert.deepEqual(result, { state: "known", ...FLAGS });
  result.hosting = false;
  assert.equal(h.cache.observe("::ffff:8.8.8.8").hosting, true, "caller mutations must not alter cached intelligence");
  assert.equal(h.cache.getStatus().lookups, 1);
  assert.equal(h.cache.getStatus().deduplicated, 2);
  assert.equal(h.timers.size, 0);
});

test("invalid, private, local, documentation and transition IPs never reach the provider", async t => {
  const h = harness();
  t.after(() => h.cache.close());
  const addresses = [
    null, 123, {}, "", "example.com", "https://8.8.8.8", "8.8.8.8:443", "[2606:4700::1111]",
    "010.0.0.1", "127.1", "0x08080808", "8.8.8.8\n", "fe80::1%eth0", "2001:4860::1%eth0",
    "0.1.2.3", "10.0.0.1", "100.64.0.1", "100.127.255.255", "127.0.0.1",
    "169.254.1.1", "172.16.0.1", "172.31.255.255", "192.0.0.1", "192.0.2.1",
    "192.88.99.1", "192.168.1.1", "198.18.0.1", "198.19.255.255", "198.51.100.1",
    "203.0.113.1", "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255",
    "::", "::1", "::ffff:127.0.0.1", "::ffff:192.168.0.1", "::ffff:cb00:7101",
    "::8.8.8.8", "::ffff:0:8.8.8.8", "fc00::1", "fd12::1", "fe80::1", "fec0::1", "ff02::1",
    "100::1", "64:ff9b::808:808", "64:ff9b:1::1", "2001::1", "2001:100::1",
    "2001:db8::1", "2002:0808:0808::1", "3ffe::1", "3fff:fff::1"
  ];
  for (const address of addresses) assert.equal(h.cache.observe(address).state, "unknown");
  await flush();
  assert.equal(h.calls.length, 0);
  assert.equal(h.cache.getStatus().skipped, addresses.length);
  assert.equal(h.cache.getStatus().cacheEntries, 0);
  assert.equal(h.timers.size, 0);
});

test("public cloud IPs and public range boundaries remain eligible; IPv6 variants share a cache key", async t => {
  const h = harness({ maxQueue: 32, lookup: async () => FLAGS });
  t.after(() => h.cache.close());
  const addresses = [
    "3.5.140.2", "13.32.0.1", "52.95.110.1", "54.239.28.85", "34.160.0.1", "35.190.0.1",
    "100.63.255.255", "100.128.0.0", "172.15.255.255", "172.32.0.0", "192.0.3.1",
    "192.169.0.1", "198.17.255.255", "198.20.0.0", "223.255.255.255", "8.8.8.0", "8.8.8.255"
  ];
  for (const address of addresses) assert.equal(h.cache.observe(address).state, "pending");
  assert.equal(h.cache.observe("2606:4700:4700::1111").state, "pending");
  assert.equal(h.cache.observe("2606:4700:4700:0:0:0:0:1111").state, "pending");
  for (let step = 0; step < 10; step++) await flush();
  assert.deepEqual(h.calls.map(call => call.ip), [...addresses, "2606:4700:4700:0000:0000:0000:0000:1111"]);
  assert.equal(h.cache.observe("2606:4700:4700::1111").state, "known");
  assert.equal(h.cache.getStatus().active, 0);
  assert.equal(h.cache.getStatus().queued, 0);
});

test("positive TTL does not slide on hits and cache entries obey the LRU cap", async t => {
  const h = harness({ maxEntries: 2, ttlMs: 100, lookup: async () => FLAGS });
  t.after(() => h.cache.close());
  h.cache.observe("8.8.8.8"); await flush();
  h.cache.observe("1.1.1.1"); await flush();
  assert.equal(h.cache.observe("8.8.8.8").state, "known");
  h.cache.observe("9.9.9.9"); await flush();
  assert.equal(h.cache.getStatus().cacheEntries, 2);
  assert.equal(h.cache.getStatus().evicted, 1);
  assert.equal(h.cache.observe("1.1.1.1").state, "pending", "the least recently observed entry was evicted");
  await flush();
  await h.advance(99);
  assert.equal(h.cache.observe("1.1.1.1").state, "known");
  await h.advance(1);
  assert.equal(h.cache.observe("1.1.1.1").state, "pending", "a cache hit must not extend TTL");
  await flush();
  assert.ok(h.cache.getStatus().cacheEntries <= 2);
  assert.ok(h.cache.getStatus().expired > 0);
});

test("provider errors use negative TTL, recover, and expose only fixed safe status codes", async t => {
  const h = harness({ negativeTtlMs: 20 });
  t.after(() => h.cache.close());
  h.cache.observe("8.8.8.8"); await flush();
  await h.reject(0, new Error("token=private-test-value https://provider.example/8.8.8.8"));
  assert.deepEqual(h.cache.observe("8.8.8.8"), { state: "unknown", hosting: null, vpn: null, proxy: null, residentialProxy: null, source: null });
  assert.equal(h.cache.getStatus().lastError, "lookup_failed");
  assert.equal(h.cache.getStatus().failed, 1);
  assert.doesNotMatch(JSON.stringify(h.cache.getStatus()), /private-test-value|provider\.example|8\.8\.8\.8|https:/);
  await h.advance(19);
  assert.equal(h.cache.observe("8.8.8.8").state, "unknown");
  assert.equal(h.calls.length, 1);
  await h.advance(1);
  assert.equal(h.cache.observe("8.8.8.8").state, "pending");
  await flush();
  await h.resolve(1, { hosting: false, vpn: false, proxy: false, residentialProxy: false, source: "test-provider" });
  assert.equal(h.cache.observe("8.8.8.8").hosting, false);
  assert.equal(h.cache.getStatus().lastError, null);
  assert.equal(h.cache.getStatus().lookups, 2);
});

test("explicit unavailable indicators use negative TTL without becoming errors or known safe flags", async t => {
  const h = harness({ negativeTtlMs: 20 });
  t.after(() => h.cache.close());
  h.cache.observe("8.8.8.8"); await flush();
  await h.resolve(0, { state: "unknown", reason: "indicators_unavailable", hosting: null, proxy: null,
    vpn: null, residentialProxy: null, source: "ipapi.is", message: "private ignored response" });
  assert.deepEqual(h.cache.observe("8.8.8.8"), { state: "unknown", hosting: null, proxy: null,
    vpn: null, residentialProxy: null, source: "ipapi.is" });
  assert.equal(h.cache.getStatus().unknownResponses, 1);
  assert.equal(h.cache.getStatus().failed, 0);
  assert.equal(h.cache.getStatus().lastError, null);
  assert.equal(h.cache.getStatus().lastUnknownReason, "indicators_unavailable");
  assert.doesNotMatch(JSON.stringify(h.cache.getStatus()), /private|message|8\.8\.8\.8/);
  await h.advance(19);
  assert.equal(h.cache.observe("8.8.8.8").state, "unknown");
  assert.equal(h.calls.length, 1);
  await h.advance(1);
  assert.equal(h.cache.observe("8.8.8.8").state, "pending");
  await flush();
  await h.resolve(1, { hosting: false, vpn: false, proxy: false, source: "ipapi.is" });
  assert.equal(h.cache.observe("8.8.8.8").hosting, false);
  assert.equal(h.cache.observe("8.8.8.8").state, "known");
  assert.equal(h.cache.getStatus().lastUnknownReason, null);
  assert.equal(h.cache.getStatus().failed, 0);
  assert.equal(h.cache.getStatus().unknownResponses, 1);
});

test("unavailable indicator metadata cannot mask malformed data or expose arbitrary reasons", async () => {
  for (const value of [{ state: "unknown", reason: "private-message" },
    { state: "unknown", reason: "indicators_unavailable", hosting: "false" },
    { state: "unknown", reason: "indicators_unavailable", hosting: false }]) {
    const h = harness({ lookup: async () => value });
    h.cache.observe("8.8.8.8"); await flush();
    assert.equal(h.cache.getStatus().unknownResponses, 0);
    assert.equal(h.cache.getStatus().failed, 1);
    assert.equal(h.cache.getStatus().lastUnknownReason, null);
    assert.equal(h.cache.getStatus().lastError, "invalid_response");
    assert.doesNotMatch(JSON.stringify(h.cache.getStatus()), /private-message/);
    h.cache.close();
  }
});

test("empty or malformed provider data remains unknown, and source URLs are not returned", async t => {
  for (const value of [null, undefined, {}, { hosting: "true" }, { vpn: 1 }]) {
    const h = harness({ lookup: async () => value });
    h.cache.observe("8.8.8.8"); await flush();
    assert.equal(h.cache.observe("8.8.8.8").state, "unknown");
    assert.equal(h.cache.getStatus().lastError, "invalid_response");
    h.cache.close();
  }
  const h = harness({ lookup: async () => ({ hosting: true, source: "https://private.example/token" }) });
  t.after(() => h.cache.close());
  h.cache.observe("8.8.8.8"); await flush();
  assert.equal(h.cache.observe("8.8.8.8").source, null);
  const branded = harness({ lookup: async () => ({ hosting: true, source: "ipapi.is" }) });
  t.after(() => branded.cache.close());
  branded.cache.observe("1.1.1.1"); await flush();
  assert.equal(branded.cache.observe("1.1.1.1").source, "ipapi.is");
});

test("queue and concurrency limits apply before dispatch, including duplicate active and queued requests", async t => {
  const h = harness({ maxQueue: 2, concurrency: 1 });
  t.after(() => h.cache.close());
  assert.equal(h.cache.observe("8.8.8.8").state, "pending");
  assert.equal(h.cache.observe("1.1.1.1").state, "pending");
  assert.equal(h.cache.observe("9.9.9.9").state, "unknown");
  assert.equal(h.calls.length, 0);
  assert.equal(h.cache.getStatus().queued, 2);
  await flush();
  h.cache.observe("8.8.8.8"); h.cache.observe("1.1.1.1");
  assert.equal(h.cache.observe("9.9.9.9").state, "pending");
  assert.equal(h.cache.observe("4.2.2.2").state, "unknown");
  assert.equal(h.cache.getStatus().queued, 2);
  assert.equal(h.cache.getStatus().active, 1);
  assert.equal(h.cache.getStatus().deduplicated, 2);
  assert.equal(h.cache.getStatus().queueDropped, 2);
  await h.resolve(0);
  assert.equal(h.calls.length, 2);
  assert.equal(h.cache.getStatus().active, 1);
  await h.resolve(1); await h.resolve(2);
  assert.equal(h.cache.getStatus().active, 0);
  assert.equal(h.cache.getStatus().queued, 0);
  assert.equal(h.timers.size, 0);
});

test("cooperative lookup timeouts abort the whole operation and cache unknown once", async t => {
  const h = harness({ timeoutMs: 10, lookup: (_ip, { signal }) => new Promise((_resolve, reject) => {
    signal.addEventListener("abort", () => reject(new Error("secret-provider-timeout")), { once: true });
  }) });
  t.after(() => h.cache.close());
  h.cache.observe("8.8.8.8"); await flush();
  await h.advance(10);
  assert.equal(h.calls[0].signal.aborted, true);
  assert.equal(h.cache.observe("8.8.8.8").state, "unknown");
  const status = h.cache.getStatus();
  assert.equal(status.failed, 1);
  assert.equal(status.timeouts, 1);
  assert.equal(status.lastError, "lookup_timeout");
  assert.equal(status.active, 0);
  assert.equal(h.timers.size, 0);
});

test("timeouts retain real concurrency slots when lookup ignores abort, and close never waits for it", async () => {
  const h = harness({ timeoutMs: 10, negativeTtlMs: 3, maxQueue: 3, concurrency: 100 });
  h.cache.observe("8.8.8.8"); h.cache.observe("1.1.1.1"); h.cache.observe("9.9.9.9");
  await flush();
  h.cache.observe("4.2.2.2"); h.cache.observe("8.8.4.4");
  assert.equal(h.cache.getStatus().limits.concurrency, 2);
  await h.advance(10);
  assert.equal(h.cache.getStatus().active, 2);
  assert.equal(h.cache.getStatus().queued, 3);
  assert.equal(h.cache.getStatus().timeouts, 2);
  assert.equal(h.timers.size, 0);
  await h.advance(10);
  for (let repeat = 0; repeat < 20; repeat++) {
    assert.equal(h.cache.observe("8.8.8.8").state, "unknown");
    assert.equal(h.cache.observe("1.1.1.1").state, "unknown");
    assert.equal(h.cache.observe("208.67.222.222").state, "unknown");
  }
  await flush();
  assert.equal(h.calls.length, 2, "timeouts and retries cannot start extra real requests");
  await h.resolve(0, FLAGS);
  assert.equal(h.calls.length, 3, "settling one real promise releases exactly one slot");
  await h.reject(1);
  assert.equal(h.calls.length, 4);
  assert.equal(h.cache.getStatus().failed, 2, "late rejection after timeout is not counted twice");
  assert.equal(h.cache.getStatus().cacheEntries, 0, "late successful timeout results are not cached");
  assert.equal(h.cache.getStatus().active, 2);
  assert.equal(h.cache.close(), undefined, "close is synchronous even with uncooperative lookups");
  assert.equal(h.cache.getStatus().closed, true);
  assert.equal(h.cache.getStatus().queued, 0);
  assert.equal(h.cache.getStatus().cacheEntries, 0);
  assert.equal(h.timers.size, 0);
  assert.equal(h.cache.observe("8.8.8.8").state, "disabled");
  assert.equal(h.calls[2].signal.aborted, true);
  assert.equal(h.calls[3].signal.aborted, true);
  await h.resolve(2); await h.reject(3);
  assert.equal(h.cache.getStatus().active, 0);
  assert.equal(h.cache.getStatus().cacheEntries, 0);
  assert.equal(h.calls.length, 4, "queued work cannot start after close");
});

test("outages keep queue/cache/timers bounded and close cancels a deferred queue before lookup", async () => {
  const h = harness({ maxEntries: 3, maxQueue: 4, lookup: async () => { throw new Error("provider outage"); } });
  for (let wave = 0; wave < 10; wave++) {
    for (let index = 1; index <= 20; index++) h.cache.observe(`8.8.${wave}.${index}`);
    await flush();
    assert.ok(h.cache.getStatus().cacheEntries <= 3);
    assert.ok(h.cache.getStatus().queued <= 4);
    assert.ok(h.cache.getStatus().active <= 2);
  }
  assert.ok(h.cache.getStatus().failed > 0);
  assert.ok(h.cache.getStatus().queueDropped > 0);
  assert.equal(h.timers.size, 0);
  h.cache.close();
  assert.equal(h.cache.getStatus().cacheEntries, 0);
  const deferred = harness();
  deferred.cache.observe("8.8.8.8");
  deferred.cache.close(); deferred.cache.close();
  await flush();
  assert.equal(deferred.calls.length, 0);
  assert.equal(deferred.cache.getStatus().queued, 0);
  assert.equal(deferred.cache.getStatus().cancelled, 1);
  assert.equal(deferred.timers.size, 0);
});
