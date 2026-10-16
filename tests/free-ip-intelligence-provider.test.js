"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const createProvider = require("../modules/risk-assessment/freeIpIntelligenceProvider.js");
const createCache = require("../modules/risk-assessment/ipIntelligenceCache.js");

const PUBLIC_IP = "8.8.8.8";
const json = value => new Response(JSON.stringify(value), { headers: { "content-type": "application/json" } });
const flush = async () => { for (let step = 0; step < 32; step++) await Promise.resolve(); };

function composition(fetch) {
  let serial = 0;
  const timers = new Map();
  const provider = createProvider({ enabled: true, fetch });
  const cache = createCache({ enabled: true, lookup: provider.lookup, maxQueue: 3, concurrency: 2,
    timeoutMs: 10, negativeTtlMs: 60000,
    setTimeout(callback) { const id = ++serial; timers.set(id, callback); return id; },
    clearTimeout(id) { timers.delete(id); }
  });
  return { provider, cache, timers, async expire() {
    for (const [id, callback] of [...timers]) { timers.delete(id); callback(); }
    await flush();
  } };
}

test("free intelligence is opt-in and requires the fixed supported provider", async () => {
  let calls = 0;
  const fetch = () => { calls += 1; return json({}); };
  const disabled = createProvider({ fetch });
  assert.equal(await disabled.lookup(PUBLIC_IP), null);
  assert.equal(disabled.getStatus().enabled, false);
  const unsupported = createProvider({ enabled: true, provider: "https://attacker.invalid/", fetch });
  assert.equal(await unsupported.lookup(PUBLIC_IP), null);
  assert.equal(unsupported.getStatus().configured, false);
  assert.equal(calls, 0);
});

test("free intelligence uses HTTPS without redirects or credentials and normalizes documented flags", async () => {
  const calls = [];
  const provider = createProvider({ enabled: true, fetch: async (url, options) => {
    calls.push({ url, options });
    return json({ is_datacenter: false, is_proxy: true, is_vpn: false, is_residential_proxy: true,
      company: { type: "isp" }, ip: PUBLIC_IP, message: "not retained" });
  } });
  assert.deepEqual(await provider.lookup(PUBLIC_IP), {
    hosting: false, proxy: true, vpn: false, residentialProxy: null, source: "ipapi.is",
  });
  assert.equal(calls[0].url, "https://api.ipapi.is/?q=8.8.8.8");
  assert.equal(calls[0].options.redirect, "error");
  assert.equal(calls[0].options.credentials, "omit");
  assert.equal(calls[0].options.cache, "no-store");
  assert.equal(calls[0].options.referrerPolicy, "no-referrer");
  assert.equal(provider.getStatus().remaining, 899);
  assert.doesNotMatch(JSON.stringify(provider.getStatus()), /8\.8\.8\.8|not retained/);
});

test("free intelligence reports absent or null flags as unavailable without inventing coverage", async () => {
  for (const payload of [{}, { is_datacenter: null, is_proxy: null, is_vpn: null },
    { data: { is_datacenter: true }, message: "private text never retained" }]) {
    const provider = createProvider({ enabled: true, fetch: async () => json(payload) });
    assert.deepEqual(await provider.lookup(PUBLIC_IP), {
      state: "unknown", reason: "indicators_unavailable",
      hosting: null, proxy: null, vpn: null, residentialProxy: null, source: "ipapi.is",
    });
    const status = provider.getStatus();
    assert.equal(status.lastResult, "unknown");
    assert.equal(status.unknownReason, "indicators_unavailable");
    assert.equal(status.failureCode, null);
    assert.equal(status.lastHttpStatus, 200);
    assert.deepEqual(status.indicatorTypes, Object.fromEntries(["is_datacenter", "is_proxy", "is_vpn"]
      .map(field => [field, Object.hasOwn(payload, field) ? "null" : "absent"])));
    assert.doesNotMatch(JSON.stringify(status), /private|message|"data":|8\.8\.8\.8/);
  }
});

test("free intelligence keeps false boolean indicators known and exposes only fixed type summaries", async () => {
  const provider = createProvider({ enabled: true, fetch: async () => json({ is_datacenter: false, is_vpn: null,
    ip: PUBLIC_IP, token: "private-value", other: { user: "private-person" } }) });
  assert.deepEqual(await provider.lookup(PUBLIC_IP), {
    hosting: false, proxy: null, vpn: null, residentialProxy: null, source: "ipapi.is",
  });
  const status = provider.getStatus();
  assert.equal(status.lastResult, "known");
  assert.equal(status.unknownReason, null);
  assert.deepEqual(status.indicatorTypes, { is_datacenter: "boolean", is_proxy: "absent", is_vpn: "null" });
  status.indicatorTypes.is_datacenter = "private-mutation";
  assert.equal(provider.getStatus().indicatorTypes.is_datacenter, "boolean");
  assert.doesNotMatch(JSON.stringify(provider.getStatus()), /private|token|user|8\.8\.8\.8/);
});

test("free intelligence rejects wrong indicator types without coercing them or exposing values", async () => {
  for (const [value, type] of [["false", "string"], [0, "number"], [[], "array"], [{ secret: "private" }, "object"]]) {
    const provider = createProvider({ enabled: true, fetch: async () => json({ is_datacenter: false, is_proxy: value }) });
    await assert.rejects(provider.lookup(PUBLIC_IP), { code: "risk_provider_invalid_indicator_types" });
    const status = provider.getStatus();
    assert.equal(status.lastResult, "error");
    assert.equal(status.unknownReason, null);
    assert.deepEqual(status.indicatorTypes, { is_datacenter: "boolean", is_proxy: type, is_vpn: "absent" });
    assert.doesNotMatch(JSON.stringify(status), /private|secret|8\.8\.8\.8/);
  }
});

test("provider and cache distinguish missing coverage from failure without retrying on panel reads", async t => {
  let requests = 0;
  const h = composition(async () => { requests += 1; return json({ company: { type: "isp" } }); });
  t.after(() => h.cache.close());
  assert.equal(h.cache.observe(PUBLIC_IP).state, "pending");
  await flush();
  assert.equal(h.cache.observe(PUBLIC_IP).state, "unknown");
  assert.equal(h.cache.observe(PUBLIC_IP).hosting, null);
  for (let count = 0; count < 36; count++) { h.cache.getStatus(); h.provider.getStatus(); }
  assert.equal(requests, 1);
  const status = h.cache.getStatus();
  assert.equal(status.failed, 0);
  assert.equal(status.unknownResponses, 1);
  assert.equal(status.lastUnknownReason, "indicators_unavailable");
  assert.equal(status.lastError, null);
  assert.equal(status.active, 0);
  assert.equal(h.timers.size, 0);
});

test("free intelligence rejects invalid IPs without spending budget or issuing requests", async () => {
  let calls = 0;
  const provider = createProvider({ enabled: true, fetch: () => { calls += 1; } });
  for (const ip of ["https://attacker.invalid/", "8.8.8.8&key=secret", "", "fe80::1%eth0", null]) {
    await assert.rejects(provider.lookup(ip), { code: "risk_provider_invalid_ip" });
  }
  assert.equal(calls, 0);
  assert.equal(provider.getStatus().used, 0);
});

test("free intelligence enforces a rolling 24-hour budget across concurrent calls and failures", async () => {
  let clock = 0;
  let calls = 0;
  const provider = createProvider({ enabled: true, dailyBudget: 2, now: () => clock,
    fetch: async () => { calls += 1; throw new Error("sensitive IP and URL"); } });
  const results = await Promise.allSettled([provider.lookup(PUBLIC_IP), provider.lookup(PUBLIC_IP), provider.lookup(PUBLIC_IP)]);
  assert.deepEqual(results.map(result => result.reason.code), ["risk_provider_network", "risk_provider_network", "risk_provider_budget_exhausted"]);
  assert.equal(calls, 2);
  assert.equal(provider.getStatus().remaining, 0);
  clock = 86400000 - 1;
  assert.equal(provider.getStatus().resetAfterSec, 1);
  await assert.rejects(provider.lookup(PUBLIC_IP), { code: "risk_provider_budget_exhausted" });
  clock += 1;
  await assert.rejects(provider.lookup(PUBLIC_IP), { code: "risk_provider_network" });
  assert.equal(calls, 3);
  assert.equal(provider.getStatus().used, 1);
  assert.equal(provider.getStatus().quotaScope, "process");
  assert.equal(createProvider({ enabled: true, dailyBudget: 99999 }).getStatus().dailyBudget, 1000);
});

test("free intelligence suppresses upstream status messages and rejects redirects", async () => {
  for (const [status, code] of [[429, "risk_provider_rate_limited"], [503, "risk_provider_http_error"], [302, "risk_provider_redirect"]]) {
    const provider = createProvider({ enabled: true, fetch: async () => new Response("sensitive response", { status }) });
    await assert.rejects(provider.lookup(PUBLIC_IP), error => {
      assert.equal(error.code, code);
      assert.equal(error.message, code);
      return true;
    });
    assert.equal(provider.getStatus().lastResult, "error");
    assert.equal(provider.getStatus().lastHttpStatus, status);
    assert.equal(provider.getStatus().indicatorTypes, null);
  }
  const provider = createProvider({ enabled: true, fetch: async () => ({ ok: true, status: 200, redirected: true }) });
  await assert.rejects(provider.lookup(PUBLIC_IP), { code: "risk_provider_redirect" });
});

test("free intelligence limits both declared and streamed response bytes", async () => {
  for (const response of [
    () => new Response("{}", { headers: { "content-length": "20000" } }),
    () => new Response(" ".repeat(16385)),
    () => new Response(new ReadableStream({ start(controller) {
      controller.enqueue(new Uint8Array(8000));
      controller.enqueue(new Uint8Array(9000));
      controller.close();
    } })),
  ]) {
    const provider = createProvider({ enabled: true, fetch: async () => response() });
    await assert.rejects(provider.lookup(PUBLIC_IP), { code: "risk_provider_response_too_large" });
  }
});

test("free intelligence distinguishes malformed JSON and API error objects without echoing their content", async () => {
  for (const [response, code] of [[() => new Response("secret invalid body"), "risk_provider_invalid_response"],
    [() => json([]), "risk_provider_invalid_response"], [() => json(null), "risk_provider_invalid_response"],
    [() => json({ error: "secret quota message" }), "risk_provider_api_error"]]) {
    const provider = createProvider({ enabled: true, fetch: async () => response() });
    await assert.rejects(provider.lookup(PUBLIC_IP), error => {
      assert.equal(error.code, code);
      assert.doesNotMatch(error.message, /secret/);
      return true;
    });
    assert.equal(provider.getStatus().lastResult, "error");
  }
});

test("free intelligence honors cooperative fetch cancellation and cancels a stalled native response body", async () => {
  for (const fetch of [
    (_url, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(new Error("sensitive cancellation")), { once: true });
    }),
    async () => new Response(new ReadableStream({ start() {}, cancel() {} })),
  ]) {
    const controller = new AbortController();
    const provider = createProvider({ enabled: true, fetch });
    const request = provider.lookup(PUBLIC_IP, { signal: controller.signal });
    await new Promise(resolve => setImmediate(resolve));
    controller.abort(new Error("sensitive cancellation reason"));
    await assert.rejects(request, { code: "risk_provider_aborted" });
  }
  const controller = new AbortController();
  controller.abort();
  const provider = createProvider({ enabled: true, fetch: () => { throw new Error("must not fetch"); } });
  await assert.rejects(provider.lookup(PUBLIC_IP, { signal: controller.signal }), { code: "risk_provider_aborted" });
  assert.equal(provider.getStatus().used, 0);
});

test("provider and cache retain only two ignored-abort fetches and discard late results", async t => {
  const calls = [];
  let inFlight = 0;
  let peak = 0;
  let cancelledBodies = 0;
  const h = composition((_url, { signal }) => new Promise(resolve => {
    inFlight += 1;
    peak = Math.max(peak, inFlight);
    calls.push({ signal, resolve(value) { inFlight -= 1; resolve(value); } });
  }));
  t.after(() => h.cache.close());
  h.cache.observe("8.8.8.8");
  h.cache.observe("1.1.1.1");
  await flush();
  for (let index = 1; index <= 50; index++) h.cache.observe(`11.0.0.${index}`);
  await h.expire();
  assert.equal(calls.length, 2, "timeouts must not dispatch more ignored-abort fetches");
  assert.ok(calls.every(call => call.signal.aborted));
  assert.equal(h.cache.getStatus().active, 2);
  assert.equal(h.cache.getStatus().queued, 3);
  assert.equal(h.cache.getStatus().queueDropped, 47);
  assert.equal(h.timers.size, 0);
  assert.equal(h.provider.getStatus().used, 2);
  const lateResponse = () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new TextEncoder().encode('{"is_datacenter":true}')); },
    cancel() { cancelledBodies += 1; }
  }));
  calls[0].resolve(lateResponse());
  await flush();
  assert.equal(cancelledBodies, 1);
  assert.equal(calls.length, 3, "one genuinely settled fetch releases exactly one slot");
  assert.equal(peak, 2);
  assert.equal(h.cache.observe("8.8.8.8").state, "unknown", "late success must not replace timeout result");
  assert.equal(h.cache.observe("8.8.8.8").hosting, null);
  assert.equal(h.cache.close(), undefined, "close returns without waiting for ignored cancellation");
  assert.equal(h.cache.getStatus().queued, 0);
  assert.equal(h.timers.size, 0);
  calls[1].resolve(lateResponse());
  calls[2].resolve(lateResponse());
  await flush();
  assert.equal(cancelledBodies, 3);
  assert.equal(calls.length, 3);
  assert.equal(inFlight, 0);
  assert.equal(h.cache.getStatus().active, 0);
  assert.equal(h.cache.getStatus().cacheEntries, 0);
});

test("provider and cache keep ownership until both ignored body reads and cancellation settle", async t => {
  const calls = [];
  const h = composition(async (_url, { signal }) => {
    const call = { signal, cancellations: 0 };
    calls.push(call);
    return { ok: true, status: 200, headers: { get() { return null; } }, body: { getReader() {
      return {
        read() { return new Promise(resolve => { call.finishRead = resolve; }); },
        cancel() { call.cancellations += 1; return new Promise(resolve => { call.finishCancel = resolve; }); },
        releaseLock() { call.released = true; }
      };
    } } };
  });
  t.after(() => h.cache.close());
  h.cache.observe("8.8.8.8");
  h.cache.observe("1.1.1.1");
  await flush();
  for (let index = 1; index <= 20; index++) h.cache.observe(`11.0.0.${index}`);
  await h.expire();
  assert.equal(calls.length, 2);
  assert.equal(h.cache.getStatus().active, 2);
  assert.equal(h.cache.getStatus().queued, 3);
  assert.ok(calls.every(call => call.cancellations === 1 && call.signal.aborted));
  calls[0].finishRead({ done: true });
  await flush();
  assert.equal(calls.length, 2, "settled read with pending cancel still owns its slot");
  assert.equal(h.cache.getStatus().active, 2);
  calls[0].finishCancel();
  await flush();
  assert.equal(calls.length, 3);
  assert.equal(calls[0].released, true);
  assert.equal(h.cache.observe("8.8.8.8").state, "unknown");
  assert.equal(h.cache.close(), undefined);
  assert.equal(h.timers.size, 0);
  for (const call of calls.slice(1)) {
    assert.equal(call.cancellations, 1);
    call.finishRead({ done: true });
    call.finishCancel();
  }
  await flush();
  assert.equal(calls.length, 3);
  assert.equal(h.cache.getStatus().active, 0);
  assert.equal(h.cache.getStatus().queued, 0);
});

test("late aborted fetch responses retain ownership until their body cancellation settles", async () => {
  let resolveFetch;
  let resolveCancel;
  let cancellations = 0;
  const controller = new AbortController();
  const provider = createProvider({ enabled: true, fetch: () => new Promise(resolve => { resolveFetch = resolve; }) });
  const request = provider.lookup(PUBLIC_IP, { signal: controller.signal });
  const rejection = assert.rejects(request, { code: "risk_provider_aborted" });
  let settled = false;
  request.catch(() => { settled = true; });
  controller.abort();
  resolveFetch({ body: { cancel() { cancellations += 1; return new Promise(resolve => { resolveCancel = resolve; }); } } });
  await flush();
  assert.equal(cancellations, 1);
  assert.equal(settled, false);
  resolveCancel();
  await rejection;
  assert.equal(settled, true);
});
