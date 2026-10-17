"use strict";

const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { createCipheriv, createHash, randomBytes, randomUUID } = require("node:crypto");
const { once } = require("node:events");
const fs = require("node:fs/promises");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const DESTINATION = "https://landing.example.test/welcome";
const BROWSER = {
  "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
  accept: "text/html,application/xhtml+xml", "accept-language": "en-US,en;q=0.9",
  "sec-ch-ua": '"Chromium";v="126"', "sec-fetch-site": "none",
  "sec-fetch-mode": "navigate", "sec-fetch-dest": "document"
};
const PROFILES = {
  "8.8.8.8": { is_vpn: true, is_datacenter: false, is_proxy: false },
  "9.9.9.9": { is_vpn: false, is_datacenter: true, is_proxy: false },
  "4.2.2.2": { is_vpn: true, is_datacenter: true, is_proxy: true },
  "1.1.1.1": { is_vpn: false, is_datacenter: false, is_proxy: false },
  "94.140.14.14": { is_datacenter: false },
  "208.67.220.220": null,
  "208.67.222.222": "failure"
};

function encrypt(url, key) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const bytes = Buffer.concat([cipher.update(url, "utf8"), cipher.final()]);
  return Buffer.concat([iv, bytes, cipher.getAuthTag()]).toString("base64url");
}

async function fixture(t, { vpn = true, datacenter = false, enabled = true,
  dailyBudget = 900, providerDelay = 50, stallProvider = false, extraProfiles = {}, extraEnv = {} } = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "network-policy-http-"));
  const listener = net.createServer();
  listener.listen(0, "127.0.0.1");
  await once(listener, "listening");
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  const key = randomBytes(32);
  const adminToken = randomBytes(32).toString("base64url");
  const namespace = `network-http-${randomUUID()}`;
  const base = `http://127.0.0.1:${port}`;
  // Exercise the production server, cache, identity resolution, challenge
  // verification and final redirect gate. Only outbound fetch is substituted;
  // every endpoint other than these explicit fixtures is refused.
  const child = spawn(process.execPath, ["-e", `
    const profiles = JSON.parse(process.env.TEST_NETWORK_PROFILES);
    const providerDelay = Number(process.env.TEST_NETWORK_DELAY);
    let releaseProvider;
    const released = new Promise(resolve => { releaseProvider = resolve; });
    const upstream = { active: 0, maximum: 0, started: 0 };
    process.on('message', message => {
      if (message === 'test:release-provider') releaseProvider();
      if (message === 'test:provider-status') process.send({ type: 'test:provider-status', ...upstream });
    });
    globalThis.fetch = async (input, options = {}) => {
      const url = String(input && input.url || input);
      if (url === 'https://challenges.cloudflare.com/turnstile/v0/api.js') return new Response(null, { status: 200 });
      if (url === 'https://challenges.cloudflare.com/turnstile/v0/siteverify') {
        const token = new URLSearchParams(options.body).get('response') || '';
        const match = /^valid_([A-Za-z0-9_-]{32})_[A-Za-z0-9_-]+$/.exec(token);
        return Response.json(match ? {
          success: true, action: 'link_redirect', hostname: 'redirect.example.test',
          cdata: match[1] + '_' + Math.floor(Date.now() / 1000)
        } : { success: false, 'error-codes': ['invalid-input-response'] });
      }
      if (url.startsWith('https://api.ipquery.io/')) {
        upstream.started += 1;
        upstream.active += 1;
        upstream.maximum = Math.max(upstream.maximum, upstream.active);
        try {
          // The stalled fixture deliberately ignores AbortSignal until its
          // owner releases it, exercising original-promise slot ownership.
          if (process.env.TEST_NETWORK_STALL === '1') await released;
          else {
            await new Promise(resolve => setTimeout(resolve, providerDelay));
            if (options.signal && options.signal.aborted) throw options.signal.reason;
          }
          const ip = decodeURIComponent(url.slice('https://api.ipquery.io/'.length));
          if (!Object.hasOwn(profiles, ip)) throw new Error('unexpected fixture IP');
          if (profiles[ip] === 'failure') throw new Error('private upstream failure details');
          return Response.json(profiles[ip] === null ? { ip } : { ip, risk: profiles[ip] });
        } finally { upstream.active -= 1; }
      }
      throw new Error('network policy fixture refuses external HTTP');
    };
    require('./server.js');
  `], {
    cwd: path.resolve(__dirname, ".."),
    env: {
      PATH: process.env.PATH, NODE_ENV: "development", PORT: String(port),
      AES_KEY_HEX: key.toString("hex"), ADMIN_TOKEN: adminToken,
      TURNSTILE_SITEKEY: "1x00000000000000000000AA", TURNSTILE_SECRET: "1x0000000000000000000000000000000AA",
      TURNSTILE_EXPECT_HOSTNAME: "redirect.example.test", ALLOWLIST_DOMAINS: "landing.example.test",
      REQUIRE_CF_HEADERS: "false", TRUST_CLIENT_IP_HEADERS: "1", TRUST_UPSTREAM_GEO_HEADERS: "1",
      OPTIONAL_URL_PREFIX: "go", RATE_LIMIT_MAX_REQUESTS: "1000", RATE_CAPACITY: "1000",
      CHALLENGE_CAPACITY: "100", CHALLENGE_VIEW_CAPACITY: "100", PUBLIC_ENABLE_BACKGROUND: "0",
      HEADLESS_BLOCK: "0", LOG_TO_FILE: "0", LOG_DIR: path.join(directory, "logs"),
      LOG_FILE: path.join(directory, "logs", "visitors.log"), RUNTIME_DIAG_DIR: path.join(directory, "diagnostics"),
      DEBUG_SHOW_KEYS_ON_START: "0", DEBUG_ALLOW_PLAINTEXT_KEYS: "0", IPINFO_LITE_ENABLED: "0",
      GEO_ENRICH_IPAPI_ENABLED: "0", eSCANNER_CONFIG_URL: "", SCANNER_FETCH_ENABLED: "0",
      ANALYTICS_STORAGE_DIR: path.join(directory, "analytics"), SHUTDOWN_GRACE_MS: "1000",
      TRAFFIC_METRICS_NAMESPACE: namespace, RISK_NAMESPACE: namespace, RISK_HASH_SECRET: randomBytes(32).toString("hex"),
      RISK_REPORTING_ENABLED: "1", RISK_IP_INTELLIGENCE_ENABLED: enabled ? "1" : "0", RISK_IP_PROVIDER: "ipquery",
      RISK_IP_DAILY_BUDGET: String(dailyBudget), RISK_IP_TIMEOUT_MS: "800",
      ...(vpn == null ? {} : { NETWORK_POLICY_VPN: vpn ? "1" : "0" }),
      ...(datacenter == null ? {} : { NETWORK_POLICY_DATACENTER: datacenter ? "1" : "0" }),
      INTERSTITIAL_BYPASS_SECRET: "fixture-interstitial-bypass", TEST_NETWORK_PROFILES: JSON.stringify({ ...PROFILES, ...extraProfiles }),
      TEST_NETWORK_DELAY: String(providerDelay), TEST_NETWORK_STALL: stallProvider ? "1" : "0", ...extraEnv
    }, stdio: ["ignore", "ignore", "pipe", "ipc"]
  });
  let stderr = "";
  child.stderr.on("data", data => { stderr = (stderr + data.toString()).slice(-4096); });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, "exit");
      child.kill("SIGTERM");
      const deadline = setTimeout(() => child.kill("SIGKILL"), 4000);
      try { await exited; } finally { clearTimeout(deadline); }
    }
    await fs.rm(directory, { recursive: true, force: true });
  });
  async function request(route, options = {}) {
    const response = await fetch(base + route, { ...options, redirect: "manual", signal: AbortSignal.timeout(5000) });
    const text = await response.text();
    return { response, text, json: () => JSON.parse(text) };
  }
  await once(child, "spawn");
  for (let attempt = 0; ; attempt++) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error(`Network fixture exited before readiness: ${stderr}`);
    try { if ((await request("/livez")).response.status === 200) break; } catch {}
    if (attempt >= 99) throw new Error(`Network fixture did not become ready: ${stderr}`);
    await new Promise(resolve => setTimeout(resolve, 40));
  }
  async function metrics() {
    const result = await request("/admin/traffic-metrics", { headers: { authorization: `Bearer ${adminToken}` } });
    assert.equal(result.response.status, 200);
    return result.json();
  }
  async function waitFor(predicate) {
    const deadline = Date.now() + 4000;
    for (;;) {
      const report = await metrics();
      if (predicate(report)) return report;
      if (Date.now() >= deadline) assert.fail("Expected network policy/cache state was not reached");
      await new Promise(resolve => setTimeout(resolve, 20));
    }
  }
  async function visit(ip, { verified = false, invalidToken = false, route = "r", query = "", headers = {}, destination = DESTINATION } = {}) {
    const payload = encrypt(destination, key);
    const hash = createHash("sha256").update(payload).digest("base64url").slice(0, 32);
    const params = new URLSearchParams();
    if (route.endsWith("r")) params.set("d", payload);
    if (verified) params.set("cft", `valid_${hash}_${randomBytes(8).toString("hex")}`);
    if (invalidToken) params.set("cft", "forged-invalid-token");
    const target = route === "r" ? "/r" : route === "go/r" ? "/go/r" : route === "catchall" ? `/${payload}` : `/go/${payload}`;
    return request(target + "?" + params.toString() + (query ? "&" + query : ""), {
      headers: { ...BROWSER, "x-forwarded-for": ip, ...headers }
    });
  }
  async function warm(ip) {
    const before = await metrics();
    const result = await visit(ip);
    assert.equal(result.response.status, 302, "a cold visit follows the existing mandatory challenge");
    assert.match(result.response.headers.get("location") || "", /\/challenge\?/);
    return waitFor(report => report.risk.intelligence.cache.lookups > before.risk.intelligence.cache.lookups && report.risk.intelligence.cache.active === 0);
  }
  async function providerStatus() {
    let timer;
    return new Promise((resolve, reject) => {
      const handler = message => {
        if (!message || message.type !== "test:provider-status") return;
        clearTimeout(timer);
        child.off("message", handler);
        resolve(message);
      };
      child.on("message", handler);
      timer = setTimeout(() => { child.off("message", handler); reject(new Error("Provider fixture status timed out")); }, 2000);
      child.send("test:provider-status");
    });
  }
  return { request, visit, metrics, waitFor, warm, adminToken, providerStatus,
    releaseProvider: () => child.send("test:release-provider") };
}

function redirected(result) {
  assert.equal(result.response.status, 302);
  assert.equal(result.response.headers.get("location"), DESTINATION);
}

function blocked(result) {
  assert.equal(result.response.status, 403);
  assert.equal(result.response.headers.get("location"), null);
}

test("strict VPN policy gates real redirect routes after verification and cannot be disabled by visitor parameters", { timeout: 30000 }, async t => {
  const app = await fixture(t);
  const before = await app.metrics();
  assert.equal(before.networkPolicy.version, 2);
  assert.equal(Object.hasOwn(before.networkPolicy, "mode"), false);
  assert.equal(Object.hasOwn(before.networkPolicy, "effectiveMode"), false);
  assert.equal(before.networkPolicy.enabled, true);
  assert.deepEqual(before.networkPolicy.targets, { vpn: true, datacenter: false });
  await app.warm("8.8.8.8");
  for (const route of ["r", "go/r", "catchall", "go/catchall"]) {
    blocked(await app.visit("8.8.8.8", { route, verified: true }));
  }
  for (const options of [
    { query: "network_policy=off&NETWORK_POLICY_VPN=0&vpn=false" },
    { query: "ib=fixture-interstitial-bypass" },
    { headers: { "x-interstitial-bypass": "fixture-interstitial-bypass" } }
  ]) blocked(await app.visit("8.8.8.8", { ...options, verified: true }));
  const invalid = await app.visit("8.8.8.8", { invalidToken: true });
  assert.equal(invalid.response.status, 302);
  assert.match(invalid.response.headers.get("location") || "", /\/challenge\?/);
  const after = await app.metrics();
  assert.equal(after.networkPolicy.totals.blocked, 7);
  assert.ok(after.networkPolicy.totals.matchedVpn >= 7);
  assert.equal(after.networkPolicy.totals.errors, 0);
  assert.equal(after.risk.intelligence.providerStatus.used, 1, "enforcement and post-response reporting share one cached lookup");
  assert.equal(after.risk.intelligence.cache.active, 0);
  assert.equal(after.risk.intelligence.cache.queued, 0);
  const serialized = JSON.stringify(after.networkPolicy);
  assert.ok(!serialized.includes("8.8.8.8"));
  assert.ok(!serialized.includes(app.adminToken));
  const unauthorized = await app.visit("8.8.8.8", { verified: true, destination: "https://unlisted.example.test/private" });
  blocked(unauthorized);
  assert.equal(unauthorized.text, "Unauthorized URL", "destination validation retains priority over a matching strict network policy");
  assert.equal((await app.metrics()).networkPolicy.totals.blocked, 7);
});

test("independent VPN and datacenter targets select either category without blocking explicit false indicators", { timeout: 30000 }, async t => {
  for (const config of [{ vpn: false, datacenter: true }, { vpn: true, datacenter: true }]) {
    await t.test(config.vpn ? "both categories" : "datacenter only", async t => {
      const app = await fixture(t, config);
      for (const ip of ["8.8.8.8", "9.9.9.9", "4.2.2.2", "1.1.1.1"]) await app.warm(ip);
      for (const ip of ["9.9.9.9", "4.2.2.2"]) blocked(await app.visit(ip, { verified: true }));
      const vpn = await app.visit("8.8.8.8", { verified: true });
      config.vpn ? blocked(vpn) : redirected(vpn);
      redirected(await app.visit("1.1.1.1", { verified: true }));
      const report = await app.metrics();
      assert.equal(report.networkPolicy.totals.blocked, config.vpn ? 3 : 2);
      assert.equal(report.networkPolicy.totals.errors, 0);
    });
  }
});

test("zero or unset switches preserve existing verification and reporting even with a leftover mode variable", { timeout: 30000 }, async t => {
  for (const [name, settings] of [
    ["unset switches", { vpn: null, datacenter: null }],
    ["explicit zero", { vpn: false, datacenter: false }],
    ["obsolete block setting alone", { vpn: null, datacenter: null, extraEnv: { NETWORK_POLICY_MODE: "block" } }]
  ]) await t.test(name, async t => {
    const app = await fixture(t, settings);
    await app.warm("4.2.2.2");
    const unverified = await app.visit("4.2.2.2");
    assert.equal(unverified.response.status, 302);
    assert.match(unverified.response.headers.get("location") || "", /\/challenge\?/);
    redirected(await app.visit("4.2.2.2", { verified: true }));
    const report = await app.metrics();
    assert.equal(report.networkPolicy.enabled, false);
    assert.deepEqual(report.networkPolicy.targets, { vpn: false, datacenter: false });
    assert.deepEqual(report.networkPolicy.configErrors, []);
    assert.equal(report.networkPolicy.totals.evaluated, 0);
    assert.equal(report.networkPolicy.totals.blocked, 0);
    assert.equal(report.risk.intelligence.providerStatus.used, 1);
    assert.ok(report.risk.totals.observedRequests > 0, "disabling category blocking keeps ordinary risk reporting active");
  });
});

test("leftover report or challenge mode cannot override an enabled blocking switch", { timeout: 30000 }, async t => {
  for (const legacyMode of ["report", "challenge"]) await t.test(legacyMode, async t => {
    const app = await fixture(t, { vpn: true, datacenter: true, extraEnv: { NETWORK_POLICY_MODE: legacyMode } });
    await app.warm("4.2.2.2");
    blocked(await app.visit("4.2.2.2", { verified: true }));
    const report = await app.metrics();
    assert.equal(report.networkPolicy.enabled, true);
    assert.equal(report.networkPolicy.totals.blocked, 1);
    assert.equal(report.networkPolicy.totals.allowedAfterChallenge, 0);
    assert.deepEqual(report.networkPolicy.configErrors, []);
  });
});

test("unknown classification, provider failures, timeouts and exhausted budget preserve existing verified access", { timeout: 30000 }, async t => {
  await t.test("missing indicators and failed lookup", async t => {
    const app = await fixture(t);
    for (const ip of ["208.67.220.220", "208.67.222.222", "94.140.14.14"]) {
      await app.warm(ip);
      redirected(await app.visit(ip, { verified: true }));
    }
    const report = await app.metrics();
    assert.equal(report.networkPolicy.totals.blocked, 0);
    assert.equal(report.networkPolicy.totals.allowedUnknown, 3, "a missing selected VPN flag stays unknown even when datacenter is explicitly false");
    assert.equal(report.risk.intelligence.cache.failed, 1);
    assert.equal(report.risk.intelligence.cache.unknownResponses, 1);
    assert.ok(!JSON.stringify(report).includes("private upstream failure details"));
  });
  await t.test("daily allowance exhausted", async t => {
    const app = await fixture(t, { dailyBudget: 1 });
    await app.warm("1.1.1.1");
    await app.warm("8.8.8.8");
    redirected(await app.visit("8.8.8.8", { verified: true }));
    const report = await app.metrics();
    assert.equal(report.risk.intelligence.providerStatus.used, 1);
    assert.equal(report.risk.intelligence.providerStatus.remaining, 0);
    assert.equal(report.networkPolicy.totals.allowedUnknown, 1);
    assert.equal(report.networkPolicy.totals.blocked, 0);
  });
  await t.test("provider timeout", async t => {
    const app = await fixture(t, { providerDelay: 350, extraEnv: { RISK_IP_TIMEOUT_MS: "100" } });
    await app.warm("8.8.8.8");
    redirected(await app.visit("8.8.8.8", { verified: true }));
    const report = await app.metrics();
    assert.equal(report.risk.intelligence.cache.timeouts, 1);
    assert.equal(report.networkPolicy.totals.allowedUnknown, 1);
    assert.equal(report.networkPolicy.totals.blocked, 0);
  });
});

test("network policy never overrides existing token, headless, geo, ASN and destination restrictions", { timeout: 30000 }, async t => {
  const app = await fixture(t, { extraEnv: { HEADLESS_BLOCK: "1", BLOCKED_COUNTRIES: "CA", BLOCKED_ASNS: "AS64501" } });
  await app.warm("8.8.8.8");
  const invalid = await app.visit("8.8.8.8", { invalidToken: true });
  assert.equal(invalid.response.status, 302);
  assert.match(invalid.response.headers.get("location") || "", /\/challenge\?/);
  const before = await app.metrics();
  const headless = await app.visit("9.9.9.9", { verified: true, headers: { "x-headless-browser": "1" } });
  blocked(headless);
  const geo = await app.visit("4.2.2.2", { verified: true, headers: { "x-railway-ip": "4.2.2.2", "x-railway-country": "CA" } });
  blocked(geo);
  const asn = await app.visit("1.1.1.1", { verified: true, headers: { "x-asn": "AS64501" } });
  blocked(asn);
  const after = await app.metrics();
  assert.equal(after.networkPolicy.totals.evaluated, before.networkPolicy.totals.evaluated, "hard security rejects before network enforcement");
  const unauthorized = await app.visit("8.8.8.8", { verified: true, destination: "https://unlisted.example.test/private" });
  blocked(unauthorized);
  assert.equal(unauthorized.text, "Unauthorized URL");
  const final = await app.metrics();
  assert.equal(final.networkPolicy.totals.blocked, 0, "existing denials are not misattributed as network-policy blocks");
});

test("operational routes stay outside network policy and disabled intelligence safely exposes inactive enforcement", { timeout: 30000 }, async t => {
  const app = await fixture(t);
  await app.warm("8.8.8.8");
  blocked(await app.visit("8.8.8.8", { verified: true }));
  const before = await app.metrics();
  for (const prefix of ["", "/go"]) {
    for (const route of ["/health", "/healthz", "/readyz", "/livez"]) {
      const result = await app.request(prefix + route, { headers: { ...BROWSER, "x-forwarded-for": "8.8.8.8" } });
      assert.ok([200, 503].includes(result.response.status));
      if (route === "/healthz" || route === "/livez") assert.equal(result.response.status, 200);
    }
    assert.equal((await app.request(prefix + "/admin/traffic-panel")).response.status, 200);
    assert.equal((await app.request(prefix + "/admin/traffic-metrics")).response.status, 401);
  }
  const after = await app.metrics();
  assert.deepEqual(after.networkPolicy.totals, before.networkPolicy.totals);
  assert.equal(after.risk.intelligence.providerStatus.used, 1);
  await t.test("blocking switches cannot themselves authorize external lookup", async t => {
    const disabled = await fixture(t, { enabled: false });
    redirected(await disabled.visit("8.8.8.8", { verified: true }));
    const report = await disabled.metrics();
    assert.equal(report.networkPolicy.enabled, false);
    assert.equal(report.networkPolicy.unavailableReason, "intelligence_disabled");
    assert.equal(report.risk.intelligence.providerStatus.used, 0);
    assert.equal(report.risk.intelligence.cache.lookups, 0);
    assert.equal(report.networkPolicy.totals.blocked, 0);
  });
  await t.test("no selected category leaves enforcement inactive", async t => {
    const disabled = await fixture(t, { vpn: false, datacenter: false });
    redirected(await disabled.visit("8.8.8.8", { verified: true }));
    const report = await disabled.metrics();
    assert.equal(report.networkPolicy.enabled, false);
    assert.equal(report.networkPolicy.unavailableReason, "no_targets");
    assert.equal(report.networkPolicy.totals.evaluated, 0);
    assert.equal(report.networkPolicy.totals.blocked, 0);
  });
});

test("concurrent verified visitors and operations remain responsive while ignored-abort lookups retain bounded slots", { timeout: 30000 }, async t => {
  const ips = Array.from({ length: 72 }, (_, index) => `45.32.0.${index + 1}`);
  const extraProfiles = Object.fromEntries(ips.map(ip => [ip, { is_vpn: true, is_datacenter: false, is_proxy: false }]));
  const app = await fixture(t, { stallProvider: true, extraProfiles, extraEnv: { RISK_IP_TIMEOUT_MS: "100" } });
  // Hold the first two original fetch promises open before filling the queue.
  // Visitor requests must finish without waiting for those promises.
  for (const result of await Promise.all(ips.slice(0, 2).map(ip => app.visit(ip, { verified: true })))) redirected(result);
  await app.waitFor(report => report.risk.intelligence.cache.active === 2);
  const requests = await Promise.all(ips.slice(2).map(ip => app.visit(ip, { verified: true })));
  for (const result of requests) redirected(result);
  const timedOut = await app.waitFor(report => report.risk.intelligence.cache.timeouts === 2);
  assert.equal(timedOut.risk.intelligence.cache.active, 2, "timeout does not release an upstream promise that ignored cancellation");
  assert.ok(timedOut.risk.intelligence.cache.queued <= 64);
  assert.ok(timedOut.risk.intelligence.cache.queueDropped > 0);
  assert.equal(timedOut.networkPolicy.totals.blocked, 0);
  assert.equal(timedOut.networkPolicy.totals.allowedUnknown, ips.length);
  const upstream = await app.providerStatus();
  assert.deepEqual({ active: upstream.active, maximum: upstream.maximum, started: upstream.started }, { active: 2, maximum: 2, started: 2 });
  assert.equal((await app.request("/healthz")).response.status, 200);
  assert.equal((await app.request("/admin/traffic-panel")).response.status, 200);
  app.releaseProvider();
  const settled = await app.waitFor(report => report.risk.intelligence.cache.active === 0 && report.risk.intelligence.cache.queued === 0);
  assert.equal(settled.risk.intelligence.cache.timeouts, 2);
  assert.ok((await app.providerStatus()).maximum <= 2);
  // Timed-out positive results cannot later become blocking classifications.
  for (const ip of ips.slice(0, 2)) redirected(await app.visit(ip, { verified: true }));
  blocked(await app.visit(ips[2], { verified: true }));
  const final = await app.metrics();
  assert.equal(final.networkPolicy.totals.blocked, 1);
  assert.equal(final.networkPolicy.totals.errors, 0);
});
