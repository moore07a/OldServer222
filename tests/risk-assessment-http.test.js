"use strict";

const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { randomBytes, randomUUID, createHmac } = require("node:crypto");
const { once } = require("node:events");
const fs = require("node:fs/promises");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

async function fixture(t, { reporting = true, conversionTokenConfigured = true, redisUrl = "" } = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "risk-assessment-http-"));
  const listener = net.createServer();
  listener.listen(0, "127.0.0.1");
  await once(listener, "listening");
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  const adminToken = randomBytes(32).toString("base64url");
  const conversionToken = randomBytes(32).toString("base64url");
  const hashSecret = randomBytes(32).toString("hex");
  const namespace = `risk-http-${randomUUID()}`;
  const base = `http://127.0.0.1:${port}`;
  // Block every outbound HTTP request inside the fixture. The existing health
  // probe gets a deterministic response; external IP intelligence is disabled.
  const child = spawn(process.execPath, ["-e", `
    let ipIntelligenceAttempts = 0;
    globalThis.fetch = async (input) => {
      const url = String(input && input.url || input);
      if (/ipapi\\.is/i.test(url)) ipIntelligenceAttempts += 1;
      if (/^https:\\/\\/challenges\\.cloudflare\\.com\\/turnstile\\/v0\\/api\\.js$/.test(url)) return new Response(null, { status: 200 });
      throw new Error('test fixture blocks external HTTP');
    };
    process.on('message', message => {
      if (message === 'test:risk-provider-attempts') process.send({ ipIntelligenceAttempts });
    });
    require('./server.js');
  `], {
    cwd: path.resolve(__dirname, ".."),
    env: {
      ...process.env, NODE_ENV: "development", PORT: String(port),
      AES_KEY_HEX: randomBytes(32).toString("hex"), AES_KEY: "", AES_KEYS: "", AES_KEY_SHA256: "",
      ADMIN_TOKEN: adminToken, DEBUG_SHOW_KEYS_ON_START: "0", DEBUG_ALLOW_PLAINTEXT_KEYS: "0",
      TURNSTILE_SITEKEY: "1x00000000000000000000AA", TURNSTILE_SECRET: "1x0000000000000000000000000000000AA",
      TURNSTILE_EXPECT_HOSTNAME: "", ALLOWLIST_DOMAINS: "example.com", REQUIRE_CF_HEADERS: "false",
      OPTIONAL_URL_PREFIX: "view-log", RATE_LIMIT_MAX_REQUESTS: "1000", CHALLENGE_VIEW_CAPACITY: "100",
      LOG_TO_FILE: "0", RUNTIME_DIAG_DIR: directory, IPINFO_LITE_ENABLED: "0", GEO_ENRICH_IPAPI_ENABLED: "0",
      REDIS_URL: "", REDIS_PRIVATE_URL: "", TRAFFIC_METRICS_REDIS_URL: "", eSCANNER_CONFIG_URL: "",
      RISK_REPORTING_ENABLED: reporting ? "1" : "0", RISK_IP_INTELLIGENCE_ENABLED: "0",
      RISK_CAMPAIGN_IDS: "ad_alpha", RISK_CONVERSION_TOKEN: conversionTokenConfigured ? conversionToken : "",
      RISK_HASH_SECRET: hashSecret, RISK_NAMESPACE: namespace, RISK_REDIS_URL: redisUrl, RISK_WINDOW_SECONDS: "300"
    },
    stdio: ["ignore", "ignore", "ignore", "ipc"]
  });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exit = once(child, "exit");
      child.kill("SIGTERM");
      const force = setTimeout(() => child.kill("SIGKILL"), 3000);
      try { await exit; } finally { clearTimeout(force); }
    }
    if (redisUrl) {
      const Redis = require("ioredis");
      const connection = new Redis(redisUrl, { lazyConnect: true, enableOfflineQueue: false, commandTimeout: 1000, retryStrategy: null });
      connection.on("error", () => {});
      try {
        await connection.connect();
        let cursor = "0";
        do {
          const [next, keys] = await connection.scan(cursor, "MATCH", `campaign-risk:{${namespace}:v1}:*`, "COUNT", 100);
          cursor = next;
          if (keys.length) await connection.del(...keys);
        } while (cursor !== "0");
      } finally { connection.disconnect(); }
    }
    await fs.rm(directory, { recursive: true, force: true });
  });
  await once(child, "spawn");
  async function request(route, options = {}) {
    const response = await fetch(base + route, { ...options, redirect: "manual", signal: AbortSignal.timeout(5000) });
    const text = await response.text();
    return { response, text, json: () => JSON.parse(text) };
  }
  for (let attempt = 0; ; attempt++) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error("Risk HTTP fixture exited before readiness");
    try { if ((await request("/livez")).response.status === 200) break; } catch {}
    if (attempt >= 79) throw new Error("Risk HTTP fixture did not become ready");
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  const admin = { headers: { authorization: `Bearer ${adminToken}` } };
  async function metrics(prefix = "") {
    const result = await request(`${prefix}/admin/traffic-metrics`, admin);
    assert.equal(result.response.status, 200);
    return result;
  }
  function conversion(body, { token = conversionToken, route = "/admin/risk-conversions", query = "", authorization } = {}) {
    return request(route + query, { method: "POST", headers: { "content-type": "application/json", ...(token ? { authorization: authorization ?? `Bearer ${token}` } : {}) }, body: JSON.stringify(body) });
  }
  async function providerAttempts() {
    const message = once(child, "message");
    child.send("test:risk-provider-attempts");
    return (await message)[0].ipIntelligenceAttempts;
  }
  return { request, metrics, conversion, providerAttempts, adminToken, conversionToken, hashSecret, namespace };
}

function campaign(report, id = "ad_alpha") { return report.risk.campaignWindow.campaigns.find(row => row.id === id); }

test("actual server reports risk without changing redirect validation, exposing identifiers, or observing operational paths", { timeout: 30000 }, async t => {
  const redisUrl = process.env.TRAFFIC_METRICS_TEST_REDIS_URL || "";
  const app = await fixture(t, { redisUrl });
  assert.equal((await app.request("/admin/traffic-metrics")).response.status, 401);
  const before = (await app.metrics()).json();
  assert.equal(before.risk.mode, "report_only");
  assert.equal(before.risk.classification, "indicators_only");
  assert.equal(before.risk.totals.observedRequests, 0);
  assert.equal(before.risk.intelligence.enabled, false);
  assert.equal(before.risk.intelligence.capabilities.residentialProxy, false);
  assert.equal(before.risk.conversions.enabled, true);
  assert.equal(before.risk.observerErrors, 0);
  if (redisUrl) {
    // Connection readiness is asynchronous, so obtain one fresh snapshot if the
    // startup read preceded the dedicated Redis client's ready event.
    const current = (await app.metrics()).json();
    assert.equal(current.risk.campaignWindow.scope, "redis");
  } else assert.equal(before.risk.campaignWindow.scope, "current_process");

  for (const prefix of ["", "/view-log"]) {
    for (const route of ["/health", "/healthz", "/readyz", "/livez"]) {
      const result = await app.request(prefix + route);
      assert.ok((route === "/health" || route === "/readyz" ? [200, 503] : [200]).includes(result.response.status));
      const body = result.json();
      assert.equal(body.ok, result.response.status === 200);
      if (route === "/health" || route === "/readyz") {
        assert.ok(body.checks.turnstile.lastHeartbeat === null || Number.isFinite(Date.parse(body.checks.turnstile.lastHeartbeat)));
        assert.equal(typeof body.checks.turnstile.okStreak, "number");
      }
      if (route !== "/livez") {
        assert.ok(body.stats.memory.rssMb > 0);
        assert.equal(typeof body.stats.cpu.processPercent, "number");
        assert.equal(body.stats.resources.sseListeners, 0);
      }
    }
    for (const route of ["/admin/traffic-panel", "/admin/traffic-panel.js"]) assert.equal((await app.request(prefix + route)).response.status, 200);
    assert.equal((await app.metrics(prefix)).json().risk.totals.observedRequests, 0);
    for (const route of ["/view-log", "/view-log-live", "/stream-log"]) assert.equal((await app.request(prefix + route.toUpperCase())).response.status, 404);
  }
  assert.equal((await app.metrics()).json().risk.totals.observedRequests, 0, "health, admin, panel and retired requests are excluded");

  const privateQuery = "unique-private-campaign-query";
  const privateUa = "HeadlessChrome/123 private-user-agent-marker";
  const headers = { "user-agent": privateUa, "accept-language": "en-US", accept: "text/html", "x-forwarded-for": "198.51.100.27" };
  for (const prefix of ["", "/view-log"]) {
    const result = await app.request(`${prefix}/r?campaign_id=ad_alpha&tracking=${privateQuery}`, { headers });
    assert.ok([400, 429].includes(result.response.status), "malformed redirect keeps its existing validation/limiter response");
  }
  for (const campaignValue of ["unconfigured-campaign-secret", "ad_alpha&campaign_id=unconfigured-campaign-secret"]) {
    const result = await app.request(`/r?campaign_id=${campaignValue}`, { headers });
    assert.ok([400, 429].includes(result.response.status));
  }
  const result = await app.metrics("/view-log");
  const report = result.json();
  assert.equal(report.risk.totals.observedRequests, 4);
  assert.equal(report.risk.totals.headlessMarkers, 4);
  assert.equal(report.risk.totals.networkUnknown, 4);
  assert.equal(report.risk.totals.networkKnown, 0);
  assert.equal(campaign(report).requests, 2);
  assert.equal(campaign(report).headless, 2);
  assert.equal(campaign(report, "__unattributed__").requests, 2, "unknown and repeated campaign IDs use a single fixed slot");
  assert.equal(report.risk.campaignWindow.campaigns.length, 2);
  assert.equal(report.risk.observerErrors, 0);
  assert.doesNotMatch(JSON.stringify(report.risk), /\b[a-f0-9]{64}\b/i, "no HMAC values appear in reports");
  assert.equal(await app.providerAttempts(), 0, "reporting performs no external IP lookup while disabled");
  for (const secret of [privateQuery, privateUa, "198.51.100.27", "127.0.0.1", "unconfigured-campaign-secret", app.adminToken, app.conversionToken, app.hashSecret]) assert.ok(!result.text.includes(secret), "snapshots exclude request identifiers and secrets");
  const sourceHash = createHmac("sha256", app.hashSecret).update(`${app.namespace}:source:127.0.0.1`).digest("hex");
  assert.ok(!result.text.includes(sourceHash), "source hashes are not exposed");
});

test("conversion HTTP API requires its dedicated bearer token and validates events before counting", { timeout: 30000 }, async t => {
  const app = await fixture(t, { redisUrl: process.env.TRAFFIC_METRICS_TEST_REDIS_URL || "" });
  const event = { campaignId: "ad_alpha", eventId: "private-trusted-order-123" };
  for (const options of [
    { token: "" }, { token: app.adminToken }, { token: "wrong-token-value" },
    { token: "", query: `?token=${app.conversionToken}` },
    { authorization: `bearer ${app.conversionToken}` }, { authorization: `Bearer  ${app.conversionToken}` }
  ]) {
    const result = await app.conversion(event, options);
    assert.equal(result.response.status, 401, "admin/query/wrong/malformed authorization cannot submit conversions");
    assert.match(result.response.headers.get("cache-control"), /no-store/);
  }
  for (const body of [
    { ...event, campaignId: "unconfigured" }, { ...event, extra: "unexpected" },
    { ...event, campaignId: ["ad_alpha"] }, { ...event, eventId: 123 },
    { ...event, eventId: "contains spaces" }, { campaignId: "ad_alpha" }, [], null
  ]) assert.equal((await app.conversion(body)).response.status, 400);
  const oversized = await app.conversion({ ...event, eventId: "x".repeat(70 * 1024) });
  assert.equal(oversized.response.status, 413, "the existing global JSON body limit remains enforced");
  const first = await app.conversion(event);
  assert.equal(first.response.status, 200);
  assert.deepEqual(first.json(), { ok: true, accepted: true, duplicate: false, scope: process.env.TRAFFIC_METRICS_TEST_REDIS_URL ? "redis" : "current_process" });
  const duplicate = await app.conversion(event, { route: "/view-log/admin/risk-conversions" });
  assert.equal(duplicate.response.status, 200);
  assert.equal(duplicate.json().duplicate, true);
  const result = await app.metrics();
  const report = result.json();
  assert.equal(campaign(report).conversions, 1);
  assert.equal(report.risk.totals.observedRequests, 0, "conversion reporting is operational, not visitor traffic");
  for (const secret of [event.eventId, app.adminToken, app.conversionToken, app.hashSecret]) assert.ok(!result.text.includes(secret));
  const eventHash = createHmac("sha256", app.hashSecret).update(`${app.namespace}:conversion:${event.eventId}`).digest("hex");
  assert.ok(!result.text.includes(eventHash), "conversion hashes remain internal to dedupe storage");
  assert.equal(await app.providerAttempts(), 0);
});

test("conversion endpoints are unavailable when the token is absent or risk reporting is disabled", { timeout: 30000 }, async t => {
  for (const options of [{ conversionTokenConfigured: false }, { reporting: false }]) {
    await t.test(options.reporting === false ? "reporting disabled" : "dedicated token absent", async t => {
      const app = await fixture(t, options);
      for (const route of ["/admin/risk-conversions", "/view-log/admin/risk-conversions"]) {
        assert.equal((await app.conversion({ campaignId: "ad_alpha", eventId: "trusted-order" }, { route })).response.status, 404);
      }
      const report = (await app.metrics()).json();
      assert.equal(report.risk.conversions.enabled, false);
      assert.equal(report.risk.mode, options.reporting === false ? "disabled" : "report_only");
      assert.equal(await app.providerAttempts(), 0);
    });
  }
});
