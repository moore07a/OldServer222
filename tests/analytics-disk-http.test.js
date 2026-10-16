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

async function workspace(t, { invalidDirectory = false, storageMode = "explicit" } = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "analytics-disk-http-"));
  const storageDir = path.join(directory, invalidDirectory ? "private-storage-file" : "analytics");
  if (invalidDirectory) await fs.writeFile(storageDir, "a file cannot be an analytics directory");
  const credentials = {
    adminToken: randomBytes(32).toString("base64url"),
    conversionToken: randomBytes(32).toString("base64url"),
    hashSecret: randomBytes(32).toString("hex"), aesKey: randomBytes(32).toString("hex")
  };
  const namespace = `disk-http-${randomUUID()}`;
  // Keep the restart inside one campaign window without freezing the app clock.
  const remaining = seconds => seconds * 1000 - Date.now() % (seconds * 1000);
  const windowSeconds = [3600, 3599, 3593].sort((a, b) => remaining(b) - remaining(a))[0];
  const children = new Set();
  t.after(async () => {
    for (const app of children) await app.stop();
    await fs.rm(directory, { recursive: true, force: true });
  });

  async function start() {
    const listener = net.createServer();
    listener.listen(0, "127.0.0.1");
    await once(listener, "listening");
    const port = listener.address().port;
    await new Promise(resolve => listener.close(resolve));
    const diagnostics = path.join(directory, `diagnostics-${port}`);
    const child = spawn(process.execPath, ["-e", `
      globalThis.fetch = async input => {
        const url = String(input && input.url || input);
        if (url === 'https://challenges.cloudflare.com/turnstile/v0/api.js') return new Response(null, { status: 200 });
        throw new Error('isolated fixture blocks external HTTP');
      };
      require('./server.js');
    `], {
      cwd: path.resolve(__dirname, ".."),
      env: {
        PATH: process.env.PATH, NODE_ENV: "development", PORT: String(port),
        AES_KEY_HEX: credentials.aesKey, ADMIN_TOKEN: credentials.adminToken,
        TURNSTILE_SITEKEY: "1x00000000000000000000AA", TURNSTILE_SECRET: "1x0000000000000000000000000000000AA",
        ALLOWLIST_DOMAINS: "example.com", REQUIRE_CF_HEADERS: "false", OPTIONAL_URL_PREFIX: "",
        DEBUG_SHOW_KEYS_ON_START: "0", DEBUG_ALLOW_PLAINTEXT_KEYS: "0", LOG_TO_FILE: "0",
        LOG_FILE: path.join(diagnostics, "visitors.log"), RUNTIME_DIAG_DIR: diagnostics, NPM_CONFIG_LOGS_DIR: diagnostics,
        RATE_LIMIT_MAX_REQUESTS: "1000", CHALLENGE_VIEW_CAPACITY: "100", PUBLIC_ENABLE_BACKGROUND: "0",
        IPINFO_LITE_ENABLED: "0", GEO_ENRICH_IPAPI_ENABLED: "0", eSCANNER_CONFIG_URL: "",
        REDIS_URL: "", REDIS_PRIVATE_URL: "", TRAFFIC_METRICS_REDIS_URL: "", RISK_REDIS_URL: "",
        TRAFFIC_METRICS_NAMESPACE: namespace, RISK_NAMESPACE: namespace,
        ANALYTICS_STORAGE_DIR: storageMode === "auto" ? undefined : storageMode === "off" ? "off" : storageDir,
        RAILWAY_VOLUME_MOUNT_PATH: storageMode === "explicit" ? "" : directory,
        RISK_REPORTING_ENABLED: "1", RISK_IP_INTELLIGENCE_ENABLED: "0", RISK_CAMPAIGN_IDS: "ad_alpha",
        RISK_CONVERSION_TOKEN: credentials.conversionToken, RISK_HASH_SECRET: credentials.hashSecret,
        RISK_WINDOW_SECONDS: String(windowSeconds), SHUTDOWN_GRACE_MS: "1000"
      },
      stdio: ["ignore", "ignore", "ignore"]
    });
    async function request(route, options = {}) {
      const response = await fetch(`http://127.0.0.1:${port}${route}`, {
        ...options, redirect: "manual", signal: AbortSignal.timeout(5000)
      });
      const text = await response.text();
      return { response, text, json: () => JSON.parse(text) };
    }
    const app = {
      request,
      async metrics() {
        const result = await request("/admin/traffic-metrics", { headers: { authorization: `Bearer ${credentials.adminToken}` } });
        assert.equal(result.response.status, 200, "monitoring remains available with disk persistence");
        return result;
      },
      conversion(eventId) {
        return request("/admin/risk-conversions", {
          method: "POST", headers: { authorization: `Bearer ${credentials.conversionToken}`, "content-type": "application/json" },
          body: JSON.stringify({ campaignId: "ad_alpha", eventId })
        });
      },
      async stop(signal = "SIGTERM") {
        if (child.exitCode !== null || child.signalCode !== null) return;
        const exited = once(child, "exit");
        child.kill(signal);
        const deadline = setTimeout(() => child.kill("SIGKILL"), 4000);
        try { await exited; } finally { clearTimeout(deadline); }
      }
    };
    children.add(app);
    await once(child, "spawn");
    for (let attempt = 0; ; attempt++) {
      assert.equal(child.exitCode, null, "disk fixture exited before HTTP startup");
      assert.equal(child.signalCode, null, "disk fixture was killed before HTTP startup");
      try { if ((await request("/livez")).response.status === 200) break; } catch {}
      if (attempt >= 119) throw new Error("Disk HTTP fixture did not become live");
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    return app;
  }

  function redact(report, markers = []) {
    const serialized = JSON.stringify(report);
    const sourceHash = createHmac("sha256", credentials.hashSecret).update(`${namespace}:source:127.0.0.1`).digest("hex");
    for (const forbidden of [...Object.values(credentials), sourceHash, storageDir, "127.0.0.1", ...markers]) {
      assert.equal(serialized.includes(forbidden), false, "analytics API must exclude identifiers, secrets and checkpoint locations");
    }
    assert.doesNotMatch(serialized, /campaign-risk:\{|traffic-metrics:\{|eventIdHash|sourceHash|checkpointPath|lockPath/);
  }
  return { start, storageDir, credentials, namespace, redact };
}

function campaign(report) { return report.risk.campaignWindow.campaigns.find(row => row.id === "ad_alpha"); }

async function checkOperationalRoutes(app) {
  for (const route of ["/health", "/readyz", "/healthz", "/livez"]) {
    const result = await app.request(route);
    assert.equal(result.response.status, 200, `${route} remains healthy with the mocked provider`);
    assert.equal(result.json().ok, true);
  }
  for (const route of ["/VIEW-LOG", "/view-log-live/child", "/StReAm-LoG/"]) {
    const result = await app.request(`${route}?token=retired-private-marker`);
    assert.equal(result.response.status, 404);
    assert.equal(result.response.headers.get("location"), null);
    assert.equal(result.response.headers.get("link"), null);
    assert.doesNotMatch(result.text, /retired-private-marker|event-stream/);
  }
}

test("disk analytics survive a crash, reset process metrics, and durably deduplicate conversions after restart", { timeout: 40000 }, async t => {
  const disk = await workspace(t);
  const first = await disk.start();
  assert.equal((await first.request("/admin/traffic-metrics")).response.status, 401);
  const initial = (await first.metrics()).json();
  assert.equal(initial.diskStorage.configured, true);
  assert.equal(initial.diskStorage.ready, true);
  assert.equal(initial.diskStorage.backend, "disk");
  assert.equal(initial.persistent.scope, "disk");
  assert.equal(initial.risk.campaignWindow.scope, "disk");
  const marker = "private-visitor-query-marker";
  const rejected = await first.request(`/r?campaign_id=ad_alpha&tracking=${marker}`);
  assert.equal(rejected.response.status, 400);
  const tokenBody = Buffer.from(JSON.stringify({ next: "/r?d=fixture", ts: Date.now(), exp: Date.now() + 60000 })).toString("base64url");
  const challengeToken = `${tokenBody}.${createHmac("sha256", disk.credentials.adminToken).update(tokenBody).digest("base64url")}`;
  const fragment = await first.request("/challenge-fragment?campaign_id=ad_alpha", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ct: challengeToken })
  });
  assert.equal(fragment.response.status, 200);
  const before = (await first.metrics()).json();
  assert.equal(before.challenges.shown, 1);
  assert.equal(campaign(before).requests, 2);
  const eventId = "private-trusted-durable-order-1";
  const accepted = await first.conversion(eventId);
  assert.equal(accepted.response.status, 200);
  assert.equal(accepted.json().accepted, true);
  assert.equal(accepted.json().duplicate, false);
  assert.equal(accepted.json().scope, "disk");
  // Kill immediately after the durable acknowledgement, without a shutdown flush.
  await first.stop("SIGKILL");

  const restarted = await disk.start();
  const result = await restarted.metrics();
  const restored = result.json();
  assert.equal(restored.diskStorage.ready, true, "the crash releases the owned disk lock");
  assert.ok(Number.isFinite(Date.parse(restored.diskStorage.lastSaveAt)));
  assert.equal(restored.persistent.scope, "disk");
  assert.equal(restored.persistent.startedAt, before.persistent.startedAt);
  assert.ok(restored.persistent.total.completed >= before.total.completed);
  assert.ok(restored.persistent.byKind.get.completed >= before.byKind.get.completed);
  assert.ok(restored.persistent.challenges.shown >= before.challenges.shown);
  assert.equal(restored.byKind.get.requests, 0, "process visitor counters reset on restart");
  assert.equal(restored.byKind.other.requests, 0);
  assert.equal(restored.challenges.shown, 0);
  assert.equal(restored.risk.totals.observedRequests, 0, "risk lifetime totals remain process-local");
  assert.equal(restored.risk.campaignWindow.scope, "disk");
  assert.equal(restored.risk.campaignWindow.windowStartedAt, before.risk.campaignWindow.windowStartedAt);
  assert.equal(campaign(restored).requests, 2);
  assert.equal(campaign(restored).conversions, 1);
  const duplicate = await restarted.conversion(eventId);
  assert.equal(duplicate.response.status, 200);
  assert.equal(duplicate.json().duplicate, true);
  assert.equal(duplicate.json().scope, "disk");
  const afterDuplicate = (await restarted.metrics()).json();
  assert.equal(campaign(afterDuplicate).conversions, 1);
  disk.redact(afterDuplicate, [marker, eventId, challengeToken]);
  await checkOperationalRoutes(restarted);
});

test("a second process cannot write through an analytics directory owned by another live process", { timeout: 40000 }, async t => {
  const disk = await workspace(t);
  const owner = await disk.start();
  assert.equal((await owner.metrics()).json().diskStorage.ready, true);
  const contender = await disk.start();
  const report = (await contender.metrics()).json();
  assert.equal(report.diskStorage.configured, true);
  assert.equal(report.diskStorage.backend, "disk");
  assert.equal(report.diskStorage.ready, false);
  assert.match(report.diskStorage.lastError, /^[A-Za-z][A-Za-z0-9_.:-]{0,79}$/);
  assert.notEqual(report.risk.campaignWindow.scope, "disk");
  const rejected = await contender.conversion("private-contended-order");
  assert.equal(rejected.response.status, 503, "lock contention must not accept an in-memory conversion");
  assert.equal(rejected.json().accepted, false);
  disk.redact(report, ["private-contended-order"]);
  await checkOperationalRoutes(contender);
  const accepted = await owner.conversion("owner-durable-order");
  assert.equal(accepted.response.status, 200, "the original disk owner remains functional");
  assert.equal(accepted.json().scope, "disk");
});

test("an unusable disk path leaves HTTP available and reports safe storage errors without local conversion acceptance", { timeout: 30000 }, async t => {
  const disk = await workspace(t, { invalidDirectory: true });
  const app = await disk.start();
  const report = (await app.metrics()).json();
  assert.equal(report.diskStorage.configured, true);
  assert.equal(report.diskStorage.backend, "disk");
  assert.equal(report.diskStorage.ready, false);
  assert.match(report.diskStorage.lastError, /^[A-Za-z][A-Za-z0-9_.:-]{0,79}$/);
  const response = await app.request("/r?campaign_id=ad_alpha&private_query=private-invalid-disk-marker");
  assert.equal(response.response.status, 400, "redirect validation keeps working when disk storage is unavailable");
  const rejected = await app.conversion("private-invalid-disk-order");
  assert.equal(rejected.response.status, 503);
  assert.equal(rejected.json().accepted, false);
  const after = (await app.metrics()).json();
  assert.equal(after.risk.totals.observedRequests, 1);
  assert.equal(campaign(after).conversions, 0);
  disk.redact(after, ["private-invalid-disk-marker", "private-invalid-disk-order"]);
  await checkOperationalRoutes(app);
});

test("Railway mount detection selects its analytics directory and an explicit off setting overrides it", { timeout: 20000 }, async t => {
  for (const storageMode of ["auto", "off"]) await t.test(storageMode, async sub => {
    const disk = await workspace(sub, { storageMode });
    const app = await disk.start();
    const report = (await app.metrics()).json();
    assert.equal(report.diskStorage.configured, storageMode === "auto");
    if (storageMode === "auto") {
      assert.equal(report.diskStorage.ready, true);
      assert.equal(report.persistent.scope, "disk");
      assert.ok((await fs.stat(path.join(disk.storageDir, `${disk.namespace}.json`))).size <= 1024 * 1024);
    } else {
      assert.equal(report.persistent, null);
      await assert.rejects(fs.stat(disk.storageDir), { code: "ENOENT" });
    }
    disk.redact(report);
  });
});
