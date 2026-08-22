"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const test = require("node:test");

function encryptPayload(url, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(url, "utf8"), cipher.final()]);
  return Buffer.concat([iv, ciphertext, cipher.getAuthTag()]).toString("base64url");
}

async function waitForServer(baseUrl, child) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`server exited with ${child.exitCode}`);
    try {
      const response = await fetch(`${baseUrl}/healthz`);
      if (response.ok) return;
    } catch (_) {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("server did not become ready");
}

test("scanner safety lane works through real Express HTTP routes", { timeout: 30000 }, async (t) => {
  const key = crypto.randomBytes(32);
  const port = 21000 + (process.pid % 10000);
  const baseUrl = `http://127.0.0.1:${port}`;
  const payload = encryptPayload("https://landing.example.test/welcome", key);
  const shortPayload = encryptPayload("https://landing.example.test", key);
  let output = "";
  const child = spawn(process.execPath, ["server.js"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(port),
      AES_KEY: key.toString("base64url"),
      ALLOWLIST_DOMAINS: "landing.example.test",
      TURNSTILE_SITEKEY: "1x00000000000000000000AA",
      TURNSTILE_SECRET: "1x0000000000000000000000000000000AA",
      TURNSTILE_ORIGIN: "https://challenges.cloudflare.com",
      SCANNER_SAFE_HTML_ENABLED: "1",
      SCANNER_COMPAT_HEADERS: "1",
      INTERSTITIAL_REASON_HEADER: "1",
      INTERSTITIAL_BYPASS_SECRET: "scanner-test-bypass",
      IMPERSONATE_SCANNER: "1",
      IMPERSONATE_SCANNER_STRICT: "1",
      IMPERSONATE_MIN_CONFIDENCE: "0.85",
      LOG_TO_FILE: "0",
      IPINFO_LITE_ENABLED: "0"
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { output += chunk; });
  t.after(() => { if (child.exitCode === null) child.kill("SIGTERM"); });
  await waitForServer(baseUrl, child);

  const emptyEmailHead = await fetch(`${baseUrl}/e`, {
    method: "HEAD",
    headers: { "user-agent": "", accept: "", "accept-language": "" },
    redirect: "manual"
  });
  assert.equal(emptyEmailHead.status, 200);
  const afterEmptyProbe = await fetch(`${baseUrl}/${payload}`, {
    headers: { "user-agent": "", accept: "", "accept-language": "" },
    redirect: "manual"
  });
  assert.equal(afterEmptyProbe.status, 302);
  assert.match(afterEmptyProbe.headers.get("location") || "", /\/challenge\?/);

  const trusted = await fetch(`${baseUrl}/${payload}`, {
    headers: { "user-agent": "safelinks.protection.outlook.com" },
    redirect: "manual"
  });
  const trustedBody = await trusted.text();
  assert.equal(trusted.status, 200);
  assert.match(trusted.headers.get("content-type") || "", /^text\/html/);
  assert.equal(trusted.headers.get("location"), null);
  assert.match(trustedBody, /Simple Wellness Habits for Everyday Health/);
  assert.doesNotMatch(trustedBody, /landing\.example\.test|Checking this link|window\.location/);
  for (const header of ["cache-control", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy", "cross-origin-resource-policy", "cross-origin-opener-policy"]) {
    assert.ok(trusted.headers.has(header), `${header} should be present`);
  }
  const csp = trusted.headers.get("content-security-policy") || "";
  const nonceMatch = trustedBody.match(/<style nonce="([A-Za-z0-9_-]+)">/);
  assert.ok(nonceMatch, "style nonce should be present");
  assert.match(csp, new RegExp(`style-src 'nonce-${nonceMatch[1]}'`));
  assert.doesNotMatch(csp, /unsafe-inline/);
  assert.ok(trusted.headers.has("x-ms-exchange-organization-authas"));

  const genericGet = await fetch(`${baseUrl}/${payload}`, {
    headers: { "user-agent": "Mozilla/5.0 (compatible; URLScanner/1.0)" }, redirect: "manual"
  });
  assert.doesNotMatch(await genericGet.text(), /Simple Wellness Habits/);

  for (const candidate of [payload, shortPayload]) {
    for (const cookie of [false, true]) {
      const head = await fetch(`${baseUrl}/${candidate}`, {
        method: "HEAD",
        headers: {
          "user-agent": "Mozilla/5.0 (compatible; URLScanner/1.0)",
          ...(cookie ? { cookie: "scanner_test=1" } : {})
        }
      });
      assert.equal(head.status, 200);
      assert.match(head.headers.get("content-type") || "", /^text\/html/);
      assert.equal(head.headers.get("x-interstitial-reason-code"), "head_probe");
      assert.equal(await head.text(), "");
    }
  }

  const emailHead = await fetch(`${baseUrl}/e/${payload}`, {
    method: "HEAD",
    headers: { "user-agent": "Mozilla/5.0 (compatible; URLScanner/1.0)" }
  });
  assert.equal(emailHead.status, 200);
  assert.equal(emailHead.headers.get("x-interstitial-reason-code"), "head_probe");
  assert.equal(await emailHead.text(), "");

  const correlatedHead = await fetch(`${baseUrl}/${payload}`, {
    method: "HEAD",
    headers: { "user-agent": "", accept: "", "accept-language": "" }
  });
  assert.equal(correlatedHead.status, 200);
  const correlatedGet = await fetch(`${baseUrl}/${payload}`, {
    headers: { "user-agent": "", accept: "", "accept-language": "" },
    redirect: "manual"
  });
  assert.equal(correlatedGet.status, 204);
  assert.equal(correlatedGet.headers.get("location"), null);
  assert.equal(correlatedGet.headers.get("x-interstitial-reason-code"), "head_probe");
  assert.equal(await correlatedGet.text(), "");

  // The scanner walks different payloads and optional-prefix normalization can
  // change the value passed to redirect handling. IP-scoped lane state must keep
  // all headerless follow-ups away from /challenge without affecting browsers.
  const differentPayloadGet = await fetch(`${baseUrl}/${shortPayload}`, {
    headers: { "user-agent": "", accept: "", "accept-language": "" },
    redirect: "manual"
  });
  assert.equal(differentPayloadGet.status, 204);
  assert.equal(differentPayloadGet.headers.get("location"), null);

  const redirectRoute = `${baseUrl}/r?d=${encodeURIComponent(payload)}`;
  const redirectHead = await fetch(redirectRoute, {
    method: "HEAD",
    headers: { "user-agent": "", accept: "", "accept-language": "" },
    redirect: "manual"
  });
  assert.equal(redirectHead.status, 200);
  assert.equal(redirectHead.headers.get("x-interstitial-reason-code"), "head_probe");
  const redirectGet = await fetch(redirectRoute, {
    headers: { "user-agent": "", accept: "", "accept-language": "" },
    redirect: "manual"
  });
  assert.equal(redirectGet.status, 204);
  assert.equal(redirectGet.headers.get("location"), null);

  const bypassedGet = await fetch(redirectRoute, {
    headers: {
      "user-agent": "",
      accept: "",
      "accept-language": "",
      "x-interstitial-bypass": "scanner-test-bypass"
    },
    redirect: "manual"
  });
  assert.equal(bypassedGet.status, 302);
  assert.match(bypassedGet.headers.get("location") || "", /\/challenge\?/);

  const browser = await fetch(`${baseUrl}/${payload}`, {
    headers: {
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
      accept: "text/html,application/xhtml+xml",
      "accept-language": "en-US,en;q=0.9",
      "sec-ch-ua": '"Chromium";v="126"',
      "sec-fetch-site": "none",
      "sec-fetch-mode": "navigate",
      "sec-fetch-dest": "document"
    },
    redirect: "manual"
  });
  assert.equal(browser.status, 302);
  assert.match(browser.headers.get("location") || "", /\/challenge\?/);
  assert.doesNotMatch(await browser.text(), /Simple Wellness Habits/);

  const emailScanner = await fetch(`${baseUrl}/e/${payload}`, {
    headers: { "user-agent": "safelinks.protection.outlook.com" }, redirect: "manual"
  });
  assert.equal(emailScanner.status, 200);
  assert.match(await emailScanner.text(), /Simple Wellness Habits for Everyday Health/);

  const emailBrowser = await fetch(`${baseUrl}/e/${payload}`, {
    headers: { "user-agent": "Mozilla/5.0", accept: "text/html" }, redirect: "manual"
  });
  const emailBrowserBody = await emailBrowser.text();
  assert.equal(emailBrowser.status, 200);
  assert.match(emailBrowserBody, /Checking this link/);
  assert.match(emailBrowserBody, />Continue<\/a>/);
  assert.doesNotMatch(emailBrowserBody, /Simple Wellness Habits/);

  await new Promise((resolve) => setTimeout(resolve, 100));
  const safetyLogs = output.split("\n").filter((line) => line.includes("[SCANNER-SAFETY-LANE]"));
  assert.ok(safetyLogs.length >= 1);
  assert.ok(safetyLogs.every((line) => !line.includes(payload)));
  assert.ok(safetyLogs.some((line) => line.includes("originalPath=/[redacted]")));
  assert.ok(!output.includes(payload), "runtime logs must not expose the campaign payload");
});
