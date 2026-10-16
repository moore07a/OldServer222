"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");
const { createRequire } = require("node:module");
const test = require("node:test");
const createTurnstileSecurity = require("../modules/challenge/turnstileSecurity");
const createOperationalRoutes = require("../modules/runtime-routes/operationalRoutes");
const createRedirectCore = require("../modules/redirect-core/redirectCore");

const noop = () => {};
const linkHash = "abcdefghijk";
const expected = { action: "link_redirect", linkHash, maxAgeSec: 300 };

function validProviderData(overrides = {}) {
  return {
    success: true,
    action: expected.action,
    cdata: `${linkHash}_${Math.floor(Date.now() / 1000)}`,
    hostname: "example.test",
    ...overrides
  };
}

function verificationHarness({ data = validProviderData(), fetch, dependencies = {}, record } = {}) {
  const events = [];
  let calls = 0;
  const security = createTurnstileSecurity({
    ENFORCE_ACTION: true,
    EXPECT_HOSTNAME_ENTRIES: ["example.test"],
    EXPECT_HOSTNAME_PATTERNS: [{ suffix: "example.test" }],
    MAX_TOKEN_AGE_SEC: 300,
    addLog: noop,
    addSpacer: noop,
    fetchWithRuntimeSpan: async (...args) => {
      calls += 1;
      return fetch ? fetch(...args) : { ok: true, json: async () => data };
    },
    hostMatchesSuffix: (hostname, pattern) => hostname === pattern.suffix,
    normHost: value => String(value).toLowerCase(),
    normalizeTurnstileEnv: () => "test-key",
    recordChallengeEvent: record || (event => events.push(event)),
    safeLogValue: String,
    ...dependencies
  });
  return { ...security, events, get calls() { return calls; } };
}

test("provider verification records one honest outcome per supplied token", async t => {
  const cases = [
    { name: "valid", event: "passed", reason: undefined },
    { name: "action mismatch", data: validProviderData({ action: "other" }), event: "failed", reason: "bad_action" },
    { name: "link mismatch", data: validProviderData({ cdata: `otherhash_${Math.floor(Date.now() / 1000)}` }), event: "failed", reason: "bad_cdata_hash" },
    { name: "known expiry", data: validProviderData({ cdata: `${linkHash}_${Math.floor(Date.now() / 1000) - 3600}` }), event: "expired", reason: "token_too_old" },
    { name: "hostname mismatch", data: validProviderData({ hostname: "other.test" }), event: "failed", reason: "bad_hostname" },
    { name: "missing hostname", data: validProviderData({ hostname: undefined }), event: "failed", reason: "missing_hostname" },
    { name: "invalid configuration", dependencies: { EXPECT_HOSTNAME_PATTERNS: [] }, event: "providerError", reason: "bad_hostname_config" },
    { name: "rejected response", data: { success: false, "error-codes": ["invalid-input-response"] }, event: "failed", reason: "not_success" },
    { name: "ambiguous timeout or duplicate", data: { success: false, "error-codes": ["timeout-or-duplicate"] }, event: "expiredOrDuplicate", reason: "not_success" },
    ...["internal-error", "missing-input-secret", "invalid-input-secret"].map(code => ({
      name: code, data: { success: false, "error-codes": [code] }, event: "providerError", reason: "not_success"
    })),
    { name: "absent response data", data: null, event: "failed", reason: "not_success" },
    { name: "unknown provider error", data: { success: false, "error-codes": ["unknown-future-code"] }, event: "failed", reason: "not_success" },
    { name: "non-array error codes", data: { success: false, "error-codes": "timeout-or-duplicate" }, event: "failed", reason: "not_success" },
    { name: "HTTP failure", fetch: async () => ({ ok: false, status: 503 }), event: "providerError", reason: "upstream_status" },
    { name: "invalid JSON", fetch: async () => ({ ok: true, json: async () => { throw new Error("bad JSON"); } }), event: "providerError", reason: "invalid_json" },
    { name: "network failure", fetch: async () => { throw new Error("offline"); }, event: "providerError", reason: "verify_error" }
  ];
  for (const scenario of cases) {
    await t.test(scenario.name, async () => {
      const harness = verificationHarness(scenario);
      const result = await harness.verifyTurnstileToken("supplied-token", "192.0.2.1", expected);
      assert.equal(result.ok, scenario.event === "passed");
      assert.equal(result.reason, scenario.reason);
      assert.deepEqual(harness.events, [scenario.event]);
      assert.equal(harness.calls, 1);
      if (scenario.name === "HTTP failure") assert.equal(result.status, 503);
      if (scenario.name === "known expiry") assert.ok(result.age >= 3600);
    });
  }
});

test("missing tokens do not become failures, and recorder exceptions preserve verification results", async () => {
  const harness = verificationHarness();
  assert.deepEqual(await harness.verifyTurnstileToken("", "192.0.2.1", expected), { ok: false, reason: "missing" });
  assert.equal(harness.calls, 0);
  assert.deepEqual(harness.events, []);

  const data = validProviderData();
  const brokenRecorder = verificationHarness({ data, record: () => { throw new Error("metrics unavailable"); } });
  assert.deepEqual(await brokenRecorder.verifyTurnstileToken("supplied-token", "192.0.2.1", expected), { ok: true, data });
  const rejected = verificationHarness({
    data: { success: false },
    record: () => { throw new Error("metrics unavailable"); }
  });
  assert.deepEqual(await rejected.verifyTurnstileToken("supplied-token", "192.0.2.1", expected), {
    ok: false, reason: "not_success", data: { success: false }
  });
});

function requestResponse({ method = "GET", token = "supplied-token" } = {}) {
  const headers = { "user-agent": "Mozilla/5.0", "sec-ch-ua": "browser", "sec-fetch-site": "same-origin" };
  const req = Object.assign(new EventEmitter(), {
    method,
    path: "/r",
    query: { cft: token, lh: linkHash, ct: "signed-challenge" },
    body: {},
    get: name => headers[name] || ""
  });
  const res = Object.assign(new EventEmitter(), {
    statusCode: 200,
    locals: { cspNonce: "test-nonce" },
    type() { return this; },
    status(code) { this.statusCode = code; return this; },
    setHeader: noop,
    send(body) { this.body = body; return this; },
    redirect(code, location) { this.statusCode = code; this.location = location; return this; }
  });
  return { req, res };
}

function fragmentHarness({ valid = true, record } = {}) {
  const routes = new Map();
  const events = [];
  const app = Object.fromEntries(["get", "post", "head", "use"].map(method => [method, (route, ...handlers) => {
    routes.set(`${method}:${route}`, handlers.at(-1));
  }]));
  createOperationalRoutes({
    app,
    express: { json: () => noop },
    OPTIONAL_URL_PREFIX: "campaign",
    withOptionalUrlPrefix: route => `/campaign${route}`,
    require: createRequire(require.resolve("../modules/runtime-routes/operationalRoutes")),
    requireAdmin: noop,
    limitChallengeView: noop,
    TURNSTILE_SITEKEY: "test-sitekey",
    TURNSTILE_ORIGIN: "https://challenges.cloudflare.com",
    addLog: noop,
    safeLogValue: String,
    sanitizeChallengeReason: String,
    verifyChallengeToken: () => valid ? { next: "encrypted-link", ts: Date.now() } : null,
    recordChallengeBypassAttempt: noop,
    recordChallengeEvent: record || (event => events.push(event)),
    safeDecode: value => value,
    hashFirstSeg: () => linkHash,
    encryptChallengeData: () => "encrypted-widget-data"
  });
  return { events, handler: (method, prefix = "") => routes.get(`${method}:${prefix}/challenge-fragment`), wrapper: routes.get("get:/challenge") };
}

test("shown counts successful widget HTML for GET and normal POST, including optional prefixes", () => {
  const harness = fragmentHarness();
  for (const method of ["GET", "POST"]) {
    for (const prefix of ["", "/campaign"]) {
      const { req, res } = requestResponse({ method });
      harness.handler(method.toLowerCase(), prefix)(req, res);
      assert.match(res.body, /cf-turnstile-script/);
      res.emit("finish");
      res.emit("close");
      res.emit("finish");
    }
  }
  assert.deepEqual(harness.events, ["shown", "shown", "shown", "shown"]);
  const wrapper = requestResponse();
  harness.wrapper(wrapper.req, wrapper.res);
  wrapper.res.emit("finish");
  assert.equal(harness.events.length, 4, "wrapper responses must not count a second showing");
});

test("shown excludes HEAD, invalid tokens, failed responses, and interrupted responses", () => {
  const harness = fragmentHarness();
  const head = requestResponse({ method: "HEAD" });
  harness.handler("get")(head.req, head.res);
  head.res.emit("finish");
  for (const event of ["close", "error", "aborted"]) {
    const { req, res } = requestResponse();
    harness.handler("get")(req, res);
    (event === "aborted" ? req : res).emit(event);
    res.emit("finish");
  }
  const failure = requestResponse();
  harness.handler("get")(failure.req, failure.res);
  failure.res.statusCode = 500;
  failure.res.emit("finish");
  const alreadyAborted = requestResponse();
  alreadyAborted.req.aborted = true;
  harness.handler("get")(alreadyAborted.req, alreadyAborted.res);
  alreadyAborted.res.emit("finish");
  assert.deepEqual(harness.events, []);
  const invalid = fragmentHarness({ valid: false });
  const rejected = requestResponse();
  invalid.handler("get")(rejected.req, rejected.res);
  rejected.res.emit("finish");
  assert.equal(rejected.res.statusCode, 400);
  assert.deepEqual(invalid.events, []);
});

function redirectHarness({ verification, limited = false, destination = "https://destination.example.test/welcome", record } = {}) {
  const events = [];
  let verifyCalls = 0;
  const core = createRedirectCore({
    app: { use: noop },
    crypto,
    UA_TRUNCATE_LENGTH: 200,
    addLog: noop,
    addSpacer: noop,
    getClientIp: () => "192.0.2.1",
    getDenyCacheIp: () => "192.0.2.1",
    getRequestIdentity: () => ({ ip: "192.0.2.1" }),
    getDenyCache: () => null,
    isBanned: () => false,
    getRequestScannerDetection: () => ({ isScanner: false }),
    headlessSuspicion: () => ({ suspicious: false }),
    getCountryResolutionAsync: async () => ({ country: null }),
    getASN: () => null,
    countryBlocked: () => false,
    asnBlocked: () => false,
    verifyTurnstileToken: async () => { verifyCalls += 1; return verification || { ok: true }; },
    isRateLimited: async () => ({ limited }),
    recordChallengeBypassAttempt: noop,
    maybeDenyForVisibleIpReputation: noop,
    createChallengeRedirect: () => "/challenge?ct=signed-challenge",
    recordChallengeEvent: record || (event => events.push(event)),
    safeLogValue: String,
    safeLogJson: JSON.stringify,
    sanitizeChallengeReason: String,
    hashUaForToken: () => "ua-hash",
    hashFirstSeg: () => linkHash,
    parseRedirectPayload: () => ({ rawUrl: destination }),
    evaluateRedirectPayloadSize: () => ({ ok: true }),
    maybeLogRedirectPayloadSizeDecision: noop,
    normHost: value => value.toLowerCase(),
    isHostAllowlisted: hostname => hostname === "destination.example.test"
  });
  return { ...core, events, get verifyCalls() { return verifyCalls; } };
}

test("redirected records one completed destination redirect after verification", async () => {
  const harness = redirectHarness();
  const { req, res } = requestResponse();
  await harness.handleRedirectCore(req, res, "encrypted-link");
  assert.equal(harness.verifyCalls, 1);
  assert.equal(req._challengeMetricsVerified, true);
  assert.equal(res.statusCode, 302);
  assert.equal(res.location, "https://destination.example.test/welcome");
  assert.deepEqual(harness.events, []);
  res.emit("finish");
  res.emit("close");
  res.emit("finish");
  assert.deepEqual(harness.events, ["redirected"]);

  const preverified = redirectHarness();
  const reused = requestResponse();
  reused.req._preverifiedTurnstile = { token: "supplied-token", linkHash, verified: { ok: true } };
  await preverified.handleRedirectCore(reused.req, reused.res, "encrypted-link");
  reused.res.emit("finish");
  assert.equal(preverified.verifyCalls, 0, "a prior provider verification must not be repeated");
  assert.deepEqual(preverified.events, ["redirected"]);
});

test("redirected excludes challenge redirects, rejected destinations, limits, and interruptions", async () => {
  for (const options of [
    { verification: { ok: false, reason: "not_success" } },
    { destination: "https://forbidden.test/" },
    { destination: "ftp://destination.example.test/" },
    { limited: true }
  ]) {
    const harness = redirectHarness(options);
    const { req, res } = requestResponse();
    await harness.handleRedirectCore(req, res, "encrypted-link");
    res.emit("finish");
    assert.deepEqual(harness.events, []);
  }
  for (const event of ["close", "error", "aborted"]) {
    const harness = redirectHarness();
    const { req, res } = requestResponse();
    await harness.handleRedirectCore(req, res, "encrypted-link");
    (event === "aborted" ? req : res).emit(event);
    res.emit("finish");
    assert.deepEqual(harness.events, []);
  }
  const alreadyAborted = redirectHarness();
  const closed = requestResponse();
  closed.req.aborted = true;
  await alreadyAborted.handleRedirectCore(closed.req, closed.res, "encrypted-link");
  closed.res.emit("finish");
  assert.deepEqual(alreadyAborted.events, []);
});

test("broken response metric recorders do not disrupt successful responses", async () => {
  const record = () => { throw new Error("metrics unavailable"); };
  const fragment = fragmentHarness({ record });
  const widget = requestResponse();
  fragment.handler("get")(widget.req, widget.res);
  assert.doesNotThrow(() => widget.res.emit("finish"));
  assert.equal(widget.res.statusCode, 200);

  const redirect = redirectHarness({ record });
  const destination = requestResponse();
  await redirect.handleRedirectCore(destination.req, destination.res, "encrypted-link");
  assert.doesNotThrow(() => destination.res.emit("finish"));
  assert.equal(destination.res.statusCode, 302);
});
