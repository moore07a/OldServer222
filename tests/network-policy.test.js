"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const createNetworkPolicy = require("../modules/risk-assessment/networkPolicy.js");

const FIELDS = ["evaluated", "matchedVpn", "matchedDatacenter", "blocked", "challenged", "allowedAfterChallenge", "allowedUnknown", "errors"];
const emptyTotals = () => Object.fromEntries(FIELDS.map(field => [field, 0]));
const configured = (extra = {}) => ({ NETWORK_POLICY_VPN: "1", ...extra });

test("network policy is disabled by default and never starts a lookup without configured targets and intelligence", () => {
  let calls = 0;
  const observeNetwork = () => { calls += 1; throw new Error("must not run"); };
  const defaults = createNetworkPolicy({ observeNetwork, now: () => 0 });
  assert.deepEqual(defaults.check({}), { action: "allow", classification: "disabled", vpn: null, datacenter: null, reason: null });
  assert.deepEqual(defaults.getSnapshot(), {
    version: 2, scope: "current_process", startedAt: "1970-01-01T00:00:00.000Z", enabled: false,
    targets: { vpn: false, datacenter: false }, unavailableReason: "intelligence_disabled", totals: emptyTotals(),
    configErrors: [], unknownAction: "existing_challenge",
  });
  const noTargets = createNetworkPolicy({ lookupEnabled: true, observeNetwork });
  assert.equal(noTargets.getSnapshot().unavailableReason, "no_targets");
  assert.equal(noTargets.check({}).classification, "disabled");
  const noProvider = createNetworkPolicy({ env: configured(), observeNetwork });
  assert.equal(noProvider.check({}).action, "allow");
  assert.equal(noProvider.getSnapshot().enabled, false);
  assert.equal(noProvider.getSnapshot().unavailableReason, "intelligence_disabled");
  assert.equal(calls, 0);
});

test("network policy accepts the two target switches and their existing trimmed boolean aliases", () => {
  for (const value of ["1", "true", "on", "yes", " YES ", true, 1]) {
    const policy = createNetworkPolicy({ env: configured({ NETWORK_POLICY_VPN: value, NETWORK_POLICY_DATACENTER: value }), lookupEnabled: true });
    assert.deepEqual(policy.getSnapshot().targets, { vpn: true, datacenter: true });
    assert.equal(policy.getSnapshot().enabled, true);
    assert.deepEqual(policy.getSnapshot().configErrors, []);
  }
  for (const value of ["0", "false", "off", "no", " NO ", false, 0, "", " ", undefined, null]) {
    const policy = createNetworkPolicy({ env: configured({ NETWORK_POLICY_VPN: value, NETWORK_POLICY_DATACENTER: value }), lookupEnabled: true });
    assert.deepEqual(policy.getSnapshot().targets, { vpn: false, datacenter: false });
    assert.equal(policy.getSnapshot().unavailableReason, "no_targets");
    assert.equal(policy.getSnapshot().enabled, false);
    assert.deepEqual(policy.getSnapshot().configErrors, []);
  }
});

test("the removed mode cannot activate disabled switches or weaken enabled blocking", () => {
  for (const mode of ["report", "challenge", "block", "none", "private-invalid-mode", "", undefined]) {
    let calls = 0;
    const disabled = createNetworkPolicy({ lookupEnabled: true, env: { NETWORK_POLICY_MODE: mode },
      observeNetwork: () => { calls += 1; return { vpn: true, hosting: true }; } });
    assert.equal(disabled.check({}).classification, "disabled");
    assert.equal(disabled.getSnapshot().enabled, false);
    assert.deepEqual(disabled.getSnapshot().configErrors, []);
    assert.equal(calls, 0);
    const enabled = createNetworkPolicy({ lookupEnabled: true, env: configured({ NETWORK_POLICY_MODE: mode }),
      observeNetwork: () => ({ vpn: true }) });
    assert.equal(enabled.check({}, { verified: true }).action, "block");
    assert.equal(enabled.getSnapshot().enabled, true);
    assert.deepEqual(enabled.getSnapshot().configErrors, []);
    assert.equal(Object.hasOwn(enabled.getSnapshot(), "mode"), false);
    assert.equal(Object.hasOwn(enabled.getSnapshot(), "effectiveMode"), false);
    assert.doesNotMatch(JSON.stringify(enabled.getSnapshot()), /private-invalid-mode/);
  }
  const env = configured();
  Object.defineProperty(env, "NETWORK_POLICY_MODE", { get() { throw new Error("must never read removed mode"); } });
  const policy = createNetworkPolicy({ lookupEnabled: true, env, observeNetwork: () => ({ vpn: true }) });
  assert.equal(policy.check({}).action, "block");
});

test("invalid configuration disables enforcement without reflecting configuration contents", () => {
  let calls = 0;
  for (const env of [
    configured({ NETWORK_POLICY_VPN: "private-token" }),
    configured({ NETWORK_POLICY_DATACENTER: "private-ip" }),
    { NETWORK_POLICY_MODE: "private-mode", NETWORK_POLICY_VPN: "private-token", NETWORK_POLICY_DATACENTER: "private-ip" },
  ]) {
    const policy = createNetworkPolicy({ env, lookupEnabled: true, observeNetwork: () => { calls += 1; return { vpn: true, hosting: true }; } });
    assert.equal(policy.check({}).classification, "disabled");
    const snapshot = policy.getSnapshot();
    assert.equal(snapshot.enabled, false);
    assert.equal(snapshot.unavailableReason, "invalid_configuration");
    assert.deepEqual(snapshot.configErrors, ["NETWORK_POLICY_VPN", "NETWORK_POLICY_DATACENTER"]
      .filter(field => Object.hasOwn(env, field) && String(env[field]).includes("private")));
    assert.doesNotMatch(JSON.stringify(snapshot), /private|secret|https:/);
  }
  assert.equal(calls, 0);
});

test("all four switch combinations preserve selected OR semantics, unknown verification, and strict blocking", () => {
  for (const [vpnTarget, datacenterTarget] of [[false, false], [true, false], [false, true], [true, true]]) {
    for (const vpn of [true, false, null]) for (const hosting of [true, false, null]) {
      for (const verified of [false, true]) {
        const policy = createNetworkPolicy({ lookupEnabled: true,
          env: { NETWORK_POLICY_VPN: String(Number(vpnTarget)), NETWORK_POLICY_DATACENTER: String(Number(datacenterTarget)) },
          observeNetwork: () => ({ vpn, hosting }) });
        const matchedVpn = vpnTarget && vpn === true;
        const matchedDatacenter = datacenterTarget && hosting === true;
        const matched = matchedVpn || matchedDatacenter;
        const unmatched = !matched && (!vpnTarget || vpn === false) && (!datacenterTarget || hosting === false);
        const enabled = vpnTarget || datacenterTarget;
        const classification = !enabled ? "disabled" : matched ? "matched" : unmatched ? "unmatched" : "unknown";
        const expectedAction = !enabled || unmatched ? "allow" : matched ? "block" : verified ? "allow" : "challenge";
        const context = JSON.stringify({ vpnTarget, datacenterTarget, vpn, hosting, verified });
        assert.deepEqual(policy.check({}, { verified }), {
          action: expectedAction, classification, vpn: enabled ? vpn : null, datacenter: enabled ? hosting : null,
          reason: !enabled ? null : matchedVpn && matchedDatacenter ? "both" : matchedVpn ? "vpn" : matchedDatacenter ? "datacenter" : unmatched ? null : "unknown",
        }, context);
        assert.equal(policy.getSnapshot().enabled, enabled, context);
      }
    }
  }
});

test("network policy never coerces malformed flags or accepts an alternative field name", () => {
  for (const result of [null, undefined, false, "private-value", [], Promise.resolve({ vpn: true }),
    { vpn: "true", hosting: 1 }, { vpn: 1, datacenter: true }, { vpn: false, hosting: "false" }]) {
    const policy = createNetworkPolicy({ env: configured({ NETWORK_POLICY_DATACENTER: "1" }), lookupEnabled: true, observeNetwork: () => result });
    const decision = policy.check({});
    assert.equal(decision.classification, "unknown");
    assert.equal(decision.action, "challenge");
    assert.ok(decision.vpn === null || decision.vpn === false);
    assert.equal(decision.datacenter, null);
    assert.equal(policy.getSnapshot().totals.errors, 0);
  }
  let vpnReads = 0;
  const policy = createNetworkPolicy({ env: configured(), lookupEnabled: true, observeNetwork: () => ({ get vpn() { vpnReads += 1; return vpnReads === 1 ? true : "private-value"; } }) });
  assert.equal(policy.check({}).vpn, true);
  assert.equal(vpnReads, 1);
});

test("known selected matches always block and the historical challenge-allow counter cannot increment", () => {
  const events = [];
  const policy = createNetworkPolicy({ env: configured({ NETWORK_POLICY_DATACENTER: "1" }), lookupEnabled: true,
    observeNetwork: () => ({ vpn: true, hosting: true }), onEvent: field => events.push(field) });
  const req = {};
  const decision = policy.check(req, { verified: true });
  for (const outcome of ["blocked", "challenged", "allowedAfterChallenge", "allowedUnknown"]) policy.record(req, outcome, decision);
  assert.deepEqual(policy.getSnapshot().totals, { ...emptyTotals(), evaluated: 1, matchedVpn: 1, matchedDatacenter: 1, blocked: 1 });
  assert.deepEqual(events, ["evaluated", "matchedVpn", "matchedDatacenter", "blocked"]);
  assert.equal(decision.action, "block");
});

test("rechecks update a cold-cache decision while each request and matching target is counted once", () => {
  let result = { vpn: null, hosting: null };
  let lookups = 0;
  const policy = createNetworkPolicy({ env: configured({ NETWORK_POLICY_DATACENTER: "1" }), lookupEnabled: true,
    observeNetwork: () => { lookups += 1; return result; } });
  const req = {};
  assert.equal(policy.check(req).action, "challenge");
  result = { vpn: true, hosting: null };
  assert.equal(policy.check(req).reason, "vpn");
  result = { vpn: true, hosting: true };
  const blocked = policy.check(req, { verified: true });
  assert.equal(blocked.action, "block");
  assert.equal(blocked.reason, "both");
  policy.record(req, "blocked", blocked);
  policy.record(req, "blocked", blocked);
  policy.check(req, { verified: true });
  assert.equal(lookups, 4);
  assert.deepEqual(policy.getSnapshot().totals, { ...emptyTotals(), evaluated: 1, matchedVpn: 1, matchedDatacenter: 1, blocked: 1 });
});

test("enforcement outcomes are recorded only once per request after a compatible authentic decision", () => {
  let network = { vpn: null };
  const policy = createNetworkPolicy({ env: configured(), lookupEnabled: true, observeNetwork: () => network });
  const req = {};
  const challenge = policy.check(req);
  for (const outcome of ["blocked", "allowedAfterChallenge", "allowedUnknown", "evaluated", "matchedVpn", "errors", "__proto__", null, {}]) {
    policy.record(req, outcome, challenge);
  }
  policy.record(req, "challenged", { ...challenge });
  policy.record({}, "challenged", challenge);
  policy.record(req, "challenged", challenge);
  policy.record(req, "challenged", challenge);
  assert.equal(policy.getSnapshot().totals.challenged, 1);
  network = { vpn: true };
  const blocked = policy.check(req, { verified: true });
  policy.record(req, "challenged", challenge);
  policy.record(req, "allowedAfterChallenge", blocked);
  policy.record(req, "allowedUnknown", blocked);
  policy.record(req, "blocked", blocked);
  policy.record(req, "blocked", blocked);
  network = { vpn: null };
  const unknown = policy.check(req, { verified: true });
  policy.record(req, "allowedAfterChallenge", unknown);
  policy.record(req, "allowedUnknown", unknown);
  policy.record(req, "allowedUnknown", unknown);
  assert.deepEqual(policy.getSnapshot().totals, { ...emptyTotals(), evaluated: 1, matchedVpn: 1, challenged: 1, blocked: 1, allowedUnknown: 1 });
  assert.throws(() => { unknown.action = "block"; }, TypeError);
});

test("observer failures become unknown decisions and count one error per request without exposing thrown details", () => {
  let useGetter = false;
  const policy = createNetworkPolicy({ env: configured(), lookupEnabled: true,
    observeNetwork: () => {
      if (useGetter) return { vpn: true, get hosting() { throw new Error("private getter"); } };
      throw new Error("private IP and token");
    }, onEvent: () => { throw new Error("private observer error"); } });
  const req = {};
  assert.equal(policy.check(req).action, "challenge");
  useGetter = true;
  assert.deepEqual(policy.check(req, { verified: true }), { action: "allow", classification: "unknown", vpn: null, datacenter: null, reason: "unknown" });
  assert.equal(policy.getSnapshot().totals.errors, 1);
  policy.check({});
  assert.equal(policy.getSnapshot().totals.errors, 2);
  assert.doesNotMatch(JSON.stringify(policy.getSnapshot()), /private|token|getter/);
});

test("independent simultaneous requests keep independent outcome bookkeeping and snapshots cannot mutate policy state", async () => {
  const policy = createNetworkPolicy({ env: configured(), lookupEnabled: true, observeNetwork: req => ({ vpn: req.vpn }) });
  await Promise.all(Array.from({ length: 64 }, async (_, index) => {
    const req = { vpn: index % 2 === 0 };
    const decision = policy.check(req, { verified: true });
    await Promise.resolve();
    if (decision.action === "block") {
      policy.record(req, "blocked", decision);
      policy.record(req, "blocked", decision);
    }
    policy.check(req, { verified: true });
  }));
  const snapshot = policy.getSnapshot();
  assert.deepEqual(snapshot.totals, { ...emptyTotals(), evaluated: 64, matchedVpn: 32, blocked: 32 });
  snapshot.totals.blocked = -1;
  snapshot.targets.vpn = false;
  snapshot.configErrors.push("private-value");
  assert.equal(policy.getSnapshot().totals.blocked, 32);
  assert.equal(policy.getSnapshot().targets.vpn, true);
  assert.deepEqual(policy.getSnapshot().configErrors, []);
});
