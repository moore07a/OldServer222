"use strict";

const TOTAL_FIELDS = ["evaluated", "matchedVpn", "matchedDatacenter", "blocked", "challenged", "allowedAfterChallenge", "allowedUnknown", "errors"];
const OUTCOME_BITS = { blocked: 1, challenged: 2, allowedAfterChallenge: 4, allowedUnknown: 8 };
const MODES = ["report", "challenge", "block"];
const TRUE_VALUES = ["1", "true", "on", "yes"];
const FALSE_VALUES = ["0", "false", "off", "no"];

function createNetworkPolicy({
  env = {}, lookupEnabled = false, observeNetwork = () => null, onEvent = () => {}, now = Date.now
} = {}) {
  const configErrors = [];
  const requestedMode = String(env.NETWORK_POLICY_MODE ?? "report").trim().toLowerCase() || "report";
  const modeValid = MODES.includes(requestedMode);
  const mode = modeValid ? requestedMode : "report";
  if (!modeValid) configErrors.push("NETWORK_POLICY_MODE");
  function target(name) {
    const raw = String(env[name] ?? "0").trim().toLowerCase() || "0";
    if (TRUE_VALUES.includes(raw)) return true;
    if (FALSE_VALUES.includes(raw)) return false;
    configErrors.push(name);
    return false;
  }
  const targets = { vpn: target("NETWORK_POLICY_VPN"), datacenter: target("NETWORK_POLICY_DATACENTER") };
  const unavailableReason = configErrors.length ? "invalid_configuration"
    : !lookupEnabled ? "intelligence_disabled" : !targets.vpn && !targets.datacenter ? "no_targets" : null;
  const canEvaluate = unavailableReason === null;
  const effectiveMode = canEvaluate ? mode : "report";
  const enabled = canEvaluate && mode !== "report";
  const startedAt = new Date(now()).toISOString();
  const totals = Object.fromEntries(TOTAL_FIELDS.map(field => [field, 0]));
  // Only the request itself owns this bookkeeping. Nothing stores an IP,
  // identity, response, or an independently retained collection of requests.
  const requests = new WeakMap();

  function increment(field) {
    if (totals[field] >= Number.MAX_SAFE_INTEGER) return;
    totals[field] += 1;
    try {
      const pending = onEvent(field);
      if (pending && typeof pending.catch === "function") pending.catch(() => {});
    } catch (_) {}
  }
  function stateFor(req) {
    if (!req || (typeof req !== "object" && typeof req !== "function")) return null;
    let state = requests.get(req);
    if (!state) {
      state = { evaluated: false, vpn: false, datacenter: false, error: false, outcomes: 0, decision: null, verified: false };
      requests.set(req, state);
    }
    return state;
  }
  function check(req, { verified = false } = {}) {
    const state = stateFor(req);
    let vpn = null;
    let datacenter = null;
    let classification = "disabled";
    let reason = null;
    let action = "allow";
    if (canEvaluate) {
      if (state && !state.evaluated) { state.evaluated = true; increment("evaluated"); }
      try {
        const network = state ? observeNetwork(req) : null;
        if (network && typeof network === "object" && !Array.isArray(network)) {
          const vpnValue = network.vpn;
          const datacenterValue = network.hosting;
          vpn = typeof vpnValue === "boolean" ? vpnValue : null;
          datacenter = typeof datacenterValue === "boolean" ? datacenterValue : null;
        }
      } catch (_) {
        vpn = null;
        datacenter = null;
        if (state && !state.error) { state.error = true; increment("errors"); }
      }
      const matchedVpn = targets.vpn && vpn === true;
      const matchedDatacenter = targets.datacenter && datacenter === true;
      if (matchedVpn || matchedDatacenter) {
        classification = "matched";
        reason = matchedVpn && matchedDatacenter ? "both" : matchedVpn ? "vpn" : "datacenter";
        if (state && matchedVpn && !state.vpn) { state.vpn = true; increment("matchedVpn"); }
        if (state && matchedDatacenter && !state.datacenter) { state.datacenter = true; increment("matchedDatacenter"); }
      } else if ((!targets.vpn || vpn === false) && (!targets.datacenter || datacenter === false)) {
        classification = "unmatched";
      } else {
        classification = "unknown";
        reason = "unknown";
      }
      if (enabled) {
        if (classification === "matched" && mode === "block") action = "block";
        else if (classification !== "unmatched" && verified !== true) action = "challenge";
      }
    }
    const decision = Object.freeze({ action, classification, vpn, datacenter, reason });
    if (state) { state.decision = decision; state.verified = verified === true; }
    return decision;
  }
  function record(req, outcome, decision) {
    if (!req || (typeof req !== "object" && typeof req !== "function") || typeof outcome !== "string" || !Object.hasOwn(OUTCOME_BITS, outcome)) return;
    const state = requests.get(req);
    if (!enabled || !state || state.decision !== decision || (state.outcomes & OUTCOME_BITS[outcome])) return;
    const compatible = outcome === "blocked" ? decision.action === "block"
      : outcome === "challenged" ? decision.action === "challenge"
        : outcome === "allowedAfterChallenge" ? mode === "challenge" && decision.action === "allow" && state.verified && decision.classification === "matched"
          : decision.action === "allow" && state.verified && decision.classification === "unknown";
    if (!compatible) return;
    state.outcomes |= OUTCOME_BITS[outcome];
    increment(outcome);
  }
  function getSnapshot() {
    return { scope: "current_process", startedAt, mode, effectiveMode, enabled, targets: { ...targets }, unavailableReason,
      totals: { ...totals }, configErrors: [...configErrors], unknownAction: "existing_challenge" };
  }
  return { check, record, getSnapshot };
}

module.exports = createNetworkPolicy;
