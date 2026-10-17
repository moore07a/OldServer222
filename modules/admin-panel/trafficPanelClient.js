"use strict";

function createTrafficPanelController(options = {}) {
  const browser = options.window || (typeof window !== "undefined" ? window : null);
  const documentObject = options.document || (browser && browser.document);
  const root = options.root || (documentObject && documentObject.getElementById && documentObject.getElementById("traffic-panel"));
  const request = options.fetch || (browser && browser.fetch && browser.fetch.bind(browser));
  const Abort = options.AbortController || (browser && browser.AbortController);
  const setTimer = options.setTimeout || (browser && browser.setTimeout && browser.setTimeout.bind(browser));
  const clearTimer = options.clearTimeout || (browser && browser.clearTimeout && browser.clearTimeout.bind(browser));
  const now = options.now || Date.now;
  const endpoint = new URL(options.metricsUrl || (root && root.dataset.metricsUrl) || "/admin/traffic-metrics", (browser && browser.location.href) || "https://localhost/");
  if (browser && endpoint.origin !== browser.location.origin) throw new Error("Metrics must use the same origin.");
  if (!request || !Abort || !setTimer || !clearTimer) throw new Error("Panel browser APIs are unavailable.");

  let token = null;
  let active = null;
  let timer = null;
  let generation = 0;
  let failures = 0;
  let paused = false;
  let pageHidden = false;
  let destroyed = false;
  let latest = null;
  let lastSuccess = null;
  let scope = "current";
  let history = [];
  let message = "Connect to load metrics.";
  let error = false;
  const listeners = [];
  const view = options.view || createDocumentView();

  function isHidden() { return pageHidden || Boolean(documentObject && documentObject.hidden); }
  function canPoll() { return Boolean(token) && !paused && !isHidden() && !destroyed; }
  function state() {
    return { connected: Boolean(token), loading: Boolean(active), paused, hidden: isHidden(), scope, lastSuccess, stale: lastSuccess !== null && Boolean(error || paused || isHidden() || active), message, error, sampleCount: history.length };
  }
  function updateView() { view.update(state()); }
  function clearScheduled() { if (timer !== null) clearTimer(timer); timer = null; }
  function cancelActive() {
    generation += 1;
    if (!active) return;
    const previous = active;
    active = null;
    clearTimer(previous.timeout);
    previous.controller.abort();
    previous.cancel(new Error("Refresh cancelled."));
  }
  function schedule(delay) {
    clearScheduled();
    if (canPoll()) timer = setTimer(() => { timer = null; refresh(); }, delay);
  }
  function paint() { if (latest) view.render(latest, scope, history); }
  function forgetMetrics() {
    latest = null;
    lastSuccess = null;
    history = [];
    view.clear();
  }
  function disconnect(nextMessage = "Disconnected. Enter an admin token to reconnect.", isError = false) {
    token = null;
    paused = false;
    failures = 0;
    clearScheduled();
    cancelActive();
    forgetMetrics();
    message = nextMessage;
    error = isError;
    updateView();
  }
  function connect(value) {
    if (destroyed) return;
    const nextToken = String(value || "").trim();
    if (!nextToken) { message = "Enter your admin token."; error = true; updateView(); return; }
    clearScheduled();
    cancelActive();
    forgetMetrics();
    token = nextToken;
    paused = false;
    failures = 0;
    error = false;
    message = isHidden() ? "Connected. Refreshing is paused while this tab is hidden." : "Connecting…";
    updateView();
    return refresh();
  }
  async function refresh() {
    if (!canPoll() || active) return false;
    clearScheduled();
    const job = { generation: ++generation, controller: new Abort(), timeout: null, cancel: null, timedOut: false };
    const cancelled = new Promise((resolve, reject) => { job.cancel = reject; });
    active = job;
    message = "Refreshing…";
    updateView();
    job.timeout = setTimer(() => {
      job.timedOut = true;
      job.controller.abort();
      job.cancel(new Error("Refresh timed out after 8 seconds."));
    }, 8000);
    try {
      const response = await Promise.race([
        request(endpoint.href, { method: "GET", headers: { Authorization: `Bearer ${token}`, Accept: "application/json" }, signal: job.controller.signal, cache: "no-store", credentials: "omit", redirect: "error", referrerPolicy: "no-referrer" }),
        cancelled
      ]);
      if (job.generation !== generation) return false;
      if (response.status === 401 || response.status === 403) {
        disconnect("Authentication rejected. Enter a valid admin token to reconnect.", true);
        return false;
      }
      if (!response.ok) throw new Error(`Metrics request returned HTTP ${response.status}.`);
      const report = await Promise.race([response.json(), cancelled]);
      if (job.generation !== generation) return false;
      if (!report || report.ok === false || !report.total || typeof report.total.requests !== "number" || !Number.isFinite(report.total.requests)) throw new Error("The metrics response was invalid.");
      const at = now();
      // Store only the counters used by the chart, never whole reports.
      history.push({ at, current: report.total.requests, shared: report.shared && report.shared.total ? report.shared.total.requests : null, persistent: report.persistent && report.persistent.total ? report.persistent.total.requests : null });
      if (history.length > 60) history.splice(0, history.length - 60);
      latest = report;
      lastSuccess = at;
      failures = 0;
      error = false;
      message = "Live · refreshes every 5 seconds.";
      paint();
      return true;
    } catch (failure) {
      if (job.generation !== generation) return false;
      failures += 1;
      error = true;
      const delay = Math.min(60000, 5000 * (2 ** Math.min(failures, 4)));
      message = `${job.timedOut ? "Refresh timed out after 8 seconds." : "Unable to refresh metrics."} ${lastSuccess === null ? "No report loaded." : "Showing the last report (stale)."} Retrying in ${delay / 1000}s.`;
      return false;
    } finally {
      clearTimer(job.timeout);
      if (job.generation === generation) {
        active = null;
        updateView();
        schedule(failures ? Math.min(60000, 5000 * (2 ** Math.min(failures, 4))) : 5000);
      }
    }
  }
  function pause() {
    if (!token || destroyed) return;
    paused = true;
    clearScheduled();
    cancelActive();
    message = "Paused. Showing the last report.";
    updateView();
  }
  function resume() {
    if (!token || destroyed) return;
    paused = false;
    error = false;
    updateView();
    return refresh();
  }
  function suspend() {
    clearScheduled();
    cancelActive();
    if (token && !paused) message = "Refresh paused while this page is hidden.";
    updateView();
  }
  function visibilityChanged() { if (isHidden()) suspend(); else if (canPoll()) refresh(); }
  function onPageHide() { pageHidden = true; suspend(); }
  function onPageShow() { pageHidden = false; visibilityChanged(); }
  function setScope(value) { scope = value === "shared" || value === "persistent" ? value : "current"; paint(); updateView(); }
  function listen(target, name, handler) {
    if (target && target.addEventListener) { target.addEventListener(name, handler); listeners.push(() => target.removeEventListener(name, handler)); }
  }
  function destroy() {
    disconnect("Disconnected.");
    destroyed = true;
    for (const remove of listeners.splice(0)) remove();
  }

  function createDocumentView() {
    if (!root) throw new Error("Panel root was not found.");
    const find = (name) => root.querySelector(`[data-role="${name}"]`);
    const fields = Array.from(root.querySelectorAll("[data-value]"));
    const output = Object.fromEntries(fields.map((element) => [element.dataset.value, element]));
    const text = (key, value) => { if (output[key]) output[key].textContent = value; };
    const numeric = (value, digits = 0) => typeof value === "number" && Number.isFinite(value) ? value.toLocaleString(undefined, { maximumFractionDigits: digits }) : "—";
    const milliseconds = (value) => typeof value === "number" && Number.isFinite(value) ? `${numeric(value, 2)} ms` : "—";
    const date = (value) => value === null || value === undefined || value === "" ? "—" : Number.isNaN(new Date(value).getTime()) ? "—" : new Date(value).toLocaleString();
    const tokenInput = find("token");
    // The form field is cleared before the controller starts a network request.
    listen(find("connect-form"), "submit", (event) => { event.preventDefault(); const entered = tokenInput.value; tokenInput.value = ""; connect(entered); });
    listen(find("refresh"), "click", () => refresh());
    listen(find("pause"), "click", () => paused ? resume() : pause());
    listen(find("disconnect"), "click", () => { tokenInput.value = ""; disconnect(); });
    listen(find("scope"), "change", (event) => setScope(event.target.value));
    function renderNetworkPolicy(policy, persisted) {
      const record = (value) => value && typeof value === "object" && !Array.isArray(value);
      const reasons = {
        invalid_configuration: "Inactive · invalid configuration",
        intelligence_disabled: "Inactive · IP intelligence disabled",
        no_targets: "Off · existing security"
      };
      const available = record(policy) && policy.version === 2 && policy.scope === "current_process" && typeof policy.enabled === "boolean" &&
        record(policy.targets) && typeof policy.targets.vpn === "boolean" && typeof policy.targets.datacenter === "boolean" &&
        (policy.unavailableReason === null || Object.prototype.hasOwnProperty.call(reasons, policy.unavailableReason));
      const targets = available ? policy.targets : {};
      const active = available && policy.enabled && (targets.vpn || targets.datacenter) && policy.unavailableReason === null;
      const reason = available && policy.unavailableReason !== null ? reasons[policy.unavailableReason] : null;
      const count = (value) => Number.isSafeInteger(value) && value >= 0 ? numeric(value) : "—";
      const totals = available && record(policy.totals) ? policy.totals : {};
      text("networkPolicy.vpn", available ? targets.vpn ? "On" : "Off" : "Unavailable");
      text("networkPolicy.datacenter", available ? targets.datacenter ? "On" : "Off" : "Unavailable");
      text("networkPolicy.status", !available ? "Unavailable" : reason || (active ? "Active" : !targets.vpn && !targets.datacenter ? "Off · existing security" : "Inactive"));
      text("networkPolicy.unknownAction", available && policy.unknownAction === "existing_challenge" ? "Existing challenge and security rules" : "Unavailable");
      const knownErrors = ["NETWORK_POLICY_VPN", "NETWORK_POLICY_DATACENTER"];
      const errors = available && Array.isArray(policy.configErrors) ? knownErrors.filter((key) => policy.configErrors.includes(key)) : [];
      text("networkPolicy.configErrors", !available ? "Unavailable" : errors.length ? errors.join(", ") : policy.unavailableReason === "invalid_configuration" ? "Invalid configuration" : "None");
      find("network-policy-note").textContent = available ? `Current process only · since ${date(policy.startedAt)}. Settings and current counters do not change with Metric scope.` : "Network policy is unavailable in this report.";
      for (const key of ["evaluated", "matchedVpn", "matchedDatacenter", "blocked", "challenged", "allowedUnknown", "errors"]) text(`networkPolicy.${key}`, available ? count(totals[key]) : "Unavailable");
      const saved = record(persisted) && persisted.scope === "disk" && record(persisted.totals);
      for (const key of ["blocked", "challenged", "allowedUnknown"]) text(`networkPolicy.disk.${key}`, saved ? count(persisted.totals[key]) : "Unavailable");
      find("network-policy-disk-note").textContent = saved ? `Last saved disk totals · since ${date(persisted.startedAt)}. These totals belong to this volume; they do not combine separate replica volumes.` : "Saved network-policy totals are unavailable.";
    }
    function renderRisk(risk) {
      const available = Boolean(risk && typeof risk === "object");
      const enabled = available && risk.mode === "report_only";
      const totals = enabled && risk.totals || {};
      const intelligence = enabled && risk.intelligence || {};
      const providerEnabled = intelligence.enabled === true;
      const capabilities = intelligence.capabilities || {};
      const provider = intelligence.providerStatus || {};
      const cache = intelligence.cache || {};
      const limitedText = (value, fallback = "—") => value === null || value === undefined || value === "" ? fallback : String(value).slice(0, 256);
      find("risk-mode").textContent = !available ? "Unavailable" : enabled ? "Report only" : "Disabled";
      find("risk-note").textContent = !available ? "Risk observations are unavailable in this report." : !enabled ? "Risk observations are not enabled. No risk rules are changed by this panel." : `Current process only · since ${date(risk.startedAt)}. Observation does not change request decisions.`;
      for (const key of ["observedRequests", "headlessMarkers", "headerAnomalies", "networkKnown", "networkUnknown"]) text(`risk.${key}`, numeric(totals[key]));
      text("risk.observerErrors", numeric(enabled ? risk.observerErrors : null));
      for (const [key, capability] of [["hostingIndicators", "hosting"], ["proxyIndicators", "proxy"], ["vpnIndicators", "vpn"], ["residentialProxyIndicators", "residentialProxy"]]) {
        text(`risk.${key}`, providerEnabled && capabilities[capability] === true ? numeric(totals[key]) : !available ? "Unavailable" : "Not provided");
      }
      text("risk.provider", !available ? "Unavailable" : !providerEnabled ? "Not enabled" : `${limitedText(intelligence.provider, "Configured provider")} · enabled`);
      for (const key of ["dailyBudget", "used", "remaining"]) text(`risk.${key}`, providerEnabled ? numeric(provider[key]) : !available ? "Unavailable" : "Not enabled");
      for (const key of ["cacheHits", "cacheEntries", "active", "queued", "failed", "timeouts", "queueDropped"]) text(`risk.${key}`, providerEnabled ? numeric(cache[key]) : !available ? "Unavailable" : "Not enabled");
      text("risk.failure", !available ? "Unavailable" : !providerEnabled ? "Not enabled" : limitedText(provider.failureCode || cache.lastError, "None"));
      const disabledProviderText = !available ? "Unavailable" : "Not enabled";
      text("risk.lookupResult", !providerEnabled ? disabledProviderText : provider.lastResult === "unknown" ? "Unknown · no network classification" : provider.lastResult === "error" ? "Lookup failed" : provider.lastResult === "known" ? "Network indicators provided" : "No lookup completed");
      text("risk.unknownReason", !providerEnabled ? disabledProviderText : limitedText(provider.unknownReason || cache.lastUnknownReason, "None"));
      text("risk.unknownResponses", providerEnabled ? numeric(cache.unknownResponses) : disabledProviderText);
      text("risk.lastHttpStatus", providerEnabled ? numeric(provider.lastHttpStatus) : disabledProviderText);
      const fieldTypes = provider.indicatorTypes;
      const knownTypes = ["absent", "null", "boolean", "string", "number", "object", "array", "undefined"];
      text("risk.indicatorTypes", !providerEnabled ? disabledProviderText : fieldTypes && typeof fieldTypes === "object" ? [["is_datacenter", "Hosting"], ["is_proxy", "Proxy"], ["is_vpn", "VPN"]].map(([key, label]) => `${label}: ${knownTypes.includes(fieldTypes[key]) ? fieldTypes[key] : "unrecognized"}`).join(" · ") : "—");

      const campaignWindow = enabled && risk.campaignWindow || {};
      const campaignStorage = campaignWindow.storage || {};
      const localFallback = campaignWindow.scope === "unavailable" && campaignStorage.fallbackScope === "current_process";
      const campaignAvailable = campaignWindow.scope === "current_process" || campaignWindow.scope === "redis" || campaignWindow.scope === "disk" || localFallback;
      const unavailableCampaignBackend = campaignStorage.backend === "disk" ? "disk checkpoint" : "shared Redis window";
      const campaignScope = localFallback ? `Local fallback · ${unavailableCampaignBackend} unavailable` : campaignWindow.scope === "redis" ? "Shared Redis window" : campaignWindow.scope === "disk" ? "Persisted disk window" : "Current process window";
      find("campaign-window").textContent = campaignAvailable ? `${campaignScope} · ${numeric(campaignWindow.windowSeconds)} seconds · since ${date(campaignWindow.windowStartedAt)}. Client-supplied campaign attribution.` : !available ? "Campaign observations are unavailable in this report." : !enabled ? "Campaign observations are not enabled." : "Campaign window is unavailable; no campaign totals are shown.";
      const campaignBackend = campaignStorage.backend === "disk" || campaignWindow.scope === "disk" ? campaignStorage.ready ? "Disk ready" : "Disk unavailable" : campaignStorage.configured ? campaignStorage.ready ? "Redis connected" : "Redis unavailable" : "current process memory";
      find("campaign-storage").textContent = !campaignAvailable ? "Campaign storage: unavailable." : `Campaign storage: ${campaignBackend} · pending ${numeric(campaignStorage.pendingOperations)} · dropped ${numeric(campaignStorage.droppedObservations)} · uncertain ${numeric(campaignStorage.uncertainObservations)} · last error: ${limitedText(campaignStorage.lastError, "None")}.`;
      const rows = [];
      const campaigns = campaignAvailable && Array.isArray(campaignWindow.campaigns) ? campaignWindow.campaigns.slice(0, 33) : [];
      for (const campaign of campaigns) {
        if (!campaign || typeof campaign !== "object") continue;
        const row = documentObject.createElement("tr");
        const values = [
          limitedText(campaign.id), numeric(campaign.requests), campaign.distinctSourcesSaturated === true ? "At capacity" : numeric(campaign.distinctSourcesEstimate), numeric(campaign.headless),
          ...["hosting", "proxy", "vpn", "residentialProxy"].map((key) => providerEnabled && capabilities[key] === true ? numeric(campaign[key]) : "Not provided"),
          risk.conversions && risk.conversions.enabled === true ? numeric(campaign.conversions) : "Not enabled",
          campaign.unusualActivity === true ? "Unusual activity signal" : "No unusual activity signal"
        ];
        for (const value of values) {
          const cell = documentObject.createElement("td");
          cell.textContent = value;
          row.appendChild(cell);
        }
        rows.push(row);
      }
      if (!rows.length) {
        const row = documentObject.createElement("tr");
        const cell = documentObject.createElement("td");
        cell.colSpan = 10;
        cell.className = "campaign-empty";
        cell.textContent = campaignAvailable ? "No attributed campaigns in this window." : "No campaign report available.";
        row.appendChild(cell);
        rows.push(row);
      }
      find("campaign-rows").replaceChildren(...rows);
    }
    return {
      update(current) {
        find("connect").disabled = current.connected;
        tokenInput.disabled = current.connected;
        find("refresh").disabled = !current.connected || current.loading || current.hidden || current.paused;
        find("pause").disabled = !current.connected;
        find("pause").textContent = current.paused ? "Resume" : "Pause";
        find("disconnect").disabled = !current.connected;
        find("scope").value = current.scope;
        find("connection-badge").textContent = !current.connected ? "Disconnected" : current.paused || current.hidden ? "Paused" : current.error ? "Retrying" : "Connected";
        find("status").textContent = current.message;
        find("status").dataset.error = String(current.error);
        find("last-success").textContent = `Last successful refresh: ${date(current.lastSuccess)}${current.stale ? " · report may be stale" : ""}`;
      },
      clear() {
        for (const element of fields) element.textContent = "—";
        find("chart").setAttribute("points", "");
        find("chart-note").textContent = "No samples yet.";
        find("risk-mode").textContent = "Unavailable";
        find("risk-note").textContent = "Connect to load observations.";
        find("network-policy-note").textContent = "Connect to load network policy.";
        find("network-policy-disk-note").textContent = "Saved network-policy totals are unavailable.";
        find("campaign-window").textContent = "No campaign report loaded.";
        find("campaign-storage").textContent = "Campaign storage: unavailable.";
        find("campaign-rows").replaceChildren();
      },
      render(report, selected, samples) {
        const shared = selected === "shared";
        const persistent = selected === "persistent";
        const current = !shared && !persistent;
        const selectedReport = shared ? report.shared : persistent ? report.persistent : report;
        const total = selectedReport && selectedReport.total || {};
        const localRecent = report.total && report.total.latencyMs && report.total.latencyMs.recent || {};
        const latency = total.latencyMs || {};
        find("scope-heading").textContent = shared ? "Shared Redis totals" : persistent ? "Persisted disk totals" : "Current process";
        find("scope-note").textContent = shared ? selectedReport ? "Acknowledged totals across replicas in this Redis namespace." : "Shared totals are unavailable. See Analytics persistence below." : persistent ? selectedReport ? "Totals resume from disk on this volume; they do not combine separate replica volumes. Unsaved changes may be lost after a crash." : "Persisted disk totals are unavailable. See Analytics persistence below." : "Counters reset when this process restarts; replicas have separate process counters.";
        text("startedAt", selectedReport && selectedReport.startedAt ? `Since ${date(selectedReport.startedAt)}` : "—");
        for (const key of ["requests", "completed", "aborted"]) text(key, numeric(total[key]));
        text("inFlight", current ? numeric(total.inFlight) : "—");
        for (const kind of ["get", "head", "prefetch", "operational", "other"]) text(`kind.${kind}`, numeric(selectedReport && selectedReport.byKind && selectedReport.byKind[kind] && selectedReport.byKind[kind].requests));
        for (const status of ["1xx", "2xx", "3xx", "4xx", "5xx", "other"]) text(`status.${status}`, numeric(total.byStatusClass && total.byStatusClass[status]));
        for (const name of ["shown", "passed", "failed", "expired", "expiredOrDuplicate", "providerError", "redirected", "payloadExpired"]) text(`challenge.${name}`, numeric(selectedReport && selectedReport.challenges && selectedReport.challenges[name]));
        text("latency.mean", milliseconds(latency.mean));
        text("latency.max", milliseconds(latency.max));
        for (const percentile of ["p50", "p95", "p99"]) text(`latency.${percentile}`, current ? milliseconds(localRecent[percentile]) : "—");
        text("latency.samples", current && typeof localRecent.sampleCount === "number" ? `${numeric(localRecent.sampleCount)} / ${numeric(localRecent.sampleLimit)}` : "—");
        const runtime = report.runtime || {};
        const memory = runtime.memory || {};
        for (const key of ["rss", "heapUsed"]) text(`memory.${key}`, numeric(memory[`${key}Mb`], 1));
        text("runtime.inFlightRequests", numeric(runtime.inFlightRequests));
        text("runtime.uptimeSec", numeric(runtime.uptimeSec));
        const resources = runtime.resources || {};
        for (const key of ["openSockets", "logFileQueueLines", "logFileQueueBytes", "logFileDroppedLines"]) text(`resources.${key}`, numeric(resources[key]));
        text("resources.logFileDrainPending", typeof resources.logFileDrainPending === "boolean" ? resources.logFileDrainPending ? "Yes" : "No" : "—");
        const logFileError = resources.logFileLastError;
        const logFileErrorText = logFileError && typeof logFileError === "object"
          ? `${logFileError.message || "Unknown error"}${logFileError.at ? ` · ${date(logFileError.at)}` : ""}`
          : logFileError || "None";
        text("resources.logFileLastError", logFileErrorText);
        const storage = report.storage || {};
        const diskStorage = report.diskStorage || {};
        text("storage.backends", [diskStorage.configured ? "Disk" : null, storage.configured ? "Redis" : null].filter(Boolean).join(" + ") || "Memory only");
        text("disk.state", !diskStorage.configured ? "Not configured" : diskStorage.ready ? "Ready" : "Unavailable");
        text("disk.lastSaveAt", date(diskStorage.lastSaveAt));
        text("disk.pending", typeof diskStorage.pending === "boolean" ? diskStorage.pending ? "Yes" : "No" : numeric(diskStorage.pending));
        text("disk.lastError", diskStorage.lastError == null || diskStorage.lastError === "" ? "None" : String(diskStorage.lastError).slice(0, 256));
        text("storage.state", !storage.configured ? "Not configured" : storage.ready ? "Connected" : "Unavailable · pending locally");
        for (const key of ["pendingObservations", "uncertainObservations", "droppedObservations"]) text(`storage.${key}`, numeric(storage[key]));
        text("storage.lastError", storage.lastError || "None");
        text("storage.lastFlushAt", date(storage.lastFlushAt));
        const values = samples.map((sample) => sample[selected]).filter((value) => typeof value === "number" && Number.isFinite(value));
        const low = values.length ? Math.min(...values) : 0;
        const high = values.length ? Math.max(...values) : 0;
        find("chart").setAttribute("points", values.map((value, index) => `${values.length > 1 ? index * 600 / (values.length - 1) : 0},${100 - ((value - low) / (high - low || 1)) * 90}`).join(" "));
        find("chart-note").textContent = values.length ? `${numeric(values.length)} samples · min ${numeric(low)} · max ${numeric(high)}` : "No samples for this scope.";
        renderNetworkPolicy(report.networkPolicy, report.persistent && report.persistent.networkPolicy);
        renderRisk(report.risk);
      }
    };
  }

  listen(documentObject, "visibilitychange", visibilityChanged);
  listen(browser, "pagehide", onPageHide);
  listen(browser, "pageshow", onPageShow);
  updateView();
  return { connect, disconnect, refresh, pause, resume, setScope, destroy, getState: state };
}

if (typeof module !== "undefined" && module.exports) module.exports = createTrafficPanelController;
else if (typeof document !== "undefined") {
  const startTrafficPanel = () => {
    if (document.getElementById("traffic-panel")) createTrafficPanelController();
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", startTrafficPanel, { once: true });
  else startTrafficPanel();
}
