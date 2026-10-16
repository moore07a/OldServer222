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
      // Store only the two numbers used by the chart, never whole reports.
      history.push({ at, current: report.total.requests, shared: report.shared && report.shared.total ? report.shared.total.requests : null });
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
  function setScope(value) { scope = value === "shared" ? "shared" : "current"; paint(); updateView(); }
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
      },
      render(report, selected, samples) {
        const shared = selected === "shared";
        const selectedReport = shared ? report.shared : report;
        const total = selectedReport && selectedReport.total || {};
        const localRecent = report.total && report.total.latencyMs && report.total.latencyMs.recent || {};
        const latency = total.latencyMs || {};
        find("scope-heading").textContent = shared ? "Shared Redis totals" : "Current process";
        find("scope-note").textContent = shared ? selectedReport ? "Acknowledged totals across replicas in this Redis namespace." : "Shared totals are unavailable. See Redis persistence below." : "Counters reset when this process restarts; replicas have separate process counters.";
        text("startedAt", selectedReport && selectedReport.startedAt ? `Since ${date(selectedReport.startedAt)}` : "—");
        for (const key of ["requests", "completed", "aborted"]) text(key, numeric(total[key]));
        text("inFlight", shared ? "—" : numeric(total.inFlight));
        for (const kind of ["get", "head", "prefetch", "operational", "other"]) text(`kind.${kind}`, numeric(selectedReport && selectedReport.byKind && selectedReport.byKind[kind] && selectedReport.byKind[kind].requests));
        for (const status of ["1xx", "2xx", "3xx", "4xx", "5xx", "other"]) text(`status.${status}`, numeric(total.byStatusClass && total.byStatusClass[status]));
        for (const name of ["shown", "passed", "failed", "expired", "expiredOrDuplicate", "providerError", "redirected", "payloadExpired"]) text(`challenge.${name}`, numeric(selectedReport && selectedReport.challenges && selectedReport.challenges[name]));
        text("latency.mean", milliseconds(latency.mean));
        text("latency.max", milliseconds(latency.max));
        for (const percentile of ["p50", "p95", "p99"]) text(`latency.${percentile}`, milliseconds(localRecent[percentile]));
        text("latency.samples", typeof localRecent.sampleCount === "number" ? `${numeric(localRecent.sampleCount)} / ${numeric(localRecent.sampleLimit)}` : "—");
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
        text("storage.state", !storage.configured ? "Not configured · memory only" : storage.ready ? "Connected" : "Unavailable · pending locally");
        for (const key of ["pendingObservations", "uncertainObservations", "droppedObservations"]) text(`storage.${key}`, numeric(storage[key]));
        text("storage.lastError", storage.lastError || "None");
        text("storage.lastFlushAt", date(storage.lastFlushAt));
        const values = samples.map((sample) => sample[selected]).filter((value) => typeof value === "number" && Number.isFinite(value));
        const low = values.length ? Math.min(...values) : 0;
        const high = values.length ? Math.max(...values) : 0;
        find("chart").setAttribute("points", values.map((value, index) => `${values.length > 1 ? index * 600 / (values.length - 1) : 0},${100 - ((value - low) / (high - low || 1)) * 90}`).join(" "));
        find("chart-note").textContent = values.length ? `${numeric(values.length)} samples · min ${numeric(low)} · max ${numeric(high)}` : "No samples for this scope.";
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
