"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const createTrafficPanelController = require("../modules/admin-panel/trafficPanelClient");
const renderTrafficPanel = require("../modules/admin-panel/renderTrafficPanel");

function eventTarget(extra = {}) {
  const events = new Map();
  return Object.assign(extra, {
    addEventListener(name, handler) { if (!events.has(name)) events.set(name, new Set()); events.get(name).add(handler); },
    removeEventListener(name, handler) { if (events.has(name)) events.get(name).delete(handler); },
    emit(name) { for (const handler of events.get(name) || []) handler(); },
    listenerCount() { return [...events.values()].reduce((sum, set) => sum + set.size, 0); }
  });
}

const flush = async () => { for (let step = 0; step < 12; step += 1) await Promise.resolve(); };
const report = (requests = 0) => ({ ok: true, total: { requests }, shared: { total: { requests: requests * 2 } } });

function viewElement(dataset = {}, tagName = "div") {
  let content = "";
  const children = [];
  return eventTarget({
    dataset, tagName, value: "", disabled: false, children,
    get textContent() { return content + children.map((child) => child.textContent).join(""); },
    set textContent(value) { content = String(value); children.splice(0); },
    set innerHTML(value) { assert.fail("Panel values must be rendered as text, never HTML"); },
    setAttribute() {},
    appendChild(child) { children.push(child); return child; },
    replaceChildren(...next) { content = ""; children.splice(0, children.length, ...next); }
  });
}

function documentViewRoot() {
  const html = renderTrafficPanel({ nonce: "test-nonce" });
  const roles = new Map([...html.matchAll(/data-role="([^"]+)"/g)].map(([, name]) => [name, viewElement()]));
  const fields = new Map([...html.matchAll(/data-value="([^"]+)"/g)].map(([, name]) => [name, viewElement({ value: name })]));
  const root = {
    querySelector(selector) {
      const match = /^\[data-role="([^"]+)"\]$/.exec(selector);
      assert.ok(match && roles.has(match[1]), `Unknown view element: ${selector}`);
      return roles.get(match[1]);
    },
    querySelectorAll(selector) {
      assert.equal(selector, "[data-value]");
      return [...fields.values()];
    }
  };
  return { root, roles, fields };
}

function harness({ root } = {}) {
  let at = 1000;
  let serial = 0;
  let clears = 0;
  const timers = new Map();
  const calls = [];
  const rendered = [];
  const states = [];
  const document = eventTarget({ hidden: false, createElement: (tagName) => viewElement({}, tagName) });
  const window = eventTarget({ location: { href: "https://app.example/campaign/admin/traffic-panel", origin: "https://app.example" } });
  const controller = createTrafficPanelController({
    window, document, root, metricsUrl: "/campaign/admin/traffic-metrics", AbortController,
    now: () => at,
    setTimeout(fn, delay) { const id = ++serial; timers.set(id, { fn, at: at + delay, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    fetch(url, options) {
      let resolve;
      let reject;
      const result = new Promise((yes, no) => { resolve = yes; reject = no; });
      calls.push({ url, options, resolve, reject });
      return result;
    },
    view: root ? undefined : {
      update(state) { states.push({ ...state }); },
      clear() { clears += 1; },
      render(data, scope, history) { rendered.push({ data, scope, history: history.map((sample) => ({ ...sample })) }); }
    }
  });
  return {
    controller, calls, rendered, states, document, window, timers,
    get clears() { return clears; },
    async advance(ms) {
      const until = at + ms;
      while (true) {
        const first = [...timers].sort((left, right) => left[1].at - right[1].at)[0];
        if (!first || first[1].at > until) break;
        at = first[1].at;
        timers.delete(first[0]);
        first[1].fn();
        await flush();
      }
      at = until;
      await flush();
    },
    async complete(index, data = report(), status = 200) {
      calls[index].resolve({ ok: status >= 200 && status < 300, status, async json() { return data; } });
      await flush();
    }
  };
}

test("panel sends same-origin authenticated no-store requests and never overlaps ordinary refreshes", async () => {
  const panel = harness();
  panel.controller.connect("private-token");
  panel.controller.refresh();
  panel.controller.refresh();
  assert.equal(panel.calls.length, 1);
  assert.equal(panel.calls[0].url, "https://app.example/campaign/admin/traffic-metrics");
  assert.equal(panel.calls[0].options.headers.Authorization, "Bearer private-token");
  assert.equal(panel.calls[0].options.cache, "no-store");
  assert.equal(panel.calls[0].options.credentials, "omit");
  assert.equal(panel.calls[0].options.redirect, "error");
  assert.equal(JSON.stringify(panel.controller.getState()).includes("private-token"), false);
  await panel.complete(0, report(0));
  assert.equal(panel.rendered.at(-1).data.total.requests, 0);
  assert.equal(panel.timers.size, 1);
  await panel.advance(4999);
  assert.equal(panel.calls.length, 1);
  await panel.advance(1);
  assert.equal(panel.calls.length, 2);
  await panel.advance(4999);
  assert.equal(panel.calls.length, 2);
  panel.controller.destroy();
});

test("hidden tabs abort pending requests; stale completion cannot replace resumed work or its timer", async () => {
  const panel = harness();
  panel.controller.connect("first-token");
  panel.document.hidden = true;
  panel.document.emit("visibilitychange");
  assert.equal(panel.calls[0].options.signal.aborted, true);
  assert.equal(panel.timers.size, 0);
  panel.document.hidden = false;
  panel.document.emit("visibilitychange");
  assert.equal(panel.calls.length, 2);
  await panel.complete(0, report(99));
  assert.equal(panel.rendered.length, 0);
  assert.equal(panel.controller.getState().loading, true);
  assert.equal(panel.timers.size, 1, "the resumed request retains its timeout");
  await panel.complete(1, report(2));
  assert.equal(panel.rendered.at(-1).data.total.requests, 2);
  assert.equal(panel.timers.size, 1);
  panel.controller.destroy();
});

test("timeout releases an uncooperative fetch and bounded exponential retry resets after success", async () => {
  const panel = harness();
  panel.controller.connect("token");
  await panel.advance(8000);
  assert.equal(panel.calls[0].options.signal.aborted, true);
  assert.equal(panel.controller.getState().loading, false);
  assert.equal(panel.controller.getState().error, true);
  assert.match(panel.controller.getState().message, /timed out/);
  assert.equal([...panel.timers.values()][0].delay, 10000);
  await panel.advance(10000);
  for (const [index, nextDelay] of [[1, 20000], [2, 40000], [3, 60000], [4, 60000]]) {
    panel.calls[index].reject(new Error("unavailable"));
    await flush();
    assert.equal([...panel.timers.values()][0].delay, nextDelay);
    await panel.advance(nextDelay);
  }
  await panel.complete(5, report(10));
  assert.equal(panel.controller.getState().error, false);
  assert.equal([...panel.timers.values()][0].delay, 5000);
  await panel.complete(0, report(999));
  assert.equal(panel.rendered.at(-1).data.total.requests, 10, "late timed-out response is ignored");
  panel.controller.destroy();
});

test("authentication rejection clears credentials and report and does not retry", async () => {
  for (const status of [401, 403]) {
    const panel = harness();
    panel.controller.connect("token");
    await panel.complete(0, report(5));
    panel.controller.refresh();
    await panel.complete(1, null, status);
    assert.equal(panel.controller.getState().connected, false);
    assert.equal(panel.controller.getState().lastSuccess, null);
    assert.equal(panel.controller.getState().sampleCount, 0);
    assert.equal(panel.timers.size, 0);
    assert.match(panel.controller.getState().message, /Authentication rejected/);
    await panel.advance(60000);
    assert.equal(panel.calls.length, 2);
    panel.controller.destroy();
  }
});

test("timeout also bounds a response body that never finishes and invalid reports preserve the last snapshot", async () => {
  const panel = harness();
  panel.controller.connect("token");
  await panel.complete(0, report(4));
  panel.controller.refresh();
  let finishBody;
  panel.calls[1].resolve({ ok: true, status: 200, json: () => new Promise((resolve) => { finishBody = resolve; }) });
  await flush();
  await panel.advance(8000);
  assert.equal(panel.calls[1].options.signal.aborted, true);
  assert.match(panel.controller.getState().message, /timed out/);
  assert.equal(panel.rendered.at(-1).data.total.requests, 4);
  assert.equal(panel.controller.getState().stale, true);
  panel.controller.refresh();
  await panel.complete(2, { ok: true, total: { requests: "invalid" } });
  assert.equal(panel.rendered.at(-1).data.total.requests, 4);
  assert.equal(panel.controller.getState().sampleCount, 1);
  finishBody(report(99));
  await flush();
  assert.equal(panel.rendered.at(-1).data.total.requests, 4);
  assert.equal(panel.controller.getState().loading, false);
  panel.controller.destroy();
});

test("pause and page lifecycle stop polling, preserve user pause, and cleanly resume", async () => {
  const panel = harness();
  panel.controller.connect("token");
  await panel.complete(0, report(1));
  panel.window.emit("pagehide");
  assert.equal(panel.timers.size, 0);
  await panel.advance(15000);
  assert.equal(panel.calls.length, 1);
  panel.window.emit("pageshow");
  assert.equal(panel.calls.length, 2);
  panel.controller.pause();
  assert.equal(panel.calls[1].options.signal.aborted, true);
  panel.document.hidden = true;
  panel.document.emit("visibilitychange");
  panel.document.hidden = false;
  panel.document.emit("visibilitychange");
  panel.window.emit("pageshow");
  assert.equal(panel.calls.length, 2, "visibility does not undo user pause");
  panel.controller.resume();
  assert.equal(panel.calls.length, 3);
  await panel.complete(2, report(3));
  panel.controller.destroy();
  assert.equal(panel.document.listenerCount(), 0);
  assert.equal(panel.window.listenerCount(), 0);
  assert.equal(panel.timers.size, 0);
});

test("logout and reconnect discard old work and fixed-size chart history never exceeds 60 samples", async () => {
  const panel = harness();
  panel.controller.connect("old-token");
  panel.controller.connect("new-token");
  assert.equal(panel.calls[0].options.signal.aborted, true);
  assert.equal(panel.calls[1].options.headers.Authorization, "Bearer new-token");
  await panel.complete(0, report(800));
  assert.equal(panel.rendered.length, 0);
  await panel.complete(1, report(0));
  for (let index = 2; index < 70; index += 1) {
    await panel.advance(5000);
    await panel.complete(index, report(index));
  }
  assert.equal(panel.controller.getState().sampleCount, 60);
  assert.equal(panel.rendered.at(-1).history.length, 60);
  assert.deepEqual(Object.keys(panel.rendered.at(-1).history[0]).sort(), ["at", "current", "shared"]);
  panel.controller.setScope("shared");
  assert.equal(panel.rendered.at(-1).scope, "shared");
  assert.equal(panel.rendered.at(-1).history.at(-1).shared, 138);
  panel.controller.disconnect();
  assert.equal(panel.controller.getState().sampleCount, 0);
  assert.equal(panel.controller.getState().lastSuccess, null);
  assert.equal(panel.timers.size, 0);
  const before = panel.calls.length;
  await panel.advance(60000);
  assert.equal(panel.calls.length, before);
  panel.controller.destroy();
});

test("document view renders log error messages and timestamps as text and clears recovered errors", async t => {
  const { root, fields } = documentViewRoot();
  const panel = harness({ root });
  t.after(() => panel.controller.destroy());
  const at = "2026-10-16T14:30:00.000Z";
  const message = 'EACCES: permission denied <img src=x onerror="alert(1)">';
  const logError = fields.get("resources.logFileLastError");
  panel.controller.connect("test-token");
  await panel.complete(0, { ...report(1), runtime: { resources: { logFileLastError: { at, message } } } });
  assert.equal(logError.textContent, `${message} · ${new Date(at).toLocaleString()}`);
  assert.equal(logError.textContent.includes("[object Object]"), false);
  assert.equal(panel.controller.getState().error, false, "the real document view rendered the report successfully");

  panel.controller.refresh();
  await panel.complete(1, { ...report(2), runtime: { resources: { logFileLastError: null } } });
  assert.equal(logError.textContent, "None", "a recovered writer clears the prior error");
});

function riskReport(campaigns = []) {
  return {
    mode: "report_only", scope: "current_process", startedAt: "2026-10-16T14:00:00Z",
    totals: { observedRequests: 11, headlessMarkers: 2, headerAnomalies: 0, networkKnown: 3, networkUnknown: 8, hostingIndicators: 1, proxyIndicators: 0, vpnIndicators: 0, residentialProxyIndicators: 999 },
    intelligence: {
      enabled: true, provider: "ipapi.is", capabilities: { hosting: true, proxy: true, vpn: true, residentialProxy: false },
      providerStatus: { dailyBudget: 900, used: 900, remaining: 0, quotaScope: "process", failureCode: null },
      cache: { active: 0, queued: 0, cacheEntries: 3, cacheHits: 4, failed: 0, timeouts: 0, queueDropped: 0, lastError: null }
    },
    campaignWindow: { scope: "redis", windowStartedAt: "2026-10-16T14:00:00Z", windowSeconds: 3600, attribution: "client_supplied", campaigns, storage: { configured: true, ready: true, pendingOperations: 0, droppedObservations: 0, uncertainObservations: 0, lastError: null } },
    conversions: { enabled: true }, observerErrors: 0
  };
}

test("risk section labels current-process scope, preserves zeroes, and renders unsupported residential intelligence honestly", async t => {
  const { root, roles, fields } = documentViewRoot();
  const panel = harness({ root });
  t.after(() => panel.controller.destroy());
  panel.controller.connect("test-token");
  await panel.complete(0, { ...report(5), risk: riskReport([{ id: "campaign-a", requests: 2, distinctSourcesEstimate: 1, headless: 0, hosting: 1, proxy: 0, vpn: 0, residentialProxy: 999, conversions: 0, unusualActivity: false }]) });
  assert.equal(fields.get("risk.observedRequests").textContent, "11");
  assert.equal(fields.get("risk.headerAnomalies").textContent, "0");
  assert.equal(fields.get("risk.remaining").textContent, "0");
  assert.equal(fields.get("risk.residentialProxyIndicators").textContent, "Not provided");
  assert.match(roles.get("risk-note").textContent, /Current process only/);
  assert.match(roles.get("campaign-window").textContent, /Shared Redis window/);
  const cells = roles.get("campaign-rows").children[0].children;
  assert.equal(cells[7].textContent, "Not provided");
  assert.equal(cells[8].textContent, "0");
  panel.controller.setScope("shared");
  assert.equal(fields.get("requests").textContent, "10");
  assert.equal(fields.get("risk.observedRequests").textContent, "11", "risk totals keep current-process scope when request scope changes");
});

test("campaign DOM is capped, replaced on refresh, and treats campaign IDs and errors as literal text", async t => {
  const { root, roles, fields } = documentViewRoot();
  const panel = harness({ root });
  t.after(() => panel.controller.destroy());
  const malicious = '<img src=x onerror="alert(1)">';
  const campaigns = Array.from({ length: 80 }, (_, index) => ({ id: index ? `campaign-${index}` : malicious, requests: 10, distinctSourcesEstimate: 2, headless: 1, hosting: 0, proxy: 0, vpn: 0, conversions: 0, unusualActivity: index === 0, rawIP: "NEVER_RENDER_RAW_IP", sourceHash: "NEVER_RENDER_SOURCE_HASH" }));
  const risk = riskReport(campaigns);
  risk.intelligence.cache.lastError = malicious;
  panel.controller.connect("test-token");
  for (let index = 0; index < 8; index += 1) {
    if (index) panel.controller.refresh();
    await panel.complete(index, { ...report(index), risk });
    assert.equal(panel.controller.getState().error, false, "the real document view successfully rendered risk data");
    assert.equal(roles.get("campaign-rows").children.length, 33);
    assert.equal(roles.get("campaign-rows").children[0].children[0].textContent, malicious);
    assert.equal(roles.get("campaign-rows").textContent.includes("NEVER_RENDER"), false);
    assert.equal(fields.get("risk.failure").textContent, malicious);
  }
  assert.equal(panel.controller.getState().sampleCount, 8, "risk rendering adds no separate history");
  panel.controller.disconnect();
  assert.equal(roles.get("campaign-rows").children.length, 0);
  assert.equal(fields.get("risk.observedRequests").textContent, "—");
  assert.equal(roles.get("risk-mode").textContent, "Unavailable");
});

test("disabled provider, disabled observations, and old reports show explicit unavailable states and clear prior rows", async t => {
  const { root, roles, fields } = documentViewRoot();
  const panel = harness({ root });
  t.after(() => panel.controller.destroy());
  const risk = riskReport([{ id: "campaign-a", requests: 1, distinctSourcesEstimate: 1, headless: 0 }]);
  risk.intelligence.enabled = false;
  risk.conversions.enabled = false;
  panel.controller.connect("test-token");
  await panel.complete(0, { ...report(1), risk });
  assert.equal(fields.get("risk.provider").textContent, "Not enabled");
  assert.equal(fields.get("risk.remaining").textContent, "Not enabled");
  assert.equal(fields.get("risk.hostingIndicators").textContent, "Not provided");
  assert.equal(roles.get("campaign-rows").children[0].children[8].textContent, "Not enabled");
  assert.equal(panel.calls.length, 1, "risk display does not create provider requests");
  panel.controller.refresh();
  await panel.complete(1, { ...report(2), risk: { ...risk, mode: "disabled" } });
  assert.equal(roles.get("risk-mode").textContent, "Disabled");
  assert.equal(fields.get("risk.observedRequests").textContent, "—");
  assert.match(roles.get("campaign-rows").textContent, /No campaign report available/);
  panel.controller.refresh();
  await panel.complete(2, report(3));
  assert.equal(panel.controller.getState().error, false);
  assert.equal(roles.get("risk-mode").textContent, "Unavailable");
  assert.equal(fields.get("risk.provider").textContent, "Unavailable");
  assert.equal(fields.get("risk.residentialProxyIndicators").textContent, "Unavailable");
  assert.equal(roles.get("campaign-rows").textContent.includes("campaign-a"), false);
});

test("campaign fallback rows are labeled local when Redis is unavailable", async t => {
  const { root, roles } = documentViewRoot();
  const panel = harness({ root });
  t.after(() => panel.controller.destroy());
  const risk = riskReport([{ id: "local-only", requests: 1 }]);
  risk.campaignWindow.scope = "unavailable";
  risk.campaignWindow.storage = { configured: true, ready: false, pendingOperations: 2, droppedObservations: 3, uncertainObservations: 4, lastError: "read_failed", fallbackScope: "current_process" };
  panel.controller.connect("token");
  await panel.complete(0, { ...report(1), risk });
  assert.match(roles.get("campaign-window").textContent, /Local fallback · shared Redis window unavailable/);
  assert.match(roles.get("campaign-storage").textContent, /Redis unavailable/);
  assert.match(roles.get("campaign-storage").textContent, /pending 2 · dropped 3 · uncertain 4/, "the view uses the actual campaign store status property names");
  assert.equal(roles.get("campaign-rows").children[0].children[0].textContent, "local-only");
  risk.campaignWindow.storage.fallbackScope = null;
  panel.controller.refresh();
  await panel.complete(1, { ...report(2), risk });
  assert.match(roles.get("campaign-window").textContent, /no campaign totals are shown/);
  assert.equal(roles.get("campaign-rows").textContent.includes("local-only"), false);
});

test("saturated source cohorts display capacity instead of a misleading count", async t => {
  const { root, roles } = documentViewRoot();
  const panel = harness({ root });
  t.after(() => panel.controller.destroy());
  const risk = riskReport([{ id: "at-capacity", requests: 10000, distinctSourcesEstimate: 1234, distinctSourcesSaturated: true }]);
  panel.controller.connect("token");
  await panel.complete(0, { ...report(1), risk });
  assert.equal(roles.get("campaign-rows").children[0].children[2].textContent, "At capacity");
  assert.equal(roles.get("campaign-rows").children[0].children[2].textContent.includes("1,234"), false);
  risk.campaignWindow.campaigns[0].distinctSourcesSaturated = false;
  risk.campaignWindow.campaigns[0].distinctSourcesEstimate = 0;
  panel.controller.refresh();
  await panel.complete(1, { ...report(2), risk });
  assert.equal(roles.get("campaign-rows").children[0].children[2].textContent, "0");
});

test("rendered shell escapes route and nonce attributes and contains no preloaded traffic data or inline handlers", () => {
  const html = renderTrafficPanel({ nonce: '\"><script>alert(1)</script>', scriptUrl: '/prefix/admin/traffic-panel.js?x="', metricsUrl: '/prefix/admin/traffic-metrics?x="' });
  assert.match(html, /nonce="&quot;&gt;&lt;script&gt;/);
  assert.match(html, /data-metrics-url="\/prefix\/admin\/traffic-metrics\?x=&quot;"/);
  assert.equal(html.includes('<script>alert(1)</script>'), false);
  assert.equal(/\son(?:click|submit|load)=/i.test(html), false);
  assert.equal(/https?:\/\//.test(html), false);
  assert.equal(/localStorage|sessionStorage/.test(html), false);
});

test("controller rejects cross-origin metrics endpoints before issuing credentials", () => {
  assert.throws(() => createTrafficPanelController({ window: { location: { href: "https://app.example/", origin: "https://app.example" } }, metricsUrl: "https://other.example/metrics" }), /same origin/);
});
