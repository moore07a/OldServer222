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

function harness({ root } = {}) {
  let at = 1000;
  let serial = 0;
  let clears = 0;
  const timers = new Map();
  const calls = [];
  const rendered = [];
  const states = [];
  const document = eventTarget({ hidden: false });
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
  function element(dataset = {}) {
    let content = "";
    return eventTarget({
      dataset, value: "", disabled: false,
      get textContent() { return content; },
      set textContent(value) { content = String(value); },
      set innerHTML(value) { assert.fail("Panel values must be rendered as text, never HTML"); },
      setAttribute() {}
    });
  }
  // Derive the real view's available elements from the rendered panel shell.
  const html = renderTrafficPanel({ nonce: "test-nonce" });
  const roles = new Map([...html.matchAll(/data-role="([^"]+)"/g)].map(([, name]) => [name, element()]));
  const fields = new Map([...html.matchAll(/data-value="([^"]+)"/g)].map(([, name]) => [name, element({ value: name })]));
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
