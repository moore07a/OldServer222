"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const createRetiredLogPolicy = require("../modules/runtime-utils/retiredLogPolicy");

test("retired log matching ignores case and query values while preserving path boundaries", () => {
  const isRetired = createRetiredLogPolicy({ optionalPrefix: "CaMpAiGn/Nested" });
  for (const path of [
    "/VIEW-LOG", "/View-Log-Live/", "/STREAM-LOG/child?token=private",
    "/CAMPAIGN/nested/Stream-Log", "/campaign/NESTED/VIEW-LOG-LIVE/child",
    "/CaMpAiGn/Nested/View-Log///?next=/healthz"
  ]) assert.equal(isRetired(path), true, path);
  for (const path of [
    "/view-log-extra", "/stream-logger", "/view-log-live.bak",
    "/campaign-extra/nested/stream-log", "/campaign/nested-extra/stream-log",
    "/campaign/nested/r?d=/VIEW-LOG", "/e/AbCdEf_012-?next=/stream-log"
  ]) assert.equal(isRetired(path), false, path);
});

test("overlapping configured namespaces take precedence over unprefixed retired subtrees", () => {
  for (const optionalPrefix of ["view-log", "VIEW-LOG/nested", "stream-log", "View-Log-Live", "campaign/view-log"]) {
    const isRetired = createRetiredLogPolicy({ optionalPrefix });
    for (const route of [
      "/health", "/healthz", "/readyz", "/livez", "/admin/traffic-panel",
      "/admin/traffic-panel.js", "/admin/traffic-metrics", "/r", "/e/AbCdEf_012-"
    ]) {
      assert.equal(isRetired(`/${optionalPrefix}${route}`), false, `${optionalPrefix}${route}`);
      assert.equal(isRetired(`/${optionalPrefix.toUpperCase()}${route}`), false);
    }
    for (const retired of ["/view-log", "/view-log-live", "/stream-log"]) {
      assert.equal(isRetired(retired.toUpperCase()), true, "bare retired URLs remain retired");
      assert.equal(isRetired(`/${optionalPrefix}${retired.toUpperCase()}/child`), true);
    }
  }
  const nested = createRetiredLogPolicy({ optionalPrefix: "view-log/nested" });
  assert.equal(nested("/view-log/other"), true, "a child outside the configured namespace remains retired");
  assert.equal(nested("/view-log/nested-extra/healthz"), true, "prefix comparison requires a segment boundary");
});

test("an absent prefix rejects retired subtrees without treating other paths as a namespace", () => {
  const isRetired = createRetiredLogPolicy();
  assert.equal(isRetired("/VIEW-LOG/healthz"), true);
  assert.equal(isRetired("/Stream-Log/admin/traffic-panel"), true);
  assert.equal(isRetired("/campaign/stream-log"), false);
  assert.equal(isRetired("/healthz"), false);
  assert.equal(isRetired("/"), false);
});
