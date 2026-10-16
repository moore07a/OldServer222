"use strict";

const fs = require("node:fs");
const renderTrafficPanel = require("./renderTrafficPanel.js");
// Load the same module tested in Node and served to the browser.
require("./trafficPanelClient.js");
const clientSource = fs.readFileSync(require.resolve("./trafficPanelClient.js"), "utf8");

function registerTrafficPanelRoutes({ app, withOptionalUrlPrefix, optionalPrefix = "" }) {
  const scriptPath = withOptionalUrlPrefix("/admin/traffic-panel.js");
  const metricsPath = withOptionalUrlPrefix("/admin/traffic-metrics");

  function paths(route) {
    return optionalPrefix ? [route, withOptionalUrlPrefix(route)] : [route];
  }

  app.get(paths("/admin/traffic-panel"), (_req, res) => {
    const nonce = res.locals.cspNonce;
    res.setHeader("Cache-Control", "private, no-store");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Content-Security-Policy", [
      "default-src 'none'", "base-uri 'none'", "frame-ancestors 'none'",
      "form-action 'self'", "connect-src 'self'",
      `script-src 'self' 'nonce-${nonce}'`, `style-src 'nonce-${nonce}'`
    ].join("; "));
    res.type("html").send(renderTrafficPanel({ nonce, scriptUrl: scriptPath, metricsUrl: metricsPath }));
  });

  app.get(paths("/admin/traffic-panel.js"), (_req, res) => {
    res.setHeader("Cache-Control", "private, no-store");
    res.type("application/javascript").send(clientSource);
  });
}

module.exports = registerTrafficPanelRoutes;
