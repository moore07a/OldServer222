"use strict";

const RETIRED_LOG_PATHS = ["/view-log", "/view-log-live", "/stream-log"];

function createRetiredLogPolicy({ optionalPrefix = "" } = {}) {
  const prefix = String(optionalPrefix).trim().replace(/^\/+|\/+$/g, "").toLowerCase();
  const prefixPath = prefix ? `/${prefix}` : "";

  return function isRetiredLogPath(pathname) {
    // Fold only a comparison copy; encrypted paths and query values keep their bytes.
    const path = String(pathname || "/").split(/[?#]/, 1)[0].replace(/\/+$/, "").toLowerCase() || "/";
    if (RETIRED_LOG_PATHS.includes(path)) return true;

    // A configured namespace takes precedence over an old unprefixed subtree.
    const inNamespace = prefixPath && (path === prefixPath || path.startsWith(`${prefixPath}/`));
    const routePath = inNamespace ? path.slice(prefixPath.length) || "/" : path;
    return RETIRED_LOG_PATHS.some(route => routePath === route || routePath.startsWith(`${route}/`));
  };
}

module.exports = createRetiredLogPolicy;
