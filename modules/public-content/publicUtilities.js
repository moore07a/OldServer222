"use strict";

function createPublicUtilities(dependencies) {
  const {
    PUBLIC_ROTATION_MODE,
    PUBLIC_SITE_BASE_URL,
    crypto
  } = dependencies;

function dayStamp(d = new Date()) {
  return d.toISOString().slice(0, 10);
}

function weekStamp(d = new Date()) {
  const dt = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const dayNum = dt.getUTCDay() || 7;
  dt.setUTCDate(dt.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(dt.getUTCFullYear(), 0, 1));
  const week = Math.ceil((((dt - yearStart) / 86400000) + 1) / 7);
  return `${dt.getUTCFullYear()}-W${String(week).padStart(2, "0")}`;
}

function wildcardMatches(hostname, wildcardPattern) {
  const cleanHost = String(hostname || "").toLowerCase().split(":")[0];
  const cleanPattern = String(wildcardPattern || "").toLowerCase().trim();
  if (!cleanHost || !cleanPattern.startsWith("*.") || cleanPattern.length < 3) return false;
  const suffix = cleanPattern.slice(2);
  if (!suffix) return false;
  if (!cleanHost.endsWith(`.${suffix}`)) return false;
  return cleanHost !== suffix;
}

function parseConfiguredBaseEntry(entry) {
  try {
    if (!entry || entry === "*") return null;
    const value = /^https?:\/\//i.test(entry) ? entry : `https://${entry}`;
    const asUrl = new URL(value);
    const wildcard = asUrl.hostname.startsWith("*.");
    const canonicalHost = wildcard ? asUrl.hostname.slice(2) : asUrl.host;
    const baseUrl = `${asUrl.protocol}//${canonicalHost}`;

    return {
      hostname: asUrl.hostname,
      protocol: asUrl.protocol,
      wildcard,
      baseUrl,
      isInternal: isLikelyInternalHostname(asUrl.hostname)
    };
  } catch {
    return null;
  }
}

function parsePublicBaseUrlEntries() {
  return PUBLIC_SITE_BASE_URL
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function rotationSeed() {
  if (PUBLIC_ROTATION_MODE === "weekly") return weekStamp();
  if (PUBLIC_ROTATION_MODE === "fixed") return "fixed";
  return dayStamp();
}

function hash32(input) {
  const hex = crypto.createHash("sha256").update(String(input)).digest("hex").slice(0, 8);
  return parseInt(hex, 16) >>> 0;
}

function deterministicPick(items, seed, count = 3) {
  if (!Array.isArray(items) || items.length === 0) return [];
  const out = [];
  const n = Math.min(Math.max(1, count), items.length);
  const used = new Set();
  let i = 0;
  while (out.length < n && i < (items.length * 3)) {
    const idx = hash32(`${seed}:${i}`) % items.length;
    if (!used.has(idx)) {
      used.add(idx);
      out.push(items[idx]);
    }
    i += 1;
  }
  return out;
}

function resolvePublicBaseUrls(req, options = {}) {
  const rawForwardedHost = String(req.get("x-forwarded-host") || "")
    .split(",")
    .map((part) => part.trim())
    .find(Boolean);
  const host = String(
    rawForwardedHost ||
    req.get("x-original-host") ||
    req.get("x-host") ||
    req.get("host") ||
    "localhost"
  ).trim();
  const hostNoPort = host.split(":")[0];
  const proto = req.secure || String(req.get("x-forwarded-proto") || "").includes("https") ? "https" : "http";
  const requestBase = `${proto}://${host}`;
  const requestHostOnly = options && options.requestHostOnly === true;
  const preferConfiguredCanonical = options && options.preferConfiguredCanonical === true;

  const configured = parsePublicBaseUrlEntries();
  const parsedConfigured = configured
    .map((entry) => parseConfiguredBaseEntry(entry))
    .filter(Boolean);

  if (requestHostOnly) {
    if (preferConfiguredCanonical) {
      const matchingConfiguredCanonical = parsedConfigured
        .filter((entry) => entry.wildcard ? wildcardMatches(hostNoPort, entry.hostname) : entry.hostname === hostNoPort)
        .sort((a, b) => Number(a.isInternal) - Number(b.isInternal))
        .map((entry) => entry.wildcard ? `${entry.protocol}//${host}` : entry.baseUrl)
        .find(Boolean);

      if (matchingConfiguredCanonical) {
        return [matchingConfiguredCanonical];
      }

      const preferredConfiguredCanonical = parsedConfigured
        .sort((a, b) => {
          const internalDiff = Number(a.isInternal) - Number(b.isInternal);
          if (internalDiff !== 0) return internalDiff;
          return Number(a.wildcard) - Number(b.wildcard);
        })
        .map((entry) => entry.baseUrl)
        .find(Boolean);

      if (preferredConfiguredCanonical) {
        return [preferredConfiguredCanonical];
      }
    }

    return [requestBase];
  }

  if (parsedConfigured.length === 0) {
    return [requestBase];
  }

  const out = [];
  for (const entry of parsedConfigured) {
    if (entry.wildcard) {
      if (wildcardMatches(hostNoPort, entry.hostname)) {
        out.push(`${entry.protocol}//${host}`);
      }
      continue;
    }

    out.push(entry.baseUrl);
  }

  const resolved = [...new Set(out.filter(Boolean))];
  return resolved.length > 0 ? resolved : [requestBase];
}

  return { rotationSeed, hash32, deterministicPick, resolvePublicBaseUrls };
}

module.exports = createPublicUtilities;
