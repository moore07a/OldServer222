"use strict";

function createClientGeo(dependencies) {
  const {
    FORWARDER_AUTH_HEADER,
    GEO_SOURCE_DEBUG,
    MDS_FORWARDER_AUTH_SECRET,
    TRUST_CLOUDFLARE_XFF_CHAIN,
    TRUST_UPSTREAM_GEO_HEADERS,
    addLog,
    hasCloudflareHeaders,
    lookupIpinfoLite,
    maybeEnrichGeoAsync,
    normalizeAsn,
    safeLogValue,
    trustProxyEffective
  } = dependencies;

// ================== CLIENT IP & GEO FUNCTIONS ==================

// Proper IP address parser that handles IPv4, IPv6, and ports correctly
function parseIpAddress(ip) {
  if (!ip || typeof ip !== 'string') return ip;

  // Remove any surrounding whitespace
  ip = ip.trim();

  // Handle IPv6 with port format: [2001:db8::1]:8080
  if (ip.startsWith('[') && ip.includes(']')) {
    const endBracket = ip.indexOf(']');
    return ip.slice(1, endBracket);
  }

  // Handle IPv4 with port: 192.168.1.1:8080
  if (ip.includes('.') && ip.includes(':')) {
    const lastColon = ip.lastIndexOf(':');
    // Verify it's actually a port by checking if the part after colon is numeric
    const potentialPort = ip.slice(lastColon + 1);
    if (/^\d+$/.test(potentialPort)) {
      return ip.slice(0, lastColon);
    }
  }

  // Plain IPv4, IPv6 without port, or unknown format
  return ip;
}

function getClientIp(req) {
  const trustedCloudflareClientIp = getTrustedCloudflareClientIp(req);
  if (trustedCloudflareClientIp) return trustedCloudflareClientIp;

  // Prefer trusted platform-normalized client-ip headers after proven Cloudflare forwarding.
  if (req.headers['x-vercel-forwarded-for']) {
    const ips = String(req.headers['x-vercel-forwarded-for']).split(',').map(ip => ip.trim());
    const clientIp = ips[0];
    if (clientIp && clientIp !== '') {
      return parseIpAddress(clientIp);
    }
  }

  if (req.headers['x-nf-client-connection-ip']) {
    const ip = String(req.headers['x-nf-client-connection-ip']).trim();
    if (ip && ip !== '') return parseIpAddress(ip);
  }

  if (req.headers['x-render-ip']) {
    const ip = String(req.headers['x-render-ip']).trim();
    if (ip && ip !== '') return parseIpAddress(ip);
  }

  if (req.headers['x-railway-ip']) {
    const ip = String(req.headers['x-railway-ip']).trim();
    if (ip && ip !== '') return parseIpAddress(ip);
  }

  // Do not blindly trust CF-Connecting-IP here: direct clients can spoof it.
  // Cloudflare-origin requests resolve through proven CF context plus edge-CIDR
  // or trusted-proxy provenance above, or through platform/forwarded headers below.

  // Heroku, AWS ELB, Google Cloud, Azure, and most other platforms
  if (req.headers['x-forwarded-for']) {
    const ips = String(req.headers['x-forwarded-for']).split(',').map(ip => ip.trim());
    // Get the first IP that's not a known proxy IP
    for (const ip of ips) {
      if (ip && ip !== '' && !isKnownProxyIp(ip)) {
        return parseIpAddress(ip);
      }
    }
    // Fallback to first IP if all are proxy IPs
    if (ips[0] && ips[0] !== '') {
      return parseIpAddress(ips[0]);
    }
  }

  // Standard headers
  const standardHeaders = [
    "x-real-ip",
    "true-client-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "forwarded"
  ];

  for (const header of standardHeaders) {
    const value = req.headers[header];
    if (value) {
      let ip = String(value).trim();

      // Handle Forwarded header (RFC 7239)
      if (header === "forwarded") {
        const forMatch = ip.match(/for=([^,;]+)/i);
        if (forMatch) {
          ip = forMatch[1].replace(/^\[?"?'?|"?'?\]?$/g, '').trim();
        }
      }

      if (ip && ip !== '') {
        return parseIpAddress(ip);
      }
    }
  }

  // Final fallback to Express
  return parseIpAddress(req.ip || "");
}

function getDirectRemoteIp(req) {
  const remote =
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    req.ip ||
    "";
  return parseIpAddress(String(remote || "").trim());
}

function shouldTrustClientIpHeaders(req) {
  if (process.env.TRUST_CLIENT_IP_HEADERS === "1") return true;

  // If proxy trust is explicitly disabled, do not trust forwarded client-ip headers.
  if (trustProxyEffective === false) return false;

  // Cloudflare deployments can trust cf-connecting-ip only when cf context is present.
  if (req.headers["cf-connecting-ip"] && hasCloudflareHeaders(req)) return true;

  // Common managed platforms where upstream populates/normalizes forwarding headers.
  if (process.env.VERCEL || process.env.NETLIFY || process.env.RENDER || process.env.RAILWAY || process.env.HEROKU) return true;

  return false;
}

function getDenyCacheIp(req) {
  const directIp = getDirectRemoteIp(req);
  const trustedCloudflareClientIp = getTrustedCloudflareClientIp(req);
  if (trustedCloudflareClientIp) return trustedCloudflareClientIp;

  // Prefer Express-normalized req.ip when proxy trust is enabled. This is
  // stable across appended forwarding chains and avoids header-driven churn.
  if (trustProxyEffective !== false) {
    const trustedReqIp = parseIpAddress(String(req.ip || "").trim());
    if (trustedReqIp) return trustedReqIp;
  }

  if (shouldTrustClientIpHeaders(req)) {
    const clientIp = getClientIp(req);
    if (clientIp) return clientIp;
  }

  return directIp || "unknown";
}

function getRequestIdentity(req) {
  const displayIp = getClientIp(req) || "unknown";
  const keyIp = getDenyCacheIp(req) || displayIp || "unknown";
  const rateLimitKey = displayIp || keyIp || "unknown";
  const source = keyIp === displayIp ? "client" : "trusted_proxy_key";
  return {
    ip: displayIp,
    displayIp,
    keyIp,
    rateLimitKey,
    banKey: keyIp,
    denyCacheKey: keyIp,
    source,
    rateLimitSource: rateLimitKey === displayIp ? "client" : "fallback_key"
  };
}

function formatRequestIdentityLogSuffix(req, options = {}) {
  const identity = getRequestIdentity(req);
  const parts = [
    `identity=${safeLogValue(identity.source, 40)}`,
    `rateKey=${safeLogValue(identity.rateLimitKey, 64)}`,
    `rateSource=${safeLogValue(identity.rateLimitSource, 40)}`
  ];
  if (identity.keyIp && identity.keyIp !== identity.ip) {
    parts.unshift(`keyIp=${safeLogValue(identity.keyIp, 64)}`);
  }
  if (options.geoSource) {
    parts.push(`geoSource=${safeLogValue(options.geoSource, 48)}`);
  }
  return parts.length ? ` ${parts.join(" ")}` : "";
}

// Helper function to identify known proxy IPs
function isKnownProxyIp(ip) {
  const proxyRanges = [
    /^3\.\d+\.\d+\.\d+$/,  // Vercel AWS IPs
    /^54\.\d+\.\d+\.\d+$/, // AWS us-east-1
    /^52\.\d+\.\d+\.\d+$/, // AWS us-east-1
    /^34\.\d+\.\d+\.\d+$/, // Google Cloud
    /^35\.\d+\.\d+\.\d+$/, // Google Cloud
    /^13\.\d+\.\d+\.\d+$/, // AWS
    /^10\.\d+\.\d+\.\d+$/, // Private
    /^192\.168\.\d+\.\d+$/, // Private
    /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$/, // Private
    /^127\.\d+\.\d+\.\d+$/, // Localhost
    /^::1$/, // IPv6 localhost
    /^f[cd][0-9a-f]{2}:/i, // IPv6 private (fc00::/7)
  ];

  return proxyRanges.some(pattern => pattern.test(ip));
}

function hasIndependentCloudflareProof(req) {
  return Boolean(req.headers["cf-ray"] || req.headers["cf-visitor"]);
}

function getForwardedForIps(req) {
  return String(req.headers["x-forwarded-for"] || "")
    .split(",")
    .map(value => parseIpAddress(value.trim()))
    .filter(Boolean);
}

function hasAuthenticatedForwarder(req) {
  if (!MDS_FORWARDER_AUTH_SECRET || !req || !req.headers) return false;
  const provided = String(req.headers[FORWARDER_AUTH_HEADER] || "").trim();
  return Boolean(provided && provided === MDS_FORWARDER_AUTH_SECRET);
}

function hasTrustedCloudflareForwardedForChain(req, cloudflareClientIp) {
  if (!TRUST_CLOUDFLARE_XFF_CHAIN) return false;
  const trustedByAuthenticatedForwarder = hasAuthenticatedForwarder(req);
  if (!trustedByAuthenticatedForwarder && (!hasTrustedProxyProvenance(req) || hasManagedPlatformSourceHeader(req))) return false;

  const forwardedForIps = getForwardedForIps(req);
  if (forwardedForIps.length < 2 || !cloudflareClientIp) return false;

  const firstForwardedIp = forwardedForIps[0];
  if (firstForwardedIp !== cloudflareClientIp) return false;

  return forwardedForIps.slice(1).some(ip => isCloudflareEdgeIp(ip));
}

function hasManagedPlatformSourceHeader(req) {
  return Boolean(
    req.headers["x-railway-ip"] ||
    req.headers["x-vercel-id"] ||
    req.headers["x-nf-client-connection-ip"] ||
    req.headers["x-render-ip"]
  );
}

function getTrustedCloudflareClientIp(req) {
  if (!hasIndependentCloudflareProof(req) || !req.headers["cf-connecting-ip"]) return null;

  const ip = parseIpAddress(String(req.headers["cf-connecting-ip"]).trim());
  if (!ip) return null;

  const directIp = getDirectRemoteIp(req);
  const trustedByCloudflareEdge = isCloudflareEdgeIp(directIp);
  const trustedByAuthenticatedForwarder = hasAuthenticatedForwarder(req);
  const trustedByForwardedForChain = hasTrustedCloudflareForwardedForChain(req, ip);

  if (!trustedByCloudflareEdge && !trustedByAuthenticatedForwarder && !trustedByForwardedForChain) {
    return null;
  }

  return ip;
}

function normalizeIpv4Mapped(ip) {
  const raw = String(ip || "").trim();
  const m = raw.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  return m ? m[1] : raw;
}

const CLOUDFLARE_IPV4_CIDRS = [
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
  "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
  "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
  "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
  "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
];

const CLOUDFLARE_IPV6_CIDRS = [
  "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
  "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
  "2c0f:f248::/32"
];

function ipv4ToInt(ip) {
  const parts = String(ip || "").split(".");
  if (parts.length !== 4) return null;
  let out = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out = (out * 256) + n;
  }
  return out >>> 0;
}

function isIpv4InCidr(ip, cidr) {
  const [base, bitsRaw] = String(cidr || "").split("/");
  const bits = Number(bitsRaw);
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt == null || baseInt == null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

function expandIpv6ToBigInt(ip) {
  const normalized = String(ip || "").toLowerCase();
  if (!normalized || normalized.includes(".")) return null;
  const halves = normalized.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":").filter(Boolean) : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":").filter(Boolean) : [];
  const missing = 8 - (left.length + right.length);
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;
  const groups = [...left, ...Array(missing).fill("0"), ...right];
  if (groups.length !== 8) return null;
  let out = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(group)) return null;
    out = (out << 16n) + BigInt(parseInt(group, 16));
  }
  return out;
}

function isIpv6InCidr(ip, cidr) {
  const [base, bitsRaw] = String(cidr || "").split("/");
  const bits = Number(bitsRaw);
  const ipInt = expandIpv6ToBigInt(ip);
  const baseInt = expandIpv6ToBigInt(base);
  if (ipInt == null || baseInt == null || !Number.isInteger(bits) || bits < 0 || bits > 128) return false;
  if (bits === 0) return true;
  const shift = BigInt(128 - bits);
  return (ipInt >> shift) === (baseInt >> shift);
}

function isCloudflareEdgeIp(ip) {
  const normalized = normalizeIpv4Mapped(parseIpAddress(String(ip || "")));
  if (!normalized) return false;
  if (normalized.includes(".")) {
    return CLOUDFLARE_IPV4_CIDRS.some(cidr => isIpv4InCidr(normalized, cidr));
  }
  if (normalized.includes(":")) {
    return CLOUDFLARE_IPV6_CIDRS.some(cidr => isIpv6InCidr(normalized, cidr));
  }
  return false;
}

function isPrivateOrLocalProxyIp(ip) {
  const normalized = normalizeIpv4Mapped(ip);
  const privateRanges = [
    /^10\.\d+\.\d+\.\d+$/,
    /^192\.168\.\d+\.\d+$/,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$/,
    /^127\.\d+\.\d+\.\d+$/,
    /^::1$/i,
    /^f[cd][0-9a-f]{2}:/i,
  ];
  return privateRanges.some(pattern => pattern.test(normalized));
}

function hasTrustedProxyProvenance(req) {
  const socketRemote =
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    "";
  const directIp = parseIpAddress(String(socketRemote || "").trim());
  if (!directIp) return false;

  // Only accept upstream-provided client-ip headers when the immediate
  // sender looks like a private/local proxy hop. This avoids trusting
  // broad public cloud client ranges as proxy provenance.
  return isPrivateOrLocalProxyIp(directIp);
}

function hasHeader(req, name) {
  return Boolean(req && req.headers && req.headers[name]);
}

function hasExplicitUpstreamGeoTrust(req) {
  return Boolean(TRUST_UPSTREAM_GEO_HEADERS && hasTrustedProxyProvenance(req));
}

function hasVercelGeoProvenance(req) {
  return Boolean(
    process.env.VERCEL ||
    (hasExplicitUpstreamGeoTrust(req) && (
      hasHeader(req, "x-vercel-forwarded-for") ||
      hasHeader(req, "x-vercel-id") ||
      hasHeader(req, "x-vercel-proxied-for")
    ))
  );
}

function hasNetlifyGeoProvenance(req) {
  return Boolean(
    process.env.NETLIFY ||
    (hasExplicitUpstreamGeoTrust(req) && (
      hasHeader(req, "x-nf-client-connection-ip") ||
      hasHeader(req, "x-nf-request-id") ||
      hasHeader(req, "x-nf-geo")
    ))
  );
}

function hasRenderGeoProvenance(req) {
  return Boolean(process.env.RENDER || (hasExplicitUpstreamGeoTrust(req) && hasHeader(req, "x-render-ip")));
}

function hasRailwayGeoProvenance(req) {
  return Boolean(process.env.RAILWAY || (hasExplicitUpstreamGeoTrust(req) && hasHeader(req, "x-railway-ip")));
}

function hasCloudflareGeoProvenance(req) {
  if (!(hasHeader(req, "cf-ipcountry") || hasHeader(req, "cf-edge-country"))) return false;
  if (!hasHeader(req, "cf-connecting-ip") || !hasIndependentCloudflareProof(req)) return false;

  const cloudflareClientIp = parseIpAddress(String(req.headers["cf-connecting-ip"] || "").trim());
  if (!cloudflareClientIp) return false;

  return Boolean(
    isCloudflareEdgeIp(getDirectRemoteIp(req)) ||
    hasAuthenticatedForwarder(req) ||
    hasTrustedCloudflareForwardedForChain(req, cloudflareClientIp) ||
    (hasTrustedProxyProvenance(req) && !hasManagedPlatformSourceHeader(req))
  );
}

function canTrustGeoCountryHeader(req, header, platform) {
  if (!req || !req.headers || !req.headers[header]) return false;
  switch (platform) {
    case "cloudflare":
      return hasCloudflareGeoProvenance(req);
    case "vercel":
      return hasVercelGeoProvenance(req);
    case "netlify":
      return hasNetlifyGeoProvenance(req);
    case "render":
      return hasRenderGeoProvenance(req);
    case "railway":
      return hasRailwayGeoProvenance(req);
    default:
      return false;
  }
}

function shouldTrustGeoHeaders(req) {
  return hasCloudflareGeoProvenance(req) ||
    hasVercelGeoProvenance(req) ||
    hasNetlifyGeoProvenance(req) ||
    hasRenderGeoProvenance(req) ||
    hasRailwayGeoProvenance(req);
}

function getCountryResolution(req) {
  const h = req.headers;
  const trustGeoHeaders = shouldTrustGeoHeaders(req);
  const requestIp = getClientIp(req) || "unknown";
  const geoDebug = GEO_SOURCE_DEBUG || process.env.IP_DEBUG === "1";
  const logGeoSource = (source, country) => {
    if (!geoDebug) return;
    addLog(`[GEO-SOURCE] ip=${safeLogValue(requestIp)} source=${safeLogValue(source, 40)} country=${safeLogValue(String(country || ""), 8)} trustedHeaders=${trustGeoHeaders ? "1" : "0"}`);
    maybeEnrichGeoAsync(requestIp, country, source);
  };

  // Platform-specific country headers
  const countryHeaders = [
    ["x-vercel-ip-country", "vercel"],
    ["cf-ipcountry", "cloudflare"],
    ["cf-edge-country", "cloudflare"],
    ["x-nf-country", "netlify"],
    ["x-render-country", "render"],
    ["x-railway-country", "railway"],
  ];

  if (trustGeoHeaders) {
    for (const [header, platform] of countryHeaders) {
      const value = h[header];
      if (value && canTrustGeoCountryHeader(req, header, platform)) {
        const country = String(value).toUpperCase();
        logGeoSource(`${platform}:${header}`, country);
        return { country, source: `${platform}:${header}` };
      }
    }

    // Netlify geo JSON
    if (h["x-nf-geo"] && hasNetlifyGeoProvenance(req)) {
      try {
        const geo = JSON.parse(h["x-nf-geo"]);
        if (geo.country) {
          const country = String(geo.country).toUpperCase();
          logGeoSource("netlify:x-nf-geo", country);
          return { country, source: "netlify:x-nf-geo" };
        }
      } catch {}
    }
  }

  // Fly.io region (sometimes contains country)
  // Keep this outside header-trust gating: Fly region is often the only
  // platform signal when the IPinfo Lite fallback is unavailable.
  if (h["fly-region"]) {
    const region = String(h["fly-region"]).toLowerCase();
    const regionToCountry = {
      'iad': 'US', 'atl': 'US', 'dfw': 'US', 'den': 'US', 'lax': 'US', 'mia': 'US',
      'ord': 'US', 'phx': 'US', 'qro': 'MX', 'scl': 'CL', 'bog': 'CO', 'eze': 'AR',
      'gru': 'BR', 'lhr': 'GB', 'cdg': 'FR', 'ams': 'NL', 'fra': 'DE', 'mad': 'ES',
      'waw': 'PL', 'arn': 'SE', 'nrt': 'JP', 'hkg': 'HK', 'sin': 'SG', 'bom': 'IN',
      'syd': 'AU', 'mel': 'AU'
    };
    if (regionToCountry[region]) {
      const country = regionToCountry[region];
      logGeoSource(`fly:fly-region:${region}`, country);
      return { country, source: `fly:fly-region:${region}` };
    }
  }

  return null;
}

async function getCountryResolutionAsync(req) {
  const resolution = getCountryResolution(req);
  if (resolution) return resolution;

  const requestIp = getClientIp(req) || "unknown";
  const ipinfo = await lookupIpinfoLite(requestIp);
  const geoDebug = GEO_SOURCE_DEBUG || process.env.IP_DEBUG === "1";
  if (ipinfo) {
    if (geoDebug) {
      addLog(`[GEO-SOURCE] ip=${safeLogValue(requestIp)} source=ipinfo-lite country=${safeLogValue(ipinfo.country || "", 8)} trustedHeaders=${shouldTrustGeoHeaders(req) ? "1" : "0"}`);
    }
    return ipinfo;
  }

  if (geoDebug) {
    addLog(`[GEO-SOURCE] ip=${safeLogValue(requestIp)} source=none country= trustedHeaders=${shouldTrustGeoHeaders(req) ? "1" : "0"}`);
  }
  return null;
}

function getCountry(req) {
  const resolution = getCountryResolution(req);
  return resolution ? resolution.country : null;
}

function getASN(req) {
  const asnHeaders = [
    "cf-asn",
    "x-asn",
    "x-vercel-ip-asn",
    "x-nf-asn",
    "x-render-asn"
  ];

  for (const header of asnHeaders) {
    const value = req.headers[header];
    if (value) {
      return normalizeAsn(value);
    }
  }
  return null;
}


  return {
    getClientIp,
    getDenyCacheIp,
    getRequestIdentity,
    formatRequestIdentityLogSuffix,
    isKnownProxyIp,
    normalizeIpv4Mapped,
    getCountryResolutionAsync,
    getCountry,
    getASN
  };
}

module.exports = createClientGeo;
