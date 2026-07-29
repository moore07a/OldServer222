"use strict";

function createTurnstileSecurity(dependencies) {
  const {
    ENFORCE_ACTION,
    EXPECT_HOSTNAME_ENTRIES,
    EXPECT_HOSTNAME_PATTERNS,
    MAX_TOKEN_AGE_SEC,
    addLog,
    addSpacer,
    fetchWithRuntimeSpan,
    hostMatchesSuffix,
    makeIpLimiter,
    normHost,
    normalizeTurnstileEnv,
    safeLogValue
  } = dependencies;

// ================== HEADLESS / PREFETCH DETECTION ==================
const UA_HEADLESS_MARKS = [
  "headless","puppeteer","playwright","phantomjs","selenium","wdio","cypress",
  "curl","wget","python-requests","httpclient","okhttp","java","go-http-client",
  "libwww","aiohttp","node-fetch","powershell"
];
const SUSPICIOUS_HEADERS = [
  "x-puppeteer","x-headless-browser","x-headless","x-should-not-exist",
  "x-playwright","x-automation","x-bot"
];

function headlessSuspicion(req){
  const reasons = [];
  const hard = [];
  const soft = [];

  const uaRaw = req.get("user-agent") || "";
  const ua = uaRaw.toLowerCase();

  const isChromiumUA = /\b(Chrome|CriOS|Edg|OPR|Brave)\b/i.test(uaRaw) && !/\bMobile Safari\b/i.test(uaRaw);
  const isSafariUA   = /\bSafari\/\d+/i.test(uaRaw) && !/\b(Chrome|CriOS)\/\d+/i.test(uaRaw);
  const isFirefoxUA  = /\bFirefox\/\d+/i.test(uaRaw);

  const expect = {
    clientHints: isChromiumUA,
    fetchMeta:   isChromiumUA
  };

  for (const m of UA_HEADLESS_MARKS) {
    if (ua.includes(m)) { reasons.push("ua:" + m); hard.push("ua:" + m); break; }
  }
  for (const h of SUSPICIOUS_HEADERS) {
    if (req.headers[h]) { reasons.push("hdr:" + h); hard.push("hdr:" + h); }
  }

  if (!req.get("accept-language")) { reasons.push("missing:accept-language"); soft.push("missing:accept-language"); }

  if (expect.clientHints && !req.get("sec-ch-ua")) {
    reasons.push("missing:sec-ch-ua"); soft.push("missing:sec-ch-ua");
  }
  if (expect.fetchMeta && !req.get("sec-fetch-site")) {
    reasons.push("missing:sec-fetch-site"); soft.push("missing:sec-fetch-site");
  }

  const fetchSite = (req.get("sec-fetch-site") || "").toLowerCase();
  const fetchMode = (req.get("sec-fetch-mode") || "").toLowerCase();
  const fetchDest = (req.get("sec-fetch-dest") || "").toLowerCase();

  if (fetchMode && fetchMode !== "navigate" && fetchMode !== "document") {
    reasons.push("mode:" + fetchMode); soft.push("mode:" + fetchMode);
  }
  if (fetchDest && fetchDest !== "document" && fetchDest !== "empty") {
    reasons.push("dest:" + fetchDest); soft.push("dest:" + fetchDest);
  }

  const accept = req.get("accept") || "";
  if (accept && !/text\/html|application\/xhtml\+xml/i.test(accept)) {
    reasons.push("accept-not-html"); hard.push("accept-not-html");
  }

  return {
    suspicious: reasons.length > 0,
    reasons,
    hardCount: hard.length,
    softCount: soft.length,
    isSafariUA,
    isFirefoxUA,
    isChromiumUA
  };
}

// ================== TURNSTILE FUNCTIONS ==================
const TURNSTILE_SITEKEY = normalizeTurnstileEnv(process.env.TURNSTILE_SITEKEY);
const TURNSTILE_SECRET  = normalizeTurnstileEnv(process.env.TURNSTILE_SECRET);
const TURNSTILE_ORIGIN  = "https://challenges.cloudflare.com";
const EXPOSE_TURNSTILE_SITEKEY_ENDPOINT = String(process.env.EXPOSE_TURNSTILE_SITEKEY_ENDPOINT || "").trim().toLowerCase() === "true";
if (!TURNSTILE_SITEKEY || !TURNSTILE_SECRET) {
  console.error("❌ TURNSTILE_SITEKEY and TURNSTILE_SECRET must be set.");
  process.exit(1);
}

async function verifyTurnstileToken(token, remoteip, expected) {
  if (!TURNSTILE_SECRET || !token) return { ok:false, reason:"missing" };
  try {
    const resp = await fetchWithRuntimeSpan("turnstile_verify", TURNSTILE_ORIGIN + "/turnstile/v0/siteverify", {
      method:"POST",
      headers:{ "Content-Type":"application/x-www-form-urlencoded" },
      body:new URLSearchParams({ secret:TURNSTILE_SECRET, response:token, remoteip:remoteip||"" })
    }, process.env.TURNSTILE_VERIFY_TIMEOUT_MS || 8000);
    if (!resp.ok) {
      addLog(`[TS] verify upstream status=${resp.status}`);
      return { ok:false, reason:"upstream_status", status: resp.status };
    }

    let data;
    try {
      data = await resp.json();
    } catch (jsonErr) {
      addLog(`[TS] verify invalid_json err=${safeLogValue(jsonErr && jsonErr.message || jsonErr, 80)}`);
      return { ok:false, reason:"invalid_json" };
    }

    if (!data || !data.success) {
      addLog("[TS] verify failed codes=" + JSON.stringify((data && data["error-codes"]) || []));
      return { ok:false, reason:"not_success", data };
    }

    if (ENFORCE_ACTION && expected?.action && data.action !== expected.action)
      return { ok:false, reason:"bad_action", data };

    if (expected?.linkHash) {
      const raw = String(data.cdata||"");
      const m = /^([A-Za-z0-9_-]{8,})_([0-9]{9,})$/.exec(raw);
      const h = m ? m[1] : null;
      const tsSec = m ? parseInt(m[2],10) : 0;
      const age = Math.abs(Math.floor(Date.now()/1000) - tsSec);
      if (h !== expected.linkHash) {
        addLog(`[TS] cdata mismatch got=${h||'-'} want=${expected.linkHash} age=${age}s`);
        return { ok:false, reason:"bad_cdata_hash", data };
      }
      if (age > (expected.maxAgeSec||MAX_TOKEN_AGE_SEC)) return { ok:false, reason:"token_too_old", data, age };
    }

    if (EXPECT_HOSTNAME_ENTRIES.length && !EXPECT_HOSTNAME_PATTERNS.length) {
      addLog(`[TS-HOST-CONFIG-ERROR] TURNSTILE_EXPECT_HOSTNAME has no valid patterns raw=[${EXPECT_HOSTNAME_ENTRIES.join(",")}]`);
      return { ok:false, reason:"bad_hostname_config" };
    }

    if (EXPECT_HOSTNAME_PATTERNS.length && !data.hostname) {
      addLog("[TS-HOST-MISMATCH] missing hostname");
      return { ok:false, reason:"missing_hostname", data };
    }

    if (EXPECT_HOSTNAME_PATTERNS.length && data.hostname) {
      const got = normHost(data.hostname);
      const matched = EXPECT_HOSTNAME_PATTERNS.some(pattern => hostMatchesSuffix(got, pattern));

      if (!matched) {
        const expected = EXPECT_HOSTNAME_PATTERNS
          .map(p => (p.allowSubdomains ? `*.${p.suffix}` : p.suffix))
          .join(",") || "-";
        addLog(`[TS-HOST-MISMATCH] got=${got} expected=[${expected}]`);
        addSpacer();
        data.hostname = got;
        return { ok:false, reason:"bad_hostname", data };
      }

      data.hostname = got;
    }

    addLog(`[TS] ok action=${data.action||'-'} hostname=${data.hostname||'-'} cdata=${String(data.cdata||'').slice(0,12)}…`);
    return { ok:true, data };
  } catch (e) {
    addLog("Turnstile verify error: " + e.message);
    return { ok:false, reason:"verify_error" };
  }
}


  return {
    headlessSuspicion,
    TURNSTILE_SITEKEY,
    TURNSTILE_SECRET,
    TURNSTILE_ORIGIN,
    verifyTurnstileToken
  };
}

module.exports = createTurnstileSecurity;
