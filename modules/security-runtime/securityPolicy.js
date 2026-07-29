module.exports = function createSecurityPolicy(dependencies) {
  const {
    AES_KEYS, ADMIN_TOKEN, ALLOWED_COUNTRIES, ALLOWLIST_DOMAINS, BLOCKED_ASNS,
    BLOCKED_COUNTRIES, EXPECT_HOSTNAME_ENTRIES,
    EXPECT_HOSTNAME_INVALID_ENTRIES, EXPECT_HOSTNAME_PATTERNS, RATE_CAPACITY,
    RATE_WINDOW_SECONDS, safeZone
  } = dependencies;
// ================== CONFIGURATION VALIDATION ==================
const normalizeTurnstileEnv = (value) => String(value || "").trim();

function validateConfig() {
  const errors = [];
  const warnings = [];
  const addConfigIssue = (message, { fatalInProduction = false } = {}) => {
    const target = fatalInProduction && process.env.NODE_ENV === "production" ? errors : warnings;
    target.push(message);
  };
  const isTurnstileKey = (value) => {
    const trimmed = normalizeTurnstileEnv(value);
    if (!trimmed) return false;
    return /^(?:0x)?[0-9a-zA-Z_-]{20,}$/.test(trimmed);
  };

  // Validate AES keys (extra safety; loadKeysFromEnv already enforces this)
  if (!AES_KEYS || AES_KEYS.length === 0) {
    errors.push("No AES keys configured (set AES_KEYS, AES_KEY, or AES_KEY_HEX)");
  } else {
    AES_KEYS.forEach((key, idx) => {
      if (key.length !== 32) {
        errors.push(`AES key #${idx} must be 32 bytes, got ${key.length} bytes`);
      }
    });
  }

  // Validate allowlist configuration
  if (ALLOWLIST_DOMAINS.length === 0) {
    addConfigIssue("No allowlist domains configured - all redirects will be blocked unless explicitly allowed", { fatalInProduction: true });
  }

  if (EXPECT_HOSTNAME_INVALID_ENTRIES.length > 0) {
    errors.push(`Invalid TURNSTILE_EXPECT_HOSTNAME pattern(s): ${EXPECT_HOSTNAME_INVALID_ENTRIES.join(",")}`);
  }
  if (EXPECT_HOSTNAME_ENTRIES.length > 0 && EXPECT_HOSTNAME_PATTERNS.length === 0) {
    errors.push("TURNSTILE_EXPECT_HOSTNAME does not contain any valid host pattern");
  }

  // Validate TURNSTILE credentials format
  const turnstileSitekey = normalizeTurnstileEnv(process.env.TURNSTILE_SITEKEY);
  const turnstileSecret = normalizeTurnstileEnv(process.env.TURNSTILE_SECRET);
  if (!isTurnstileKey(turnstileSitekey)) {
    errors.push(`Invalid TURNSTILE_SITEKEY format (got: ${turnstileSitekey ? `${turnstileSitekey.slice(0, 8)}...` : "empty"})`);
  }
  if (!isTurnstileKey(turnstileSecret)) {
    errors.push(`Invalid TURNSTILE_SECRET format (got: ${turnstileSecret ? `${turnstileSecret.slice(0, 8)}...` : "empty"})`);
  }

  // Validate timezone
  const configuredTz = process.env.TIMEZONE || "UTC";
  if (safeZone(configuredTz) !== configuredTz) {
    warnings.push(`Invalid TIMEZONE: ${configuredTz}. Using UTC as fallback.`);
  }

  // Validate rate limit settings
  if (RATE_CAPACITY < 1 || RATE_CAPACITY > 1000) {
    errors.push(`RATE_CAPACITY must be between 1-1000, got ${RATE_CAPACITY}`);
  }
  if (RATE_WINDOW_SECONDS < 1 || RATE_WINDOW_SECONDS > 86400) {
    errors.push(`RATE_WINDOW_SECONDS must be between 1-86400, got ${RATE_WINDOW_SECONDS}`);
  }

  // Validate admin token
  if (!ADMIN_TOKEN || ADMIN_TOKEN.length < 16) {
    addConfigIssue("ADMIN_TOKEN is weak or missing. Admin endpoints may be insecure.", { fatalInProduction: true });
  }

  // Validate INTERSTITIAL_BYPASS_SECRET
  const bypassSecret = process.env.INTERSTITIAL_BYPASS_SECRET || "";
  if (bypassSecret && bypassSecret.length < 8) {
    addConfigIssue("INTERSTITIAL_BYPASS_SECRET is too short (min 8 chars)", { fatalInProduction: true });
  }

  return { errors, warnings };
}

// Run validation
const configValidation = validateConfig();
if (configValidation.errors.length > 0) {
  console.error("❌ Configuration errors:");
  configValidation.errors.forEach(err => console.error(`   ${err}`));
  if (process.env.NODE_ENV === "production") process.exit(1);
}
if (configValidation.warnings.length > 0) {
  console.warn("⚠️ Configuration warnings:");
  configValidation.warnings.forEach(warn => console.warn(`   ${warn}`));
}

// Hardening: fail fast in production if ADMIN_TOKEN is weak/missing.
if (process.env.NODE_ENV === "production" && (!ADMIN_TOKEN || ADMIN_TOKEN.length < 16)) {
  console.error("❌ ADMIN_TOKEN must be set with at least 16 characters in production.");
  process.exit(1);
}

function countryBlocked(country){
  if (!country) return false;
  if (ALLOWED_COUNTRIES.length && !ALLOWED_COUNTRIES.includes(country)) return true;
  if (BLOCKED_COUNTRIES.includes(country)) return true;
  return false;
}

function asnBlocked(asn){ return !!asn && BLOCKED_ASNS.includes(asn); }


  return { normalizeTurnstileEnv, validateConfig, countryBlocked, asnBlocked };
};
