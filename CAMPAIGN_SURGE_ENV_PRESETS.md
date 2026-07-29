# Campaign Surge / Attack Env Presets (Log-Driven)

This version is tuned against your **May 16–23, 2026** 404 batches.

## What your logs actually show

Most 404 traffic is automated reconnaissance, not real visitor navigation.

### Repeating bot patterns observed
- Credential/secret hunts (`/service-account.json`, `/sa.json`, `/.ssh/id_rsa`, `/.npmrc`, `/config.env`, etc.).
- CMS and framework probes (`/wp*`, `/user/login`, `/register`, `/webmail/`, `/manager/html`).
- API discovery probes (`/api/env`, `/api/config`, `/swagger.json`, `/openapi.json`, `/graphql`).
- File and config enumeration (`/application.yml`, `/composer.json`, `/server.js`, `/app.js`).
- Repeated root `POST /` and `POST //` sweeps from recurring sources.

### Important mixed-traffic caveat
These paths are **mixed traffic** (legit crawlers/browsers + scrapers):
- `/favicon.png`
- `/apple-touch-icon.png`
- `/sitemaps.xml`, `/sitemap_index.xml`, `/sitemap.txt`

Do **not** blindly whitelist by path only. Prefer behavior-aware handling:
- Normal browser / known-good crawler -> serve lightweight cached 200/204
- Suspicious high-rate probe behavior -> keep challenge/rate-limit/block policy


## How to get faster bot/scanner responses (target ~0-2ms)

Goal: reject before heavy middleware and avoid origin work wherever possible.

1. **Edge-first drops (best impact)**
   - Put path-based block/challenge rules at CDN/WAF for high-confidence probes.
   - Prefer edge `block` or `managed_challenge` over origin pass-through.
   - Cache deny outcomes briefly at edge for repeated probes.

2. **Create an ultra-early fast-path deny layer in app**
   - Run before expensive logic (security header composition, token checks, rendering, scanner impersonation).
   - Use simple lowercase string/prefix lookup (no heavy regex backtracking, no DB/network calls).
   - Return minimal body (`res.status(404).end()` or `res.status(403).end()`).

3. **Short-circuit repeated offenders**
   - Keep short TTL in-memory deny cache keyed by normalized client IP and path class.
   - On hit, return immediately with minimal logging.

4. **Log less on repeated noise**
   - Aggregate/sampled logging for repeated scanner signatures.
   - Avoid per-request heavy string formatting for hot probe families.

5. **Protect connection budget**
   - Keep `MAX_CATCHALL_CONCURRENCY` conservative during attacks.
   - Reduce keep-alive/header/request timeouts under attack preset to free sockets quickly.

6. **Normalize tricky paths early**
   - Collapse duplicate slashes (`//`) and detect invalid path forms before routing.
   - Handle `HEAD` probe floods with an immediate minimal response path.

7. **Keep “mixed-traffic” asset endpoints cheap, not open**
   - Serve tiny cached responses for `/favicon.png`, `/apple-touch-icon.png`, and sitemap aliases.
   - Still apply rate/behavior controls when caller is clearly scanner-like.

Expected result: with edge filtering + early in-app short-circuit, hot scanner probes usually stay in the ~0-2ms range at origin, and many never hit origin at all.

---

---

## How to apply

1. Pick the preset matching current conditions.
2. Deploy/restart.
3. Re-check after 10 minutes:
   - p95 latency
   - 499/5xx
   - origin CPU/memory
   - conversion

---

## Preset A — Normal Campaign (balanced)

```env
MAX_CATCHALL_CONCURRENCY="35"
BROWNOUT_TIMEOUT_THRESHOLD="10"
BROWNOUT_WINDOW_MS="60000"
BROWNOUT_DURATION_MS="30000"

REQUEST_TIMEOUT_MS="9000"
SERVER_HEADERS_TIMEOUT_MS="5500"
SERVER_KEEP_ALIVE_TIMEOUT_MS="3500"

RATE_LIMIT_MAX_REQUESTS="60"
RATE_LIMIT_WINDOW_SECONDS="30"
CHALLENGE_CAPACITY="8"
CHALLENGE_WINDOW_SEC="300"
SSE_UNAUTH_CAPACITY="4"
SSE_UNAUTH_WINDOW_SEC="60"

HEADLESS_BLOCK="0"
HEADLESS_SOFT_STRIKE="1"
IMPERSONATE_SCANNER="1"
IMPERSONATE_SCANNER_STRICT="1"
IMPERSONATE_MIN_CONFIDENCE="0.85"

DEBUG_ALLOW_PLAINTEXT_KEYS="0"
IP_DEBUG="0"
```

---

## Preset B — Surge (high traffic + scanner pressure)

```env
MAX_CATCHALL_CONCURRENCY="25"
BROWNOUT_TIMEOUT_THRESHOLD="8"
BROWNOUT_WINDOW_MS="60000"
BROWNOUT_DURATION_MS="45000"

REQUEST_TIMEOUT_MS="8000"
SERVER_HEADERS_TIMEOUT_MS="5000"
SERVER_KEEP_ALIVE_TIMEOUT_MS="3000"

RATE_LIMIT_MAX_REQUESTS="50"
RATE_LIMIT_WINDOW_SECONDS="30"
CHALLENGE_CAPACITY="7"
CHALLENGE_WINDOW_SEC="300"
SSE_UNAUTH_CAPACITY="3"
SSE_UNAUTH_WINDOW_SEC="60"

HEADLESS_BLOCK="0"
HEADLESS_SOFT_STRIKE="1"
IMPERSONATE_SCANNER="1"
IMPERSONATE_SCANNER_STRICT="1"
IMPERSONATE_MIN_CONFIDENCE="0.85"

DEBUG_ALLOW_PLAINTEXT_KEYS="0"
IP_DEBUG="0"
```

---

## Preset C — Active Attack (availability-first)

```env
MAX_CATCHALL_CONCURRENCY="18"
BROWNOUT_TIMEOUT_THRESHOLD="6"
BROWNOUT_WINDOW_MS="60000"
BROWNOUT_DURATION_MS="60000"

REQUEST_TIMEOUT_MS="7000"
SERVER_HEADERS_TIMEOUT_MS="4500"
SERVER_KEEP_ALIVE_TIMEOUT_MS="2500"

RATE_LIMIT_MAX_REQUESTS="35"
RATE_LIMIT_WINDOW_SECONDS="30"
CHALLENGE_CAPACITY="5"
CHALLENGE_WINDOW_SEC="300"
SSE_UNAUTH_CAPACITY="2"
SSE_UNAUTH_WINDOW_SEC="60"

HEADLESS_BLOCK="0"
HEADLESS_SOFT_STRIKE="1"
IMPERSONATE_SCANNER="1"
IMPERSONATE_SCANNER_STRICT="1"
IMPERSONATE_MIN_CONFIDENCE="0.85"

DEBUG_ALLOW_PLAINTEXT_KEYS="0"
IP_DEBUG="0"
```

---

## Edge/WAF rules (strongly recommended)

Apply at CDN/WAF so origin is protected:

1. Block/Challenge known probe paths:
   - `/.env`, `/.git`, `/.ssh/`, `/.npmrc`, `/wp`, `/wp-`, `/manager/html`, `/WEB-INF/`, `/phpmyadmin`, `/graphql`, `/swagger.json`, `/openapi.json`
2. Rate limit root `POST /` and `POST //` by IP/ASN.
3. Add bot score threshold challenge for repeated 404 scanners.
4. Exempt known good crawlers you actually need.

---

## Quick wins for mixed-traffic 404 noise

Serve lightweight responses for:
- `/favicon.png`
- `/apple-touch-icon.png`
- `/sitemaps.xml` and `/sitemap_index.xml` (or redirect to your canonical sitemap)

---

## Rollback rule

If conversion drops while 499/5xx is stable, move one step less strict:
- `C -> B`
- `B -> A`

If 499 rises and origin saturation appears, move one step stricter:
- `A -> B`
- `B -> C`
