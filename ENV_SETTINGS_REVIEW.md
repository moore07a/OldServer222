# Environment Settings Review

Checked against runtime parsing in `server.js`.

## Verdict

Most settings are syntactically valid and will be parsed as intended.

## Confirmed good

- `CHALLENGE_*` and `RATE_*` values are numeric strings and match expected integer parsing.
- `HEALTH_INTERVAL="4h"` and `HEALTH_HEARTBEAT="10h"` are valid (`m`/`h` parser).
- `TIMEZONE="America/New_York"` is a valid IANA timezone.
- `REQUIRE_CF_HEADERS="true"` matches exact boolean parsing for that flag.
- `TRUST_PROXY_HOPS="1"` with `TRUST_PROXY_MODE="safe"` is coherent for a single reverse-proxy hop.

## Potential issues / recommendations

1. **Production debug flags are enabled**
   - `DEBUG_ALLOW_PLAINTEXT_KEYS="1"`
   - `DEBUG_DECRYPT="1"` (currently appears unused)
   - `IP_DEBUG="1"`
   
   Recommendation: set these to `0` in production.

2. **`SCANNER_LOGGING` appears unused**
   - `SCANNER_LOGGING="1"` is not currently consumed in `server.js`.
   
   Recommendation: remove it or implement consumption to avoid configuration drift.

3. **Strict edge header requirement**
   - `REQUIRE_CF_HEADERS="true"` will reject requests missing Cloudflare headers.
   
   Recommendation: keep only if all traffic is guaranteed to arrive through Cloudflare.

4. **Aggressive rate/challenge limits**
   - `RATE_CAPACITY=5` / `RATE_WINDOW_SECONDS=300`
   - `CHALLENGE_CAPACITY=5` / `CHALLENGE_WINDOW_SEC=300`
   
   Recommendation: monitor false positives; these are strict for shared IP/NAT environments.

## Suggested production-safe adjustments

```env
DEBUG_ALLOW_PLAINTEXT_KEYS="0"
DEBUG_DECRYPT="0"
IP_DEBUG="0"
```
