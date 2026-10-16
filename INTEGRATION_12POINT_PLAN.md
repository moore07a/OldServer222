# Railway Reliability Integration Plan (12-Point)

This project now includes runtime support for the reliability hardening plan discussed for intermittent 499/502 behavior.

## Implementation status

1. ✅ **Dedicated lightweight health endpoint**
   - `/healthz` and `/livez` (liveness) and `/health`/`/readyz` (full status) are present, including optional-prefix variants.
   - The dependency health checker and `[HEALTH] heartbeat` logging remain active independently of the retired log stream.

2. ✅ **Request lifecycle logging middleware**
   - Runtime accounting tracks in-flight, completed, aborted requests.
   - Includes timeout logging and abort/close tracking hooks.

3. ✅ **Per-route metrics support**
   - Runtime status endpoint already exposes request counters and timing data.
   - Panel, admin API, retired log routes, and health requests are classified separately from ordinary GET traffic.

4. ✅ **Bounded admin monitoring**
   - `/admin/traffic-panel` polls the authenticated metrics API with one request at a time, hidden-tab pauses, timeouts, and backoff.
   - `/view-log`, `/view-log-live`, and `/stream-log` are retired with finite 404 responses for all methods, including mixed-case, optional-prefix, and child paths, before redirect processing. Configured namespaces take precedence when their prefix overlaps an old name.
   - Raw details remain available in server stdout/file logs and authenticated diagnostic APIs; the panel displays aggregate metrics.

5. ✅ **Graceful shutdown on SIGTERM/SIGINT**
   - Process signal handlers call `gracefulShutdown(...)`.

6. ✅ **Server timeout tuning**
   - Tunable request, keep-alive, and headers timeout envs are implemented.

7. ✅ **Upstream/dependency timeout controls**
   - `fetchWithTimeout(...)` wraps external calls and enforces abort semantics.

8. ✅ **Rate limiting / scanner noise controls**
   - Probe path sanitization and route-aware limiter logic are present.

9. ✅ **Edge/proxy correctness + security headers**
   - Explicit `trust proxy` resolution for managed platforms.
   - Security header middleware is enabled globally.

10. ✅ **Incident runbook material in-repo**
   - `RAILWAY_SOAK_RUNBOOK.md` and this plan file provide operational guidance.

11. ⚠️ **Synthetic uptime checks from multiple regions** *(external setup required)*

12. ⚠️ **Dashboards + alerts in Railway/monitoring provider** *(external setup required)*
   - Configure in external monitor (e.g., Better Stack, UptimeRobot, Checkly, Pingdom).
   - Probe `/healthz` and `/` from at least 2 regions.

## Manual/external integrations (required outside this repo)
   - Create per-route alerting for redirect traffic and `/admin/traffic-metrics` separately.
   - Suggested starter thresholds:
     - `/` p95 latency > 2s for 10m
     - `/` 5xx > 1% for 10m
     - `/` 499 > 2-3% sustained

## Suggested environment values

- `REQUEST_TIMEOUT_MS=30000`
- `SERVER_KEEP_ALIVE_TIMEOUT_MS=5000`
- `SERVER_HEADERS_TIMEOUT_MS=6000`
- `FETCH_TIMEOUT_MS=8000`
- `SHUTDOWN_GRACE_MS=10000`
- `TRUST_PROXY_MODE=safe`
