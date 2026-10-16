# Traffic metrics

The article's useful starting point is separating different kinds of traffic
before changing protection rules. A request count alone cannot establish how
many people visited, whether someone is a bot, or whether an ad converted.

## Open the live panel

Open `/admin/traffic-panel` on the deployed app, or its configured
`OPTIONAL_URL_PREFIX` variant. The page initially shows a login shell with no
traffic data. Enter the existing `ADMIN_TOKEN` to connect. The token is sent
only in the API authorization header and is kept in this page's memory; it is
not placed in URLs, cookies, local storage, or session storage. Disconnecting
or reloading clears it.

The panel refreshes every five seconds, schedules the next poll after the
previous one settles, and limits each fetch and response body to eight seconds.
Hidden tabs pause requests. Pause, disconnect, navigation, and reconnect cancel
pending work; late responses cannot overwrite a newer session. Failed refreshes
back off up to 60 seconds and mark the last report stale. Authentication
rejection stops polling and clears the session. The chart retains at most 60
numeric samples; the DOM does not grow with incoming traffic.

Choose **Current process** or **Shared Redis totals** for the counters. Recent
latency percentiles and runtime resources always describe the responding
process and are labelled accordingly. Redis errors and pending observations
remain visible so a connected socket is not mistaken for durable delivery.

The old `/view-log`, `/view-log-live`, and `/stream-log` URLs return `404 Not Found`,
including their optional-prefix, trailing-slash, and child paths, for every HTTP
method. Retired-name and prefix matching ignore case. If the configured prefix
overlaps a retired name, its namespace takes precedence: with
`OPTIONAL_URL_PREFIX=view-log`, `/view-log/healthz` remains a health endpoint,
while `/view-log/stream-log` is retired. Bare retired URLs still return 404.
Matching uses a comparison copy and never rewrites encrypted paths or query
values. Retired routes remain reserved so old monitoring requests cannot enter
redirect or challenge handling or count as visitor traffic. They do not redirect to the
panel or expose a log stream. The standalone `live-log.html` viewer, stream
listeners, broadcasts, stream heartbeats, and backlog replay have been removed.

The independent health checker and its `[HEALTH] heartbeat` logs remain active.
`/health` and `/readyz` still report dependency readiness, including `503` when
a dependency check fails; `/healthz` and `/livez` still report liveness. Their
optional-prefix variants remain available. The compatibility health gauge
`sseListeners` is always zero.

The panel summarizes traffic; use the hosting platform's stdout logs for raw
request and error details, or configured file logging and the authenticated
`/__debug/log-file` and `/__debug/runtime-incidents` diagnostics. Bounded log
history, crash incidents, and the existing logging configuration remain intact.

## Read the JSON summary

`GET /admin/traffic-metrics` requires the existing `Authorization: Bearer`
admin token. It also works under `OPTIONAL_URL_PREFIX` when configured. The
response uses `Cache-Control: private, no-store`.

```bash
curl --fail --silent --show-error \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$REDIRECTOR_URL/admin/traffic-metrics"
```

The JSON contains `scope: "current_process"`, `startedAt`, `total`, `byKind`,
and `challenges`. It also includes `shared` Redis aggregates, `storage` status,
and current-process `runtime` memory and resource gauges. The fixed request
groups are:

| Group | Meaning |
| --- | --- |
| `operational` | Health, admin, logging, telemetry, and known static utility endpoints. |
| `head` | Other HEAD requests; these do not fetch a page body. |
| `prefetch` | Other GET requests explicitly declaring prefetch or prerender in `Purpose`, `Sec-Purpose`, or `X-Purpose`. |
| `get` | Remaining GET requests, including ordinary page and challenge requests. |
| `other` | Remaining methods, such as POST and OPTIONS. |

Operational classification takes precedence over method and purpose headers.
The utility routes `/ads.txt` and `/.well-known/security.txt`, including their
optional-prefix variants, are operational traffic.
Purpose headers are client supplied and do not identify all automated traffic.
The `get` group can also contain bots and repeat visits. None of these groups
represents unique visitors, verified humans, destination arrivals, or conversions.

## Interpret the counters

Each group and the total include:

- `requests`: requests observed by the collector.
- `inFlight`: requests whose response has not completed or aborted.
- `completed`: responses that emitted `finish`, counted once.
- `aborted`: requests that disconnected or errored before `finish`, counted once.
- `byStatusClass`: completed responses grouped into `1xx` through `5xx`, plus
  `other`. Aborted responses do not count as successful responses.
- `latencyMs.mean` and `latencyMs.max`: completed-response duration statistics
  since collector startup.
- `latencyMs.recent`: sample count, a limit of 512, and nearest-rank p50/p95/p99
  for the most recent completed responses in that group. Empty statistics are
  `null`.

Collection starts after path normalization and before early response
middleware, so early rejections and rate limits are included. Durations use a
monotonic clock and stop when the server finishes its response; they do not
measure browser page-load time or successful delivery to the visitor. The
admin request reading the snapshot is itself operational and may appear in
`inFlight`.

## Challenge outcomes

`challenges` contains fixed counters for server observations:

| Counter | Meaning |
| --- | --- |
| `shown` | Successful GET or POST responses serving the widget fragment. The wrapper, HEAD requests, rejected links, and interrupted responses do not count. This does not prove browser rendering. |
| `passed` | Supplied Turnstile responses accepted by Cloudflare and all existing local action, link, age, and hostname checks. |
| `failed` | Supplied Turnstile responses rejected by validation, excluding the separate expiry and provider-error outcomes. Missing tokens on first visits do not count. |
| `expired` | Provider-accepted responses rejected by the existing local token-age check. |
| `expiredOrDuplicate` | Cloudflare returned `timeout-or-duplicate`; it cannot distinguish those two cases. |
| `providerError` | Verification network, HTTP, JSON, provider-service, or configuration errors. |
| `redirected` | Completed GET destination redirects following accepted verification. Challenge redirects, rejected destinations, and interrupted responses do not count. |
| `payloadExpired` | Authenticated encrypted challenge payloads rejected by the existing payload-age check. |

These are attempt and response counts, not a deduplicated visitor funnel. A
reload or another verification attempt may increment a counter again. A passed
verification can still be followed by a rate limit or rejected destination.
Signed challenge links currently return the same response for invalid and
expired links; that response does not increment confirmed expiry. Untrusted
browser telemetry is not used to establish these outcomes.

## Persistence and deployment

The top-level totals, challenge counts, in-flight counts, and recent latency
samples describe the current process and reset on restart. The separate
`shared` object has `scope: "redis"` and combines acknowledged HTTP and
challenge observations from all replicas using the same namespace.

Configure a Redis connection in the application's secure environment settings:

- `TRAFFIC_METRICS_REDIS_URL`: optional dedicated connection. Falls back to
  existing `REDIS_URL`, then `REDIS_PRIVATE_URL`. Use `rediss://` when the
  provider requires TLS; certificate verification remains enabled.
- `TRAFFIC_METRICS_NAMESPACE`: stable application/environment identifier,
  default `oldserver222`; 1–80 letters, numbers, colons, underscores, or hyphens.
  Use the same value across replicas and restarts, and different values for
  production and test deployments.

No Redis URL means local-only operation: `shared` is `null` and
`storage.configured` is false. An unavailable or unreadable Redis also returns
`shared: null`; local metrics and normal request handling continue.

Shared HTTP counts record settled responses: `requests = completed + aborted`.
They include status classes, lifetime mean/max completed-response latency, and
challenge outcomes. In-flight counts and recent p50/p95/p99 samples remain
local; they are not presented as deployment-wide statistics. An admin read
flushes this replica's pending observations before reading shared totals;
other replicas flush approximately once per second. The current metrics
request appears in shared totals after it completes and is flushed.

Redis writes run outside ordinary request handling. Atomic batches have writer
sequence watermarks so an acknowledgment lost during reconnect does not cause
the same batch to increment counters twice. Unacknowledged batches may retry
for up to 24 hours; their deduplication markers expire after seven days. Only
fixed accumulators and one unacknowledged batch are kept in memory.

`storage` reports connection readiness, last successful flush/read times,
pending observations, safe error codes, and historical uncertain/dropped batch
and observation counts. An uncertain write may already have reached Redis;
successful retry deduplicates it. A batch older than the retry window is
discarded and reported as dropped rather than replayed after deduplication
expires. Shared totals can lag or omit unacknowledged observations; inspect
these status fields when interpreting them.

Graceful shutdown attempts a final flush after HTTP responses drain, within
the existing shutdown deadline. A crash or forced termination can lose buffered
observations. Retaining acknowledged metrics across **Redis** restarts requires
the provider's persistence (such as AOF), durable storage, and suitable backup
settings. Use Redis `noeviction` or equivalent isolation that preserves the
writer watermarks along with aggregate counters: evicting only a watermark
could allow an acknowledged batch to be counted again after a lost reply. The
app does not configure the Redis server or promise lossless analytics.

These metrics do not merge with the older daily ops metrics, which cover a
different part of the middleware pipeline. Shared aggregate fields do not
expire automatically; use a separate monitoring collector for time-series
history or reporting by day.

The local collector retains only fixed counters and up to 512 duration samples
for each of five request groups and the total. Redis retains aggregate counters
and temporary writer watermarks. Neither collector retains URLs, query
parameters, IP addresses, emails, referrers, or user agents. Routing and
protection decisions do not depend on these counters.

Use the response mix and latency measurements to establish a baseline before
tuning protection. A 4xx response is an HTTP outcome, not proof of a bot;
conversion events would still be needed to assess advertising results. The
article's claims about sub-100 ms detection and conversion
improvements are not benchmarks for this application.

## Validation

```bash
npm test
```

The metrics tests cover request groups, optional URL prefixes, early rejections,
single-event accounting, premature disconnects, bounded samples, percentile
calculations, snapshot isolation, challenge outcomes, authenticated real HTTP
routes, retired-path rejection, preserved health endpoints and heartbeat logs,
Redis retry behavior, and graceful shutdown.

To run the additional integration checks against an isolated real Redis:

```bash
TRAFFIC_METRICS_TEST_REDIS_URL=redis://127.0.0.1:6379 npm test
```

Those tests use a unique namespace and clean up only their own keys. Without
that variable, the real-Redis tests are explicitly skipped. Mocked provider tests
exercise verification outcomes without external requests; they do not verify
live Cloudflare credentials or browser challenge completion.

Additional panel checks:

```bash
# Requires Playwright and Chromium; uses a separate local fixture server.
node tests/traffic-panel-browser.js --output /tmp/traffic-panel-browser.json

# Five-minute local load check, including three simulated polling panels.
node tests/traffic-panel-soak.js --duration-sec 300 --rps 30 --panels 3 \
  --output /tmp/traffic-panel-soak.json

# Optional 20-second Redis network outage during the same load test.
TRAFFIC_METRICS_TEST_REDIS_URL=redis://127.0.0.1:6379 \
  node tests/traffic-panel-soak.js --duration-sec 300 --redis-outage-sec 20 \
  --output /tmp/traffic-panel-outage-soak.json
```

The soak can also use `TRAFFIC_METRICS_TEST_REDIS_URL`. It launches its own
isolated server with generated test credentials, exercises valid widget HTML
responses, malformed redirect requests, slow readers, and deliberate client
disconnects, then checks resource draining and runtime errors. The existing
malformed-request limiter's 429 responses are counted separately as expected
defensive responses. Reports never contain credentials or Redis URLs. A local
run does not prove long-term leak freedom or cover the deployed proxy's 499
behaviour; deliberate disconnections are reported separately.

Outage injection requires an isolated local Redis fixture. A temporary TCP
proxy owned by the test disconnects and reconnects the app; it never stops or
reconfigures the supplied Redis service. The checks require the API to continue
serving local metrics during the interruption, then recover shared totals and
drain pending observations afterward.

### Recorded panel validation

The local validation on 2026-10-16 passed all 296 automated tests, including
the real-Redis checks. Chromium passed 50 connect/disconnect cycles with
34 event listeners before and after, at most one metrics request in flight,
60 retained chart samples, and no uncaught browser or CSP errors.

The five-minute run targeted 30 requests/second with three polling panels and
a 20-second Redis outage. It completed 9,696 HTTP requests, 905 widget-fragment
responses, 299 slow-reader checks, and 299 separate deliberate disconnects.
There were no unexpected HTTP statuses, 5xx responses, network errors, request
timeouts, uncaught exceptions, or unhandled rejections. Expected validation
rate limits remained active. Local metrics stayed available during the outage;
shared delivery recovered and pending observations drained afterward.

Sampled RSS peaked at 189.69 MB and heap usage at 70.97 MB; the last-third heap
floor was 1.69 MB above the first-third floor. After draining, tracked requests
and log queue bytes were zero, with one remaining health-check connection.
These are observations from a short local run, subject to the limits above.
