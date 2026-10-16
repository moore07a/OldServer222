# Traffic metrics

The article's useful starting point is separating different kinds of traffic
before changing protection rules. A request count alone cannot establish how
many people visited, whether someone is a bot, or whether an ad converted.

## Read the summary

`GET /admin/traffic-metrics` requires the existing `Authorization: Bearer`
admin token. It also works under `OPTIONAL_URL_PREFIX` when configured. The
response uses `Cache-Control: private, no-store`.

```bash
curl --fail --silent --show-error \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$REDIRECTOR_URL/admin/traffic-metrics"
```

The JSON contains `scope: "current_process"`, `startedAt`, `total`, `byKind`,
and `challenges`. It also includes `shared` Redis aggregates and `storage`
status when persistence is configured. The fixed request groups are:

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
routes, Redis retry behavior, and graceful shutdown.

To run the additional integration checks against an isolated real Redis:

```bash
TRAFFIC_METRICS_TEST_REDIS_URL=redis://127.0.0.1:6379 npm test
```

Those tests use a unique namespace and clean up only their own keys. Without
that variable, the real-Redis tests are explicitly skipped. Mocked provider tests
exercise verification outcomes without external requests; they do not verify
live Cloudflare credentials or browser challenge completion.
