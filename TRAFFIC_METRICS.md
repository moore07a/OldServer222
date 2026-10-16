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

The JSON contains `scope: "current_process"`, `startedAt`, `total`, and
`byKind`. The fixed request groups are:

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

## Retention and use

These are in-memory, per-process aggregates. Restarting resets them, and each
replica reports its own counts. They do not merge with the older daily ops
metrics, which cover a different part of the middleware pipeline. Use a
monitoring collector if deployment-wide history is needed.

The collector retains only fixed counters and up to 512 duration samples for
each of five request groups and the total. It does not retain URLs, query
parameters, IP addresses, emails, referrers, or user agents. Routing and
protection decisions do not depend on these counters.

Use the response mix and latency measurements to establish a baseline before
tuning protection. A 4xx response is an HTTP outcome, not proof of a bot;
separate challenge-completion and conversion events would be needed to assess
those outcomes. The article's claims about sub-100 ms detection and conversion
improvements are not benchmarks for this application.

## Validation

```bash
npm test
```

The metrics tests cover request groups, optional URL prefixes, early rejections,
single-event accounting, premature disconnects, bounded samples, percentile
calculations, snapshot isolation, and authentication through real HTTP routes.
