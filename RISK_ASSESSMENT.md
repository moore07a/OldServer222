# Report-only traffic risk observations

The live panel at `/admin/traffic-panel` includes browser indicators, optional
network indicators, and a bounded campaign window. The authenticated
`/admin/traffic-metrics` response includes the same data under `risk`. Optional
URL-prefix variants work too. These observations do not change redirects,
challenges, rate limits, blocking decisions, or health checks.

Optional [VPN/datacenter access policy](NETWORK_POLICY.md) is configured
separately using two independent blocking switches; risk observations
themselves remain report-only.

This is not an AI model or proof that a visitor is fraudulent. Headless markers
come from existing browser checks; header anomalies require at least two
existing soft signals. Legitimate automation can trigger either. Actual
server-verified challenge passes/failures are recorded separately. Client
telemetry cannot claim a pass; missing tokens, provider errors, and expiry do
not count as confirmed failures here.

## Enable free network information

Network lookups are **off by default**. To use the free IPQuery adapter, set
both values in deployment environment settings and restart:

```dotenv
RISK_IP_INTELLIGENCE_ENABLED=1
RISK_IP_PROVIDER=ipquery
```

IPQuery's [official account](https://github.com/ipqwery/ipqwery) describes its
free API, and its [official SDK](https://github.com/ipqwery/ipapi-py/blob/main/ipapi/client.py)
uses HTTPS without an API key. This adapter reads only `risk.is_datacenter`,
`risk.is_proxy`, and `risk.is_vpn`. A manual request from Railway to the public
test IP `8.8.8.8` returned HTTP 200 with all three boolean fields, identifying
that address as a datacenter. This confirms that response schema is available
there; it does not establish coverage of every VPN or SOCKS5 exit.

The existing default remains `RISK_IP_PROVIDER=ipapi.is`, using
[ipapi.is's anonymous API](https://github.com/ipapi-is/ipapi#the-ip-api). A
successful anonymous response observed on Railway supplied geolocation fields
without the documented network flags, so those results correctly remain
unknown. Selecting `ipquery` is explicit: the app never switches providers or
falls back to a second provider automatically.

Enabling lookups sends visitor public IPs to the selected third party over
HTTPS. It does not send visited URLs, user agents, or application secrets.
Selecting a provider alone does not enable lookups. Lookups use the existing
trusted request identity; private, reserved, documentation, and unsupported
special-purpose addresses are skipped.

Documented fields cover datacenter/hosting, proxy, and VPN indicators.
Residential-proxy classification remains unknown and displays **Not provided**
because neither adapter documents that field. An ISP name plus a proxy
flag does not establish a residential proxy. Hosting or VPN use alone does not
establish abusive traffic. Proxy/VPN indicators come from provider data rather
than active protocol scanning. Automated provider tests use mocked responses,
not live visitor lookups; availability, accuracy, and provider limits can change.

Visitor requests never wait for intelligence. A cache miss counts as unknown
and queues background work; later requests can use the cached result. Earlier
observations are not reclassified. Failures, timeouts, absent fields, and
exhausted budgets remain unknown rather than being treated as safe traffic.

A successful JSON response that supplies no documented boolean indicators is
now shown as **Unknown — no network classification**, rather than the generic
cache `invalid_response` failure. Missing/null fields stay unknown; the app does
not guess alternate wrappers or coerce strings such as `"false"`. Wrong field
types, malformed JSON, API error objects, HTTP failures, and quota limits remain
distinct failures. Safe diagnostics expose only HTTP status and fixed field
types for `is_datacenter`, `is_proxy`, and `is_vpn`, never their raw response,
visitor IP, or request URL. Unknown responses use the short negative-cache TTL.
Panel polling is operational traffic and does not retry a visitor lookup;
another eligible visitor request can retry after that TTL expires.

Cache-hit counts describe cache accesses, not unique visitor requests. An
enabled network policy can access the same cache during warmup, the final
redirect check, and settled-request reporting.

The default budget is 900 attempted lookups per rolling 24 hours **per running
process**, including failures. It resets on restart and is not shared through
Redis or disk. This is an application limit, not a promise about the provider's
allowance. ipapi.is documents 1,000 anonymous requests per day shared by outbound
IP; IPQuery may impose its own limits. Replicas, frequent restarts, other apps,
and shared hosting egress can consume a shared allowance sooner. Divide
`RISK_IP_DAILY_BUDGET` across replicas. Rate limits leave results unknown and do
not interrupt redirects.

## Campaign windows

Configure an explicit allowlist:

```dotenv
RISK_CAMPAIGN_IDS=ad_alpha,ad_beta
```

Append `campaign_id=ad_alpha` to an existing visitor URL using its normal
query-string separator. This is a client-supplied label, not proof of a paid
ad click. Only exact allowlisted single string values are accepted; everything
else goes into `__unattributed__`. At most 32 configured campaigns plus that
bucket exist. Arbitrary query values cannot create rows or Redis keys.

Attribution applies to the current request only. The app does not automatically
carry `campaign_id` through challenge redirects or cookies; a follow-up request
without it goes into `__unattributed__`. These rows do not form a campaign
funnel across the existing challenge flow.

Rows cover the current clock-aligned window (five minutes by default), with
requests, approximate distinct IP sources, browser/network indicators,
challenge outcomes, and trusted conversions. Local estimates use a fixed
bitmap; Redis uses HyperLogLog. They count approximate IP sources, not people,
devices, or sessions. Shared connections, changing IPs, and address formatting
affect estimates. A saturated bitmap displays **At capacity**.

An **unusual activity** flag requires at least 200 requests, 20 estimated
sources, and browser indicators on at least half the window's requests. It is
suppressed for saturated local estimates. Thresholds are configurable. This
is a review signal, not confirmed click-farm detection. There is no individual
click/conversion linking, fraud rate, ROI, or deduplicated visitor funnel.

Lifetime risk totals describe the responding process and reset on restart,
regardless of the panel's HTTP-total scope selector. Campaign windows label
shared Redis data, local-only data, or local fallback when Redis is unavailable.
Window keys expire at window start plus twice the window duration. They do
not provide historical campaign reporting.

With [volume storage configured](TRAFFIC_METRICS.md#railway-volume-storage),
the campaign window uses **Persisted disk window** and restores its current
counts/bitmaps after a restart. An expired or changed-length window starts fresh.
Adding/removing campaigns keeps matching current-window rows and preserves
bounded valid conversion dedupe, including previously configured IDs. Top-level
risk counters still describe the current process; aggregate saved risk totals
are available separately in `persistent.risk`.

Changing a valid `RISK_NAMESPACE` deliberately starts fresh campaign counters
and conversion dedupe for that namespace. HTTP, challenge, and aggregate risk
totals still restore from the unchanged analytics namespace. The saved campaign
state must pass full validation before this reset; changing namespaces does not
allow malformed checkpoint data to be overwritten.

## Trusted backend conversions

Conversions stay disabled until campaigns and a dedicated
`RISK_CONVERSION_TOKEN` are configured. Generate a separate 32–256-character
printable secret without spaces and keep it in backend secret settings. Neither
`ADMIN_TOKEN` nor query tokens authorize writes. Never put the conversion
secret in browser code or a visitor URL.

After your backend confirms a conversion, send a stable opaque event ID:

```bash
curl --fail --silent --show-error \
  -H "Authorization: Bearer $RISK_CONVERSION_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"campaignId":"ad_alpha","eventId":"order_123"}' \
  "$REDIRECTOR_URL/admin/risk-conversions"
```

Optional-prefix variants also work. JSON accepts only `campaignId` and
`eventId`. Campaigns must be allowlisted. IDs must be 1–128 letters, numbers,
underscores, periods, colons, or hyphens; use opaque IDs rather than personal
data. The existing 64 KB request-body limit applies.

`200` returns `accepted: true` and `duplicate` to indicate whether this
campaign/event pair was already accepted within 24 hours. Accepted retries do
not increment another window. Responses use `401` for invalid authorization,
`400` for invalid events, `404` when disabled, `429` for dedupe capacity, and
`503` for unavailable configured storage. The last two include `Retry-After: 5`.

Memory-only dedupe retains at most 4,096 IDs across campaigns and resets on restart.
When disk storage is selected, those bounded HMAC identifiers are checkpointed
with the campaign state. New events and accepted retries wait for a durable
checkpoint before returning `200`; a failed or uncertain commit returns `503`
and retains the in-memory marker so a later retry cannot count it twice. Disk
conversion commits have a fixed queue of 32 and finite deadlines; saturation
returns `429`. Startup restore completes before accepting HTTP requests.

Shared dedupe requires Redis and consistent namespace/hash secrets across
replicas. It admits at most 2,048 distinct IDs per campaign per UTC day;
current/previous-day buckets support the rolling 24-hour check and expire 48
hours after their last write. Capacity rejects new events rather than evicting
valid dedupe markers. Configured Redis outage or connection-construction
failure rejects conversions instead of accepting them locally.

These are best-effort analytics. An interrupted Redis operation can be
uncertain and undercount. Recording dedupe before the counter prevents a retry
from double-counting an uncertain conversion. Use your order/payment system
as the source of truth. Redis durability and eviction also affect retention.

## Bounds and configuration

Observation happens after a response finishes or aborts and skips operational
routes, including health, admin, and retired log URLs. Challenge evidence uses
a WeakMap and is consumed once per settled request. No stream or health timer
is added or removed.

Defaults are 2,048 IP cache entries, two active lookups, 64 queued lookups,
800 ms reporting deadlines, and 16 KB maximum response bodies. Positive cache
TTL is one hour; negative TTL is one minute. Pressure evicts entries or drops
work. An operation that ignores cancellation retains its worker slot until
the original operation settles; late results cannot replace timed-out results.
Shutdown immediately clears timers/cache/queue and aborts active work. No
per-visitor polling timer is created.

Campaign storage allows 128 pending operations including its single active
operation. Its dedicated Redis connection uses a one-second command deadline,
no offline queue, and no automatic resends. A separate finite store deadline
bounds waiting. Queued work is dropped during outages; uncertain observations
are not replayed. Snapshots are single-flight. The panel reports dropped and
uncertain observations and local fallback explicitly. Visitor responses do
not wait for snapshots or Redis writes.

Within this feature, raw IPs exist only in the bounded intelligence cache and
work queue. Redis contains HMAC source/event identifiers and aggregate counts,
not raw IPs, URLs, user agents, or conversion IDs. The risk API returns none
of these identifiers, cache keys, or secrets. Existing application logging is
separate.

| Setting | Default and accepted values |
| --- | --- |
| `RISK_REPORTING_ENABLED` | On; `0`, `false`, `off`, or `no` disables reporting/conversions. |
| `RISK_IP_INTELLIGENCE_ENABLED` | Off; `1`, `true`, `on`, or `yes` enables third-party lookups. |
| `RISK_IP_PROVIDER` | `ipapi.is`; accepts `ipapi.is` or `ipquery` (case-insensitive). An unsupported value disables lookups and reports this setting's name in configuration errors. |
| `RISK_IP_DAILY_BUDGET` | `900`; integer 0–1,000 per process per rolling day. |
| `RISK_IP_CACHE_MAX_ENTRIES` | `2048`; integer 1–10,000. |
| `RISK_IP_QUEUE_MAX` | `64`; integer 1–128. Active concurrency stays at two. |
| `RISK_IP_TIMEOUT_MS` | `800`; integer 100–2,000. |
| `RISK_IP_CACHE_TTL_MS` | `3600000`; integer 60,000–86,400,000. |
| `RISK_IP_NEGATIVE_TTL_MS` | `60000`; integer 1,000–3,600,000. |
| `RISK_CAMPAIGN_IDS` | Empty; comma-separated IDs, at most 32 unique, each 1–64 letters/numbers/underscores/hyphens. `__unattributed__` is reserved. |
| `RISK_WINDOW_SECONDS` | `300`; integer 10–3,600. |
| `RISK_BURST_MIN_REQUESTS` | `200`; integer 10–100,000. |
| `RISK_BURST_MIN_SOURCES` | `20`; integer 2–10,000. |
| `ANALYTICS_STORAGE_DIR` | Optional persistent analytics directory; Railway volumes can auto-select their `analytics` subdirectory. See the volume guide. |
| `RISK_REDIS_URL` | Explicit URL selects Redis. Otherwise configured disk storage takes precedence; without disk it falls back to the metrics Redis URL, then `REDIS_URL` / `REDIS_PRIVATE_URL`. TLS verification remains enabled. |
| `RISK_NAMESPACE` | Falls back to `TRAFFIC_METRICS_NAMESPACE`, then `oldserver222`; 1–80 letters/numbers/colons/underscores/hyphens. |
| `RISK_HASH_SECRET` | Falls back to `ADMIN_TOKEN`; keep consistent across replicas/restarts. Rotation changes identifiers and dedupe. |
| `RISK_CONVERSION_TOKEN` | Empty/disabled; separate 32–256-character printable ASCII backend secret, without spaces. |

Use distinct namespaces for environments and consistent campaign/window
settings across replicas. Invalid numeric settings use defaults and appear by
name in `risk.configErrors`. Invalid campaigns disable named attribution and
conversions. Invalid namespaces force local observations and disable
conversions instead of writing to a fallback Redis namespace. Secrets and raw
invalid values do not appear in configuration errors.

## Validation

```bash
npm test
TRAFFIC_METRICS_TEST_REDIS_URL=redis://127.0.0.1:6379 npm test
node tests/traffic-panel-browser.js --output /tmp/risk-browser.json
node tests/traffic-panel-soak.js --disk --duration-sec 300 --rps 30 --panels 3 \
  --disk-outage-sec 20 --output /tmp/disk-soak.json
TRAFFIC_METRICS_TEST_REDIS_URL=redis://127.0.0.1:6379 \
  node tests/traffic-panel-soak.js --duration-sec 300 --rps 30 --panels 3 \
  --redis-outage-sec 20 --output /tmp/risk-soak.json
```

Use isolated local Redis for integration/outage checks. Tests use unique
namespaces; fault injection interrupts only its own TCP proxy. Provider tests
mock quotas, errors, size limits, ignored cancellation, and unknown fields.
Browser checks cover auth, reconnects, bounded history, timeouts, and cleanup.
A short local soak can expose regressions; it cannot prove there will never
be a memory leak or hosting-proxy `499`.
