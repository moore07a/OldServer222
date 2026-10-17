# VPN and datacenter blocking

Two independent environment switches control network-category blocking. Keep
these settings in Railway variables and restart the updated application:

```dotenv
NETWORK_POLICY_VPN=1
NETWORK_POLICY_DATACENTER=1
```

`1` means block known matches for that category. `0`, an empty value, or an
unset variable means category blocking is off. Trimmed boolean aliases
`true`/`false`, `on`/`off`, and `yes`/`no` also remain accepted.

| VPN switch | Datacenter switch | Network blocking |
| --- | --- | --- |
| `0` or unset | `0` or unset | Off; existing bot protection and verification continue. |
| `1` | `0` or unset | Block known VPN matches. |
| `0` or unset | `1` | Block known datacenter/hosting matches. |
| `1` | `1` | Block either known VPN or known datacenter matches. |

The switches do not disable scanner rules, bans, rate limits, destination
restrictions, Turnstile, or risk reporting. A category switch at `0` does not
guarantee access: another enabled category or existing security rule can still
reject that request. Proxy flags alone do not count as VPN flags.
Residential-proxy classification is not available from these adapters.

## Existing IP intelligence configuration

Keep the existing IPQuery configuration enabled:

```dotenv
RISK_IP_INTELLIGENCE_ENABLED=1
RISK_IP_PROVIDER=ipquery
```

`RISK_REPORTING_ENABLED` must also remain enabled (its default). These existing
settings govern the shared intelligence service; the two new blocking switches
do not authorize third-party lookups by themselves. Provider selection remains
explicit, without automatic fallback to another recipient. See the
[IP intelligence guide](RISK_ASSESSMENT.md#enable-free-network-information).

If intelligence is disabled, no targets are selected, or a target value is
invalid, category blocking is inactive. The panel shows each switch separately
from **Enforcement status**. Invalid target values produce fixed setting names
in configuration errors, without reflecting their contents.

## Upgrade from the earlier policy

Remove `NETWORK_POLICY_MODE` from Railway. It is no longer read or supported.
A leftover `report`, `challenge`, `block`, or any other value cannot enable or
disable blocking. **A target switch set to `1` now directly blocks known
matches**, even if the removed setting previously selected reporting or
challenge mode. Use `0` or remove both target variables to retain only existing
security and reporting.

The authenticated metrics API exposes network-policy configuration version 2,
with `enabled`, `targets`, status, and counters. There are no configured-action
or effective-action modes. The updated panel treats older policy payloads as
unavailable instead of interpreting an old challenge setting as active blocking.

## Redirect enforcement and unknown classifications

After existing hard security checks pass, a synchronous cache check can queue
a background lookup. It never waits for the provider. The app checks the cache
again immediately before the destination redirect, after Turnstile, its rate
limit, decryption, protocol/host pinning, and destination allowlist validation.
Both `/r?d=...` and ciphertext path routes, including optional-prefix variants,
use that final gate. Scanner bypass options do not bypass this gate.

An explicit boolean `true` on an enabled category is a match. Either enabled
category can match even when the other is unknown. A matching request receives
generic HTTP `403` before reaching its destination, even after successful
Turnstile verification. Network matches do not add strikes or populate the
existing IP deny cache.

When all selected indicators are explicitly `false`, the result is unmatched.
Otherwise it is unknown. **Unknown classifications follow the existing
challenge and security rules.** A first lookup may not finish before verification.
Timeouts, provider errors, quota limits, exhausted local budgets, unsupported
addresses, or missing fields can also leave a result unknown. A verified visitor
can then continue to an allowed destination. Blocking therefore does not
identify or reject every VPN or datacenter visit, and unknown does not mean safe.

Every normal destination redirect already requires server-verified Turnstile.
No additional challenge system is introduced. Existing security decisions retain
priority. Health/readiness, administration, challenge endpoints, public pages,
assets, telemetry, and scanner safety responses remain outside this network gate.
`HEADLESS_BLOCK` remains a separate existing setting and is unchanged.

Real people use VPNs and cloud gateways; bots can use residential connections.
These switches restrict network categories, rather than establishing whether
every visitor is human.

## Panel, API, and persistence

The read-only Network policy card displays **Block VPN traffic**, **Block
datacenter traffic**, enforcement status, current-process counters, and separate
saved disk totals. Settings and current counters do not change with the HTTP
Metric scope selector. No panel write endpoint or token storage is added.

The authenticated `/admin/traffic-metrics` API returns `networkPolicy` with
fixed aggregate counters:

- `evaluated`: redirect requests checked, once per request across cache rechecks.
- `matchedVpn` and `matchedDatacenter`: requests matching each enabled category,
  once per category per request; the two counters can overlap.
- `blocked`: matching decisions rejected at the final network gate.
- `challenged`: unknown policy decisions sent into the existing challenge flow;
  these are not additional widget counts.
- `allowedUnknown`: unknown classifications allowed after verification.
- `errors`: request-local cache-access errors; provider errors remain in the
  existing IP intelligence diagnostics.

These are decision counts, not completed response counts or unique people.
The legacy `allowedAfterChallenge` counter stays at zero in the current-process
API for compatibility; matching visitors can no longer bypass category blocking
by passing a challenge. The panel does not display that unused counter.
Requests rejected by earlier rules are not counted as network-policy blocks.

With analytics disk storage, `persistent.networkPolicy` contains the last
successfully saved aggregate counters. Existing checkpoints retain HTTP,
challenge, risk, campaign, and policy totals, including historical fields. Disk
block/challenge/unknown totals are displayed separately and belong to this
volume, without combining separate replica volumes. No raw IPs, lookup cache,
per-request records, or individual decisions are persisted.

The shared cache, daily budget, two-active-lookup limit, bounded queue, response
size limit, cancellation, shutdown, and background disk writer are unchanged.
No stream, duplicate lookup service, or per-visitor timer is added.
