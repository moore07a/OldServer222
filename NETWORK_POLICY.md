# VPN and datacenter access policy

The network policy adds optional enforcement to normal visitor redirects. It
shares the IP intelligence cache with risk reporting. It does not replace
scanner rules, bans, rate limits, destination restrictions, or Turnstile.
The traffic panel remains read-only; configure the policy in Railway variables
and restart the updated application.

## Configure the action and targets

For challenge mode targeting both VPN and datacenter indicators:

```dotenv
RISK_IP_INTELLIGENCE_ENABLED=1
RISK_IP_PROVIDER=ipquery
NETWORK_POLICY_MODE=challenge
NETWORK_POLICY_VPN=1
NETWORK_POLICY_DATACENTER=1
```

`RISK_REPORTING_ENABLED` must also remain enabled (its default). Provider
selection is explicit and no fallback sends an IP to another provider. See
[IP intelligence configuration](RISK_ASSESSMENT.md#enable-free-network-information).

| Setting | Default | Accepted values |
| --- | --- | --- |
| `NETWORK_POLICY_MODE` | `report` | `report`, `challenge`, or `block`. |
| `NETWORK_POLICY_VPN` | `0` | `1`, `true`, `on`, or `yes` selects VPNs; `0`, `false`, `off`, or `no` does not. |
| `NETWORK_POLICY_DATACENTER` | `0` | The same boolean values select datacenter/hosting IPs independently. |

Values are trimmed and case-insensitive. Empty values use defaults. Selecting
both targets matches **either** indicator; it does not require both to be true.
Leave one target at `0` to select only the other category. Proxy flags alone
are not treated as VPN flags, and residential-proxy classification is not
available from these adapters.

| Action | Behavior |
| --- | --- |
| `report` | Record selected matches without adding access restrictions. This is the default. |
| `challenge` | Use the existing mandatory Turnstile flow. A verified matching visitor can continue if all other checks pass. No second challenge is introduced. |
| `block` | Reject a known selected match with generic HTTP `403` before the destination redirect, even after successful Turnstile verification. |

Every normal destination redirect already requires server-verified Turnstile.
Consequently, challenge mode makes the network decision observable and warms
the shared cache during that flow; it does not make the existing challenge
stronger or create an additional verification system. `HEADLESS_BLOCK` is a
separate existing setting and is unchanged by the network policy.

## First visits and unavailable classifications

After existing hard security checks pass, a synchronous cache check can queue
a background lookup. It never waits for the provider. The app checks the cache
again immediately before the destination redirect, after Turnstile, its rate
limit, decryption, protocol/host pinning, and destination allowlist validation.
Both `/r?d=...` and ciphertext path routes, including optional-prefix variants,
use that final gate. Scanner bypass options do not bypass this gate.

Only explicit boolean `true` on a selected indicator counts as a match. When
all selected indicators are explicitly `false`, the result is unmatched.
Otherwise it is unknown. A positive match on one selected indicator still
matches when the other is unknown.

**Unknown classifications continue under the existing challenge and security
rules.** A first lookup may not finish before the visitor completes verification.
Timeouts, provider failures, rate limits, exhausted local budgets, unsupported
IP addresses, or missing fields may also leave a classification unknown. A
verified visitor can then reach an allowed destination, including in `block`
mode. This policy therefore does not guarantee blocking every VPN or datacenter
visit. Unknown data is not evidence that a visitor is safe.

Invalid policy values, disabled IP intelligence/reporting, or no selected
targets disable enforcement. The API and panel show the configured mode and
effective mode separately, with an inactive reason. Invalid values are not
reflected in responses. Check **Effective action** and **Enforcement status**
after changing settings; a configured `block` mode alone does not establish
active enforcement.

Network matches do not add strikes or populate the existing IP deny cache.
This avoids turning a temporary provider classification into a longer ban.
Existing security can still reject a request independently. Health/readiness,
administration, challenge endpoints, public pages/assets, telemetry, and scanner
safety responses do not pass through the network enforcement gate.

Real people use VPNs and cloud gateways; bots can use residential connections.
Provider data can be incomplete or wrong. Start with report or challenge mode
and assess your own traffic before choosing strict category blocking.

## Panel, API, and persistence

The authenticated `/admin/traffic-metrics` response exposes `networkPolicy`:
current-process settings, status, start time, and fixed aggregate counters.
The Network policy card displays these independently of the HTTP Metric scope
selector. No new panel write endpoint or browser token storage is added.

- `evaluated`: redirect requests checked, once per request across cache rechecks.
- `matchedVpn` and `matchedDatacenter`: requests matching each selected target,
  once per target per request. The two counters can overlap.
- `blocked`: matching decisions rejected at the final network gate.
- `challenged`: network-policy decisions sent into the existing challenge flow,
  including unknown classifications. These are not additional widget counts.
- `allowedAfterChallenge`: known matches allowed after verification in challenge mode.
- `allowedUnknown`: unknown classifications allowed after verification during active enforcement.
- `errors`: request-local cache-access errors, once per request; provider errors
  remain in the existing IP intelligence diagnostics.

These are decision counts rather than completed response counts or unique
people. In report mode the evaluation/match counters run for selected targets,
but enforcement outcome counters do not increment. Requests rejected by earlier
security checks are not counted as network-policy blocks.

When analytics disk storage is configured, `persistent.networkPolicy` contains
the last successfully saved aggregate counters. The panel labels saved disk
block/challenge/unknown totals separately. Existing valid checkpoints from
before this feature restore their HTTP, challenge, risk, and campaign totals;
network-policy totals start at zero and are included in subsequent normal saves.
No raw IPs, lookup cache, per-request records, or individual enforcement
decisions are persisted. Disk saves use the existing bounded background checkpoint writer.
These totals belong to one volume and do not combine separate replica volumes.

The shared intelligence service retains its existing daily budget, two active
lookups, bounded queue/cache, response-size limit, cancellation, and shutdown
behavior. Network enforcement adds no polling stream or per-visitor timer.
