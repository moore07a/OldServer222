# Cloudflare WAF + Railway hardening playbook

This runbook documents a practical, copy/paste baseline to prevent common scanner and brute-force traffic from reaching the Node/Express app deployed on Railway.

## 1) Put Railway origin behind Cloudflare proxy

1. In Cloudflare DNS, create a `CNAME` for your app hostname (example: `app.example.com`) pointing to the Railway-provided hostname.
2. Set the DNS record to **Proxied** (orange cloud ON).
3. Use SSL/TLS mode **Full (strict)** when possible.

If traffic is not proxied, Cloudflare WAF cannot protect the origin.

## 2) Recommended custom WAF rules

Create rules in **Security → WAF → Custom rules**, in this order.

### Rule A — Block obvious scanner probe paths

- **Action**: `Block`
- **Expression**:

```cf
(
  http.request.uri.path contains "/.git/" or
  http.request.uri.path contains "/wp-admin/" or
  http.request.uri.path eq "/wp-login.php" or
  ends_with(http.request.uri.path, ".php") or
  ends_with(http.request.uri.path, ".asp") or
  ends_with(http.request.uri.path, ".jsp") or
  http.request.uri.path eq "/sitemap.txt" or
  http.request.uri.path eq "/sitemap.xml.gz" or
  http.request.uri.path eq "/th1s_1s_a_4o4.html"
)
```

### Rule B — Block malformed double-slash POST probes

- **Action**: `Block`
- **Expression**:

```cf
(http.request.method eq "POST" and raw.http.request.uri.path contains "//")
```

### Rule C — Block traversal probes

- **Action**: `Block`
- **Expression**:

```cf
(
  http.request.uri.path contains "../" or
  lower(http.request.uri.path) contains "%2e%2e" or
  lower(http.request.uri.path) contains "%252e%252e"
)
```

## 3) Recommended rate-limit rule

Create in **Security → WAF → Rate limiting rules**:

- **Match**: scanner-heavy paths from Rule A + Rule B (use the same raw-path logic for double-slash checks).
- **Threshold**: start with `20 requests / 10 seconds / IP`.
- **Action**: `Managed Challenge` first; switch to `Block` during active attack windows.
- **Mitigation timeout**: 1–10 minutes.

## 4) Avoid breaking normal traffic

Keep or add an allow/skip policy for known good paths used by platform and app operations:

- `/health`, `/healthz`, `/readyz`
- `/sitemap.xml`
- app-specific challenge/verification endpoints

## 5) Railway + app-side validation checklist

- Ensure Express trusts proxy headers correctly (`app.set("trust proxy", ...)`) so per-IP controls use real client IPs.
- Keep app early-exit scanner middleware enabled as fallback.
- Keep per-IP rate-limiter before expensive routes.

## 6) Safe rollout process

1. Deploy WAF custom rules in `Log` mode first for 15–30 minutes.
2. Review sampled matches for false positives.
3. Switch Rule A/B/C to `Block`.
4. Enable rate-limit rule with `Managed Challenge`.
5. Watch origin metrics (request volume, p95/p99 latency, saturation, 5xx).

## 7) Quick verification commands

From any terminal:

```bash
curl -i https://app.example.com/.git/config
curl -i https://app.example.com/wp-admin/install.php
curl -i -X POST https://app.example.com//
```

Expected outcome after WAF policy is active: blocked/challenged at edge, with reduced origin load.
