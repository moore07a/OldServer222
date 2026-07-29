# IPinfo Lite Geo Fallback

This app uses trusted upstream country headers first (Cloudflare, Vercel,
Netlify, Render, Railway, and Fly region hints). When those sources do not
provide a trusted country, the app can call the IPinfo Lite API as the final
country/ASN fallback.

## Required environment

Set an IPinfo Lite token to enable the fallback automatically:

```env
IPINFO_TOKEN=your_ipinfo_token
```

You can also use `IPINFO_ACCESS_TOKEN` as an alias. If no token is configured,
the app still starts and relies on trusted upstream geo headers only.

## Optional environment

```env
IPINFO_LITE_ENABLED=1
IPINFO_LITE_TIMEOUT_MS=800
IPINFO_LITE_CACHE_TTL_MS=21600000
IPINFO_LITE_CACHE_MAX_ENTRIES=50000
```

`IPINFO_LITE_ENABLED` defaults to enabled when `IPINFO_TOKEN` or
`IPINFO_ACCESS_TOKEN` is present. Set it to `0` to disable IPinfo without
removing the token.

`IPINFO_LITE_TIMEOUT_MS` keeps geo lookups from holding requests too long. If
IPinfo is unavailable, slow, or returns an error, the app fails open for geo-only
policy checks by treating the country as unknown.

`IPINFO_LITE_CACHE_TTL_MS` and `IPINFO_LITE_CACHE_MAX_ENTRIES` reduce repeated
API calls for the same visitor IP and keep the fallback resilient during traffic
bursts.

## Deployment note

There is no startup database refresh and no local GeoIP database file to store.
Runtime lookup uses the IPinfo Lite API only after trusted upstream headers and
Fly region mapping fail to identify the visitor country.

IPinfo Lite responses include country and ASN fields. The app uses `country_code`
for `ALLOWED_COUNTRIES` / `BLOCKED_COUNTRIES` and can use `asn` as an additional
fallback for `BLOCKED_ASNS` when platform ASN headers are unavailable.
