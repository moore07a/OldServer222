# Supported URL Formats

This document lists the redirect URL formats currently supported by the app.

## Placeholder legend

- `<base>`: your app host, for example `https://your-domain.com`
- `<payload>`: encrypted/base64url redirect payload, or a raw URL payload where supported
- `<email>`: raw email, percent-encoded email, or base64/base64url email
- `<ignore>`: cosmetic/tracking/ignored path segment
- `<url-prefix>`: ignored full URL prefix, for example `https://example.com`, `https://example.com/path`, or encoded `https%3A%2F%2Fexample.com`
- `<delimiter>`: one configured email delimiter. Defaults are `//`, `__`, `--`, and `~~`; these can be overridden with `REDIRECT_EMAIL_DELIMITERS`, `DELIMITER`, or `Delimiter`.
- `<OPTIONAL_URL_PREFIX>`: optional leading prefix configured with `OPTIONAL_URL_PREFIX`, for example `qs/_z`.

## 1. Plain ciphertext / simple payload

```text
<base>/<payload>
```

Example:

```text
https://your-domain.com/PrDHTspG-f7xe7J5TBMZKirSbnkV4...
```

## 2. Payload + email

```text
<base>/<payload><delimiter><email>
<base>/<payload>/<email>
```

Examples:

```text
https://your-domain.com/PrDHT...//alice@example.com
https://your-domain.com/PrDHT...__alice@example.com
https://your-domain.com/PrDHT...--alice@example.com
https://your-domain.com/PrDHT...~~alice@example.com
https://your-domain.com/PrDHT.../YWxpY2VAZXhhbXBsZS5jb20
```

## 3. Payload + ignored segment, no email

```text
<base>/<payload>/<ignore>
```

Example:

```text
https://your-domain.com/PrDHT.../campaign
```

## 4. Payload + ignored segment + email

```text
<base>/<payload>/<ignore>/<email>
<base>/<payload>/<ignore><delimiter><email>
<base>/<payload>/<ignore>//<email>
```

Examples:

```text
https://your-domain.com/PrDHT.../campaign/alice@example.com
https://your-domain.com/PrDHT.../campaign//alice@example.com
https://your-domain.com/PrDHT.../campaign__alice@example.com
```

## 5. Payload + email + ignored segment

```text
<base>/<payload>/<email>/<ignore>
<base>/<payload>//<email>/<ignore>
<base>/<payload><delimiter><email>/<ignore>
```

Examples:

```text
https://your-domain.com/PrDHT.../alice@example.com/campaign
https://your-domain.com/PrDHT...//alice@example.com/campaign
https://your-domain.com/PrDHT...__alice@example.com/campaign
```

## 6. Email-first payload

```text
<base>/<email>/<payload>
```

Examples:

```text
https://your-domain.com/alice@example.com/PrDHT...
https://your-domain.com/YWxpY2VAZXhhbXBsZS5jb20/PrDHT...
https://your-domain.com/alice%23tag@example.com/PrDHT...
```

## 7. Ignored prefix before payload

```text
<base>/<ignore>/<payload>
```

Examples:

```text
https://your-domain.com/campaign/PrDHT...
https://your-domain.com/nytimes/PrDHT...
https://your-domain.com/url.com/path/PrDHT...//alice@example.com
```

## 8. Ignored prefix + email + payload

```text
<base>/<ignore><delimiter><email>/<payload>
<base>/<ignore>//<email>/<payload>
```

Examples:

```text
https://your-domain.com/campaign//alice@example.com/PrDHT...
https://your-domain.com/anything/goes//alice@example.com/PrDHT...
https://your-domain.com/https://example.com//alice@example.com/PrDHT...
```

## 9. Ignored full URL prefix before payload, no email

```text
<base>/<url-prefix>/<payload>
```

Examples:

```text
https://your-domain.com/https://example.com/PrDHT...
https://your-domain.com/https://example.com/path/PrDHT...
https://your-domain.com/https%3A%2F%2Fcdn.example.com/PrDHT...
```

## 10. Ignored full URL prefix + payload + email suffix

```text
<base>/<url-prefix>/<payload>//<email>
<base>/<url-prefix>/<payload><delimiter><email>
<base>/<url-prefix>/<payload>/<email>
```

Examples:

```text
https://your-domain.com/https://example.com/PrDHT...//alice@example.com
https://your-domain.com/https://example.com/path/PrDHT...//alice@example.com
https://your-domain.com/https://example.com/PrDHT...__alice@example.com
```

## 11. Ignored full URL prefix + email + payload

```text
<base>/<url-prefix>//<email>/<payload>
<base>/<url-prefix><delimiter><email>/<payload>
```

Examples:

```text
https://your-domain.com/https://example.com//alice@example.com/PrDHT...
https://your-domain.com/https://www.123.com__alice@example.com/PrDHT...
```

## 12. URL-prefix payloads with query, fragment, or trailing slash

```text
<base>/<url-prefix>/<payload>?utm=x
<base>/<url-prefix>/<payload>#frag
<base>/<url-prefix>/<payload>/
<base>/<encoded-url-prefix>/<payload>%23frag
<base>/<url-prefix>/<payload>//<email>?utm=x
```

Examples:

```text
https://your-domain.com/https://cdn.example.com/PrDHT...?utm=x
https://your-domain.com/https://cdn.example.com/PrDHT...#frag
https://your-domain.com/https://cdn.example.com/PrDHT.../
https://your-domain.com/https%3A%2F%2Fcdn.example.com/PrDHT...%23frag
https://your-domain.com/https://cdn.example.com/PrDHT...//alice@example.com?utm=x
```

## 13. Raw destination URL as the payload

```text
<base>/https://destination.example/path
<base>/https%3A%2F%2Fdestination.example%2Fpath
<base>/https://destination.example/path?query=1#fragment
```

Examples:

```text
https://your-domain.com/https://landingpage.com/pricing?utm=1#hero
https://your-domain.com/https%3A%2F%2Flandingpage.com
```

## 14. Raw destination URL + email suffix

```text
<base>/https://destination.example//<email>
<base>/https://destination.example/<delimiter><email>
<base>/https%3A%2F%2Fdestination.example//<email>
```

Examples:

```text
https://your-domain.com/https://rawurl.com//alice@example.com
https://your-domain.com/https://rawurl.com__alice@example.com
https://your-domain.com/https%3A%2F%2Frawurl.com//YWxpY2VAZXhhbXBsZS5jb20
```

## 15. Raw destination URL + ignored suffix, no email

```text
<base>/https://destination.example/<ignore>
```

Examples:

```text
https://your-domain.com/https://rawurl.com/https:test.com
https://your-domain.com/https%3A%2F%2Frawurl.com%2Fhttps%3Atest.com
```

## 16. Raw destination URL + email + ignored suffix

```text
<base>/https://destination.example//<email>/<ignore>
<base>/https://destination.example<delimiter><email>/<ignore>
```

Examples:

```text
https://your-domain.com/https://rawurl.com//alice@example.com/campaign
https://your-domain.com/https://rawurl.com__alice@example.com/campaign
https://your-domain.com/https%3A%2F%2Frawurl.com__alice@example.com/campaign
```

## 17. Platform-collapsed URL-prefix forms

Some platforms or proxies collapse `https://example.com` into forms like `https:/example.com` or `url=https:/example.com`.

```text
<base>/<payload>/url=https:/example.com/<email>
<base>/<payload>/<email>/url=https:/example.com
<base>/https:/example.com/<payload>/<email>
<base>/https:/example.com/<email>/<payload>
```

Examples:

```text
https://your-domain.com/PrDHT.../url=https:/test.com/alice@example.com
https://your-domain.com/PrDHT.../alice@example.com/url=https:/test.com
https://your-domain.com/https:/example.com/PrDHT.../alice@example.com
https://your-domain.com/https:/example.com/alice@example.com/PrDHT...
```

## 18. Optional URL prefix

Any supported pattern above can also be prefixed with `<OPTIONAL_URL_PREFIX>` when that environment variable is configured.

```text
<base>/<OPTIONAL_URL_PREFIX>/<any-supported-pattern>
```

Examples:

```text
https://your-domain.com/qs/_z/<payload>
https://your-domain.com/qs/_z/<payload>//<email>
https://your-domain.com/qs/_z/<email>/<payload>
https://your-domain.com/qs/_z/<ignore>/<payload>
https://your-domain.com/qs/_z/https://example.com/<payload>
https://your-domain.com/qs/_z/https://example.com/<payload>//<email>
```

## Compact checklist

```text
/<payload>
/<payload>/<email>
/<payload><delimiter><email>
/<payload>/<ignore>
/<payload>/<ignore>/<email>
/<payload>/<ignore><delimiter><email>
/<payload>/<email>/<ignore>
/<payload><delimiter><email>/<ignore>

/<email>/<payload>

/<ignore>/<payload>
/<ignore>/<payload>/<email>
/<ignore>/<payload><delimiter><email>
/<ignore><delimiter><email>/<payload>

/<url-prefix>/<payload>
/<url-prefix>/<payload>/<email>
/<url-prefix>/<payload><delimiter><email>
/<url-prefix><delimiter><email>/<payload>

/<raw-url>
/<encoded-raw-url>
/<raw-url>//<email>
/<encoded-raw-url>//<email>
/<raw-url>/<ignore>
/<raw-url>//<email>/<ignore>

/<OPTIONAL_URL_PREFIX>/<any pattern above>
```
