# `old.js` to modular server parity audit

## Scope and result

This audit treats `old.js` as the legacy reference and the combination of
`server.js` plus every JavaScript file under `modules/` as the active server.
The review found **no missing named function/helper and no missing literal HTTP
route registration** in the active implementation.

The source inventory found 502 named callable declarations in `old.js`. All 502
names occur in the active implementation. The active implementation contains 41
additional named callables, primarily module factories and scanner safety/store
helpers. The literal route inventory contains 50 distinct method/path pairs in
both implementations, with no additions or omissions.

## Checks performed

1. Inventoried traditional function declarations and named arrow-function
   assignments in the legacy and active sources.
2. Inventoried literal `app.get`, `app.post`, `app.head`, `app.use`, and related
   method/path registrations. Dynamic optional-prefix registrations were also
   inspected at their call sites.
3. Compared normalized bodies for the traditional named functions. Of 467
   legacy declarations, 450 remain textually equivalent after whitespace is
   removed. The remaining 17 are present but intentionally evolved in the
   modular server (dependency injection, stricter parsing/validation, async error
   forwarding, scanner safety, runtime memory handling, or XML escaping).
4. Reviewed the only four legacy local bindings not reproduced by name:
   `looksEncoded`, `longPath`, `hasCookies`, and `looksPrefetch`. These were
   implementation details of the early deep-link probe heuristic, not helpers.
   Their combined `looksDeep` heuristic is deliberately replaced by
   `validateBase64Url(clean)` in the modular redirect core, so the behavior is
   retained with stricter payload recognition rather than copied verbatim.
5. Ran the complete automated suite, including HTTP-level scanner safety tests,
   redirect payload behavior, security policy, runtime health/services, logging,
   geo provenance, and module import/export contracts.

## Permanent regression guard

`tests/legacy-parity.test.js` now fails if a future refactor removes a named
legacy callable or literal route from the active server. The tests include
minimum inventory-size assertions so accidental truncation or replacement of
the reference file cannot silently turn the comparison into a false pass.

This is a structural migration guard, not a claim that every future internal
implementation must remain byte-for-byte identical. Behavioral differences are
covered by the focused runtime tests, while intentional post-legacy hardening is
allowed to remain in place.
