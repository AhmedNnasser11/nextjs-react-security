# Security Headers

Do not copy a generic header list into a project. Derive each header's value
from what the application actually does — an over-tightened CSP that breaks
the app gets disabled wholesale by frustrated developers, which is worse
than a well-scoped one.

## Headers to review

- **Content-Security-Policy** — see CSP section below.
- **X-Content-Type-Options: nosniff** — generally safe to set unconditionally.
- **Referrer-Policy** — pick a value (e.g. `strict-origin-when-cross-origin`)
  consistent with whether the app needs referrer data cross-origin.
- **Permissions-Policy** — restrict browser features (camera, microphone,
  geolocation, etc.) the app doesn't use.
- **Strict-Transport-Security** — appropriate once the app is served
  exclusively over HTTPS in production; confirm this is actually true
  before enabling, including for all subdomains if `includeSubDomains` is
  used.
- **frame-ancestors** (via CSP) — restrict who can iframe the app, as a
  clickjacking defense; prefer this over the legacy `X-Frame-Options` header
  where CSP is already in use, but check current guidance.
- **Cache-Control** on sensitive responses — confirm authenticated/
  personalized responses aren't cacheable by shared/public caches
  (`private, no-store` or equivalent where appropriate), especially for
  Route Handlers returning user-specific data.

## Constructing CSP

Build the policy from an actual inventory of what the app loads, not a
template:

1. List every script source: first-party bundles, `next/script` third-party
   scripts, inline scripts (and whether they're truly needed).
2. Decide on `nonce`-based or `strict-dynamic` inline script handling if
   inline scripts are required, rather than `unsafe-inline`.
3. List analytics/telemetry origins that need `connect-src`/`script-src`
   entries.
4. List image, font, and iframe origins actually used.
5. List API origins the client calls directly (`connect-src`).
6. Confirm behavior differs appropriately between development (which often
   needs more relaxed rules for HMR/dev tooling) and production — don't ship
   a dev-relaxed policy to production.
7. Start in report-only mode if the app has meaningful existing traffic and
   the policy's real-world impact is uncertain, then tighten to enforcing.

Avoid `unsafe-inline` and `unsafe-eval` unless a specific, identified
dependency requires them and no alternative exists — if so, document why.

## CORS

- Confirm `Access-Control-Allow-Origin` isn't set to `*` on endpoints that
  also accept credentials/cookies (the two are mutually exclusive per the
  spec, but misconfigurations combining a reflected-origin allowlist with
  overly broad matching are common — check the actual matching logic).
- Confirm the allowed-origins list is an explicit allowlist, not a
  regex/substring match that could be bypassed (e.g. matching
  `example.com` as a substring would also match `evil-example.com.attacker.net`
  depending on how it's implemented).
