# Open Redirects

Trace attacker-controlled destinations into `redirect()`, `NextResponse.redirect`, `router.push`,
`Location`, login callbacks, and middleware rewrites.

- Prefer relative internal paths or an explicit origin allowlist.
- Reject protocol-relative URLs, unexpected schemes, encoded separators, credentials, and
  alternate host representations.
- Normalize and validate once at the server boundary; do not trust a client-side allowlist.
- Confirm the redirect is reachable and can send a victim to an attacker-controlled destination
  before reporting `CONFIRMED`; otherwise classify it as `POTENTIAL` or `HARDENING`.
