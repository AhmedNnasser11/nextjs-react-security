# Next.js Security

Treat framework behavior as version-sensitive. Fetch current Next.js documentation and
official advisories before making version-specific claims.

Check:

- Server Actions: direct invocation, server-side validation, authorization, origin checks,
  replay/rate limits, and side effects.
- Route Handlers and Proxy: method checks, authentication, redirects, cache behavior, and
  responses that expose internal errors or secrets.
- App Router/RSC: server/client boundaries, serialization, hydration mismatches, and
  untrusted values crossing into client components.
- Caching/revalidation: user-specific data must not enter shared caches; tags and paths
  must not be attacker-controlled without an allowlist.
- Redirects/rewrites: validate destinations and reject attacker-controlled absolute URLs.
- Image optimization: restrict `remotePatterns`; do not allow arbitrary hosts, schemes,
  private addresses, or attacker-controlled optimizer URLs.
- Headers: verify CSP, frame, MIME, referrer, and permissions policies in the deployed
  response rather than relying only on configuration.
