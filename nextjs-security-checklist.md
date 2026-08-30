# Next.js App Router Security Checklist

Use this when auditing the framework-specific surface of an App Router
project. Verify current behavior per `source-priority.md` before relying on
version-specific defaults (e.g. Server Action security hardening, caching
defaults) — these have changed across Next.js releases.

## Server Components vs Client Components

- Confirm server-only secrets/data never end up in a Client Component's
  props, closures, or serialized state.
- Check for accidental leakage of server-only modules into the client
  bundle (e.g. a module that should be marked `server-only` isn't).
- Confirm Client Components don't re-implement authorization checks that
  should live on the server (UI-only role checks are not a control).

## Server Actions — treat as public endpoints

- Every Server Action must independently authenticate and authorize the
  caller; do not assume "only my form calls this."
- Every Server Action must validate its inputs server-side, even if the
  calling form already validates client-side.
- Check for over-posting / mass assignment: does the action accept an
  entire object and persist it, or does it only accept and apply the
  specific fields it should?
- Check ownership: if the action mutates a resource by ID, does it verify
  the authenticated user actually owns/can access that resource?
- Check for sensitive operations gated only by obscurity (unlisted action
  name) rather than real authorization.

## Route Handlers (`app/**/route.ts`)

- Confirm the HTTP method(s) actually implemented match what's intended
  (no unintended `GET` handler exposing a mutation, etc.).
- Confirm authentication/authorization checks run before any data access.
- Confirm request body size limits are reasonable for the endpoint's
  purpose.
- Confirm responses don't leak internal error detail (stack traces, DB
  errors, file paths) in production.

## Middleware / proxy

- Confirm middleware-based auth checks can't be bypassed by directly
  hitting a Route Handler or Server Action that middleware doesn't cover.
- Confirm middleware isn't the *only* authorization layer for sensitive
  routes — defense in depth means the handler itself should also check.
- Review origin/host validation logic if middleware makes trust decisions
  based on headers (e.g. `Host`, `X-Forwarded-*`) — these are attacker
  influenceable unless the deployment terminates and rewrites them
  trustworthily.

## Cookies and sessions

- Confirm session cookies are `HttpOnly`, `Secure` (in production), and use
  an appropriate `SameSite` value for the app's cross-origin needs.
- Confirm session tokens are opaque or properly verified (signed/encrypted)
  — not client-decodable sensitive data trusted at face value.
- Confirm session invalidation actually works (logout, password change,
  role change all invalidate prior sessions where required).

## searchParams, dynamic routes, and route params

- Treat `searchParams` and dynamic route segments as fully untrusted input,
  equivalent to query strings — validate before using in queries, file
  paths, redirects, or rendering.

## Caching and revalidation

- Confirm responses containing user-specific or sensitive data aren't
  cached in a way that could serve one user's data to another (check
  `fetch` cache options, Route Handler caching, and any shared cache
  layer).
- Confirm revalidation (`revalidatePath`/`revalidateTag` or equivalent) is
  only triggerable by authorized callers, since it can be a vector for
  cache poisoning or resource exhaustion if exposed.

## Redirects

- Confirm redirect targets derived from user input (`searchParams`,
  request body) are validated against an allowlist or restricted to
  relative/same-origin paths, to prevent open redirect.

## Environment variables

- Anything exposed via `NEXT_PUBLIC_*` is shipped to the client bundle —
  confirm no secret, internal URL, or sensitive config uses this prefix.
- Confirm server-only env vars are only referenced from server-only code
  paths (Server Components, Route Handlers, Server Actions, server-only
  modules), not from files that could be included in a Client Component
  bundle.

## External fetches / SSRF

- Any server-side `fetch`/HTTP call built from user-controlled input
  (a URL, hostname, or path fragment) needs validation: protocol
  allowlist, hostname allowlist/denylist for internal ranges and cloud
  metadata endpoints, and redirect handling.
- Don't trust a URL just because it starts with `http://`/`https://`.

## File uploads (see also injection-checklist.md for path traversal)

- Server-side validation of size, MIME type, and content — not just the
  client-provided filename/extension.
- Generated storage filenames/paths must not incorporate raw user input.
- SVG and other "image" formats capable of embedding scripts/markup need
  explicit handling (strip/sanitize or refuse), not implicit trust.

## Third-party scripts and CSP

- Inventory third-party scripts (`next/script`, inline scripts, analytics,
  widgets) and confirm CSP accounts for each origin/nonce requirement.
  See `security-headers.md` for CSP construction.

## Edge vs Node runtime

- Confirm security-relevant code (crypto, validation libraries) behaves as
  expected on the runtime it's actually deployed to — some Node APIs and
  npm packages aren't available or behave differently on the Edge runtime.
