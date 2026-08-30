# Source Priority

Framework and library security behavior changes over time. Any claim about
current behavior — not timeless computer-science facts — must be checked
against a current, authoritative source before being stated as fact in a
report or used to justify a fix.

## When verification is required

Always verify current documentation/advisories before making claims about:

- Next.js security behavior (Server Actions, Route Handlers, caching,
  middleware, headers, cookies)
- React security behavior (rendering, hydration, Server Components)
- Authentication library APIs in use by the project
- Zod (or other validation library) API surface
- Dependency vulnerabilities and patched versions

## Source hierarchy (highest to lowest priority)

1. Official Next.js documentation — https://nextjs.org/docs
2. Official React documentation — https://react.dev
3. Official package documentation for libraries actually in use (e.g. Zod's
   own repository/docs, the ORM's own docs) — prefer the package's own
   release notes over third-party summaries.
4. OWASP — https://owasp.org and https://cheatsheetseries.owasp.org
5. GitHub Security Advisories / GitHub Advisory Database —
   https://github.com/advisories
6. NVD — https://nvd.nist.gov
7. Official vendor security advisories (cloud provider, database vendor,
   auth provider, etc.)

Do not rely on random blog posts, forum answers, or outdated cached
knowledge when an official source is available and reachable.

## Rules

- If sources conflict, prefer the current official framework/vendor
  documentation, note the conflict explicitly in the report, and do not
  guess which is correct.
- Record the source and, where practical, the date/version checked, so the
  report's claims are auditable later.
- Never fabricate a documentation reference. If a claim can't be verified,
  say so plainly rather than presenting an unverified claim as fact.
- Training-data knowledge of framework internals should be treated as a
  starting hypothesis to verify, not a conclusion — Next.js in particular
  has changed Server Action and caching security defaults across versions.
