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
3. MDN Web Docs — https://developer.mozilla.org — for Web Platform behavior
   itself (cookie attributes, CSP directives, `fetch`/`URL`/`Request`
   semantics, `Content-Type`/CORS headers, Trusted Types, sanitization-
   relevant DOM APIs). Use MDN when the question is about the platform
   rather than the framework.
4. Official package documentation for libraries actually in use (e.g. Zod's
   own repository/docs, the ORM's own docs) — prefer the package's own
   release notes over third-party summaries.
5. OWASP — https://owasp.org and https://cheatsheetseries.owasp.org
   (attack patterns, defensive guidance, e.g. OWASP Top 10, ASVS, Cheat
   Sheet Series for injection/XSS/auth/CSRF/SSRF-specific guidance)
6. GitHub Security Advisories / GitHub Advisory Database —
   https://github.com/advisories (best first stop for npm-ecosystem CVEs,
   usually includes affected/patched version ranges directly)
7. CVE.org / MITRE CVE — https://www.cve.org — canonical CVE records when
   an advisory needs cross-referencing to its authoritative CVE entry
8. NVD — https://nvd.nist.gov (CVSS scoring and enrichment data for a CVE
   already identified via GitHub Advisories or CVE.org)
9. CISA Known Exploited Vulnerabilities (KEV) Catalog —
   https://www.cisa.gov/known-exploited-vulnerabilities-catalog — check
   when a dependency vulnerability is found, to see if it's under active
   real-world exploitation (raises urgency even if CVSS score alone looks
   moderate)
10. npm security advisories — https://www.npmjs.com/advisories — useful for
    package-manager-native advisory lookups alongside `npm audit` output
11. Node.js security release notes — https://nodejs.org/en/blog/vulnerability
    — when the finding involves the Node.js runtime itself rather than an
    npm package
12. Official vendor security advisories (cloud provider, database vendor,
    auth provider, etc.) for anything specific to a managed service the
    project depends on

Do not rely on random blog posts, forum answers, vulnerability-database
aggregators of unclear provenance, or outdated cached knowledge when an
official source is available and reachable. Third-party vulnerability
scanners/dashboards (e.g. Snyk's own advisory pages) can be used as a
secondary cross-check but should not replace the official sources above
when they conflict.

## Programmatic sources — browse URL + API/feed URL

The entries above are for reading documentation. When the skill needs to
pull structured vulnerability data programmatically (e.g. via `web_fetch`
or an HTTP call from implementation code), use these. Each has a browse URL
for a human-readable check and an API/feed URL for automated retrieval.

### Official advisories

- **GitHub Advisory Database (npm ecosystem)**
  Browse: https://github.com/advisories?query=ecosystem%3Anpm
  API: REST — https://docs.github.com/en/rest/security-advisories/global-advisories
  (filter by `ecosystem=npm`; also usable per-package)
- **Next.js Security Bulletins**
  Browse: https://github.com/vercel/next.js/security/advisories
  API: same GitHub Advisories REST API above, scoped to the `vercel/next.js`
  repository
- **Node.js Security Advisories**
  Browse: https://github.com/nodejs/security-advisories

### Vulnerability databases (API-first)

- **OSV.dev (Open Source Vulnerabilities)** — preferred first stop for
  automated dependency checks: free, no auth required, structured JSON,
  covers the npm ecosystem well.
  Browse: https://osv.dev/
  API: `POST https://api.osv.dev/v1/query` — query by package name +
  ecosystem (`npm`) and version to get affected/fixed ranges directly.
  API guide: https://google.github.io/osv.dev/post-v1-query/
  Prefer this over manually parsing GitHub Advisory HTML when a
  programmatic yes/no + version-range answer is needed for a specific
  package.
- **Snyk Vulnerability Database**
  Browse (npm): https://security.snyk.io/vuln/npm
  API docs: https://snyk.docs.apiary.io/
  Treat as a secondary cross-check per the rule above, not a replacement
  for GitHub Advisories/OSV/NVD when they conflict.

### Supply-chain / malicious-package checks

Relevant to `references/dependency-security.md`'s "suspicious or
unnecessary packages" check — these look for typosquatting, protestware,
credential-stealing installers, and other supply-chain risk, not just known
CVEs.

- **Socket.dev**
  Security blog/research: https://socket.dev/blog/category/security
  Per-package check (example): https://socket.dev/npm/package/next
  API docs: https://docs.socket.dev/reference/getting-started-with-socket-api
  Use when a new dependency is being considered, or an existing one looks
  suspicious (unclear maintainer, sudden ownership transfer, obfuscated
  install scripts) — this is a different concern from CVE lookups above.

### Attack-technique research and news (context, not primary authority)

Use these for understanding current real-world attack techniques and
emerging patterns, not as the authoritative source for framework behavior
or a specific CVE's details — for those, use the tiers above instead.

- **PortSwigger Web Security Research**
  Browse: https://portswigger.net/research
  RSS feed: https://portswigger.net/research/rss
- **The Daily Swig (Cybersecurity News, Web Security)**
  Browse: https://portswigger.net/daily-swig/web-security
- **OWASP Web Security Testing Guide (WSTG)**
  Browse: https://owasp.org/www-project-web-security-testing-guide/
  Use for structured testing methodology when planning how to probe a
  suspected vulnerability class (complements the Cheat Sheet Series, which
  is more remediation-focused).



This is an instruction to use tools, not just a reading list. When a claim
in Phase 4 needs verification:

1. Use the web search tool to find the current page (e.g. search
   `nextjs.org/docs server actions security`, `mdn Content-Security-Policy
   script-src`, `github advisories <package name>`). For a specific
   package + version's known vulnerabilities, prefer querying the OSV.dev
   API directly (`POST https://api.osv.dev/v1/query`) over search when
   structured version-range data is what's actually needed.
2. Use the web fetch tool to actually retrieve the page content — don't
   answer from the search snippet alone if the detail matters (exact
   header syntax, exact default value, exact patched version number).
3. Record what was actually retrieved (source URL, and version/date if
   shown on the page) next to the claim in the report's `Source:` field.
4. If the tools are unavailable in the current environment, or a fetch
   fails, say so explicitly in the report rather than silently falling back
   to unverified prior knowledge and presenting it as current.
5. Re-check rather than reuse a stale answer from earlier in a long session
   if enough time/context has passed that the same fact is being restated
   for a new finding — framework defaults and advisory status can be
   version-specific, so don't assume one lookup covers every finding that
   touches the same area.

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
