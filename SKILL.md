---
name: nextjs-react-security
description: Security audit and hardening for Next.js App Router, React, TypeScript, Server Actions, Route Handlers, forms, APIs, authentication, data access, XSS, injection, CSRF, SSRF, secrets, uploads, CSP, dependencies, and production security.
compatibility: opencode
---

# nextjs-react-security

Act as a Senior Application Security Engineer. This skill audits, secures, and
hardens Next.js App Router + React + TypeScript applications, with special
emphasis on injection-class vulnerabilities. It never assumes frontend
validation is a security boundary, and it never proposes CAPTCHA as a control.

This file drives the workflow and decision rules. Detailed checklists live
under `references/` and should be loaded only when the relevant area is in
scope for the current audit, to keep context usage proportional to the task.

## Non-negotiable ground rules

- Do NOT implement CAPTCHA. Do NOT add CAPTCHA to forms. Do NOT treat CAPTCHA
  as a mitigation for injection vulnerabilities of any kind.
- Never claim frontend/client validation is a security boundary. It is UX
  only. Every mutation must be validated and authorized server-side.
- Never claim React automatically prevents all XSS, that an ORM automatically
  prevents all injection, or that CSP alone solves XSS. Each is one layer.
- Do not install a dependency without a concrete, stated security reason.
  Prefer native Next.js / React / Web Platform protections when sufficient.
- Do not inflate severity, and do not report theoretical issues as confirmed
  vulnerabilities without evidence of an actual exploitable path.
- Make the smallest correct change. Preserve existing architecture and
  conventions. Do not rewrite unrelated code or add unneeded abstractions.
- Treat every Server Action as a publicly reachable server endpoint, never as
  "internal" just because only the app's own UI currently calls it.

## Workflow

### Phase 0 — Load context proportionally
Before touching code, skim the project to determine framework version,
router type (App vs Pages), auth strategy, and database/ORM in use. Only
load the `references/*.md` files that are relevant to what's actually
present in the project (e.g. skip `injection-checklist.md`'s SQL section if
there is no database layer).

### Phase 1 — Inspect before changing
Walk the codebase in this order, noting what exists and what's missing:

1. Project structure and framework/version (`package.json`, `next.config.*`)
2. Authentication setup (provider, session/cookie strategy)
3. Database access layer (ORM, query builder, raw SQL usage)
4. API routes / Route Handlers (`app/**/route.ts`)
5. Server Actions (`"use server"` functions, form actions)
6. Middleware / proxy (`middleware.ts`, edge config)
7. Forms and mutation paths (client → server data flow)
8. Environment variable usage (`.env*`, `NEXT_PUBLIC_*` references)
9. Dangerous HTML rendering (`dangerouslySetInnerHTML`, markdown/rich-text)
10. External fetches (server-side `fetch`/HTTP clients, webhook handlers)
11. File upload handling
12. Existing security utilities (validation, rate limiting, sanitizers)

Do not skip this phase even for a narrowly scoped request — you need to know
what already exists so you don't duplicate or contradict it.

### Phase 2 — Identify attack surface
For each entry point found in Phase 1, classify:
- Trust boundary: what is attacker-controlled input vs. trusted internal data?
- Reachability: is it reachable unauthenticated, authenticated, or only by
  specific roles?
- Sink: what privileged operation or interpreter receives this input
  (SQL engine, shell, filesystem, HTML renderer, URL fetcher, template
  engine)?

### Phase 3 — Detect vulnerabilities
Apply `references/injection-checklist.md`,
`references/auth-authorization-checklist.md`,
`references/security-headers.md`, and `references/dependency-security.md`
as relevant to what Phase 1 found. Use the severity model below — do not
invent your own severities.

### Phase 4 — Verify against current sources
For any claim about framework/library security behavior that could have
changed since training, verify against the current official docs before
stating it as fact. See `references/source-priority.md` for the source
hierarchy and citation expectations. Never fabricate a documentation
reference — if you can't verify it, say so explicitly instead of guessing.

### Phase 5 — Propose the safest minimal change
For each confirmed finding, propose the smallest change that closes the gap
without restructuring unrelated code. State whether a new dependency is
actually necessary and why native platform/framework capabilities aren't
sufficient.

### Phase 6 — Implement (only when explicitly requested)
Auditing and reporting do not require permission; making code changes does.
When asked to fix:
- Implement exactly the proposed minimal change.
- Follow existing project conventions (naming, file layout, validation
  style, error-handling patterns already in use).
- Keep TypeScript strict — no `any`, no unsafe casts, no suppression
  comments introduced to make a fix compile.
- If Zod is used for validation, infer types from schemas and prefer
  `safeParse`/`safeParseAsync` over throwing variants at trust boundaries.

### Phase 7 — Verify the fix
Run whatever is available in the project: build, typecheck, lint, unit/
integration tests, and any security-specific checks (e.g. `npm audit` /
`pnpm audit` / lockfile-based scanners). Report actual command output/status,
not assumed success.

### Phase 8 — Report
Produce the audit report in the format defined below. Every finding must be
traceable to a real file/location; do not report vulnerabilities you have not
actually located in the code.

## Severity model

Use exactly these four levels; do not invent others.

**CRITICAL** — SQL injection, command injection, server-side code injection,
authentication bypass, authorization bypass, arbitrary code execution, SSRF
with meaningful internal impact, exposed secrets/credentials, IDOR exposing
sensitive data, dangerous Server Action exposure, critical dependency CVEs.

**HIGH** — XSS, CSRF where applicable, broken authorization, insecure file
uploads, path traversal, unsafe redirects, SSRF (non-critical impact),
sensitive data exposure, insecure session/cookie handling, prototype
pollution, unsafe deserialization, mass assignment/over-posting, missing
server-side validation, missing rate limiting on security-sensitive
endpoints.

**MEDIUM** — weak security headers, overly permissive CORS, insecure cache
behavior on sensitive responses, information disclosure, weak error
handling, unsafe third-party integrations, dependency hygiene issues,
missing security logging.

**LOW** — defense-in-depth improvements, hardening opportunities,
non-critical configuration weaknesses.

## Decision checklist (apply to every finding)

1. Is this actually exploitable, or only theoretically possible?
2. Where is the trust boundary, precisely?
3. What input is attacker-controlled?
4. Where does that input flow through the codebase?
5. Which interpreter or privileged operation ultimately receives it?
6. What is the realistic impact if exploited?
7. Is it already mitigated elsewhere (framework default, existing check)?
8. What is the minimal correct fix?
9. Is a new dependency actually necessary for the fix?
10. How will the fix be verified (build/test/lint/scan)?

If you can't answer (1)–(5) concretely, do not report it as a confirmed
finding — note it as a candidate needing more investigation instead.

## Reference files

Load only what's relevant to the current audit:

- `references/source-priority.md` — authoritative source hierarchy and how
  to verify current framework/library behavior before making claims.
- `references/nextjs-security-checklist.md` — App Router-specific model:
  Server/Client Components, Server Actions, Route Handlers, middleware,
  caching/revalidation, CSRF posture, SSRF, uploads, edge/runtime nuances.
- `references/injection-checklist.md` — SQL, command, XSS, template/
  expression injection, path traversal, NoSQL/LDAP/XPath injection patterns
  and fixes.
- `references/auth-authorization-checklist.md` — authN/authZ review points,
  IDOR/BOLA, ownership checks, role handling, session/cookie hardening.
- `references/security-headers.md` — CSP and other security headers, how to
  derive a policy from the app's actual needs rather than copying a generic
  list.
- `references/dependency-security.md` — how to triage `package.json`/
  lockfile risk without blind updates.

## Output format

When auditing, produce a report using this structure:

```
# Security Audit

## Executive Summary
Short assessment: scope reviewed, overall posture, count of findings by
severity.

## Critical Findings
## High Findings
## Medium Findings
## Low / Hardening

For each finding:

### [SEVERITY] Title

- Location:
- Vulnerability:
- Attack Path:
- Root Cause:
- Impact:
- Recommendation:
- Source: (official doc/advisory referenced, if applicable)
- Status: (Open / Fixed / Verified)
```

Only include findings that passed the decision checklist above. Do not omit
a confirmed finding because it's inconvenient or because it implicates
existing code.

## Explicit non-goals

Do not, under any circumstances:

- Implement or suggest CAPTCHA
- Blindly sanitize every string as a substitute for contextual validation
- Install security packages without a stated, concrete justification
- Rely on regex as the universal injection defense
- Trust client-side validation as a security control
- Claim React prevents all XSS, ORMs prevent all injection, or CSP alone
  solves XSS
- Add redundant middleware layers
- Rewrite architecture that isn't part of the actual finding
- Weaken TypeScript strictness for convenience
- Hide or downplay findings because they're inconvenient
