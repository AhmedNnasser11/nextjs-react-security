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
under `references/`. Every reference file applicable to the project's actual
stack must be opened and read during the audit (Phase 0) — this is not
optional context you may substitute with recalled knowledge of what such a
checklist would contain. "Applicable" is scoped to keep effort proportional
(e.g. skip the auth checklist for a project with no auth system), but a
reference is never skipped merely because the topic feels familiar.

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

### Phase 0 — Load context, then load the relevant references
Before touching code, skim the project to determine framework version,
router type (App vs Pages), auth strategy, and database/ORM in use. Then
**actually open (read) every `references/*.md` file that applies** to what
you just found — reading the file means invoking your file-read tool on it,
not recalling its contents from earlier in this document or from training
knowledge of what such a checklist would probably contain. A reference is
"not applicable" only when the corresponding subsystem is genuinely absent
from the project (e.g. skip the SQL portion of `injection-checklist.md`
only if there is no database layer at all) — "I already know this from
training" is never a valid reason to skip opening the file. Note in your
own working notes which files you opened; Phase 8's execution log requires
this list.

### Phase 1 — Inspect before changing
Walk the codebase in this order, noting what exists and what's missing:

1. Project structure and framework/version (`package.json`, `next.config.*`)
2. Authentication setup (provider, session/cookie strategy)
3. Database access layer (ORM, query builder, raw SQL usage)
4. API routes / Route Handlers (`app/**/route.ts`)
5. Server Actions (`"use server"` functions, form actions)
6. Middleware / proxy (`middleware.ts`, edge config)
7. Forms and mutation paths (client → server data flow), including search/
   filter inputs specifically — check whether the handler behind them
   validates server-side or merely relies on client-side filtering/UX
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
Work through each reference file you opened in Phase 0 against the actual
code, not from memory of "what these checklists usually say." Use the
severity model below — do not invent your own severities.

**Dependency security is not optional and is not gated on whether the rest
of the app has other findings.** Every audit run — even one scoped to a
single feature or file — includes actually running the project's package
manager audit command (`npm audit` / `pnpm audit` / `yarn npm audit`, per
`references/dependency-security.md`) and reviewing its real output. If the
command can't be run in the current environment, state that explicitly in
the report instead of silently omitting the dependency-security check.

### Phase 4 — Verify against current sources
For any claim about framework/library/web-platform security behavior that
could have changed since training — this includes version-specific
behavior like current Server Action CSRF protections, current caching
defaults, or a specific CVE's patched version — **actually invoke the web
search and web fetch tools** per `references/source-priority.md` before
stating the claim as fact. This step is mandatory whenever such a claim
appears in the report, not just when convenient. Do not substitute
memorized/training-time knowledge for this step and then phrase the report
as if it were verified. If a source can't be reached, say so explicitly in
the finding rather than presenting an unverified claim as current.

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

### Phase 8 — Execution gate (mandatory, before writing the report)
Before producing the final report, verify against your own actions in this
session — not your intent — that:

1. Every applicable `references/*.md` file was actually opened with a file-
   read tool call in Phase 0/3 (list which ones; state explicitly if one
   was skipped and why it was judged not applicable).
2. The dependency audit command was actually run in Phase 3, with real
   output reviewed (or its absence explicitly noted, per Phase 3's rule).
3. Every version- or advisory-specific claim in the draft report has a
   corresponding web search/fetch tool call behind it from Phase 4 (or is
   explicitly flagged as unverified in the report if it doesn't).

If any of these didn't actually happen, either go back and do them now, or
report the gap explicitly in the Execution Log below — do not write a
report that implies verification occurred when it didn't.

### Phase 9 — Report
Produce the audit report in the format defined below, including the
Execution Log. Every finding must be traceable to a real file/location; do
not report vulnerabilities you have not actually located in the code.

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

Open every file below that applies to the project's actual stack — see
Phase 0. Skipping one because the subsystem is genuinely absent is fine;
skipping one because you already "know" the checklist is not.

- `references/source-priority.md` — authoritative source hierarchy
  (Next.js, React, MDN, package docs, OWASP, GitHub Advisories, NVD, vendor
  advisories) and the concrete steps for actually searching/fetching them
  before making a version- or advisory-specific claim.
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

## Execution Log
- Reference files opened: (list each, or "N/A — subsystem absent" per skip)
- Dependency audit: (command run + summary of real output, or why it
  couldn't be run)
- Source verification: (list version-/advisory-specific claims below that
  were checked via search/fetch, with the source used — or "unverified,
  based on training knowledge" for any that weren't, called out plainly)

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

The Execution Log is not decorative — it's the evidence that Phase 0's
reference loading, Phase 3's dependency audit, and Phase 4's source
verification actually happened rather than being assumed. A report with an
empty or vague Execution Log is incomplete.

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
