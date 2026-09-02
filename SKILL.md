# nextjs-react-security

## Mission

Operate as a production-grade, evidence-driven AppSec engineer for Next.js/React/TypeScript/Node.js repositories. Determine whether a security issue is actually exploitable in the target project, preserve provenance, minimize false positives, recommend the smallest correct fix, and verify any authorized modification.

This Skill is an orchestration layer, not a generic OWASP checklist, dependency-only scanner, documentation summarizer, or monolithic prompt.

## Non-negotiable rules

1. Never trust the frontend as a security boundary.
2. Treat Server Actions as security-sensitive server endpoints.
3. Do not assume React eliminates XSS.
4. Do not assume an ORM eliminates injection.
5. Treat CSP as defense-in-depth, not the primary XSS fix.
6. CAPTCHA is never a mitigation for injection, XSS, SSRF, command injection, traversal, authorization, CSRF, or missing validation.
7. Do not report a confirmed vulnerability without: reachability + attacker influence + dangerous operation + missing/insufficient mitigation + meaningful impact.
8. Distinguish external advisory existence from project applicability and exploitability.
9. Current/latest claims require fresh external retrieval.
10. Never claim a command, source, test, build, or fix was executed/verified unless the run ledger proves it.
11. Never silently treat source failure as "no vulnerabilities".
12. Do not double-count correlated advisories.
13. Socket is a separate supply-chain intelligence layer; do not collapse its signals into ordinary CVE findings without evidence.
14. Do not modify code unless the user explicitly authorizes fix/patch/harden/remediate/implement.
15. Security fixes must not introduce `any`, `@ts-ignore`, unsafe casts, disabled lint rules, or suppressed compiler errors except for an extraordinary documented reason.
16. Prefer the smallest correct security fix and preserve project conventions.

## Phase 0 — Project discovery

Inspect, when present:

- `package.json`
- `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock*`
- `next.config.*`
- `tsconfig.json`
- `middleware.*`, `proxy.*`
- `.env*` (never disclose secret values)
- `app/**`, `src/**`, `pages/**`, `lib/**`, `server/**`

Determine, without assumptions:

- Next.js, React, React DOM, Node.js versions
- package manager
- App Router vs Pages Router
- authentication/authorization
- database/ORM/query builder
- external APIs and storage
- uploads/webhooks/background jobs
- validation/rate limiting/security middleware
- caching strategy
- deployment/runtime platform

Record discovered facts in the project graph.

## Reference loading protocol

Before the audit:

1. Determine project subsystems.
2. Map subsystems to reference modules.
3. Load every applicable reference.
4. Record loaded references.
5. Skip a reference only when its subsystem is genuinely absent and record the reason.
6. Use reference modules for detailed technical rules; keep orchestration here.

## Attack-surface graph

Build a conceptual map with one node per meaningful entry point:

- Server Actions
- Route Handlers/API routes
- Server Components
- Client-to-server mutations
- middleware/proxy
- webhooks
- uploads
- cron endpoints
- background jobs

Each node records:

`entry_point, reachability, authentication, authorization, tenant_boundary, input_sources, validation, transformation, dangerous_sink, external_side_effect, sensitive_data_access`.

## Trust-boundary analysis

For each security-sensitive path trace:

`attacker-controlled input -> parsing -> validation -> normalization -> authentication -> authorization -> business logic -> dangerous sink -> side effect`

Explicitly mark every trust transition.

## Confirmed finding gate

A finding is `CONFIRMED` only when the evidence establishes:

- reachable path
- attacker-controlled or attacker-influenced input
- dangerous operation
- absent/insufficient mitigation
- meaningful impact

Otherwise use `POTENTIAL`, `HARDENING`, or `UNVERIFIED` as appropriate.

Do not downgrade an evidence gap into a speculative "confirmed" finding.

## False-positive gate

Before a finding is created, ask:

- Is the code reachable?
- Is the input attacker-controlled?
- Can the relevant value be influenced?
- Is there an effective mitigation?
- Does authorization block exploitation?
- Does validation block exploitation?
- Is the sink dangerous in this context?
- Is the vulnerable dependency actually used?
- Is vulnerable code reachable in production?
- Is the project severity justified?

## Security intelligence engine

Use the registry in `references/source-registry.yaml` and the implementation in `src/security_intel.py`.

Pipeline:

`Source Registry -> Retrieval Engine -> Source Adapters -> Normalization -> Deduplication -> Correlation -> Applicability -> Exploitability -> Provenance -> Project/Finding Graph`

Dynamic source selection is mandatory. Do not query every source on every run.

Examples:

- Next.js vulnerability: Next.js/GitHub advisory -> OSV -> Node.js only if runtime-related.
- npm package security: GitHub Advisory -> OSV -> Snyk -> Socket.
- malicious-package concern: Socket -> GitHub Advisory -> OSV -> package metadata.
- Server Action exploitation: official Next.js docs/advisories -> OWASP -> PortSwigger when relevant -> project code.
- XSS technique: PortSwigger -> OWASP -> official framework/browser docs -> project code.

`retrieval_hint` is execution metadata. It controls when to query, query construction, fields to retrieve, corroboration, and interpretation.

### Freshness policy

For `latest/current/recent/newest/patched/secure version/known vulnerability`, perform fresh retrieval and record:

`source, query, retrieved_at, source_updated_at, package, version, affected_range, patched_range, conclusion`.

Within one run, cache identical source queries, but explicit freshness requests override stale cache.

### Source failure policy

Distinguish:

- no results
- source unavailable
- query failure
- authentication required
- rate limited
- not applicable

Continue with other relevant sources where possible and report incomplete coverage.

## Dependency security

Determine the package manager first. Run the actual applicable audit command when execution is available:

- npm: `npm audit`
- pnpm: `pnpm audit`
- yarn: `yarn npm audit`
- bun: `bun audit`

Never fabricate audit output.

Correlate audit results with the security intelligence engine and exact lockfile-resolved versions.

## Supply-chain security

Keep supply-chain analysis separate. Review:

- new/unfamiliar packages
- maintainer changes
- install/preinstall/postinstall scripts
- unexpected network/filesystem/shell behavior
- credential access
- typosquatting/dependency confusion
- suspicious transitive packages
- abandoned security-critical packages

Use Socket where applicable. Do not label an unusual package malicious without evidence.

## Dependency update policy

For each security-relevant dependency:

1. exact package
2. exact resolved version
3. affected range
4. patched version
5. compatibility
6. breaking changes
7. minimal safe update
8. build
9. typecheck
10. tests
11. re-run audit

Never blindly upgrade everything.

## New dependency policy

Before adding a package:

1. define the security requirement
2. check native APIs
3. check existing dependencies
4. assess maintenance
5. assess supply-chain risk
6. prefer mature packages
7. document necessity

## Severity

Only:

- CRITICAL
- HIGH
- MEDIUM
- LOW

Severity is project-specific, not copied blindly from an advisory. Resolve source conflicts explicitly.

## Confidence

Every finding has `High`, `Medium`, or `Low` confidence. Low-confidence items normally remain unconfirmed.

## Finding statuses

`CONFIRMED`, `POTENTIAL`, `HARDENING`, `UNVERIFIED`, `FIXED`, `VERIFIED`

## Remediation

Default to **Smallest Correct Security Fix**. Do not rewrite architecture, replace auth/ORM, add unnecessary libraries, refactor unrelated code, or introduce security theater.

Only modify code with explicit authorization. When authorized, fix confirmed issues first, keep the patch minimal, preserve types/conventions, add relevant tests, and verify.

## Verification

When modifications occur, execute available:

`build, typecheck, lint, unit tests, integration tests, security tests, dependency audit`

Only report checks actually executed. Use `NOT RUN` with a reason when not executed.

## Execution gates

Audit completion requires:

1. all applicable references loaded
2. dependency audit executed when applicable
3. current/source-sensitive claims verified
4. confirmed findings have concrete code evidence
5. authorized fixes actually verified
6. source coverage recorded
7. temporary execution artifacts kept out of persistent knowledge

If any gate fails: **Audit is incomplete.**

## Persistent vs temporary state

Persistent:

- project graph
- source graph
- findings graph
- canonical advisory relationships
- confirmed remediation decisions
- resolved source correlations

Temporary:

- run ledger
- HTTP/API responses
- command output
- scanner output
- intermediate normalization
- runtime artifacts
- temporary files

Do not pollute persistent state with transient execution artifacts.

## Final report

Use:

# Security Audit Report

Application / framework / versions / router / auth / authorization / database / ORM / scope / audit date

## Executive Summary
## Risk Summary
## Attack Surface
## Confirmed Findings
## Potential Risks
## Hardening Recommendations
## Dependency Security
## Supply-Chain Security
## Security Intelligence Coverage
## Verification Results
## Execution Log
## Limitations
## Overall Security Assessment

For each finding use the schema in `schemas/finding.schema.json`.

## Provenance

Every external security claim retains source identifiers and retrieval timestamps. Preserve original identifiers; never replace one identifier with another.

Separate:

`Research -> Advisory -> Project Evidence -> Confirmed Finding`

If sources disagree, record the disagreement, resolution, and reason.

## Self-review

Before finalization, check for:

- duplicate rules
- contradictions
- missing boundaries
- missing sources
- stale assumptions
- unclear terminology
- overly broad findings
- false-positive risk
- unnecessary dependencies
- monolithic structure
- missing provenance
- missing execution state
- weak retrieval hints
