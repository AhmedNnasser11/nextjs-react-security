# Design Review

## Reviewed against supplied specification

The implementation preserves the supplied architecture and adds concrete operational support for:

- modular reference loading
- source registry with operational `description` and `retrieval_hint`
- dynamic source selection
- GitHub global advisory retrieval
- OSV single and batch-ready retrieval model
- Next.js repository advisory retrieval
- normalized advisory records
- cross-source deduplication by GHSA/CVE/OSV/package-range identity
- provenance records
- source failure states
- persistent/temporary state separation
- JSON schemas for source, advisory, finding, project and run ledger
- deterministic tests for registry integrity and deduplication

## Important corrections/guardrails

1. Provider-specific API contracts are not invented for Snyk/Socket. Their registry entries exist, but the shipped stdlib engine marks them `adapter_not_configured` until a deployment supplies a verified adapter/credential contract.
2. The GitHub API uses the current versioned REST API and supports `affects=package@version`.
3. OSV exposes `/v1/query` and `/v1/querybatch`; batch responses return vulnerability identifiers/modified data and can be followed with full vulnerability retrieval.
4. Next.js advisories are retrieved from the project's GitHub security-advisory endpoint, but version applicability still requires correlation against advisory ranges.
5. A source record is never interpreted as a project finding by itself.
6. Vendor severity is not copied blindly into project severity.
7. "No results" and "source unavailable" remain distinct states.

## Current-source spot checks performed during build review

- GitHub global security advisory API documentation
- OSV API documentation, including querybatch
- Next.js security advisory pages
- Socket API documentation

The source registry intentionally remains configurable because external provider endpoints, authentication, rate limits, and response shapes can change.

## Quality gates

- No monolithic technical checklist was put into `SKILL.md`.
- Security rules are modularized.
- Source provenance is first-class.
- Supply-chain intelligence remains distinct.
- Temporary run artifacts are not persistent graph knowledge.
- The engine is conservative about unverified provider integrations.
- The package contains no fabricated audit output or project-specific vulnerability claims.

## Upgrade: dynamic Exa/Web query generation

Added `src/query_planner.py`: security-research tasks are generated from framework, dependency, runtime and observed attack-surface evidence instead of a fixed three-search list. It covers exact package/version advisories, Next.js/RSC/Server Actions/middleware/SSRF/cache, React RSC, runtime, supply-chain and conditional technique research.
