# nextjs-react-security

Production-oriented security audit and hardening Skill for Next.js, React, TypeScript, Node.js, App Router, Server Actions, Route Handlers, API endpoints, SSR, and React Server Components.

## What is included

- `SKILL.md` — orchestration and decision logic
- `references/` — modular security knowledge
- `references/source-registry.yaml` — source registry and retrieval metadata
- `references/web-research-checklist.md` — search/open/corroboration policy
- `scripts/external_research.py` — external search provider gateway
- `scripts/open_url.py` — allowlisted HTTPS source-opening gateway
- `schemas/` — machine-readable models
- `src/security_intel.py` — stdlib-only retrieval/normalization/deduplication/provenance engine
- `examples/` — example project and finding records
- `tests/` — lightweight deterministic tests
- `state/persistent/` — intended persistent graph storage
- `state/runs/` — intended temporary run-ledger storage

## Design

The Skill separates project evidence from external intelligence.

```text
Project discovery
      |
      v
Attack-surface graph
      |
      +-------------------+
      |                   |
      v                   v
Project evidence      Source registry
                          |
                          v
                    Retrieval engine
                          |
                          v
                     Normalization
                          |
                          v
                    Deduplication
                          |
                          v
                      Correlation
                          |
                          v
                  Applicability analysis
                          |
                          v
                  Exploitability analysis
                          |
                          v
                      Provenance
                          |
                          v
                 Findings / Source Graph
```

Socket remains a supply-chain intelligence layer rather than a CVE replacement.

## Source notes

The implementation deliberately uses configurable adapters. GitHub's global advisory REST API is public for public resources and supports package/version filters; OSV provides single and batch package-version queries. Socket's current API supports package issues, scores, and full scans. Source URLs and API details are registry data and should be revalidated when a deployment depends on a provider's changing API.

## External web-search execution

The Skill now has an explicit `external_research.py` adapter contract and `open_url.py` gateway. The intended flow is:

`plan query → external search → capture results → open authoritative URL → hash/provenance → use as evidence`

The search provider is deliberately configurable. A deployment may bind `SEARCH_PROVIDER_COMMAND` to an approved provider adapter or provide a verified Exa endpoint via `EXA_SEARCH_URL` + `EXA_API_KEY`. The provider request schema must be verified against its current official documentation before production use; the package does not assume an unverified API contract.

`open_url.py` fails closed for non-HTTPS, non-allowlisted domains and restricted/private DNS targets, and re-validates redirects.

## Basic use

```bash
python -m src.security_intel --registry references/source-registry.yaml --package next --version 16.3.3 --ecosystem npm
```

Environment variables may provide optional credentials:

- `GITHUB_TOKEN`
- `SNYK_TOKEN`
- `SOCKET_API_KEY`

The engine never treats unavailable credentials or failed sources as "no vulnerabilities".

## Runtime assumptions

- Python 3.10+
- standard library only for the included engine
- network access is required for live source retrieval
- repository analysis and command execution are performed by the surrounding Skill/agent runtime

## Verification

```bash
python -m unittest discover -s tests -v
```
