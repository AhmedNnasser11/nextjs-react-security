# Dependency Security

## What to check

- Run the project's package manager audit command (`npm audit`,
  `pnpm audit`, `yarn npm audit`, etc.) where available, and review the
  actual output rather than assuming a result.
- Cross-reference flagged packages against GitHub Advisory Database first
  (fastest path to affected/patched version ranges for npm packages), or
  query the OSV.dev API directly (`POST https://api.osv.dev/v1/query`) for
  a structured, no-auth answer keyed on package name + ecosystem + version.
  Then CVE.org/NVD for the canonical record and CVSS scoring if more detail
  is needed. Check the CISA KEV catalog too — a vulnerability under active
  exploitation should be prioritized above its CVSS score alone would
  suggest. See `source-priority.md` for URLs and how to actually fetch
  them.
- Check unfamiliar or newly-added packages against Socket.dev
  (https://socket.dev/npm/package/<name> or its API) for supply-chain risk
  signals — typosquatting, obfuscated install scripts, sudden maintainer
  changes — which a CVE database won't catch since it isn't a "known
  vulnerability" in the traditional sense.
- Check for packages that are unmaintained/abandoned where a maintained
  alternative exists and the package is security-relevant (auth, crypto,
  input parsing, sanitization).
- Check for suspicious or unnecessary packages: dependencies with no clear
  usage in the codebase, or packages pulled in for a single trivial utility
  that could be inlined instead of adding supply-chain surface.

## Update policy

- Do not update every dependency blindly. For each flagged, security-
  relevant advisory:
  1. Identify the affected package and version range.
  2. Identify the patched version from the official advisory/release notes.
  3. Confirm the patched version is compatible with the project (check for
     breaking changes in the intervening releases, not just the target
     version's changelog).
  4. Apply the update, then verify with build/typecheck/tests.
- Prefer minimal-diff updates (patch the vulnerable package to the
  minimum safe version) over broad "update everything" sweeps, which
  introduce unrelated risk and make review harder.
- For dependencies that are only used in build tooling (not shipped to
  production), weigh severity accordingly — a vulnerability in a dev-only
  tool is not automatically CRITICAL/HIGH in the same way a runtime
  dependency vulnerability is, though supply-chain compromise of build
  tooling is still a real risk worth flagging.

## New dependencies

Before adding any new package as part of a fix:

- State the concrete security reason it's needed (e.g. "the project has no
  HTML sanitizer and one is required to safely render user-supplied HTML").
- Confirm no sufficient native Next.js/React/Web Platform capability exists
  first.
- Prefer well-known, actively maintained packages with a track record for
  the specific security-relevant purpose (e.g. a maintained HTML sanitizer
  rather than a small unmaintained one) — verify current maintenance status
  rather than assuming from training data.
