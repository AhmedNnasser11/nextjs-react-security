# Source Priority

Tier 1: official vendor/framework advisories, GitHub-reviewed advisories, project-maintained advisories.

Tier 2: OSV, CVE.org, NVD, Snyk.

Tier 3: Socket, npm security intelligence, OpenSSF.

Tier 4: PortSwigger, OWASP.

Tier 5: reputable security news.

Higher authority normally wins conflicts, but discrepancies must be analyzed rather than
silently discarded. Registry `priority` is retrieval ordering, not a replacement for this
authority tier: specialized sources may receive a high retrieval priority while remaining
secondary evidence for a vulnerability claim.

Context7 is a documentation source, not vulnerability evidence. Exa is discovery-only.
