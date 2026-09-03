# Web Research Checklist

## Search

- Generate query from project evidence or an unresolved security question.
- Prefer exact package/version/advisory identifiers.
- Restrict domains to trusted/official sources when possible.
- Record provider, query, freshness requirement, and result metadata.

## Open

A search result is discovery, not evidence.

Before using a result substantively:

1. Open the original URL.
2. Validate the hostname against the approved domain policy.
3. Revalidate redirects.
4. Record final URL and retrieval timestamp.
5. Hash captured content where feasible.
6. Classify source authority.

## Corroborate

Prefer:

`official advisory/docs > structured vulnerability record > expert security research > reputable news`

Do not upgrade confidence merely because multiple low-authority pages repeat the same claim.

## Stop conditions

Do not claim that a project is vulnerable when the web result establishes only that a technique or vulnerability exists in the ecosystem. Project evidence still must establish applicability and exploitability.
