# Caching

Analyze Next.js caching, fetch caching, revalidation, static generation, RSC data, CDN/shared
caches, cache keys, and personalized/authorization-sensitive responses.

- Verify current Next.js semantics before making version-sensitive claims.
- Ensure auth-sensitive responses are dynamic or isolated from shared caches.
- Check cache keys, tags, paths, and revalidation inputs for attacker control.
- Review cache poisoning through headers, query parameters, redirects, and content negotiation.
- Verify invalidation after mutations and do not claim a cache fix without runtime evidence.
