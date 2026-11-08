# Caching security

Caching bugs in Next.js leak data across users or serve stale authorization decisions. Treat any cached response that depends on identity as a potential finding.

## What to check

1. **Per-user data in shared caches.** `unstable_cache`, `'use cache'`, `fetch` with `force-cache` or `revalidate`, and ISR/static pages must not contain data derived from cookies, headers or session unless the cache key includes the user or tenant.
2. **Dynamic APIs.** Reading `cookies()`, `headers()` or `searchParams` should make the route dynamic. Check for patterns that read identity in a cached scope or pass it in from outside the cache key.
3. **Authorization is evaluated per request.** A cached page or data function must not be the only place an access decision is made.
4. **CDN and HTTP caching.** Authenticated responses send `Cache-Control: private, no-store`. Check `Vary` for headers that change the response, and check custom `headers()` in `next.config` that apply `public` caching to broad path patterns.
5. **Cache poisoning.** The cache key must cover every input that changes the response (host, forwarded headers, locale, query parameters). Do not reflect unkeyed headers into cached HTML.
6. **Invalidation.** `revalidatePath`/`revalidateTag` calls from Server Actions or Route Handlers must be authenticated, and their tags or paths must not be attacker-controlled.
7. **Data Cache vs Router Cache.** After a permission change or logout, confirm that stale client-side or server-side cached data cannot still be viewed.

## Vulnerable pattern

```ts
const getProfile = unstable_cache(async () => {
  const session = await getSession() // reads cookies inside the cached scope
  return db.user.findUnique({ where: { id: session.userId } })
}, ['profile'])
```

The key is the same for every user, so the first user's data can be served to others.

## Fixed pattern

```ts
const getProfile = (userId: string) =>
  unstable_cache(
    () => db.user.findUnique({ where: { id: userId } }),
    ['profile', userId],
    { tags: [`profile:${userId}`] }
  )()
```

Read the session outside the cache and pass the ID in, so it becomes part of the key.

## Do not report as a finding

- Public, identity-independent data cached with a long lifetime.
- `no-store` already set on authenticated responses and the route verified as dynamic.
