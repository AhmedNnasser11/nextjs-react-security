# CSRF checklist

CSRF matters when the browser attaches credentials automatically (cookies, HTTP auth) to a state-changing request that an attacker's page can trigger.

## Where CSRF applies in Next.js

| Surface | Built-in protection | Review |
|---|---|---|
| Server Actions | Origin is compared with Host/X-Forwarded-Host; POST only | Check `serverActions.allowedOrigins` for wildcards or untrusted hosts; check proxies that rewrite Host or drop Origin |
| Route Handlers (`app/**/route.ts`) | None | Any cookie-authenticated POST/PUT/PATCH/DELETE needs its own defense |
| Pages Router `pages/api/*` | None | Same as Route Handlers |
| GET handlers | None | Any state change on GET is a finding (cross-site navigation, `<img>`) |

## What to check

1. State-changing Route Handlers verify `Origin` (or `Sec-Fetch-Site`) against an allowlist, or require a CSRF token, or require a non-cookie credential such as a bearer header.
2. Session cookies set `SameSite=Lax` or `Strict`. `SameSite=None` needs a justification and a second defense.
3. CORS: `Access-Control-Allow-Origin` is never reflected from the request with `Allow-Credentials: true`.
4. No state change on GET, including logout, unsubscribe and delete links.
5. JSON-only endpoints do not accept `text/plain` or form-encoded bodies by accident. Reject unexpected `Content-Type`.
6. Login CSRF and OAuth callbacks: `state` is generated, bound to the session and verified.

## Vulnerable pattern

```ts
// app/api/email/route.ts
export async function POST(req: Request) {
  const session = await getSession(req) // cookie auth
  const { email } = await req.json()
  await db.user.update({ where: { id: session.userId }, data: { email } })
  return Response.json({ ok: true })
}
```

## Fixed pattern

```ts
export async function POST(req: Request) {
  const origin = req.headers.get('origin')
  if (origin !== process.env.APP_ORIGIN) return new Response('Forbidden', { status: 403 })
  if (!req.headers.get('content-type')?.startsWith('application/json')) {
    return new Response('Unsupported', { status: 415 })
  }
  // then authenticate, validate, authorize
}
```

## Do not report as a finding

- Endpoints authenticated only by an `Authorization: Bearer` header that the browser does not attach automatically.
- Missing CSRF token on a Server Action when the Origin/Host check is intact.
- A CAPTCHA is never a CSRF mitigation, and its absence is not a CSRF finding.
