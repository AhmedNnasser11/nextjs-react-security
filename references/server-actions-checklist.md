# Server Actions checklist

Every Server Action is a public HTTP POST endpoint. Anyone can call it directly with arbitrary arguments, whether or not your UI renders the button. Review each exported `'use server'` function as an API route.

## What to check

1. **Authentication inside the action.** Do not rely on middleware, layout checks or hidden UI. The action must call the session check itself.
2. **Authorization per object.** Verify that the current user may act on the specific record ID passed in, not just that they are logged in (IDOR/BOLA).
3. **Server-side validation of every argument and FormData field.** Use a schema (for example Zod) with strict types, lengths and allowlists. TypeScript types do not exist at runtime.
4. **Never trust values closed over from the component.** Closed-over variables are serialized to the client (encrypted, not authoritative). Re-derive prices, roles, tenant IDs and owner IDs on the server.
5. **Exported helpers in a `'use server'` file become endpoints.** Keep non-action helpers in a separate server-only module.
6. **CSRF.** Next.js compares Origin with Host for Server Actions. Check `serverActions.allowedOrigins` for overly broad entries, and check any custom reverse proxy that rewrites Host or strips Origin. Route Handlers get no such protection.
7. **Return values and errors.** Do not return raw DB rows, stack traces or secrets. Return only the fields the caller may see.
8. **Rate limiting and abuse.** Login, password reset, invitation, email and expensive actions need per-user and per-IP limits.
9. **Side effects.** Check redirects (`redirect()` with user-controlled targets), `revalidatePath`/`revalidateTag` with user-controlled input, file writes and outbound requests (SSRF).

## Vulnerable pattern

```ts
'use server'
export async function deletePost(id: string) {
  await db.post.delete({ where: { id } })
}
```

No authentication, no ownership check, no validation of `id`.

## Fixed pattern

```ts
'use server'
import { z } from 'zod'

const Input = z.object({ id: z.string().uuid() })

export async function deletePost(raw: unknown) {
  const { id } = Input.parse(raw)
  const session = await requireSession()
  const post = await db.post.findUnique({ where: { id }, select: { authorId: true } })
  if (!post || post.authorId !== session.userId) throw new Error('Not found')
  await db.post.delete({ where: { id } })
}
```

## Do not report as a finding

- An action that authenticates and authorizes inside its own body, even if middleware also exists.
- Missing CSRF tokens on Server Actions when Origin/Host checking is intact and `allowedOrigins` is narrow.
- Actions that only touch the caller's own data selected from the session, not from arguments.
