# Input validation and code-rejection

Use this reference whenever the target project has Server Actions, Route Handlers, forms, or any client-controlled input that reaches a server-side sink.

## Documentation

Before recommending or reviewing validation patterns, fetch the current documentation for the installed validation library. Use Context7 (`npx ctx7@latest library <name> "<query>"`, then `npx ctx7@latest docs <id> "<query>"`). Typical queries:

- zod: "string regex validation", "refine validation", "safeParse vs parse", "v4 API changes".
- yup/joi/valibot/arktype/ajv: equivalent string validation and coercion APIs.
- sanitize-html: current options for allowed tags, attributes, styles, and URI schemes.

Record the library version, doc source, and retrieval timestamp. Do not rely on memory for version-sensitive API details.

## Goal

Ensure attacker-controlled values are constrained before they are parsed, stored, or forwarded. A string that "accepts code" — HTML tags, control characters, executable URI schemes, or shell metacharacters — is a latent injection vector even if it is not immediately rendered.

## Free-form string fields

Examples: `name`, `subject`, `notes`, `specialRequests`, `origin`, `destination`, `message`, `comment`.

- Reject HTML/JS markers: `<`, `>`, control characters (`U+0000–U+001F`, `U+007F`), and executable URI prefixes (`javascript:`, `vbscript:`, `data:`).
- Prefer an allowlist over a blocklist:
  - Names: letters, marks, spaces, apostrophe, hyphen, dot (`[\p{L}\p{M}\s'.-]+` with the `u` flag).
  - Free text that must remain permissive: use a `.refine()` or regex that blocks `<`, `>`, control bytes, and executable URI prefixes while preserving Arabic and Unicode text.
- Keep `.min()` / `.max()` length checks, but do not rely on them as the only defense. A 10-character `phone` value can still contain `<`.
- Never use `z.string()` with only a length check for fields that will be forwarded to an API, rendered, or logged.

## Phone / numeric-looking strings

- Restrict to the smallest safe character class, e.g. `^[0-9+\-\s()]+$`.
- Validate after trimming whitespace; do not trust the client for parsing.

## Route and path segments

- Use an allowlist/segment guard before interpolation (e.g. `safePathSegment`).
- Reject path separators (`/`, `\`), traversal dots (`.`), percent-encoding (`%`), and control characters.
- Decode once, then guard the decoded value. Next.js route parameters are normally already decoded; never decode them a second time. Reject a value that still contains `%` when encoded input is not expected.

## Query parameters

- Build URLs with `URLSearchParams`, not template-literal concatenation.
- Validate and coerce types before appending. Allow only the expected character set for keys and values.
- Never forward raw `searchParams` to an external API without validation.

## URI schemes

- If you must allow rich content, restrict `allowedSchemes` in sanitizers and never permit `javascript:` or `data:` where HTML/JS execution is possible.
- In `sanitize-html`, `data:` may be acceptable for an `img src` data image, but scope that exception to `img` only. Never allow it for `a href`, scripts, objects, frames, or executable contexts.

## Server Actions / Route Handlers

- Run validation inside the action, not only in the client form. Client-side validation is UX; server-side validation is the trust boundary.
- Re-validate values received from the client even if they were previously validated client-side.

## Code-rejection as defense-in-depth

Code rejection is a `HARDENING` finding when:
- The field accepts code characters and is forwarded to a backend or external API.
- The field is not currently rendered in the DOM, but a future change or downstream consumer could render it.

It is a `CONFIRMED` vulnerability when:
- The field accepts code and is rendered unsanitized in the DOM, embedded in JSON-LD without escaping, interpolated into a command/SQL/URL, or stored and reflected without sanitization.

## Minimal fix pattern (zod)

Name:
```ts
z.string()
  .min(2)
  .regex(/^[\p{L}\p{M}\s'.-]+$/u, "Only letters, spaces, apostrophes, hyphens and dots allowed");
```

Free-text notes with code rejection:
```ts
const noCode = (value: string) =>
  !/[<>]/.test(value) &&
  !/[\x00-\x1f\x7f]/.test(value) &&
  !/^\s*(?:javascript|vbscript|data):/i.test(value);

z.string()
  .max(2000)
  .refine(noCode, { message: "Text contains disallowed characters or schemes" });
```

Phone:
```ts
z.string()
  .min(10)
  .regex(/^[0-9+\-\s()]+$/, "Invalid phone number");
```

## What to avoid

- Do not add a new dependency solely to check character classes — zod/regex is enough.
- Do not reject Arabic, CJK, or diacritics by accident — use Unicode properties.
- Do not silently strip code characters unless the field genuinely needs no fidelity; failing closed is safer.
- Do not change the validation in client-only files and skip the matching server-side schema.
