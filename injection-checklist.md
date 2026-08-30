# Injection Defense Checklist

Injection is the top audit priority for this skill. For every sink below,
trace back to confirm whether attacker-controlled input can reach it, per
the decision checklist in SKILL.md.

## SQL injection

- Flag any raw SQL built via string concatenation or template literals that
  interpolate request-derived values directly into the query text.
- Prefer parameterized queries, prepared statements, or the project's
  existing ORM/query-builder API (Prisma, Drizzle, Supabase client, etc.)
  used correctly.
- An ORM does not automatically make every query safe: flag raw/`$queryRaw`-
  style escape hatches, dynamically constructed table/column names, and
  unvalidated `ORDER BY`/`sort` expressions built from user input (these
  usually can't be parameterized the normal way and need an allowlist of
  permitted column names instead).
- Flag unvalidated filter/search logic that lets a user influence query
  structure (not just values), e.g. arbitrary JSON passed straight into a
  `where` clause.

## Search / free-text query inputs

Search boxes are a recurring blind spot: teams add client-side filtering or
a placeholder/debounce UX and treat that as "handled," leaving the actual
server-side handler accepting arbitrary text — including script tags,
SQL/NoSQL operators, or template syntax — with no validation at all.

- Treat every search input the same as any other trust boundary: client-side
  filtering, disabling, or debouncing is UX only and is never a substitute
  for server-side validation on the Route Handler / Server Action that
  actually executes the search.
- Flag a search endpoint as a finding if the raw query string is passed
  through to any of the following without validation first:
  - A SQL/NoSQL query (`LIKE`/`ILIKE` concatenation, `$regex`, `$where`,
    full-text search functions) — see SQL injection and NoSQL injection
    above for the specific sink rules.
  - A rendered results list via `dangerouslySetInnerHTML` or a raw HTML
    sink (e.g. highlighting matched terms) — see XSS Rule 2/3 above.
  - A shell command, template engine, or external API call built by
    concatenation.
- Minimum server-side validation for a search input, even when it's "just
  a keyword field": enforce a max length, strip/reject control and null
  characters, and validate against an explicit allowed character set or
  Zod schema (e.g. `z.string().trim().max(N).regex(...)`) rather than
  accepting an unbounded free-text string as-is.
- Do not attempt to blocklist "code-looking" patterns (`<script>`, `SELECT`,
  `{{`, etc.) as the primary defense — that's a blocklist, not a boundary,
  and it's trivially bypassed. The actual fix is: (1) parameterize/allowlist
  the query itself so structure can't be influenced, and (2) constrain the
  input shape at the schema boundary so malformed/oversized/control-character
  payloads are rejected outright, regardless of what they contain.
- If search results are highlighted, faceted, or reflected back into the
  page in any form, re-check that reflected value against XSS Rule 2/3 —
  a search term is attacker-controlled input like any other, even though it
  "just came back from what the user typed."
- Severity: **HIGH** if unvalidated search input reaches a raw HTML sink or
  an unparameterized query with attacker influence over structure;
  **MEDIUM** if input is unbounded/unvalidated but the sink itself is
  already safely parameterized (missing defense-in-depth, not a confirmed
  exploit path).

## Command injection

- Flag any use of shell-executing APIs (`child_process.exec`, `execSync`,
  shell-invoking library calls) where any part of the command string or
  arguments originates from user input.
- Prefer APIs that take an argument array without shell interpretation
  (`execFile`/`spawn` with an args array) over string-based shell execution.
- If shell execution is unavoidable, the input must be strictly validated
  against an allowlist (not just escaped) before use.

## XSS

Audit every HTML/DOM sink. Rules 1–4 below are project-mandated zero-tolerance
architecture, not general suggestions — apply them as written, not as one
option among several.

### Rule 1 — Safe DOM injection for widgets/scripts (the `useRef` standard)

Applies to: any third-party widget, external JS library, custom HTML
element, or dynamic *executable* content (anything that isn't plain
user-authored rich text — see Rule 2 for that case).

Required architecture, exactly in this order:

1. The component must be `"use client"`.
2. External JS libraries load via Next.js `<Script>`, not a manually
   injected `<script>` tag.
3. DOM insertion happens inside `useEffect`, targeting a container via
   `useRef` (never targeting `document.body`/`document.head` directly from
   inside a component).
4. Elements are created exclusively with `document.createElement()`,
   attributes set exclusively with `.setAttribute()`, and insertion happens
   exclusively via `containerRef.current.appendChild()` (or equivalent DOM
   node methods — `insertBefore`, etc. — never string-based insertion).
5. `.innerHTML`, `.outerHTML`, `document.write()`, and template-literal HTML
   strings are **never** used to construct or inject this content, under
   any circumstance, including for "trusted" first-party widget code.

Flag any deviation from this exact pattern for widget/script injection as a
**HIGH** finding (CRITICAL if the injected content can include
attacker-influenced data, e.g. a URL parameter or user-configurable widget
ID passed into the script).

If the widget/script needs any sensitive data (API keys, tokens, auth
state, non-`NEXT_PUBLIC_` env vars) to configure or authenticate itself,
Rule 1's DOM pattern alone is not sufficient — see Rule 4 for the required
Server/Client split before this pattern is applied.

### Rule 2 — Rich text rendering: `dangerouslySetInnerHTML` is conditional, not banned

Applies to: rendering user-authored formatted text from a rich text editor
or similar source (`<b>`, `<p>`, `<i>`, links, lists — structural markup,
not arbitrary executable content).

- `dangerouslySetInnerHTML` **may** be used for this case, but **only** when
  the HTML has been sanitized immediately before injection by a maintained
  sanitizer:
  - **DOMPurify, pinned to version ≥ 3.4.5** (2026 saw multiple distinct
    bypasses — a rawtext-element regex gap, a prototype-pollution-based
    tag/attribute injection, and a default-allowed `<selectedcontent>`
    re-clone bypass — all fixed by 3.4.5; anything older is a known-bad
    version, not a hypothetical risk), **or**
  - `sanitize-html`, configured with an explicit allowlist of tags/
    attributes/protocols rather than its permissive defaults.
- Sanitization must happen at render time (or immediately before storage
  **and** immediately before every render path, if sanitizing once at
  write time) — never assume a value sanitized once upstream is still safe
  at every place it's later rendered.
- **CRITICAL RULE — zero tolerance:** any `dangerouslySetInnerHTML` call
  that renders unsanitized data — user input, third-party API responses,
  CMS content, anything not hard-coded by the developer — is a confirmed
  finding regardless of how unlikely exploitation seems. Flag it and
  refactor immediately to add sanitization; do not defer or downgrade
  severity because the field "seems safe in practice."
- Severity: **CRITICAL** if the unsanitized source is directly
  attacker-controlled (form input, URL param, uploaded content); **HIGH**
  if it's an indirect but still untrusted source (third-party API,
  webhook payload, CMS/database content not written exclusively by trusted
  admins).

### Rule 3 — Input validation rejects raw executables

Applies to: every API Route Handler and every Server Action.

- Reject payloads containing raw executable content (script tags, event
  handler attributes, `javascript:`/`data:` URLs, template/expression
  syntax) at the validation boundary — before the value is ever persisted
  or passed downstream — not only at render time. Rendering-time
  sanitization (Rule 2) is a second, independent layer; it does not excuse
  skipping input-side validation.
- Prefer schema validation (Zod or equivalent) with an explicit shape,
  rather than a blocklist regex trying to catch "dangerous" patterns —
  reject unexpected fields and unexpected structure outright.
- This applies even to fields intended to hold rich text: input-side
  validation should still reject anything outside the rich-text editor's
  own expected output shape (e.g. a JSON/AST format from the editor, not
  arbitrary raw HTML from an API caller bypassing the UI entirely).

### Rule 4 — The Hybrid Component Pattern (Server-First Approach) for widgets/scripts

Applies to: any third-party widget or dynamic script from Rule 1 that
requires sensitive data — API keys, auth tokens, session/user state, or any
environment variable not prefixed `NEXT_PUBLIC_` — to configure, initialize,
or authenticate itself. This extends Rule 1; it does not replace it. If the
widget needs no sensitive data at all, Rule 1 alone applies.

Required architecture, exactly in this order:

1. **Data fetching (Server Component):** retrieve all sensitive data,
   server-only env vars, and authentication state inside a Server
   Component. This data must never be fetched, decrypted, or derived
   inside a Client Component.
2. **Safe injection (Client Component):** the Server Component passes only
   the specific, already-fetched values the widget actually needs as plain
   props to a minimal, dedicated Client Component (`"use client"`) — not
   the full session/user object, not raw credentials the widget doesn't
   need, and nothing beyond what's required for that widget's
   configuration.
3. **Execution:** the Client Component's sole responsibility is DOM
   injection using the exact `useRef` + `document.createElement()` /
   `.setAttribute()` / `appendChild()` pattern from Rule 1. It does not
   independently fetch, request, or derive any additional sensitive data.
4. **Enforcement:** flag any Client Component that fetches sensitive data
   directly (an API call, a direct env var reference, a client-side auth
   check used to gate secret-bearing logic) when that data was available
   to — or should have been resolved in — a parent Server Component.
   Refactor into the Server/Client pair described above. Treat this as a
   **HIGH** finding if the exposed value is a live credential/token/key
   reachable in the client bundle or network tab (**CRITICAL** if it grants
   write/administrative access to a third-party service); **MEDIUM** if the
   issue is unnecessary sensitive-data plumbing into client code without an
   actual secret ending up client-visible yet (e.g. an internal user ID
   passed further than needed).

This rule composes with the boundary checks in
`nextjs-security-checklist.md`'s "Environment variables" and "Server
Components vs Client Components" sections — treat a violation here as both
an XSS-adjacent DOM-injection finding (wrong component owns wrong
responsibility) and a secrets-exposure finding (Section 11 of the parent
skill) simultaneously; report it once, but note both angles in the
finding's Impact field.

### Other XSS sinks (still in scope, same trace-back requirement)

- Markdown/rich-text rendering — confirm the renderer doesn't allow raw
  HTML passthrough or unsafe link/image protocols unless explicitly
  intended and sanitized per Rule 2.
- `javascript:` and `data:` URLs in `href`/`src` built from user input —
  validate protocol against an allowlist (`http:`/`https:`/`mailto:` as
  appropriate) before rendering as a link/attribute.
- Third-party embedded HTML/widgets not covered by Rule 1 (e.g. iframes) —
  confirm the source is trusted and the embed is scoped (sandboxing where
  applicable).
- Do not claim "React escapes everything" as a blanket statement — it
  escapes text content in JSX by default, but `dangerouslySetInnerHTML`,
  direct DOM manipulation, and attribute-based sinks (`href`/`src`) bypass
  that and need the rules above.

## Template / expression injection

- Flag any place a string derived from user input is passed to an
  expression evaluator, template compiler, or `Function`/`eval`-style
  construct, even indirectly (e.g. a "formula" or "template" feature).

## Path traversal

- Flag any filesystem path built by concatenating user input (filenames,
  IDs, upload names) without normalizing and verifying the result stays
  within an intended base directory.
- Prefer generating server-side identifiers/filenames rather than trusting
  client-supplied names for storage paths.

## NoSQL / LDAP / XPath / other interpreter injection

- If the project uses a NoSQL database (MongoDB, etc.), flag query objects
  built directly from parsed request bodies without stripping operator keys
  (e.g. `$where`, `$gt`) or validating shape via a schema first.
- Apply the same "input reaches an interpreter" reasoning to any LDAP,
  XPath, GraphQL resolver, or other interpreter present in the project —
  audit only if actually relevant to the codebase.

## General principles across all injection classes

- Client-side validation is never sufficient; require server-side
  validation on every trust boundary.
- Prefer allowlists over blocklists wherever the valid input space can be
  enumerated or pattern-constrained (enum values, known column names,
  allowed protocols, allowed file extensions).
- Regex alone is not a universal injection defense — use it for format
  validation (e.g. matching an expected shape), not as a substitute for
  parameterization, sanitization libraries, or allowlists.
- Validate type, length, format, range, and enum membership server-side;
  prefer schema validation (e.g. Zod) at the boundary and infer domain
  types from the schema rather than maintaining two parallel type
  definitions.
