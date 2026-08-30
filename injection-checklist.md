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

## Command injection

- Flag any use of shell-executing APIs (`child_process.exec`, `execSync`,
  shell-invoking library calls) where any part of the command string or
  arguments originates from user input.
- Prefer APIs that take an argument array without shell interpretation
  (`execFile`/`spawn` with an args array) over string-based shell execution.
- If shell execution is unavoidable, the input must be strictly validated
  against an allowlist (not just escaped) before use.

## XSS

Audit every HTML/DOM sink:

- `dangerouslySetInnerHTML` — is the source trusted, or does it include any
  user- or third-party-controlled content? If untrusted content must be
  rendered as HTML, require sanitization with a maintained sanitizer
  library and validate allowed tags/attributes/protocols; don't hand-roll
  a regex sanitizer.
- Markdown/rich-text rendering — confirm the renderer doesn't allow raw
  HTML passthrough or unsafe link/image protocols unless explicitly
  intended and sanitized.
- `javascript:` and `data:` URLs in `href`/`src` built from user input —
  validate protocol against an allowlist (`http:`/`https:`/`mailto:` as
  appropriate) before rendering as a link/attribute.
- Direct DOM manipulation (`innerHTML`, `document.write`, manual DOM APIs
  in `useEffect`) bypassing React's normal escaping.
- Third-party embedded HTML/widgets — confirm the source is trusted and
  the embed is scoped (iframe sandboxing where applicable).
- Do not claim "React escapes everything" as a blanket statement — it
  escapes text content in JSX by default, but the sinks above bypass that,
  and attributes like `href`/`src` still need protocol validation.

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
