# Authentication & Authorization Checklist

## Core principle

Authorization must happen on the server, on every request/invocation, for
every sensitive operation. Never trust:

- hidden form fields
- disabled buttons
- client-side state or route guards
- route "visibility" (a page not being linked doesn't make it protected)
- UI-level role checks
- a role/permission value supplied by the client in a request body

## Authentication

- Confirm session/token validation happens before any protected data
  access, in Route Handlers, Server Actions, and Server Components alike —
  not only in middleware.
- Confirm password handling (if applicable) uses a modern, salted hashing
  algorithm via a maintained library — never custom hashing or reversible
  encryption for passwords.
- Confirm authentication error responses don't reveal whether a given
  identifier (email/username) exists in the system, where that distinction
  matters for the app's threat model.
- Confirm session tokens are invalidated on logout, password change, and
  any other security-relevant state change.

## Authorization

- For every mutation and every read of a specific resource, confirm there
  is an explicit check that the authenticated principal is allowed to
  perform that action on that specific resource — not just that they're
  logged in.
- Ownership checks: when a resource is fetched/mutated by ID, confirm the
  code verifies the resource belongs to (or is otherwise accessible by) the
  requesting user, rather than trusting the ID alone. This is the core
  IDOR/BOLA defense.
- Role checks: confirm role/permission checks read from a trusted source
  (server-side session/DB lookup), never from a client-supplied field.
- Admin routes/actions: confirm they're gated by an actual role check on
  the server, applied consistently across every entry point (page, Route
  Handler, Server Action) that can reach the admin functionality — not just
  the primary admin page.
- Privilege escalation: check whether a lower-privileged user can modify
  their own role/permissions field via a mutation that wasn't designed to
  allow that (mass assignment intersecting with authorization).

## Mass assignment / over-posting

- Confirm mutation handlers apply only an explicit, intended set of fields
  from the input to the persisted record, rather than spreading an entire
  validated (or worse, unvalidated) input object onto the database record.

## Session / cookie hardening

- `HttpOnly` on session cookies to prevent JS-based theft via XSS.
- `Secure` in production so cookies aren't sent over plain HTTP.
- `SameSite` set appropriately for the app's cross-origin needs (`Lax` is
  usually right for standard first-party session cookies; `Strict` or
  `None` only where the app's actual cross-origin behavior requires it).
- Reasonable session expiry / idle timeout for the sensitivity of the app.
- Confirm sensitive session data isn't stored in a client-readable cookie
  without integrity protection (signing) if the app relies on its
  contents for authorization decisions.

## CSRF

- Determine whether CSRF is actually a live risk given the auth mechanism:
  cookie-based sessions with state-changing GET/POST requests are the
  classic risk; pure bearer-token-in-header APIs (not sent automatically
  by the browser) are generally not vulnerable to classic CSRF the same
  way.
- Understand what the framework/auth library already provides (e.g.
  same-site cookie defaults, built-in origin checks for Server Actions)
  before adding a custom CSRF token mechanism — verify current behavior per
  `source-priority.md` rather than assuming.
- Do not add a redundant CSRF layer on top of an already-sufficient
  existing protection without a concrete gap identified.
