# Server Actions

Treat every Server Action as a security-sensitive endpoint.

Verify authentication, authorization, ownership/tenant boundaries, validation, mass assignment, rate limiting where applicable, data access, dangerous sinks and side effects. Assume direct invocation unless proven otherwise.

Input validation must reject code-bearing values (HTML/JS markers, control characters, executable URI schemes). Client-side validation is never sufficient; validate and sanitize on the server before touching any sink. See `input-validation-checklist.md` for concrete patterns.
