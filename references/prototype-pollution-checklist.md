# Prototype Pollution

Trace attacker-controlled keys into object construction and merge operations.

- Review deep merge, recursive assignment, query-string-to-object parsing, `Object.assign`,
  spread helpers, and utility functions for `__proto__`, `constructor`, and `prototype`.
- Prefer schema validation that rejects unknown keys where appropriate and use null-prototype
  maps or own-property checks for dynamic dictionaries.
- Do not treat a key blocklist as sufficient if a later parser decodes or normalizes keys.
- Confirm impact: polluted configuration, authorization checks, template behavior, or code
  execution. A suspicious dependency advisory is not automatically a project finding.
