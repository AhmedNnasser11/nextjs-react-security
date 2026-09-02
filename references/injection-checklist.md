# Injection

Trace dangerous sinks backward to attacker-controlled inputs.

## SQL
Inspect raw SQL, template literals, concatenation, dynamic filters, ORDER BY, columns/tables, search, pagination, sorting, reports and exports. Prefer parameterization and allowlists.

## NoSQL/search
Constrain length, control characters, shape, allowed structure and query semantics. Do not rely on simplistic blocklists.

## Command
Inspect `exec`, `execSync`, `spawn`, `child_process`, shell wrappers, image/video/PDF processors and git utilities. Prefer non-shell APIs with structured arguments.
