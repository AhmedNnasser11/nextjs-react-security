# CSRF

Determine actual exploitability. Trace an attacker-controlled cross-site request to a state
change and identify the browser credential that makes it effective.

- Analyze cookie authentication, SameSite, Origin/Referer checks, CORS, credentialed requests,
  CSRF tokens, and framework protections.
- Treat Server Actions as endpoints; verify the framework's Origin/Host behavior and any
  configured allowed origins against the deployed proxy topology.
- Confirm method/content-type constraints and whether a simple cross-origin request can reach
  the mutation.
- Do not add redundant infrastructure without identifying a real reachable gap.
