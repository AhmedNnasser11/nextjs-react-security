# Dependency Security

- Determine the package manager and lockfile-resolved versions.
- Run the actual audit command and preserve its result or failure state.
- Correlate exact versions against GitHub Advisory, OSV, and relevant vendor sources.
- Check whether vulnerable code is reachable in production and whether exploit conditions hold.
- Fetch current library docs before relying on version-sensitive API behavior.
- Prefer the smallest compatible update; inspect breaking changes, then build, typecheck, lint,
  test, and rerun the audit.
- Never fabricate results or blindly upgrade every package.
