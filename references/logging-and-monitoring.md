# Logging and Monitoring

- Review security-relevant events: login success/failure, password changes, MFA, role/permission
  changes, admin actions, authorization failures, abuse limits, and security-sensitive mutations.
- Include timestamp, actor/request identity, action, target, outcome, and correlation ID without
  recording secrets or unnecessary personal data.
- Protect logs from injection by encoding structured fields and normalizing control characters.
- Alert on repeated failures, privilege changes, unusual export/download activity, and source
  failures that could hide incomplete security coverage.
- Never log passwords, raw session tokens, secrets, API credentials, or full authentication material.
