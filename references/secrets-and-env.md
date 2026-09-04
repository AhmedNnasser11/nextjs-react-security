# Secrets and Environment

- Review `.env*`, `NEXT_PUBLIC_*`, server-only variables, build output, client bundles, logs,
  error responses, source maps, API keys, DB credentials, webhook secrets, OAuth secrets, and
  cloud credentials.
- Confirm secret values are absent from Git history, generated assets, client bundles, and error
  messages; report names and locations, never values.
- Validate environment presence at startup and fail safely without leaking configuration.
- Rotate exposed credentials through the authorized operational process; do not modify production
  secrets automatically.
- Never expose server secrets in client bundles or print secret values in reports.
