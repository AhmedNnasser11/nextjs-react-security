# SSRF

Inspect server-side requests influenced by user input: `fetch`, image proxies, URL previews,
import-from-URL, webhooks, PDF/image fetchers, metadata requests, and Next.js image
optimization.

- Prefer an explicit hostname allowlist. If arbitrary destinations are required, parse the
  URL, allow only HTTPS, resolve DNS, reject loopback/private/link-local/reserved/metadata
  ranges and validate every redirect.
- Consider alternate IP forms, IPv6, credentials in URLs, protocol confusion, DNS rebinding,
  redirect chains, and parser differences.
- For `/_next/image`, audit `remotePatterns`/`domains`, upstream redirects, response limits,
  and whether user input can select the optimizer target.
- Treat preflight DNS validation as insufficient unless the connection is pinned or the
  destination is revalidated at connection time.
