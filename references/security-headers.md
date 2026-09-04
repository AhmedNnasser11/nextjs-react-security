# Security Headers

- Review CSP, HSTS, X-Content-Type-Options, frame protection, Referrer-Policy, Permissions-Policy,
  CORS, and cookie attributes in actual responses.
- Check CSP sources, nonces/hashes, unsafe-inline/eval, object/base/frame restrictions, and report
  violations without treating CSP as the primary XSS fix.
- Enable HSTS only when HTTPS is universal and subdomain/preload choices are intentional.
- Ensure CORS allows only required origins and does not combine wildcard origins with credentials.
- Do not introduce incompatible or overly aggressive policies blindly. Preserve legitimate assets
  and verify desktop/mobile production responses.
