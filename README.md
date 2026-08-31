# nextjs-react-security

## Overview

This is a **security audit and hardening skill** for Next.js App Router, React, TypeScript, and modern web applications. It provides comprehensive security checklists, guidelines, and reference materials for identifying and mitigating vulnerabilities in production applications.

The skill acts as a **Senior Application Security Engineer**, performing detailed security audits with emphasis on injection-class vulnerabilities, authentication, authorization, API security, and production hardening.

## What This Contains

### Security Checklists & References

All checklists and reference files live under `references/`:

- **[nextjs-security-checklist.md](nextjs-security-checklist.md)** — Framework-specific security for Next.js App Router, Server Actions, Route Handlers, middleware, and configuration
- **[auth-authorization-checklist.md](auth-authorization-checklist.md)** — Authentication strategies, session management, token validation, authorization checks, rate limiting, and security logging
- **[injection-checklist.md](injection-checklist.md)** — SQL injection, NoSQL injection, command injection, template injection, and input sanitization patterns
- **[dependency-security.md](dependency-security.md)** — Vulnerability scanning, supply chain security, and dependency management best practices
- **[security-headers.md](security-headers.md)** — HTTP security headers (CSP, X-Frame-Options, X-Content-Type-Options, etc.)
- **[source-priority.md](source-priority.md)** — Authoritative source hierarchy (official docs, advisories, CVE/NVD) and the verification workflow for version- and advisory-specific claims

### Core Documentation

- **[SKILL.md](SKILL.md)** — Master skill definition, non-negotiable ground rules, audit workflow phases, severity model, and report format

## Key Principles

✅ **Server-side validation is mandatory** — Never trust frontend validation as a security boundary  
✅ **Injection vulnerabilities first** — SQL, NoSQL, command, and template injection are high-priority  
✅ **No security theater** — No CAPTCHA, inflated severity claims, or theoretical-only issues  
✅ **Minimal, correct changes** — Preserve architecture; don't over-engineer or add unnecessary dependencies  
✅ **Every Server Action is public** — Treat all endpoints, even internal-only ones, as publicly reachable  

## How to Use

1. **Audit a project** — Load the relevant checklist(s) for the application type
2. **Identify vulnerabilities** — Follow the structured audit workflow to inspect code
3. **Reference guidelines** — Use specific checklists when addressing authentication, injection, headers, or dependencies
4. **Verify claims** — Use source-priority.md to check version- and advisory-specific claims against current, authoritative sources before stating them as fact
5. **Prioritize fixes** — Use the severity model in SKILL.md to classify and schedule remediations

## Scope

This skill covers:
- Next.js App Router applications
- React components and Server Components
- TypeScript strict mode practices
- Database access patterns (SQL, NoSQL, ORMs)
- API security (Route Handlers, Server Actions)
- Authentication & authorization flows
- Input validation & output encoding
- Dependency security & supply chain
- Security headers & CSP
- Secrets management
- File uploads & handling
- CSRF, SSRF, XSS prevention
- Rate limiting & security logging

## Not Included

- CAPTCHA (explicitly out of scope)
- Penetration testing tools
- Compliance frameworks (PCI-DSS, SOC2, etc.)
- Infrastructure security (beyond security headers)

---

**Use Case:** Security engineers, architects, and developers auditing or hardening Next.js applications for production deployment.
