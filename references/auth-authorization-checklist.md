# Authentication & Authorization

## Authentication
Review session validation, token validation, fixation/rotation, logout invalidation, password reset, MFA, credential issuance, expiration, cookie security, enumeration leakage, and client/server identity mismatches.

Authentication must precede protected data access.

## Authorization
For every sensitive read/mutation verify resource-level authorization, ownership, tenant isolation, roles, permissions, admin checks, privilege escalation, cross-user/tenant access, IDOR/BOLA, and mass assignment.

Never trust request-body `userId`, `tenantId`, role, or permissions without server-side verification.
