# File Upload Security

Review authorization, size, extension, MIME, magic bytes/content, filename/path handling,
storage, public exposure, SVG/HTML risks, archives, executability, signed URLs, tenant
isolation, malware scanning, and metadata.

- Enforce limits before buffering or processing and reject unexpected multipart fields.
- Generate storage names; never use an uploaded filename as a filesystem path.
- Store outside executable/public directories unless public delivery is intentional and safe.
- Re-encode images/documents where appropriate and strip active content/metadata.
- Validate download authorization and content disposition; prevent cross-tenant access.
- Extension checks alone are insufficient.
