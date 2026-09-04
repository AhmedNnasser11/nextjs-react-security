# Finding Model

The authoritative model is `schemas/finding.schema.json`.

Required fields: `id`, `title`, `severity`, `confidence`, `status`, `category`,
`evidence`, `minimal_remediation`, `verification`, `source_evidence`, and
`limitations`.

Recommended project-evidence fields include `affected_file`, `location`,
`entry_point`, `reachability`, `attacker_controlled_input`, `trust_boundary`,
`validation`, `authentication`, `authorization`, `dangerous_sink`, `exploit_path`,
`impact`, `existing_mitigations`, and `why_mitigation_is_insufficient`.

Status values: `CONFIRMED`, `POTENTIAL`, `HARDENING`, `UNVERIFIED`, `FIXED`, `VERIFIED`.
Severity values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
Confidence values: `High`, `Medium`, `Low`.
