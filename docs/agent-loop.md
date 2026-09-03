# Production Agent Loop

```text
Initialize run
  ↓
Discover repository deterministically
  ↓
Build project/dependency/attack-surface graphs
  ↓
Load applicable references
  ↓
Generate hypotheses
  ↓
Plan structured-source queries
  ↓
Run structured advisory retrieval
  ↓
Normalize + correlate + deduplicate
  ↓
Detect evidence gaps
  ↓
Plan targeted web research
  ↓
Search trusted/allowed domains
  ↓
OPEN authoritative results before using them as evidence
  ↓
Trace code paths / trust boundaries
  ↓
Check attacker control + mitigations
  ↓
Exploitability decision
  ↓
Finding state decision
  ↓
Optional remediation authorization gate
  ↓
Patch in sandbox if allowed
  ↓
Build / typecheck / lint / tests / audit
  ↓
Re-check advisory applicability
  ↓
Record verification + provenance
  ↓
Persist only validated knowledge
  ↓
Final report + limitations
```

## Stop conditions

Stop and mark the audit incomplete when a mandatory evidence gate cannot be satisfied and no safe fallback exists.

Do not convert missing evidence into a negative conclusion.
