# Security Decision Evaluator

A candidate may be `CONFIRMED` only when the record contains evidence for:

- reachability
- attacker influence
- dangerous operation/sink
- missing or insufficient mitigation
- meaningful impact

Dependency advisories additionally require:

- exact/resolved affected component
- affected version
- advisory applicability to the installed version
- affected code path or otherwise demonstrated production exposure where required

An external web result can support a conclusion, but cannot by itself establish project vulnerability.

### Rejection examples

- package affected but vulnerable function unreachable
- advisory applies to a version the project does not actually resolve
- attack technique exists but no attacker-controlled input reaches the sink
- mitigation exists and blocks the exploit
- source unavailable without sufficient corroborating evidence

When evidence is incomplete, use `POTENTIAL` or `UNVERIFIED` rather than `CONFIRMED`.
