# Security Documentation

Status: Phase 1 skeleton.

This section will hold the formal threat model, security hardening guide,
and fuzzing/security-test reports. The initial threat model and security
principles already exist at [../security-principles.md](../security-principles.md)
(Phase 0) and are expanded here starting Phase 2 (parser fuzzing) through
Phase 9 (production security review).

For reporting a vulnerability, see [Security Policy](security-policy.md).

- [Phase 9D Security Review](security-review.md): every finding of the
  production review, with its severity and disposition

Component security notes:

- [Detection Safety](detection-safety.md) — what the detection engine
  can and cannot do, which of those claims are structural, and what an
  attacker can do *to* the detector
