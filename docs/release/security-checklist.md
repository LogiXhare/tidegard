# Security Checklist

Status: **v1.0.0 candidate**, 2026-10-13. **Not yet signed off.**

Signed by the owner with the [production checklist](production-checklist.md)
before `v1.0.0` is tagged. Every item links to what proves it.

| # | Item | Proof |
|---|---|---|
| S-1 | No Critical or High finding is open | [Security review](../security/security-review.md) |
| S-2 | Every threat in the model has a passing test, or a recorded reason it does not | [Threat tests](../security/incident-threat-tests.md): 55 of 57 met; T-21 partial (Phase 8), T-55 met by S-9 once the first release verifies |
| S-3 | The collector's untrusted input cannot crash it or exhaust its memory | T-49 and T-50; the [allowlist and bounds](../architecture/decisions/0056-phase9d-collector-input-bounds.md); the fuzz workflow |
| S-4 | The IPFIX decoder was fuzzed for a stated time, with its coverage reported | The [fuzzing report](../security/security-review.md#fuzzing-report-fu-3): three hours, 957,841,448 executions, no crash |
| S-5 | API tokens are stored as SHA-256 only; sessions are bound to them and expire with them | [ADR 0038](../architecture/decisions/0038-phase5d-api-boundary.md), [ADR 0043](../architecture/decisions/0043-phase6c-browser-sessions.md), and their tests |
| S-6 | Every action is authorized and audited, denials included; tenants are isolated | T-05, T-06, T-19 to T-21, T-40, T-48 in the [threat tests](../security/incident-threat-tests.md) |
| S-7 | No route is announced without approval, outside the allowlist, or past the prefix floors | T-42 to T-48 |
| S-8 | Dependencies: no RustSec advisory, only approved licences, crates.io only; no High npm advisory | The `rust` job's `cargo-deny` step; the `web` job's `npm audit` |
| S-9 | Every release file and image is signed and attested, and verifies on a clean runner | The release workflow's `verify` job; [Verifying a Release](../operations/verifying-a-release.md) |
| S-10 | Images carry no fixable Critical or High vulnerability | The `package` job's Trivy scan |
| S-11 | No secret anywhere in the history the public repository will carry | The `history` job's gitleaks scan of every commit |
| S-12 | Every third-party licence ships with the binaries and the UI | The `package` job checks the notices (FU-53) |
| S-13 | An independent adversarial review of the release candidate found nothing Critical or High left open | The [security review](../security/security-review.md) |
| S-14 | How to report a vulnerability is published | [Security policy](../security/security-policy.md) |

## Sign-off

| | |
|---|---|
| Release candidate | |
| Signed off by | |
| Date | |
