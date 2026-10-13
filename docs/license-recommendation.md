# License Recommendation

Status: **Confirmed** — resolved 2026-08-21 by WeTechi Solutions
Last updated: 2026-08-30

## Confirmation

The [`LICENSE`](../LICENSE) file at the repository root contains the
standard **Apache License 2.0** text. This was originally a
**recommendation selected by the engineering process**, tracked as an
open item since Phase 0. **WeTechi Solutions explicitly confirmed
Apache-2.0 on 2026-08-21** — see
[`docs/blocking-questions.md` — BQ-1](blocking-questions.md) for the
decision record, including the permissive-license fork risk accepted
knowingly, and [ADR 0006](architecture/decisions/0006-contribution-licensing-dco-not-cla.md)
for the accompanying contribution-licensing model (DCO sign-off, no
CLA). The rest of this document is retained as the historical rationale
that led to the recommendation, especially given the commercial-tier
strategy discussion in
[`docs/commercial-boundaries.md`](commercial-boundaries.md).

## Why Apache-2.0 Was Recommended

- Widely adopted for infrastructure/networking software; low friction for
  enterprise and ISP adoption (a named target audience — see
  [`docs/product-charter.md`](product-charter.md)).
- Includes an explicit patent grant and patent-retaliation clause, which
  matters for a security/networking product where patent risk is
  non-trivial.
- Permissive — does not, by itself, force Tidegard's own source to
  stay open if WeTechi Solutions later wants closed-source Enterprise
  modules built *alongside* (not modifying) the Apache-licensed core.
- Compatible with the majority of the candidate dependencies listed in
  [`docs/dependency-license-matrix.md`](dependency-license-matrix.md)
  (most are MIT or Apache-2.0 themselves).

## Why This Still Needs Real Verification

1. **Competitive exposure**: Apache-2.0 is permissive enough that a
   competitor could take the entire codebase and offer a competing managed
   DDoS-mitigation service without contributing anything back. If WeTechi
   Solutions' business model depends on being the only viable managed-
   service provider for this code, a source-available or dual-license
   model may be a better fit — this is a business decision, not an
   engineering one.
2. **Interaction with Grafana's AGPLv3 terms**: if the eventual
   integration approach changes from "external Grafana, original
   dashboard JSON only" to something that bundles or modifies Grafana
   itself, Apache-2.0 for Tidegard's own code would not resolve that
   separate AGPLv3 exposure — see
   [`docs/dependency-license-matrix.md`](dependency-license-matrix.md).
3. **No legal review has occurred.** This document and the `LICENSE` file
   were prepared by the engineering/documentation process described in
   `prompts/CLAUDE_MASTER_PROMPT.md`, which explicitly states license
   information must never be fabricated and uncertain status must be
   marked `REQUIRES VERIFICATION` — this whole license selection is that
   marker.

## What Happened Once WeTechi Solutions Decided

Apache-2.0 was confirmed, per the plan this section originally recorded
in advance of the decision: the warning above was removed and replaced
with the confirmation date and decision record (2026-08-21, BQ-1); the
`LICENSE` file itself needed no change, since it already carried the
recommended Apache-2.0 text.

## Related Documents

- [`docs/blocking-questions.md`](blocking-questions.md) — BQ-1
- [`docs/commercial-boundaries.md`](commercial-boundaries.md)
- [`docs/dependency-license-matrix.md`](dependency-license-matrix.md)
- [`NOTICE`](../NOTICE)
