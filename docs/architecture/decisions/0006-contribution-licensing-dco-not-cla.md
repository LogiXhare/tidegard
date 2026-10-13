# 0006. Contribution Licensing: DCO Sign-Off, No CLA

Status: Accepted
Date: 2026-08-21
Deciders: WeTechi Solutions (badshashorif)

## Context

Tidegard is licensed under Apache-2.0 ([LICENSE](https://github.com/badshashorif/tidegard/blob/main/LICENSE),
[NOTICE](https://github.com/badshashorif/tidegard/blob/main/NOTICE)). Until now the project had no stated position
on the terms under which *incoming* contributions are accepted:
`CONTRIBUTING.md` at the repository root covered process but not
licensing, and there was no sign-off requirement of any kind.

That gap matters because of the intended product shape described in
[commercial-boundaries.md](../../commercial-boundaries.md): a community
edition alongside commercially-licensed editions containing features that
are not in this repository. The rights the project holds over contributed
code determine what is possible there, and those rights are fixed at the
moment a contribution is accepted — they cannot be arranged afterwards
without going back to every contributor.

The project currently has no external contributors, which makes this the
cheapest possible moment to decide.

This ADR resolves the incoming-contribution half of
[BQ-1](../../blocking-questions.md). The outgoing project license itself
was already settled as Apache-2.0; see
[license-recommendation.md](../../license-recommendation.md), which
remains subject to its own legal-verification caveat.

## Options Considered

### Option A — DCO 1.1 sign-off, no CLA

Every non-merge commit carries a `Signed-off-by` trailer certifying the
[Developer Certificate of Origin](https://github.com/badshashorif/tidegard/blob/main/DCO): that the contributor
wrote the change, or otherwise has the right to submit it under the
project's license. Contributions are accepted under Apache-2.0. This is
what the Linux kernel, Git, and most CNCF projects use.

Low friction — `git commit -s` — and nothing for a contributor to sign or
for the project to administer.

### Option B — Contributor License Agreement

A separate agreement each contributor signs, typically granting the
project rights beyond the inbound license, and often the right to
relicense the contribution under other terms.

Higher friction: it needs a signing workflow (a CLA bot), a record of who
signed what, and a contributor's willingness to sign a legal document
before their first patch. It is also the only mechanism that preserves
unilateral relicensing freedom.

## Decision

**Option A.** Specifically:

- Apache-2.0 remains the project's license.
- A DCO 1.1 `Signed-off-by` trailer is required on every non-merge commit,
  enforced in CI on pull requests (`.github/workflows/validate.yml`).
- No CLA is required, and none is introduced by this ADR.
- External contributions are accepted under Apache-2.0.

## Consequences

What this does **not** do, stated plainly so it is not assumed later:

- **The DCO is not a copyright assignment.** It is a certification about
  the origin of the contribution and the contributor's right to submit it.
  Contributors keep the copyright in what they write; nothing is
  transferred to WeTechi Solutions.
- **Contributed code cannot be relicensed unilaterally.** Because
  contributions arrive under Apache-2.0 and their copyright stays with
  their authors, WeTechi Solutions cannot on its own move that code to
  different terms — a source-available or BSL-style model, for example.
  Doing so would need either the agreement of every affected contributor
  or rights obtained in advance through a CLA.

What it does permit:

- Apache-2.0 is a permissive licence. It does not restrict commercial use
  by anyone — WeTechi Solutions or a third party. Contributed code may be
  included in a commercially-licensed edition provided the Apache-2.0
  conditions for those portions are met (license text, attribution,
  NOTICE, and the terms around modifications). That is a different thing
  from relicensing the code, which remains unavailable.
- The same permissiveness applies symmetrically: a third party may fork
  and offer a competing service. That was accepted knowingly — see the
  risk as originally framed in [BQ-1](../../blocking-questions.md).
- Work written by or for WeTechi Solutions is unaffected by the limit
  above; a copyright holder can license its own code however it chooses.

## Follow-Up

- **Revisit before the first external contribution is merged.** While the
  contributor list is empty this decision is free to reverse. Once outside
  code lands under Apache-2.0 with no CLA, the relicensing option is
  closed for that code permanently. If WeTechi Solutions wants future
  relicensing flexibility, the CLA decision must be made *before* that
  point, not after.
- Any move toward a source-available or dual-licence model should reopen
  this ADR rather than amend it.
- [license-recommendation.md](../../license-recommendation.md) still
  carries an unresolved legal-verification flag; this ADR records a
  project decision, not legal advice, and does not clear that flag.
