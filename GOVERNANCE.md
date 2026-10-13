# Governance

Status: Phase 1 — initial governance model for a founder-led, pre-v1.0
project. Expected to evolve as the contributor base grows.

## Current Model

Tidegard is currently steered directly by **WeTechi Solutions**,
represented by the repository owner. This is a founder-led model, not a
foundation or multi-vendor consortium model. There is currently one
maintainer group (see [CODEOWNERS](.github/CODEOWNERS)).

## Decision Authority

| Decision type | Authority |
|---|---|
| Product identity, naming, branding | WeTechi Solutions (recorded in [docs/naming-and-branding.md](docs/naming-and-branding.md)) |
| License selection | WeTechi Solutions, ideally with legal counsel (currently open — see [docs/blocking-questions.md](docs/blocking-questions.md) BQ-1) |
| Architecture decisions | Recorded as ADRs (see [docs/architecture/decisions/index.md](docs/architecture/decisions/index.md)); proposed by any contributor, approved by a maintainer |
| Scope/roadmap changes | Maintainer approval, reflected in [docs/roadmap.md](docs/roadmap.md) and [ROADMAP.md](ROADMAP.md) |
| Security response | Maintainer, per [SECURITY.md](SECURITY.md) |
| Code review / merge | Maintainer(s) listed in [CODEOWNERS](.github/CODEOWNERS) |

## Phased Delivery Governs Scope

No phase begins until the prior phase has documented output, acceptance
criteria, passing required tests, a summary, an explicit decision record,
a commit, and updated documentation — see
[docs/roadmap.md](docs/roadmap.md) and `prompts/CLAUDE_MASTER_PROMPT.md`
§29. This applies equally to human and AI-agent contributions.

## Escalation

Ambiguity about whether a contribution crosses the clean-room boundary
(see [docs/clean-room-boundary.md](docs/clean-room-boundary.md) §7), or
any other question that materially affects legal, licensing, or security
posture, is escalated to WeTechi Solutions directly rather than resolved
unilaterally by a contributor or automated agent.

## Evolution of This Document

As the contributor community grows beyond WeTechi Solutions' internal
team, this document will be revisited to define a more formal maintainer
nomination process, voting/consensus model, and possibly a technical
steering committee. No such structure exists yet — do not assume one.
