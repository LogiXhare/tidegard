# Contributing

Status: summary page. The authoritative document is `CONTRIBUTING.md` at
the repository root —
[read it on GitHub](https://github.com/badshashorif/tidegard/blob/main/CONTRIBUTING.md).
This page exists so the documentation site can link to the contribution
process without pointing outside the documentation tree.

## Before You Start

Read [Clean-Room Boundary](../clean-room-boundary.md) in full — it is not
optional. Contributions that copy, translate, or closely imitate any
proprietary product's code, schemas, configuration syntax, CLI syntax,
dashboards, or documentation are rejected regardless of how useful they
are. Read [Security Principles](../security-principles.md) too,
especially the rules around BGP mitigation safety.

Check the [Roadmap](../roadmap.md) for the current phase. Work ahead of
that phase's scope is usually deferred rather than rejected — open an
issue to discuss timing first.

## Licensing and Sign-Off

The project is Apache-2.0 and contributions are accepted under that same
licence. Every non-merge commit needs a Developer Certificate of Origin
sign-off:

```bash
git commit -s -m "feat(phase4): add hysteresis to threshold detection"
```

There is no CLA. The reasoning, and what the DCO does and does not grant,
is recorded in
[ADR 0006](../architecture/decisions/0006-contribution-licensing-dco-not-cla.md).

## Working Locally

See [Local Development Setup](local-setup.md), and enable the repository
hooks once per clone with `make hooks` so the Rust gate runs before every
push.

## Commits and Pull Requests

Commits follow [Conventional Commits](https://www.conventionalcommits.org/)
— `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`, `build`,
`perf`, `security`. Branch from `main` with a descriptive name.

Every pull request must update documentation in the same PR, include
tests for new behaviour, self-certify against the clean-room boundary
using the PR template checklist, carry DCO sign-off on every commit, and
pass validation CI. Prefer several small pull requests over one large
one.

New third-party dependencies need a row in the
[Dependency License Matrix](../dependency-license-matrix.md) before they
reach a build manifest. Hard-to-reverse technical decisions need an
[Architecture Decision Record](../architecture/decisions/index.md) first.

## Reporting Rules

These apply to every contributor, human or AI agent: never claim tests
passed unless they were executed, never fabricate benchmark or security
results, never enable production BGP by default, never commit secrets or
real customer data, never generate real DDoS traffic, and mark unverified
assumptions as unverified rather than presenting them as fact.
