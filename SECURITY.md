# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for a suspected security
vulnerability.**

Report it privately using one of the following:

1. GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
   feature on this repository (Security tab → "Report a vulnerability"),
   once enabled.
2. Email the maintainer directly (contact address to be published here
   once the project has a dedicated security contact — currently route
   through the repository owner, `badshashorif`, via GitHub).

Include, where possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce, or a proof of concept
- The affected component/version (or the affected document/config, if
  the report concerns documentation rather than source)
- Whether you believe this affects the reference lab deployment, a
  production deployment, or the software generically

## Response Process

This project has real, merged, tested source (Phases 0–4 and 5A) but has
not yet cut a versioned release (no Git tag, no GitHub Release) — see
[Project Status](https://github.com/badshashorif/tidegard#readme).
There is no formal SLA for response time yet. Once the first versioned
release ships, this policy will be updated with:

- Acknowledgment time target
- Triage and severity classification (e.g., CVSS-based)
- Fix and disclosure timeline targets
- Supported version policy

## Scope

Tidegard's largest attack surface is the Telemetry Collector, which
parses untrusted UDP input from network exporters (IPFIX/NetFlow/sFlow).
See [docs/security-principles.md](docs/security-principles.md) for the
current threat model. Reports concerning parser safety, template-cache
poisoning, collector DoS, authentication/authorization bypass, tenant
isolation, and BGP mitigation safety are all in scope once the
corresponding component exists.

## Out of Scope (for now)

- Vulnerabilities in third-party dependencies not yet vendored by this
  project (report those upstream) — see
  [docs/dependency-license-matrix.md](docs/dependency-license-matrix.md)
  for what is/isn't actually in use.
- Findings against the reference lab configuration values documented in
  the master prompt (these are placeholders, never production defaults —
  see [docs/non-functional-requirements.md](docs/non-functional-requirements.md) NFR-7).

## Coordinated Disclosure

We ask that you give us reasonable time to investigate and address a
report before any public disclosure. As the project matures, this section
will be expanded with a formal coordinated-disclosure timeline.

## Security Design Principles

See [docs/security-principles.md](docs/security-principles.md) for the
full threat model and the core security principles every phase of this
project is held to (least privilege, secure-by-default BGP mitigation,
no secrets in Git, mandatory fuzzing of protocol parsers, and more).
