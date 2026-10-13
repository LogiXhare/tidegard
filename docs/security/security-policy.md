# Security Policy

Status: summary page. The authoritative document is `SECURITY.md` at the
repository root —
[read it on GitHub](https://github.com/badshashorif/tidegard/blob/main/SECURITY.md).
This page exists so the documentation site can link to the reporting
process without pointing outside the documentation tree.

## Reporting a Vulnerability

**Do not open a public GitHub issue for a suspected security
vulnerability.** Report it privately, either through GitHub's
[private vulnerability reporting](https://github.com/badshashorif/tidegard/security/advisories/new)
on this repository, or by contacting the repository owner
(`badshashorif`) through GitHub until a dedicated security contact is
published.

Include, where you can: what the vulnerability is and its impact, steps
to reproduce or a proof of concept, the affected component or version,
and whether you believe it affects the reference lab deployment, a
production deployment, or the software generically.

## Response Process

The project is pre-release, so there is no response-time SLA yet. Once
the first software release ships (targeting v0.2.0, the IPFIX collector
MVP), the root `SECURITY.md` gains acknowledgment targets, severity
classification, fix and disclosure timelines, and a supported-version
policy.

## Scope

The largest attack surface is the Telemetry Collector, which parses
untrusted UDP input from network exporters (IPFIX/NetFlow/sFlow). Parser
safety, template-cache poisoning, collector denial of service,
authentication and authorization bypass, tenant isolation, and BGP
mitigation safety are all in scope once the corresponding component
exists. See [Security Principles](../security-principles.md) for the
current threat model.

Out of scope for now: vulnerabilities in third-party dependencies this
project has not vendored (report those upstream — see the
[Dependency License Matrix](../dependency-license-matrix.md) for what is
actually in use), and findings against documented reference-lab
configuration values, which are placeholders rather than production
defaults.

## Coordinated Disclosure

Please allow reasonable time to investigate and address a report before
disclosing it publicly. A formal coordinated-disclosure timeline will be
added as the project matures.
