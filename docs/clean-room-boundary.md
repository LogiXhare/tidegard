# Clean-Room Boundary

Status: Phase 0 draft — binding for all future phases
Last updated: 2026-08-20

## 1. Statement of Independence

Tidegard is an independently engineered clean-room implementation. It
is built from public specifications, public documentation, and
independently designed schemas and interfaces. It is not a derivative,
port, clone, or reverse-engineered edition of any proprietary product,
named or unnamed.

## 2. Never Do

The following are prohibited at every phase, without exception:

- Copying, reproducing, translating, reconstructing, imitating, or
  decompiling proprietary source code (e.g. FastNetMon Advanced)
- Copying proprietary configuration databases
- Reverse-engineering undocumented proprietary APIs
- Reproducing internal proprietary algorithms
- Copying licensed dashboards or dashboard layouts
- Copying UI layouts or UI terminology
- Copying proprietary table definitions or configuration/command syntax
- Copying proprietary documentation, installation logic, or deployment
  scripts
- Using or referencing confidential operational information from any
  proprietary vendor
- Using the FastNetMon name, logo, trademark, repository identity, package
  name, CLI name, UI terminology, service names, or dashboard identities

## 3. Always Permitted

Standard networking functions may be independently implemented using:

- Public RFCs
- Public protocol specifications
- Vendor documentation
- Publicly documented network operations
- Permissively licensed open-source libraries
- Independently designed schemas and interfaces

Examples of functions that fall in this category: NetFlow v5/v9 decoding,
IPFIX decoding, sFlow decoding, sampling correction, traffic aggregation,
moving averages, static threshold detection, statistical anomaly detection,
BGP RTBH, BGP FlowSpec, Prometheus metrics, ClickHouse storage, InfluxDB
compatibility, Grafana dashboards, REST APIs, gRPC APIs, webhook
notifications.

## 4. Required Product Description

All product-facing text must use:

> "Tidegard is an independently engineered open network telemetry,
> DDoS detection, traffic analytics, and policy-controlled mitigation
> platform."

Never: "clone", "replica", "copy", "alternative build", "reverse-engineered
edition", or "replacement edition" of any named or unnamed proprietary
product.

## 5. Dependency Vetting Process

Before adding any third-party dependency, a dependency record must be
created (see [dependency-license-matrix.md](dependency-license-matrix.md))
containing:

1. Project name
2. Selected version
3. Upstream repository
4. License
5. Copyright notice requirements
6. Purpose
7. Integration method
8. Static or dynamic linking implications
9. Commercial distribution implications
10. Source-code disclosure obligations
11. Security maintenance status
12. Approved or rejected decision

License information must never be fabricated. Uncertain license status is
marked `REQUIRES VERIFICATION` and treated as blocking for commercial
distribution until resolved.

## 6. Enforcement in Process

- Every pull request that adds a networking protocol implementation,
  detection algorithm, dashboard, or CLI surface must self-certify against
  this document (checklist to be added to the PR template in Phase 1).
- Any contributor (human or agent) who has had direct access to proprietary
  FastNetMon Advanced source, configuration, or confidential documentation
  must not author Tidegard protocol, detection, dashboard, or CLI code.
  This charter assumes no such access has occurred or will occur; if that
  assumption is ever false, treat it as a blocking legal question, not an
  engineering one.
- Naming, CLI command surface, and dashboard identity must be independently
  designed — see [naming-and-branding.md](naming-and-branding.md).

## 7. Escalation

Any ambiguity about whether a specific implementation choice crosses this
boundary is a **blocking question** (see
[blocking-questions.md](blocking-questions.md)), not an engineering
judgment call to be resolved silently.
