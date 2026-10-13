# Commercial Deployment Guide

Status: **Phase 10B**, 2026-10-13. Covers the **Community Edition as
built** in v1.0.0. The Enterprise and Managed editions in
[commercial boundaries](../commercial-boundaries.md) remain proposals:
nothing here describes them as available.

For WeTechi Solutions, and for anyone else, deploying WetechiNetMon for a
paying customer: what the product is, the ways to deploy it, what to
size, and who is responsible for what. It is a technical guide, not a
contract: it sets no price and no service level.

## What v1.0.0 is

- IPFIX flow collection, classification by the customer's prefixes,
  aggregation per host, network, hostgroup, ASN, exporter and interface,
  and history in ClickHouse.
- Static threshold detection per tenant, and an incident lifecycle with
  notes, assignment, an audit trail and notifications.
- Manual, approved BGP mitigation: RTBH, a parent-prefix blackhole and
  FlowSpec, through GoBGP, dry-run until turned on.
- A REST API, a CLI, a NOC UI, Prometheus metrics and Grafana
  dashboards.

What it is not yet is in [known issues](../release/known-issues.md).

## Licence

WetechiNetMon is Apache-2.0 (BQ-1). You may run, modify and redistribute
it, commercially included. When you redistribute it, keep `LICENSE`,
`NOTICE` and the third-party notices the release carries
(`THIRD-PARTY-NOTICES.txt` and `THIRD-PARTY-NOTICES-WEB.txt`). Grafana,
if you ship it with the dashboards, is AGPL-3.0 and is a separate
product: see the [dependency licence matrix](../dependency-license-matrix.md).

## Ways to deploy it

| Model | How | Suits |
|---|---|---|
| **On the customer's premises** | The release tarball on a host the customer owns, or the Compose stack | A customer who keeps their flow data in house |
| **Hosted for one customer** | One deployment per customer on infrastructure you run | Customers who need isolation a database administrator cannot cross |
| **Hosted for several customers** | One deployment, one tenant per customer, operated by your NOC | Managed monitoring where only your staff hold lead roles; see [onboarding](../operations/customer-onboarding.md) for the limits |

Every model is one node per deployment in v1.0.0.

## Sizing

Measured on a 4-core GitHub runner
([capacity planning](../operations/capacity-planning.md)): the collector
took 200,000 flow records a second without loss in 13 MiB, and five
hours at 50,000 without memory growth. Size from the customer's flow
rate (records per second after sampling), their number of hosts, and how
long they keep history:

- **Collector:** one core per 200,000 records a second leaves room;
  memory is bounded by its settings, not by traffic.
- **PostgreSQL:** small; incidents, not flows.
- **ClickHouse:** most of the disk. Traffic is kept 30 days and detection
  events 365; disk grows with active hosts and networks, not with the
  raw flow rate.

Measure a pilot customer's own traffic before committing to a size.

## Who is responsible for what

| Area | Operator of the deployment | WetechiNetMon provides |
|---|---|---|
| Host, operating system, firewall | Yes | Hardened units and images |
| PostgreSQL and ClickHouse | Yes: install, TLS, backups | Backup and restore procedures, drilled in CI |
| Upgrades | Yes: schedule and run | [Upgrading and rolling back](../operations/upgrading.md), drilled in CI |
| Routers' IPFIX and BGP | The network owner | The collector and the mitigator's guard |
| Approving a mitigation | The network owner's NOC lead | The approval workflow and audit trail |
| Verifying what you install | Yes | [Signed releases with provenance](../operations/verifying-a-release.md) |
| Vulnerability reports | Report them | The [security policy](../security/security-policy.md) |

## Before going live

Work through the [production checklist](../release/production-checklist.md)
for the deployment, not only for the release: backups taken and restored
once, TLS on every connection off the host, the exporter allowlist set,
alerts reaching someone, and mitigation still dry-run until the customer
and you agree to turn it on.
