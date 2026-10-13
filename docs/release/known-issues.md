# Known Issues and Limitations

Status: **v1.0.0**, 2026-10-13.

What v1.0.0 does not do, or does only in part, so you can plan around
it. Each item names the record that tracks it. Nothing here is a known
Critical or High security issue: the
[security review](../security/security-review.md) has none open.

## By design in v1.0.0

- **One node.** Every service runs on one host, against one PostgreSQL
  and one ClickHouse. There is no clustering or failover; the
  [disaster recovery runbook](../operations/disaster-recovery.md) rebuilds
  a lost host from backups.
- **IPFIX only.** The collector decodes IPFIX (RFC 7011). NetFlow v5 and
  v9 and sFlow are not implemented.
- **No automatic mitigation.** Every mitigation needs a person to
  request it and, by default, another to approve it (BQ-17). The
  mitigator starts dry-run with BGP off.
- **No queue in front of the collector.** Flows that arrive while it is
  stopped, or faster than the
  [measured rate](../operations/capacity-planning.md), are dropped by
  the kernel.

## Multi-tenancy (Phase 8, v1.1.0)

- **Tenant isolation is enforced by the application**, not yet by
  PostgreSQL row-level security. The roles RLS needs exist (V11); the
  policies come with Phase 8 (risk R16).
- **An assignee is not checked against a user directory**: there is
  none yet. Naming someone grants them nothing (T-21, FU-60).
- **Deployment-wide mitigation controls** (the kill switch, the BGP peer
  list) are open to every tenant's NOC leads (FU-65).

## Smaller gaps

| Issue | Effect | Record |
|---|---|---|
| The Compose stack's collector and API share one ClickHouse user | The API's credential could write, though it never does | FU-66 |
| A detection event counts its exporters but does not name them | Tracing forged flows needs the collector's logs | FU-67 |
| An IPFIX sequence number that wraps past 2³² reads as an exporter restart | That exporter's templates are cleared, and its data is unknown until it resends them, as often as its template refresh interval | `crates/collector/src/exporter.rs` |
| The kernel's UDP receive-buffer drops are not exported as a metric | Read them with `netstat -su` or `nstat` | `crates/collector/src/metrics.rs` |
| `GET /api/v1/incidents/{id}` serves part of the planned representation | Some planned fields are absent | FU-54 |
| Acknowledging takes no note | Add a note separately | FU-55 |
| An incident's title and description cannot be edited | They stay as detection set them | FU-56 |
| The CLI trusts only an explicit CA bundle, not the system store | Set `TIDEGARD_API_CA_FILE` | FU-57 |
| Every incident uses one staleness timeout | Not tunable per policy | FU-51 |
| The backup drill restores a logical dump within one cluster | Point-in-time recovery is documented, not drilled | FU-61 |
