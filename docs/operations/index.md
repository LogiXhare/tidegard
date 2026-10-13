# Operations

Status: Phase 1 skeleton.

NOC operations runbook, incident response runbook, capacity planning,
performance tuning, backup/restore, upgrade/rollback, and troubleshooting
guides will live here. Populated starting with the phases that introduce
the corresponding capability (backup/restore and upgrade/rollback land in
Phase 9; runbooks land alongside Phase 5 incident management and Phase 7
BGP mitigation).

Written so far:

- [Aggregator Monitoring](aggregator-monitoring.md) — Phase 3
- [Detection Monitoring](detection-monitoring.md) — Phase 4: the metrics,
  what to alert on, and the ClickHouse queries worth having
- [Capacity Planning](capacity-planning.md)
- [Incident Runbook](incident-runbook.md) — Phase 5F: operating the
  incident manager, its alerts, and the dead-letter procedure
- [Disaster Recovery](disaster-recovery.md) — Phase 9C: rebuilding a lost
  host from the release tarball and the two backups, as CI does on every
  pull request.
- [Verifying a Release](verifying-a-release.md) — Phase 10A: checking a
  release's signatures, checksums and provenance before installing it
- [Upgrading and Rolling Back](upgrading.md) — Phase 10B: moving to a new
  release, from v0.9.0 on, and back
- [Backup and Restore](backup-and-restore.md) — Phase 5F: the incident
  database, and the drill CI runs on every pull request
- [RTBH Guide](rtbh-guide.md) — Phase 7F: blackholing, and what the edge
  routers must do
- [FlowSpec Guide](flowspec-guide.md) — Phase 7F: discard and rate limit
- [Mitigation Runbook](mitigation-runbook.md) — Phase 7F: the kill switch,
  stale routes, peers down and failed mitigations
