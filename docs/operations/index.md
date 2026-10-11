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
- [Backup and Restore](backup-and-restore.md) — Phase 5F: the incident
  database, and the drill CI runs on every pull request
