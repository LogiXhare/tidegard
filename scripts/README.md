# Scripts

Helper scripts that CI runs and that operators can run too.

| Script | What it does |
|---|---|
| [`postgres-backup-restore-drill.sh`](postgres-backup-restore-drill.sh) | The incident database's backup and restore drill (Phase 5F). It needs the ephemeral test database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL` and must never point at a real one. See [docs/operations/backup-and-restore.md](../docs/operations/backup-and-restore.md). |
