# Installation

Status: Phase 9A.

- **From the release tarball:** `install.sh` puts the binaries, the web
  UI, one system user per service, the example settings and hardened
  systemd units in place
  ([systemd deployment](https://github.com/LogiXhare/tidegard/tree/main/deployments/systemd)).
  Then follow the guides below from the database onward.
- **With Docker Compose:** one image per service and a reference stack
  with PostgreSQL and ClickHouse, TLS between every container, started
  by `setup.sh` and `docker compose up`
  ([Compose stack](https://github.com/LogiXhare/tidegard/tree/main/deployments/docker-compose)).
- [Incident Management](incident-management.md): a single-node
  installation with the collector, the incident manager, the API and the
  CLI against PostgreSQL. It builds from source; with the tarball, skip
  the build.
- [BGP Mitigation](mitigation.md): the mitigator and its `gobgpd`, added
  to that installation, turned on in stages from dry-run.

Kubernetes manifests and a Helm chart are not part of v1.0.0
([ADR 0052](../architecture/decisions/0052-phase9a-packaging.md)). For a
contributor setup, see [local setup](../development/local-setup.md).
