# 0053. Phase 9A The Collector's ClickHouse Connection

Status: **Accepted**
Date: 2026-10-12
Deciders: Repository owner (BQ-16, 2026-10-12); the details under the
delegation of 2026-10-05 to industry practice

## Context

Packaging the services for containers (9A-3,
[ADR 0052](0052-phase9a-packaging.md)) put the collector and ClickHouse
on different hosts of a container network for the first time. The
collector's export, written in Phase 3, then had three gaps the API's
ClickHouse connection
([ADR 0042](0042-phase6b-traffic-read-api.md)) never had:

- **No TLS.** The `clickhouse` crate was built without a TLS feature, so
  flows went over plain HTTP to wherever the URL pointed.
- **No credentials.** The collector always used ClickHouse's `default`
  user without a password.
- **No loopback rule.** Nothing refused plain HTTP to another host. Every
  other connection in WetechiNetMon refuses it: the incident database,
  the API's listener and the API's ClickHouse connection.

## Decision

### The same rule as everywhere else

The collector refuses to start when its ClickHouse settings could send
flows in plaintext off the machine:

| URL | Accepted when |
|---|---|
| `http://host:port` | `host` is `localhost` or a loopback address |
| `https://host:port` | `WETECHINETMON_COLLECTOR_CLICKHOUSE_CA_FILE` is set |

A URL holding credentials, a path or a query is refused, so a password
can never reach a log by way of the URL. Logs show only the scheme, host
and port.

The URL parser and the loopback test move from the API into
`wetechinetmon-common` (`http_endpoint`), and the API re-exports them
unchanged, so both connections apply exactly one rule.

### Credentials

`WETECHINETMON_COLLECTOR_CLICKHOUSE_USER` and
`WETECHINETMON_COLLECTOR_CLICKHOUSE_PASSWORD_FILE`, as the API has. The
password is read from its file at startup, never from the environment.

### TLS

`https://` builds a `hyper-rustls` connector from a rustls configuration
whose only roots are the configured CA bundle, on the `aws-lc-rs`
provider the rest of the workspace uses. It is handed to the
`clickhouse` crate through `Client::with_http_client`, with the same TCP
keepalive and pool idle timeout as the crate's own client. `hyper-rustls`
0.27.10 is the one new crate in `Cargo.lock`, with its native and webpki
root stores off (row 51 of the
[dependency licence matrix](../../dependency-license-matrix.md)).

### Failure at startup

As before, if ClickHouse cannot be reached or migrated, the collector
logs an error and runs without export. Decoding, aggregation and
detection do not depend on it. A configuration that breaks the rule above
is different: it stops the collector, because it is a mistake to fix,
not a condition to wait out.

## Consequences

- An existing installation with an `http://` URL to another host stops
  at startup after upgrading. The upgrade notes must say so: switch to
  `https://` with a CA bundle, or run ClickHouse on the same host.
- The Compose stack (9A-3) runs ClickHouse with TLS and a collector user.
- The plaintext export this replaces is recorded in the 9D security
  review as a finding fixed before v1.0.0.

## Alternatives considered

- **The `clickhouse` crate's `rustls-tls` feature.** It trusts the
  system's or Mozilla's roots, and has no setting for a deployment's own
  CA, which is how every other WetechiNetMon connection verifies its
  server.
- **A hand-written TLS connector** over `tokio-rustls`, already in the
  tree. It would avoid one crate, but means maintaining an implementation
  of hyper-util's `Connect` trait that `hyper-rustls` already provides
  and maintains.
- **Upgrading the `clickhouse` crate first (FU-6).** It does not change
  the TLS question, and would mix a risky upgrade into a security fix.
