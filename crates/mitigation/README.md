# wetechinetmon-mitigation

The mitigation domain: a mitigation's record, its states and the commands
that move it ([ADR 0046](../../docs/architecture/decisions/0046-phase7a-mitigation-record.md)).

Pure: no database, no BGP, no network. The dependency closure test holds
it to a reviewed allowlist. Persistence is in
[`crates/incident-postgres`](../incident-postgres) (`src/mitigation.rs`,
migration V19). Talking to GoBGP is the mitigator's alone
(`crates/mitigator`, Phase 7C).

- `prefix`: canonical IPv4 and IPv6 prefixes.
- `action`: RTBH, parent prefix, FlowSpec discard and rate-limit (BQ-15).
- `state`: the lifecycle; nothing reaches a route without approval.
- `mitigation`: request, propose, approve, reject, withdraw, and the
  mitigator's steps, each authorized and versioned.

```sh
cargo test -p wetechinetmon-mitigation
```
