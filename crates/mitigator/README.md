# wetechinetmon-mitigator

The only code in WetechiNetMon that speaks to GoBGP
([ADR 0048](../../docs/architecture/decisions/0048-phase7c-gobgp-adapter.md)).
GoBGP runs as its own process, `gobgpd`; this crate is a client of its
gRPC API, generated from the vendored `.proto` files in `proto/`
(GoBGP v4.9.0) with `protox`, so no `protoc` is needed.

- `route`: the deployment's route attributes, the path for each action,
  the ownership community, and reading a path back into its mitigation.
- `gobgp`: the connection (plain HTTP to loopback only; TLS with a CA,
  and optionally a client certificate, anywhere else), announce,
  withdraw, and the routes WetechiNetMon owns.

Nothing here decides whether to mitigate: that is the mitigation record,
its approval and the safety guard (`crates/mitigation`).

```sh
cargo test -p wetechinetmon-mitigator
# The lab test needs a throwaway gobgpd on loopback:
WETECHINETMON_GOBGP_TEST_ENDPOINT=http://127.0.0.1:50051 cargo test -p wetechinetmon-mitigator --test gobgp_lab
```
