# Local Prefix Configuration

Status: Phase 3. See [../architecture/direction-classification.md](../architecture/direction-classification.md)
for the design behind this.

## `TIDEGARD_COLLECTOR_LOCAL_PREFIXES`

| Field | Value |
|---|---|
| Type | Comma-separated list of `network/prefix_len[@tenant[@hostgroup]]` entries |
| Default | Empty (no local prefixes — every flow classifies as `Unknown`) |
| Allowed values | Valid IPv4 or IPv6 network + prefix length; `tenant` defaults to `"default"`; `hostgroup` defaults to none |
| Example | `TIDEGARD_COLLECTOR_LOCAL_PREFIXES=10.0.0.0/8@wetechi@core,2001:db8::/32@wetechi@core-v6` |
| Security implications | None directly — this is classification metadata, not an access-control boundary |
| Reload requirement | Restart required — read once at process startup |
| Related metrics | `tidegard_collector_prefix_lookup_failures_total`, `tidegard_collector_classified_flows_by_direction_total{direction="unknown"}` |
| Verification command | `curl -s http://<metrics_bind>/metrics \| grep classified_flows_by_direction` after sending known-local/known-external test traffic via `tools/flow-replay` |
| Troubleshooting | An invalid entry (bad prefix length, unparseable address) causes the collector to log the bad entry and start with an otherwise-valid registry (or empty, if every entry is bad) — check startup logs for `invalid local-prefix configuration entry` |

## Why `@` and Not `:`

IPv6 addresses contain colons. A format like `network/len:tenant:hostgroup`
would make `2001:db8::/32:tenant` genuinely ambiguous to parse correctly.
`@` was chosen specifically because it cannot appear in an IP address,
prefix length, tenant name, or hostgroup name in any of this project's
current usage.

## Duplicate and Overlap Handling

- An **exact duplicate** (same network and prefix length appearing twice)
  is a hard configuration error — the collector logs it and drops that
  entry from the registry (see `crates/collector/src/lib.rs`
  `build_registry` error handling).
- An **overlap** (e.g. `10.0.0.0/8` and `10.0.0.0/24` both configured) is
  expected and valid — it's how you express "this /8 is generally ours,
  this /24 within it belongs to a specific tenant/hostgroup." Overlaps
  are logged as warnings at startup, not rejected.

## What Happens With No Prefixes Configured

Every flow classifies as `Direction::Unknown`
(`tidegard_collector_prefix_lookup_failures_total` increments for
each one). The collector still runs, decodes, normalizes, and aggregates
— direction classification is the only thing degraded. This is
deliberate: a misconfigured or not-yet-configured prefix list shouldn't
prevent the collector from being useful for raw traffic totals.

## Full Reference Example

```bash
export TIDEGARD_COLLECTOR_LOCAL_PREFIXES="10.0.0.0/8@wetechi@core,203.0.113.0/24@wetechi@collector-segment,2001:db8::/32@wetechi@core-v6"
```

## Known Limitations

- No config-file support yet (env var only) — see
  [aggregation.md](aggregation.md) and
  `docs/development/local-setup.md` for why. A real Configuration
  Service (`crates/configuration`, not yet built) will replace this.
- No hot-reload — changing prefixes requires a collector restart.
