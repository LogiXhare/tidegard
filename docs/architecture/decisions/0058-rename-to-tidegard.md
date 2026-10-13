# 0058. The Product Is Renamed Tidegard

Status: **Accepted**
Date: 2026-10-13
Deciders: Repository owner (2026-10-13: "Tidegard a rename kro"), after
comparing names for a global brand; the details under the delegation of
2026-10-05 to industry practice

## Context

The product was named WetechiNetMon in Phase 0. Before its first public
release, the owner chose a name that works as a global brand: short,
pronounceable in any language, free of the company's name, and far from
any competitor's. Candidates were checked for a product of the same name,
domains and GitHub; most names built on *flow*, *fast*, *net* or *guard*
are already taken in this market. Tidegard had none of those conflicts,
and tidegard.com, .io and .net were unregistered.

v1.0.0-rc.1 had been tagged but not published: its release run was
cancelled before the publish job, so no release, image or signature
carries the old name.

## Decision

Rename everything that names the product, before the first release:

| What | Was | Is |
|---|---|---|
| Product | WetechiNetMon | Tidegard |
| Crates and binaries | `wetechinetmon-*`, `wetechinetmonctl` | `tidegard-*`, `tidegardctl` |
| Settings | `WETECHINETMON_*` | `TIDEGARD_*` |
| Metrics | `wetechinetmon_*` | `tidegard_*` |
| Images | `ghcr.io/logixhare/wetechinetmon-*` | `ghcr.io/logixhare/tidegard-*` |
| Installed files, users, units | `/opt/wetechinetmon`, `/etc/wetechinetmon`, `wetechinetmon-*` | `/opt/tidegard`, `/etc/tidegard`, `tidegard-*` |
| Repository | `LogiXhare/wetechi-netmon` | `LogiXhare/tidegard` (GitHub redirects the old URL) |

**Old settings keep working.** Every service reads `TIDEGARD_X`, and
when it is unset, `WETECHINETMON_X`, with a warning naming both
(`tidegard_common::env`). This lasts through the 1.x series, so a
settings file written for v0.9.0 survives the upgrade. The upgrade drill
runs v0.9.0 and the candidate on the same old-named settings, which
proves it.

**Some identifiers keep the first name**, because changing them would
lose data or break what already depends on them:

- the PostgreSQL role `wetechinetmon_app`: migration V11 creates it, and
  an applied migration is never edited (ADR 0024);
- the ClickHouse tables `wetechinetmon_*`: new names would leave the
  history in tables nothing reads;
- the API token prefix `wnm_` and the webhook headers `X-WNM-*`: issued
  tokens and receivers that verify signatures depend on them.

The architecture decision records keep their content; the product's name
in them is updated, as it is everywhere else.

## Consequences

- The release is published as Tidegard from its first candidate.
- Prometheus queries and alert rules written against `wetechinetmon_*`
  metrics must be renamed; the shipped dashboards already are.
- An installation from a v0.9.0 build moves to the packaged layout
  anyway (Upgrading), and now under the new paths.
- The old settings prefix is removed in 2.0.0, with a notice in the 1.x
  release notes before then.

## Alternatives considered

- **Keeping WetechiNetMon.** It ties the product to the company's name
  and reads as a variant of other "NetMon" products, which the
  clean-room boundary would rather avoid.
- **Renaming the database role and tables too**, with migrations. It
  would mean a migration that moves every ClickHouse table's data, and
  editing or superseding V11, for no gain an operator can see.
- **No fallback for the old settings.** Simpler, but every upgrade would
  stop until each settings file was renamed by hand.
