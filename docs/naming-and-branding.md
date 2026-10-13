# Naming and Branding

Status: binding decision; product renamed 2026-10-13
([ADR 0058](architecture/decisions/0058-rename-to-tidegard.md))
Last updated: 2026-10-13

## Approved Identity

| Item | Value |
|---|---|
| Company | WeTechi Solutions |
| Product | Tidegard (was WetechiNetMon until 1.0.0-rc.1) |
| Core detection/analytics engine | SentinelFlow Engine |
| CLI | `tidegardctl` |
| Tagline | "See Every Flow. Defend Every Network." |
| Repository | `LogiXhare/tidegard` |
| Service namespace | `tidegard` |
| Settings prefix | `TIDEGARD_` (the old `WETECHINETMON_` still read through 1.x) |

The name: a tide is what a flood of traffic is, and *gard* is the old
Norse word for an enclosure kept safe, as in Asgard. Pronounced
"tide-guard".

## Container Images

- `ghcr.io/logixhare/tidegard-collector`
- `ghcr.io/logixhare/tidegard-incident-manager`
- `ghcr.io/logixhare/tidegard-api`
- `ghcr.io/logixhare/tidegard-notifier`
- `ghcr.io/logixhare/tidegard-mitigator`

## Identifiers that keep the first name

Renaming these would lose data or break what already depends on them, so
they stay (ADR 0058):

- the PostgreSQL role `wetechinetmon_app`, created by migration V11, which
  is never edited;
- the ClickHouse tables, `wetechinetmon_*`, which hold the history;
- the API token prefix `wnm_` and the webhook headers `X-WNM-*`.

## Rationale

- All names are original to WeTechi Solutions and do not reuse any
  proprietary vendor's name, trademark, repository identity, package name,
  CLI name, UI terminology, service name, or dashboard identity — per the
  clean-room boundary (see [clean-room-boundary.md](clean-room-boundary.md)).
- `tidegardctl` (rather than any shortened form resembling a known
  competitor's CLI name) makes the product/company relationship obvious
  and avoids any naming collision or confusable-similarity risk.
- "SentinelFlow Engine" is used specifically for the detection/analytics
  core, distinct from the product name, to allow independent evolution
  (and potential separate licensing/packaging) of the detection engine
  from the rest of the platform.

## Rules for All Future Contributors (Human or Agent)

1. Never use "FastNetMon" or any other proprietary product's name, in code,
   comments, commit messages, documentation, UI strings, dashboard titles,
   metric names, or CLI help text — including as a comparison ("like X",
   "compatible with X's config format").
2. Never describe Tidegard as a clone, replica, copy, alternative
   build, reverse-engineered edition, or replacement edition of any
   product, named or unnamed.
3. Always use the approved product description from
   [clean-room-boundary.md](clean-room-boundary.md) in product-facing
   copy.
4. Dashboard UIDs, panel layouts, table names, and CLI command names must
   be independently designed, not copied from any reference product's
   documentation or screenshots.
5. Any proposed new branded sub-component name (e.g., a future module)
   should follow the short coined-word style of "Tidegard" or the
   `<Descriptive><Noun> Engine` pattern of "SentinelFlow Engine" —
   this is a style convention, not a hard rule, and can be revisited.

## Trademark Note

This document records a naming *decision*, not a trademark clearance. On
2026-10-13 a web, domain and GitHub search found no product named
Tidegard, and tidegard.com, .io and .net unregistered; that is not a
trademark search. If WeTechi
Solutions intends to register "Tidegard," "SentinelFlow," or
"tidegardctl" as a trademark, a proper trademark clearance search is
recommended before public launch — this is noted for awareness, not
treated as a Phase 0 blocking question, since it doesn't block engineering
work.
