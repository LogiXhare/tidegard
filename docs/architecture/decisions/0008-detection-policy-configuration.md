# 0008. Detection Policy Configuration: JSON, Not YAML

Status: Accepted
Date: 2026-08-22
Deciders: WeTechi Solutions (badshashorif)

## Context

Detection policies are the first thing in Tidegard an operator
writes by hand. Everything configured so far — bind addresses, map
caps, local prefixes — fits in environment variables, which is why the
collector has [no config file at all](../../configuration/index.md). A
policy does not: it has nested selectors, a map of thresholds, and half
a dozen durations, and there will be dozens of them.

So Phase 4 needs a document format. The obvious answer for an
operator-facing file is YAML.

## Options Considered

### Option A — YAML

What operators expect, and what comparable products use. Comments,
anchors, no quoting noise.

The problem is the Rust ecosystem's supply. As of this decision:

| Crate | Latest version | Last release | Note |
|---|---|---|---|
| `serde_yaml` | `0.9.34+deprecated` | 2024-03 | Deprecated by its own author; the version string says so |
| `serde_yaml_ng` | 0.10.x | 2024-05 | Fork, small release history |
| `serde_norway` | 0.9.x | 2024-12 | Fork, small release history |
| `serde_yml` | `0.0.13` | — | Below 0.1.0 |

A configuration parser is a parser for attacker-adjacent input in the
general case, and a permanent dependency in every case. Taking on a
deprecated or thinly-maintained one, for files whose schema this project
fully controls, is a poor trade — and this project has kept its
dependency list deliberately short (see
[dependency-license-matrix.md](../../dependency-license-matrix.md)).

### Option B — JSON via `serde_json`

Already in the dependency tree. Maintained by the same people as
`serde`. No new dependency at all.

The cost is real: no comments, and quoting noise. Operators dislike
writing JSON by hand, and a policy file is exactly the kind of file
someone wants to annotate with "raised for the March incident".

### Option C — TOML

Also well-maintained, also comment-friendly. But TOML's nested-table
syntax is awkward for a list of objects each containing a map, which is
precisely the shape of a policy document. It would add a dependency to
get a worse fit than JSON for this data.

### Option D — A bespoke format

Rejected without further analysis. A hand-written parser for
configuration is a category of bug this project does not need.

## Decision

**Option B**, with the format deliberately isolated.

- `PolicyDocument` is a plain data structure carrying no format
  knowledge. `PolicyDocument::from_json` is one constructor; adding
  `from_yaml` when a maintained crate exists is the entire change
  required, and no validation, defaulting, or compilation logic moves.
- Every structure is `deny_unknown_fields`. An operator who writes
  `trigger_for` where the schema says `triggerFor` gets a parse failure
  naming the field — not a policy that quietly takes the default and
  never fires. This is the single most valuable property of the format
  choice and is worth more than comments.
- Durations require a unit suffix (`"30s"`, `"250ms"`, `"5m"`). A bare
  number is refused, because `triggerFor: 300` reads as five minutes to
  one operator and three hundred milliseconds to another and both are
  plausible.
- Thresholds accept a decimal magnitude suffix (`"10G"`), because an
  operator asked to type `10000000000` will eventually type it with one
  zero too few.

## Consequences

**Good.** Zero new dependencies for the whole of Phase 4's configuration
surface.

**Good.** The typo-is-an-error property catches the failure mode that
actually hurts: a policy that loads successfully and does nothing.

**Cost.** No comments in the policy file. Operators who need to annotate
a threshold must do it in the `description` field or in whatever manages
the file. This is a genuine loss and the main reason to revisit.

**Cost.** JSON is more tedious to write than YAML, particularly for a
file with many similar policies. The `defaults` block exists partly to
reduce that: values common to every policy are written once.

**Revisit when** a YAML crate exists with an active maintainer and a
release history longer than a year. The seam is already there;
`from_yaml` is a small addition, and the schema does not change.
