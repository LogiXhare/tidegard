# Local Development Setup

Status: Phase 2 — the Rust workspace (collector + IPFIX parser) is
runnable. The web app (Phase 6) and other tooling are still ahead.

## What You Can Do Today

1. Build, test, lint, and run the Rust workspace (collector, IPFIX
   parser, flow-replay tool)
2. Validate Markdown formatting
3. Validate YAML syntax (workflows, Dependabot, issue templates)
4. Preview the documentation site (requires Python + MkDocs Material)

## Prerequisites

| Tool | Used for | Required now? |
|---|---|---|
| Git | Version control | Yes |
| Rust (`cargo`/`rustc`/`rustfmt`/`clippy`) | Building/testing `crates/`, `tools/flow-replay` | Yes |
| A C linker toolchain for your Rust target (see Windows note below) | Linking Rust binaries | Yes, platform-dependent |
| Node.js + npm (npx) | Markdown/YAML linting via `npx` | Yes |
| Python 3.10+ and `pip` | MkDocs Material site build/preview | Only if previewing docs site |
| GitHub CLI (`gh`) | Optional, for PRs/issues from the terminal | No |

Node build tooling for the web app and container tooling are **not**
required yet — they become relevant starting Phase 6 (web app) and this
document will be updated when that happens.

### Installing Rust

Any standard Rust install works (`rustup`, a distro package, etc.) —
this repository doesn't require a specific installation method. What
matters is that `cargo`, `rustc`, `rustfmt`, and `clippy` are all on
`PATH`, and that you have a working linker for your target.

**Windows-specific note:** if you install a **GNU-target** Rust
toolchain (`x86_64-pc-windows-gnu`) rather than the MSVC-target one, you
also need a real MinGW-w64 toolchain with GNU Binutils (`as`, `ar`,
`dlltool`, `ld`) on `PATH` — the small "self-contained" linker subset
some Rust GNU installers bundle is linker-only and is **not** enough by
itself (crates like `windows-sys` need `dlltool` to generate import
libraries, which in turn needs a full binutils, not just `dlltool.exe` on
its own). A verified-working option:
[WinLibs](https://winlibs.com/) (`winget install BrechtSanders.WinLibs.POSIX.UCRT`),
with its `mingw64\bin` directory added to `PATH`. If you install the
**MSVC-target** toolchain instead, you need the Visual Studio C++ Build
Tools instead of MinGW — that trade-off (smaller MinGW download vs.
larger, more "standard on Windows" MSVC Build Tools) is a per-contributor
choice; either target works with this workspace.

Verify your setup:

```bash
cargo --version && rustc --version && rustfmt --version && cargo clippy --version
```

## Clone

```bash
git clone https://github.com/badshashorif/tidegard.git
cd tidegard
```

## Build, Test, and Lint the Rust Workspace

```bash
cargo build --workspace --all-targets
cargo test --workspace
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
```

All four are run in CI (`.github/workflows/validate.yml`, jobs
`rust-build`, `rust-test`, `rust-fmt`, `rust-clippy`).

### Run the Collector Locally

```bash
export TIDEGARD_COLLECTOR_BIND=127.0.0.1:2055
export TIDEGARD_COLLECTOR_METRICS_BIND=127.0.0.1:9090
export RUST_LOG=info
cargo run --bin tidegard-collector
```

In another terminal, send it synthetic test traffic (never real captured
or attack traffic — see [../security-principles.md](../security-principles.md)):

```bash
cargo run -p tidegard-flow-replay -- 127.0.0.1:2055 5
curl -s http://127.0.0.1:9090/metrics | grep tidegard_collector
```

Full guide: [../integrations/ipfix-collector.md](../integrations/ipfix-collector.md).

## Validate Markdown

```bash
npx -y markdownlint-cli2 "**/*.md" "#node_modules"
```

Or via the Makefile/Taskfile wrapper:

```bash
make lint-markdown
# or
task lint:markdown
```

## Validate YAML (workflows, Dependabot, issue forms)

```bash
npx -y js-yaml .github/workflows/*.yml .github/dependabot.yml .github/ISSUE_TEMPLATE/*.yml mkdocs.yml
```

Or:

```bash
make lint-yaml
# or
task lint:yaml
```

## Preview the Documentation Site

Requires Python and `pip` (not currently installed in every contributor
environment — install separately per your OS):

```bash
pip install mkdocs-material
mkdocs serve
```

Or:

```bash
make docs-serve
# or
task docs:serve
```

## Run All Validation

```bash
make validate
# or
task validate
```

This runs Markdown lint, YAML lint, `cargo fmt --check`, `cargo clippy`,
`cargo test`, and `cargo build` — everything CI checks in
`.github/workflows/validate.yml`, runnable locally before pushing.
Frontend lint/test will be added once Phase 6 introduces the web app.

## Enable the Pre-Push Hook

`.githooks/pre-push` runs the Rust gate — `cargo fmt --check`, `cargo
clippy -D warnings`, `cargo test` — before every push, so a broken commit
never reaches a branch. Git never enables repository hooks
automatically, so turn it on once per clone:

```bash
make hooks
# or
task hooks
# or, directly:
git config core.hooksPath .githooks
```

The hook deliberately leaves the Markdown, YAML, link, and MkDocs checks
to CI: those need network access (`npx`, `pip`) and would make every push
slow and offline-hostile. `make validate` still runs the complete set.

It skips itself, with a warning, when `cargo` is not on `PATH` — a
docs-only clone does not need a Rust toolchain. To bypass it for a
work-in-progress push:

```bash
WETECHI_SKIP_PREPUSH=1 git push
```

## Contribution Workflow

See [Contributing](contributing.md) for branch naming,
commit conventions, and the pull-request checklist.
