.PHONY: help hooks validate lint-markdown lint-yaml rust-build rust-test rust-fmt rust-clippy docs-serve docs-build clean

help:
	@echo "tidegard — targets"
	@echo ""
	@echo "  make hooks          Enable the repo Git hooks (pre-push Rust gate)"
	@echo "  make validate       Run all available validation (docs + Rust)"
	@echo "  make lint-markdown  Lint all Markdown files with markdownlint-cli2"
	@echo "  make lint-yaml      Validate syntax of all YAML files"
	@echo "  make rust-build     cargo build --workspace --all-targets"
	@echo "  make rust-test      cargo test --workspace"
	@echo "  make rust-fmt       cargo fmt --check"
	@echo "  make rust-clippy    cargo clippy --workspace --all-targets -- -D warnings"
	@echo "  make docs-serve     Serve the MkDocs Material site locally (requires Python)"
	@echo "  make docs-build     Build the MkDocs Material site strictly (requires Python)"
	@echo ""
	@echo "Frontend (npm build/test) targets are added starting Phase 6 — see docs/roadmap.md."

hooks:
	git config core.hooksPath .githooks
	@echo "Git hooks enabled — .githooks/pre-push runs the Rust gate before each push."

validate: lint-markdown lint-yaml rust-fmt rust-clippy rust-test rust-build
	@echo "Validation complete."

lint-markdown:
	npx -y markdownlint-cli2 "**/*.md" "#node_modules"

lint-yaml:
	npx -y js-yaml mkdocs.yml > /dev/null && echo "OK: mkdocs.yml"
	@for f in $$(find .github -type f \( -name '*.yml' -o -name '*.yaml' \)); do \
		npx -y js-yaml "$$f" > /dev/null && echo "OK: $$f" || exit 1; \
	done

rust-build:
	cargo build --workspace --all-targets

rust-test:
	cargo test --workspace

rust-fmt:
	cargo fmt --check

rust-clippy:
	cargo clippy --workspace --all-targets -- -D warnings

docs-serve:
	mkdocs serve

docs-build:
	mkdocs build --strict

clean:
	rm -rf site/ target/
