.PHONY: all build release test clean install install-completions lint fuzz-check audit help

CARGO ?= cargo
PREFIX ?= /usr/local
DESTDIR ?=
BINDIR := $(DESTDIR)$(PREFIX)/bin
SENDBOX := target/release/sendbox
FUZZ_MANIFESTS := \
	fuzz/security/Cargo.toml \
	fuzz/git/Cargo.toml \
	fuzz/secrets/Cargo.toml \
	fuzz/credentials/Cargo.toml \
	fuzz/mcp/Cargo.toml \
	fuzz/bpf/Cargo.toml \
	fuzz/project/Cargo.toml \
	fuzz/config/Cargo.toml \
	fuzz/protocol/Cargo.toml \
	fuzz/registry/Cargo.toml

all: release

build:
	$(CARGO) build --locked --workspace

release:
	$(CARGO) build --locked --workspace --release

test:
	$(CARGO) test --locked --workspace --all-features

clean:
	$(CARGO) clean

install: release
	install -d "$(BINDIR)"
	install -m 0755 "$(SENDBOX)" "$(BINDIR)/sendbox"
	@if [ -z "$(DESTDIR)" ]; then \
		"$(SENDBOX)" completions install 2>/dev/null \
			|| echo "Shell completions not installed; run 'sendbox completions install' manually."; \
	else \
		echo "Skipping shell completions for staged install"; \
	fi
	@echo "sendbox installed to $(BINDIR)/sendbox"

install-completions: release
	@"$(SENDBOX)" completions install

lint: fuzz-check
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --locked --workspace --all-targets --all-features -- -D warnings

fuzz-check:
	@set -e; for manifest in $(FUZZ_MANIFESTS); do \
		$(CARGO) check --locked --manifest-path "$$manifest" --bins; \
	done

audit:
	$(CARGO) audit

help:
	@echo "Available targets:"
	@echo "  all                 Build the release workspace (default)"
	@echo "  build               Build the Rust workspace in debug mode"
	@echo "  release             Build the Rust workspace in release mode"
	@echo "  test                Run all Rust tests"
	@echo "  clean               Remove Cargo build artifacts"
	@echo "  install             Install the sendbox binary and user completions"
	@echo "  install-completions Install user shell completions"
	@echo "  lint                Check fuzz locks, rustfmt, and Clippy"
	@echo "  fuzz-check          Compile every standalone fuzz workspace with its lockfile"
	@echo "  audit               Audit Cargo.lock with cargo-audit"
	@echo "  help                Show this help message"
