.PHONY: all build release test clean install install-completions setup-bridge lint \
	rust-build rust-release rust-test rust-lint help

PREFIX ?= /usr/local
DESTDIR ?=
BINDIR := $(DESTDIR)$(PREFIX)/bin

all: release

build:
	swift build

release:
	swift build -c release

test:
	swift test

clean:
	swift package clean

install: release
	install -d "$(BINDIR)"
	install .build/release/sendbox "$(BINDIR)/sendbox"
	@if [ -z "$(DESTDIR)" ]; then \
		.build/release/sendbox completions install 2>/dev/null || echo "⚠ Shell completions not installed (run 'sendbox completions install' manually)"; \
	else \
		echo "Skipping shell completions for staged install"; \
	fi
	@echo "✔ sendbox installed to $(BINDIR)/sendbox"

install-completions: release
	@.build/release/sendbox completions install 2>/dev/null || echo "⚠ Shell completions not installed (run 'sendbox completions install' manually)"

setup-bridge:
	cd copilot-bridge && npm ci

lint:
	swift format lint --recursive Sources Tests

rust-build:
	cargo build --workspace

rust-release:
	cargo build --workspace --release

rust-test:
	cargo test --workspace --all-features

rust-lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings

help:
	@echo "Available targets:"
	@echo "  all                 Build release (default)"
	@echo "  build               Build in debug mode"
	@echo "  release             Build in release mode"
	@echo "  test                Run tests"
	@echo "  clean               Clean build artifacts"
	@echo "  install             Install binary + shell completions"
	@echo "  install-completions Install shell completions only"
	@echo "  setup-bridge        Install copilot-bridge dependencies"
	@echo "  lint                Lint Swift sources"
	@echo "  rust-build          Build the experimental Rust workspace"
	@echo "  rust-release        Build the experimental Rust workspace in release mode"
	@echo "  rust-test           Test the experimental Rust workspace"
	@echo "  rust-lint           Check Rust formatting and run clippy"
	@echo "  help                Show this help message"
