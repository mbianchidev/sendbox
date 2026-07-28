.PHONY: all build release test clean install install-completions lint audit help

CARGO ?= cargo
PREFIX ?= /usr/local
DESTDIR ?=
BINDIR := $(DESTDIR)$(PREFIX)/bin
SENDBOX := target/release/sendbox

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

lint:
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --locked --workspace --all-targets --all-features -- -D warnings

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
	@echo "  lint                Check rustfmt and Clippy"
	@echo "  audit               Audit Cargo.lock with cargo-audit"
	@echo "  help                Show this help message"
