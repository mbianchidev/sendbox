.PHONY: all build release test clean install install-completions setup-bridge lint help

all: release

build:
	swift build

release:
	swift build -c release

test:
	swift test

clean:
	swift package clean

install: release install-completions
	install -d /usr/local/bin
	install .build/release/sendbox /usr/local/bin/sendbox
	@echo "✔ sendbox installed to /usr/local/bin/sendbox"

install-completions: release
	@.build/release/sendbox completions install 2>/dev/null || echo "⚠ Shell completions not installed (run 'sendbox completions install' manually)"

setup-bridge:
	cd copilot-bridge && npm install

lint:
	swift format lint --recursive Sources Tests

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
	@echo "  help                Show this help message"
