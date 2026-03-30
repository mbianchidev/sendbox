.PHONY: all build release test clean install setup-bridge lint help

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
	install -d /usr/local/bin
	install .build/release/sendbox /usr/local/bin/sendbox

setup-bridge:
	cd copilot-bridge && npm install

lint:
	swift format lint --recursive Sources Tests

help:
	@echo "Available targets:"
	@echo "  all           Build release (default)"
	@echo "  build         Build in debug mode"
	@echo "  release       Build in release mode"
	@echo "  test          Run tests"
	@echo "  clean         Clean build artifacts"
	@echo "  install       Install binary to /usr/local/bin"
	@echo "  setup-bridge  Install copilot-bridge dependencies"
	@echo "  lint          Lint Swift sources"
	@echo "  help          Show this help message"
