#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SENDBOX_HOME="${HOME}/.sendbox"
INSTALL_PREFIX="${SENDBOX_INSTALL_PREFIX:-/usr/local}"
RUNTIME_PROVIDER="auto"
SENDBOX_BIN=""
CONFIG_PATH=""
APPLE_CONTAINER_VERSION="0.10.0"
APPLE_CONTAINER_SHA256="c481ce355524d036c3cddac7fd281e31794d40690bf9a21f732ef3d76fa9fe08"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

if [[ "$INSTALL_PREFIX" != /* ]]; then
    printf 'error SENDBOX_INSTALL_PREFIX must be absolute\n' >&2
    exit 2
fi

info() { printf "${BLUE}info${NC} %s\n" "$*"; }
ok() { printf "${GREEN}ok${NC}   %s\n" "$*"; }
warn() { printf "${YELLOW}warn${NC} %s\n" "$*"; }
err() { printf "${RED}error${NC} %s\n" "$*" >&2; }
header() { printf "\n${BOLD}%s${NC}\n\n" "$*"; }

detect_runtime() {
    case "$(uname -s)" in
        Darwin)
            if [[ "$(uname -m)" != "arm64" ]]; then
                err "Apple runtime requires Apple silicon; detected $(uname -m)."
                return 1
            fi
            RUNTIME_PROVIDER="apple"
            ;;
        Linux)
            RUNTIME_PROVIDER="kata"
            ;;
        *)
            err "Unsupported host operating system: $(uname -s)"
            return 1
            ;;
    esac
}

guest_architecture() {
    case "$(uname -m)" in
        arm64 | aarch64) printf '%s\n' "aarch64" ;;
        x86_64 | amd64) printf '%s\n' "x86_64" ;;
        *)
            err "Unsupported guest architecture: $(uname -m)"
            return 1
            ;;
    esac
}

resolve_sendbox_binary() {
    local candidate
    for candidate in \
        "$SCRIPT_DIR/sendbox" \
        "$SCRIPT_DIR/target/release/sendbox"; do
        if [[ -x "$candidate" ]]; then
            SENDBOX_BIN="$candidate"
            return 0
        fi
    done
    candidate="$(command -v sendbox 2>/dev/null || true)"
    if [[ -n "$candidate" && -x "$candidate" ]]; then
        SENDBOX_BIN="$candidate"
        return 0
    fi
    return 1
}

find_guest_assets() {
    local architecture root
    architecture="$(guest_architecture)"
    for root in \
        "$SCRIPT_DIR/guest/$architecture" \
        "$SCRIPT_DIR/share/sendbox/guest/$architecture" \
        "$INSTALL_PREFIX/share/sendbox/guest/$architecture" \
        "/opt/homebrew/share/sendbox/guest/$architecture"; do
        if [[ -d "$root/bundle" && -f "$root/release-public.key" ]]; then
            printf '%s\n' "$root"
            return 0
        fi
    done
    return 1
}

check_linux_build_dependencies() {
    local dependency
    local missing=()
    for dependency in ar cc clang cmake make pkg-config; do
        command -v "$dependency" >/dev/null || missing+=("$dependency")
    done
    if command -v pkg-config >/dev/null; then
        for dependency in libseccomp libelf zlib libzstd; do
            pkg-config --exists "$dependency" || missing+=("$dependency")
        done
    fi
    if ((${#missing[@]} > 0)); then
        err "Missing Linux source-build dependencies: ${missing[*]}"
        err "On Debian/Ubuntu install build-essential clang cmake libelf-dev libseccomp-dev libzstd-dev pkg-config zlib1g-dev."
        return 1
    fi
}

install_container_cli() {
    local pkg_url pkg_name temp_dir pkg_path actual_sha256
    pkg_name="container-${APPLE_CONTAINER_VERSION}-installer-signed.pkg"
    pkg_url="https://github.com/apple/container/releases/download/${APPLE_CONTAINER_VERSION}/${pkg_name}"
    info "Downloading qualified Apple container CLI ${APPLE_CONTAINER_VERSION}."

    temp_dir="$(mktemp -d)"
    pkg_path="$temp_dir/$pkg_name"
    if ! curl -fL --progress-bar -o "$pkg_path" "$pkg_url"; then
        rm -rf "$temp_dir"
        err "Apple container download failed."
        return 1
    fi
    actual_sha256="$(shasum -a 256 "$pkg_path" | awk '{print $1}')"
    if [[ "$actual_sha256" != "$APPLE_CONTAINER_SHA256" ]]; then
        rm -rf "$temp_dir"
        err "Apple container installer checksum verification failed."
        return 1
    fi
    if ! pkgutil --check-signature "$pkg_path" >/dev/null; then
        rm -rf "$temp_dir"
        err "Apple container installer signature verification failed."
        return 1
    fi
    if ! sudo installer -pkg "$pkg_path" -target /; then
        rm -rf "$temp_dir"
        err "Apple container installation failed."
        return 1
    fi
    rm -rf "$temp_dir"
    ok "Apple container CLI installed."
}

check_container_cli_version() {
    local version version_token
    if ! version="$(container --version 2>&1)"; then
        err "Could not query the Apple container CLI version."
        return 1
    fi
    version_token="${version#container CLI version }"
    version_token="${version_token%% *}"
    if [[ "$version_token" != "$APPLE_CONTAINER_VERSION" ]]; then
        err "Apple runtime requires container CLI ${APPLE_CONTAINER_VERSION}; observed: $version"
        return 1
    fi
    ok "Apple container CLI ${APPLE_CONTAINER_VERSION} found."
}

preflight() {
    header "Preflight"
    detect_runtime
    ok "Runtime provider: $RUNTIME_PROVIDER"

    if resolve_sendbox_binary; then
        ok "SendBox: $("$SENDBOX_BIN" --version)"
    elif [[ -f "$SCRIPT_DIR/Cargo.toml" ]]; then
        command -v cargo >/dev/null || {
            err "Cargo is required to build SendBox from source."
            return 1
        }
        command -v rustc >/dev/null || {
            err "rustc is required to build SendBox from source."
            return 1
        }
        if [[ "$(uname -s)" == "Linux" ]]; then
            check_linux_build_dependencies
        fi
        ok "Rust: $(rustc --version)"
    else
        err "No sendbox binary or Cargo source workspace was found."
        return 1
    fi

    if [[ "$RUNTIME_PROVIDER" == "apple" ]]; then
        if ! command -v container >/dev/null; then
            warn "Apple container CLI is not installed."
            read -r -p "Install it now? [Y/n] " install_container
            if [[ "${install_container:-y}" =~ ^[Yy]$ ]]; then
                install_container_cli
            else
                err "Apple container CLI is required."
                return 1
            fi
        fi
        check_container_cli_version
        container system status >/dev/null 2>&1 || {
            err "Apple container service is not running; run 'container system start'."
            return 1
        }
    else
        local binary
        for binary in nerdctl containerd-shim-kata-v2; do
            command -v "$binary" >/dev/null || {
                err "$binary is required for the Kata runtime."
                return 1
            }
        done
        nerdctl info >/dev/null 2>&1 || {
            err "containerd is not reachable through nerdctl."
            return 1
        }
        if command -v kata-runtime >/dev/null; then
            if kata-runtime check >/dev/null 2>&1; then
                ok "Kata host compatibility check passed."
            else
                warn "kata-runtime reported a host compatibility issue."
            fi
        fi
    fi

    if command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
        ok "GitHub CLI authentication available."
    else
        warn "GitHub CLI authentication is unavailable; credential forwarding may be disabled."
    fi

    local assets
    if assets="$(find_guest_assets)"; then
        ok "Signed guest bundle: $assets"
    else
        warn "No bundled guest artifacts found; run will request a bundle and trust root."
    fi
}

build_sendbox() {
    header "Build"
    if [[ -f "$SCRIPT_DIR/Cargo.toml" ]]; then
        command -v cargo >/dev/null || {
            err "Cargo is required to build SendBox."
            return 1
        }
        if [[ "$(uname -s)" == "Linux" ]]; then
            check_linux_build_dependencies
        fi
        (
            cd "$SCRIPT_DIR"
            cargo build --locked --release -p sendbox-cli
        )
        SENDBOX_BIN="$SCRIPT_DIR/target/release/sendbox"
    elif ! resolve_sendbox_binary; then
        err "No prebuilt sendbox binary was found."
        return 1
    fi
    "$SENDBOX_BIN" --version
    ok "Binary ready: $SENDBOX_BIN"

    local install_destination="$INSTALL_PREFIX/bin/sendbox"
    if [[ -e "$install_destination" && "$SENDBOX_BIN" -ef "$install_destination" ]]; then
        ok "Binary already installed at $install_destination."
        return 0
    fi

    read -r -p "Install to $install_destination? [y/N] " install_choice
    if [[ "${install_choice:-n}" =~ ^[Yy]$ ]]; then
        sudo install -d "$INSTALL_PREFIX/bin"
        sudo install -m 0755 "$SENDBOX_BIN" "$install_destination"
        SENDBOX_BIN="$install_destination"
        ok "Installed $install_destination."
    fi
}

initialize_home() {
    install -d -m 0700 "$SENDBOX_HOME"
    ok "Runtime state directory: $SENDBOX_HOME"
}

configure() {
    header "Configure"
    resolve_sendbox_binary || build_sendbox
    detect_runtime

    local project_path policy_choice policy
    read -r -p "Project path to sandbox: " project_path
    project_path="${project_path/#\~/$HOME}"
    if [[ ! -d "$project_path" ]]; then
        err "Project directory not found: $project_path"
        return 1
    fi
    project_path="$(cd "$project_path" && pwd -P)"
    CONFIG_PATH="$project_path/.sendbox.yaml"

    printf '%s\n' \
        "1) default - deny by default for common development tools" \
        "2) permissive - allow by default with dangerous commands denied" \
        "3) strict - read-only tools and narrow network access"
    read -r -p "Policy preset [1]: " policy_choice
    case "${policy_choice:-1}" in
        1) policy="default" ;;
        2) policy="permissive" ;;
        3) policy="strict" ;;
        *)
            err "Invalid policy selection."
            return 1
            ;;
    esac

    if [[ -e "$CONFIG_PATH" ]]; then
        warn "Using existing configuration: $CONFIG_PATH"
    else
        "$SENDBOX_BIN" init \
            --project "$project_path" \
            --policy "$policy" \
            --runtime "$RUNTIME_PROVIDER"
    fi
    "$SENDBOX_BIN" policy validate --config "$CONFIG_PATH"
    ok "Configuration ready: $CONFIG_PATH"
}

add_secrets() {
    header "Secrets"
    resolve_sendbox_binary || build_sendbox
    info "Enter each configured secret name. Values are read without argv or environment exposure."
    while true; do
        local key
        read -r -p "Secret name, or 'done': " key
        if [[ -z "$key" || "$key" == "done" ]]; then
            break
        fi
        "$SENDBOX_BIN" secrets add "$key"
    done
}

read_existing_path() {
    local prompt="$1"
    local default_path="${2:-}"
    local value
    while true; do
        if [[ -n "$default_path" ]]; then
            read -r -p "$prompt [$default_path]: " value
            value="${value:-$default_path}"
        else
            read -r -p "$prompt: " value
        fi
        value="${value/#\~/$HOME}"
        if [[ -e "$value" ]]; then
            printf '%s\n' "$value"
            return 0
        fi
        warn "Path does not exist: $value"
    done
}

run_sandbox() {
    header "Run"
    resolve_sendbox_binary || build_sendbox
    detect_runtime

    local config_path="${CONFIG_PATH:-}"
    if [[ -z "$config_path" ]]; then
        read -r -p "Path to .sendbox.yaml: " config_path
        config_path="${config_path/#\~/$HOME}"
    fi
    [[ -f "$config_path" ]] || {
        err "Configuration not found: $config_path"
        return 1
    }
    "$SENDBOX_BIN" policy validate --config "$config_path"

    local asset_root="" default_bundle="" default_trust_root=""
    if asset_root="$(find_guest_assets)"; then
        default_bundle="$asset_root/bundle"
        default_trust_root="$asset_root/release-public.key"
    fi

    local bundle trust_root image executable argument_line
    bundle="$(read_existing_path "Signed guest bundle directory" "$default_bundle")"
    trust_root="$(read_existing_path "Attested release public key" "$default_trust_root")"

    local run_arguments=(
        run
        --config "$config_path"
        --runtime "$RUNTIME_PROVIDER"
        --bundle "$bundle"
        --trust-root "$trust_root"
        --trust-root-id external-release-root
        --minimum-release-sequence 1
    )
    if [[ "$RUNTIME_PROVIDER" != "hyperlight" ]]; then
        read -r -p "Digest-pinned workload image (name@sha256:digest): " image
        [[ "$image" == *@sha256:* ]] || {
            err "A digest-pinned workload image is required."
            return 1
        }
        run_arguments+=(--image "$image")
    fi

    read -r -p "Guest executable [/bin/sh]: " executable
    executable="${executable:-/bin/sh}"
    [[ "$executable" == /* ]] || {
        err "Guest executable must be an absolute path."
        return 1
    }
    read -r -p "Guest arguments (space-separated, no shell evaluation): " argument_line
    local guest_arguments=()
    if [[ -n "$argument_line" ]]; then
        read -r -a guest_arguments <<<"$argument_line"
    fi

    "$SENDBOX_BIN" "${run_arguments[@]}" -- "$executable" "${guest_arguments[@]}"
}

full_setup() {
    preflight
    build_sendbox
    initialize_home
    configure
    run_sandbox
}

menu() {
    PS3="Select an action: "
    select option in \
        "Full setup" \
        "Preflight checks" \
        "Build SendBox" \
        "Configure a project" \
        "Add secrets" \
        "Run a sandbox" \
        "Quit"; do
        case "$option" in
            "Full setup") full_setup; break ;;
            "Preflight checks") preflight; break ;;
            "Build SendBox") build_sendbox; break ;;
            "Configure a project") configure; break ;;
            "Add secrets") add_secrets; break ;;
            "Run a sandbox") run_sandbox; break ;;
            "Quit") exit 0 ;;
            *) warn "Invalid selection." ;;
        esac
    done
}

case "${1:-full}" in
    full) full_setup ;;
    preflight) preflight ;;
    build) build_sendbox ;;
    configure) configure ;;
    secrets) add_secrets ;;
    run) run_sandbox ;;
    menu) menu ;;
    *)
        err "Usage: $0 [full|preflight|build|configure|secrets|run|menu]"
        exit 2
        ;;
esac
