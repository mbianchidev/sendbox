#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# SendBox — Interactive Setup & Run Script
# ─────────────────────────────────────────────────────────────
set -euo pipefail

SENDBOX_DIR="${HOME}/.sendbox"
CONFIG_DIR="${SENDBOX_DIR}/config"
SECRETS_DIR="${SENDBOX_DIR}/secrets"
RUNTIME_PROVIDER="auto"

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${BLUE}ℹ${NC}  $*"; }
ok()    { echo -e "${GREEN}✔${NC}  $*"; }
warn()  { echo -e "${YELLOW}⚠${NC}  $*"; }
err()   { echo -e "${RED}✘${NC}  $*" >&2; }
header(){ echo -e "\n${BOLD}${CYAN}═══ $* ═══${NC}\n"; }

CONTAINER_RELEASES_API="https://api.github.com/repos/apple/container/releases/latest"

detect_runtime() {
    case "$(uname)" in
        Darwin)
            if [[ "$(uname -m)" != "arm64" ]]; then
                err "Apple silicon (arm64) required for the Apple runtime (detected: $(uname -m))."
                exit 1
            fi
            RUNTIME_PROVIDER="apple"
            ;;
        Linux)
            RUNTIME_PROVIDER="kata"
            ;;
        *)
            err "Unsupported host operating system: $(uname)"
            exit 1
            ;;
    esac
}

# ── Install Apple Container CLI ──────────────────────────────
install_container_cli() {
    info "Fetching latest release from apple/container..."

    local release_json
    release_json="$(curl -fsSL "$CONTAINER_RELEASES_API")" || {
        err "Failed to fetch release info. Check your network connection."
        return 1
    }

    # Find the signed .pkg asset URL and name
    local pkg_url pkg_name
    pkg_url="$(echo "$release_json" | grep -o '"browser_download_url":\s*"[^"]*installer-signed\.pkg"' | head -1 | sed 's/.*"browser_download_url":\s*"\(.*\)"/\1/')"
    pkg_name="$(echo "$release_json" | grep -o '"name":\s*"[^"]*installer-signed\.pkg"' | head -1 | sed 's/.*"name":\s*"\(.*\)"/\1/')"

    if [[ -z "$pkg_url" ]]; then
        err "Could not find a signed .pkg installer in the latest release."
        err "Install manually from: https://github.com/apple/container/releases"
        return 1
    fi

    local tag_name
    tag_name="$(echo "$release_json" | grep -o '"tag_name":\s*"[^"]*"' | head -1 | sed 's/.*"tag_name":\s*"\(.*\)"/\1/')"
    info "Latest version: ${tag_name:-unknown}"
    info "Downloading ${pkg_name}..."

    local tmp_dir
    tmp_dir="$(mktemp -d)"
    local pkg_path="${tmp_dir}/${pkg_name}"

    curl -fSL --progress-bar -o "$pkg_path" "$pkg_url" || {
        err "Download failed."
        rm -rf "$tmp_dir"
        return 1
    }
    ok "Downloaded $(du -h "$pkg_path" | cut -f1 | xargs) — ${pkg_name}"

    info "Installing (requires administrator password)..."
    sudo installer -pkg "$pkg_path" -target / || {
        err "Installation failed. Try installing manually:"
        err "  open ${pkg_path}"
        return 1
    }

    rm -rf "$tmp_dir"
    ok "Apple Container CLI installed"

    # Start the system service
    info "Starting container system service..."
    if container system start 2>/dev/null; then
        ok "Container system service started"
    else
        warn "Could not start system service — you may need to run: container system start"
    fi
}

# ── Preflight checks ────────────────────────────────────────
preflight() {
    header "Preflight Checks"

    detect_runtime
    ok "Runtime provider: ${RUNTIME_PROVIDER}"

    # Swift
    if command -v swift &>/dev/null; then
        ok "Swift $(swift --version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?')"
    else
        err "Swift not found. Install Xcode or the Swift toolchain."
        exit 1
    fi

    # Node.js (for copilot-bridge)
    if command -v node &>/dev/null; then
        ok "Node.js $(node --version)"
    else
        warn "Node.js not found — copilot-bridge (auto-devcontainer) won't work."
        warn "Install Node.js 20+ for full functionality."
    fi

    if [[ "$RUNTIME_PROVIDER" == "apple" ]]; then
        # Apple Container runtime — auto-install if missing
        if command -v container &>/dev/null; then
            ok "Apple Container CLI found"
        else
            warn "Apple Container CLI not installed."
            read -rp "$(echo -e "${YELLOW}?${NC}  Download and install it now? [Y/n]: ")" install_container
            install_container="${install_container:-y}"
            if [[ "$install_container" =~ ^[Yy]$ ]]; then
                install_container_cli
            else
                warn "Skipping — container runtime will not be available."
            fi
        fi
    else
        local kata_missing=0
        for binary in nerdctl containerd-shim-kata-v2; do
            if command -v "$binary" &>/dev/null; then
                ok "$binary found"
            else
                err "$binary not found"
                kata_missing=1
            fi
        done

        if [[ "$kata_missing" -ne 0 ]]; then
            err "Install Kata Containers, containerd, CNI plugins, and nerdctl before continuing."
            err "See docs/kata-containers.md."
            exit 1
        fi

        if nerdctl info &>/dev/null; then
            ok "containerd is reachable through nerdctl"
        else
            err "Cannot connect to containerd with nerdctl."
            err "Configure socket permissions or a rootless containerd service."
            exit 1
        fi

        if command -v kata-runtime &>/dev/null; then
            kata-runtime check >/dev/null 2>&1 \
                && ok "Kata host compatibility check passed" \
                || warn "kata-runtime check reported a host compatibility issue"
        fi
    fi

    # GitHub CLI (for auth forwarding)
    if command -v gh &>/dev/null; then
        if gh auth status &>/dev/null 2>&1; then
            ok "GitHub CLI authenticated"
        else
            warn "GitHub CLI installed but not authenticated. Run: gh auth login"
        fi
    else
        warn "GitHub CLI not found — auth forwarding disabled."
    fi
}

# ── Build ────────────────────────────────────────────────────
build_sendbox() {
    header "Building SendBox"

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR"

    info "Building release binary..."
    swift build -c release 2>&1 | tail -3
    ok "Build complete"

    BINARY_PATH=".build/release/sendbox"
    if [[ ! -f "$BINARY_PATH" ]]; then
        err "Binary not found at $BINARY_PATH"
        exit 1
    fi
    ok "Binary: $BINARY_PATH"

    echo ""
    read -rp "$(echo -e "${YELLOW}?${NC}  Install to /usr/local/bin? [y/N]: ")" install_choice
    if [[ "$install_choice" =~ ^[Yy]$ ]]; then
        cp "$BINARY_PATH" /usr/local/bin/sendbox
        ok "Installed to /usr/local/bin/sendbox"
    fi
}

# ── Setup copilot-bridge ─────────────────────────────────────
setup_bridge() {
    header "Copilot Bridge Setup"

    if ! command -v node &>/dev/null; then
        warn "Skipping copilot-bridge (Node.js not installed)"
        return
    fi

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    BRIDGE_DIR="$SCRIPT_DIR/copilot-bridge"

    if [[ -d "$BRIDGE_DIR" ]]; then
        info "Installing copilot-bridge dependencies..."
        cd "$BRIDGE_DIR"
        npm ci --ignore-scripts --no-fund --silent
        npm audit --audit-level=high --silent
        npm run build --silent
        ok "copilot-bridge built"
        cd "$SCRIPT_DIR"
    else
        warn "copilot-bridge directory not found"
    fi
}

# ── Initialize directories ───────────────────────────────────
init_dirs() {
    header "Initializing SendBox Home"
    mkdir -p "$CONFIG_DIR" "$SECRETS_DIR"
    ok "Created $SENDBOX_DIR"

    # Copy default policy if not present
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ ! -f "$CONFIG_DIR/default-policy.yaml" ]] && [[ -f "$SCRIPT_DIR/config/default-policy.yaml" ]]; then
        cp "$SCRIPT_DIR/config/default-policy.yaml" "$CONFIG_DIR/"
        ok "Copied default policy to $CONFIG_DIR/"
    fi
}

# ── Interactive configuration ────────────────────────────────
configure() {
    header "Configure Sandbox"
    if [[ "$RUNTIME_PROVIDER" == "auto" ]]; then
        detect_runtime
    fi

    # Project path
    read -rp "$(echo -e "${CYAN}?${NC}  Project path to sandbox: ")" project_path
    project_path="${project_path/#\~/$HOME}"

    if [[ ! -d "$project_path" ]]; then
        err "Directory not found: $project_path"
        exit 1
    fi
    project_path="$(cd "$project_path" && pwd)"
    ok "Project: $project_path"

    # Sandbox name
    default_name="$(basename "$project_path")-sandbox"
    read -rp "$(echo -e "${CYAN}?${NC}  Sandbox name [${default_name}]: ")" sandbox_name
    sandbox_name="${sandbox_name:-$default_name}"

    # Policy preset
    echo ""
    info "Security policy presets:"
    echo "  1) default     — deny-by-default, allows common dev tools + registries"
    echo "  2) permissive  — allow-by-default, blocks dangerous system commands"
    echo "  3) strict      — read-only tools only, network limited to GitHub"
    echo ""
    read -rp "$(echo -e "${CYAN}?${NC}  Choose policy [1]: ")" policy_choice
    case "${policy_choice:-1}" in
        1) policy="default" ;;
        2) policy="permissive" ;;
        3) policy="strict" ;;
        *) policy="default" ;;
    esac
    ok "Policy: $policy"

    # Resources
    echo ""
    read -rp "$(echo -e "${CYAN}?${NC}  CPUs [4]: ")" cpus
    cpus="${cpus:-4}"
    read -rp "$(echo -e "${CYAN}?${NC}  Memory MB [4096]: ")" memory
    memory="${memory:-4096}"
    read -rp "$(echo -e "${CYAN}?${NC}  Disk MB [10240]: ")" disk
    disk="${disk:-10240}"

    # DevContainer auto-generation
    echo ""
    read -rp "$(echo -e "${CYAN}?${NC}  Auto-generate devcontainer with Copilot SDK? [Y/n]: ")" auto_devcontainer
    auto_devcontainer="${auto_devcontainer:-y}"
    if [[ "$auto_devcontainer" =~ ^[Yy]$ ]]; then
        auto_gen="true"
    else
        auto_gen="false"
    fi

    # GitHub auth forwarding
    read -rp "$(echo -e "${CYAN}?${NC}  Forward GitHub CLI auth to sandbox? [Y/n]: ")" forward_gh
    forward_gh="${forward_gh:-y}"
    if [[ "$forward_gh" =~ ^[Yy]$ ]]; then
        gh_forward="true"
    else
        gh_forward="false"
    fi

    read -rp "$(echo -e "${CYAN}?${NC}  Forward Copilot CLI auth to sandbox? [Y/n]: ")" forward_copilot
    forward_copilot="${forward_copilot:-y}"
    if [[ "$forward_copilot" =~ ^[Yy]$ ]]; then
        copilot_forward="true"
    else
        copilot_forward="false"
    fi

    # Network — allowed domains
    echo ""
    info "Extra domains to allow (comma-separated, or press Enter for defaults):"
    info "Defaults: github.com, npmjs.org, pypi.org, crates.io, etc."
    read -rp "$(echo -e "${CYAN}?${NC}  Additional domains: ")" extra_domains

    # Secrets
    echo ""
    info "Secrets to inject (stored in the host secret store via 'sendbox secrets add'):"
    read -rp "$(echo -e "${CYAN}?${NC}  Secret keys (comma-separated, or Enter to skip): ")" secret_keys

    # VS Code extensions
    echo ""
    read -rp "$(echo -e "${CYAN}?${NC}  Extra VS Code extensions (comma-separated, or Enter for defaults): ")" extra_extensions

    # ── Write config ─────────────────────────────────────────
    config_path="$project_path/.sendbox.yaml"

    header "Writing Configuration"

    cat > "$config_path" <<YAML
# SendBox Configuration — Generated $(date +%Y-%m-%d)
# Docs: https://github.com/mbianchidev/sendbox

name: ${sandbox_name}
project_path: ${project_path}

runtime:
  provider: ${RUNTIME_PROVIDER}
YAML

    if [[ "$RUNTIME_PROVIDER" == "kata" ]]; then
        cat >> "$config_path" <<YAML
  kata:
    executable: nerdctl
    runtime_handler: io.containerd.kata.v2
    namespace: sendbox
YAML
    fi

    cat >> "$config_path" <<YAML

resources:
  cpus: ${cpus}
  memory_mb: ${memory}
  disk_size_mb: ${disk}

policy:
  commands:
    default_action: deny
    log_blocked: true
    allowlist:
      - "git *"
      - "gh *"
      - "node *"
      - "npm *"
      - "npx *"
      - "python3 *"
      - "pip3 *"
      - "cargo *"
      - "go *"
      - "make *"
      - "cat *"
      - "ls *"
      - "find *"
      - "grep *"
      - "sed *"
      - "awk *"
      - "head *"
      - "tail *"
      - "echo *"
      - "mkdir *"
      - "cp *"
      - "mv *"
      - "touch *"
      - "rm *"
      - "curl *"
      - "jq *"
      - "code *"
      - "devcontainer *"
    denylist:
      - "sudo *"
      - "su *"
      - "mount *"
      - "dd *"
      - "shutdown *"
      - "reboot *"
      - "systemctl *"
      - "iptables *"
      - "passwd *"
      - "ssh *"
      - "nc *"
      - "apt *"
      - "apt-get *"

  network:
    default_action: deny
    allow_dns: true
    max_connections: 100
    allowed_domains:
      - "github.com"
      - "*.github.com"
      - "*.githubusercontent.com"
      - "registry.npmjs.org"
      - "pypi.org"
      - "*.pypi.org"
      - "crates.io"
      - "proxy.golang.org"
      - "*.docker.io"
      - "mcr.microsoft.com"
      - "*.vscode-cdn.net"
      - "marketplace.visualstudio.com"
      - "api.copilot.github.com"
YAML

    # Append extra domains
    if [[ -n "$extra_domains" ]]; then
        IFS=',' read -ra domains <<< "$extra_domains"
        for d in "${domains[@]}"; do
            d="$(echo "$d" | xargs)"  # trim whitespace
            echo "      - \"$d\"" >> "$config_path"
        done
    fi

    cat >> "$config_path" <<YAML
    blocked_domains: []

secrets:
YAML

    # Append secrets
    if [[ -n "$secret_keys" ]]; then
        IFS=',' read -ra keys <<< "$secret_keys"
        for k in "${keys[@]}"; do
            k="$(echo "$k" | xargs)"
            echo "  - ${k}" >> "$config_path"
        done
    else
        echo "  []" >> "$config_path"
    fi

    cat >> "$config_path" <<YAML

devcontainer:
  auto_generate: ${auto_gen}
  extensions:
    - github.copilot
    - github.copilot-chat
YAML

    # Append extra extensions
    if [[ -n "$extra_extensions" ]]; then
        IFS=',' read -ra exts <<< "$extra_extensions"
        for e in "${exts[@]}"; do
            e="$(echo "$e" | xargs)"
            echo "    - ${e}" >> "$config_path"
        done
    fi

    cat >> "$config_path" <<YAML

github:
  forward_auth: ${gh_forward}
  forward_copilot_auth: ${copilot_forward}
YAML

    ok "Config written to: $config_path"
    echo ""
    info "Review it with: cat $config_path"
}

# ── Add secrets interactively ────────────────────────────────
add_secrets() {
    header "Add Secrets"

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    SENDBOX_BIN="$SCRIPT_DIR/.build/release/sendbox"

    if [[ ! -f "$SENDBOX_BIN" ]]; then
        SENDBOX_BIN="$(command -v sendbox 2>/dev/null || true)"
    fi

    if [[ -z "$SENDBOX_BIN" ]]; then
        warn "sendbox binary not found. Build first with: make all"
        return
    fi

    echo ""
    info "Add secrets that your agent needs (stored in the host secret store)."
    info "Type 'done' when finished."
    echo ""

    while true; do
        read -rp "$(echo -e "${CYAN}?${NC}  Secret key (or 'done'): ")" key
        if [[ "$key" == "done" || -z "$key" ]]; then
            break
        fi
        "$SENDBOX_BIN" secrets add "$key"
        echo ""
    done
}

# ── Run the sandbox ──────────────────────────────────────────
run_sandbox() {
    header "Launch Sandbox"

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    SENDBOX_BIN="$SCRIPT_DIR/.build/release/sendbox"

    if [[ ! -f "$SENDBOX_BIN" ]]; then
        SENDBOX_BIN="$(command -v sendbox 2>/dev/null || true)"
    fi

    if [[ -z "$SENDBOX_BIN" ]]; then
        err "sendbox binary not found. Build first."
        exit 1
    fi

    read -rp "$(echo -e "${CYAN}?${NC}  Path to .sendbox.yaml config: ")" config_path
    config_path="${config_path/#\~/$HOME}"

    if [[ ! -f "$config_path" ]]; then
        err "Config not found: $config_path"
        exit 1
    fi

    info "Starting sandbox..."
    "$SENDBOX_BIN" run --config "$config_path"
}

# ── Main menu ────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║         SendBox Setup & Run           ║${NC}"
    echo -e "${BOLD}${CYAN}║      Secure Agent Sandbox Runtime      ║${NC}"
    echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════╝${NC}"
    echo ""

    # No arguments → run the default flow
    if [[ $# -eq 0 ]]; then
        preflight
        build_sendbox
        setup_bridge
        init_dirs
        configure
        run_sandbox
        return
    fi

    PS3=$'\n'"$(echo -e "${CYAN}?${NC}  Select an action: ")"
    options=(
        "Full setup (preflight → build → configure → run)"
        "Preflight checks only"
        "Build SendBox"
        "Configure a project sandbox"
        "Add secrets"
        "Run an existing sandbox"
        "Quit"
    )

    select opt in "${options[@]}"; do
        case $REPLY in
            1)
                preflight
                build_sendbox
                setup_bridge
                init_dirs
                configure
                run_sandbox
                break
                ;;
            2) preflight; break ;;
            3) build_sendbox; setup_bridge; break ;;
            4) configure; break ;;
            5) add_secrets; break ;;
            6) run_sandbox; break ;;
            7) echo "Bye!"; exit 0 ;;
            *) warn "Invalid choice" ;;
        esac
    done
}

main "$@"
