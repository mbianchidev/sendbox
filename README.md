# SendBox

**Secure, hardware-isolated agent sandboxing on macOS and Linux.**

SendBox runs AI agents inside dedicated Linux virtual machines. It uses Apple's [Containerization](https://github.com/apple/containerization) framework on Apple silicon and [Kata Containers](https://katacontainers.io/) through nerdctl/containerd on Linux.

---

## Features

- **File Isolation** — Mount only the directories an agent needs. Everything else is invisible.
- **Command Filtering** — Allowlist or denylist which binaries an agent may execute inside the sandbox.
- **Network Firewall** — Restrict outbound traffic to specific hosts, ports, or protocols.
- **Runtime Providers** — Select Apple Containerization, Kata Containers, or Hyperlight through one lifecycle API and `--runtime`.
- **Hyperlight Execution** — Run commands and MCP servers in one-shot Hyperlight/Unikraft micro-VMs on Linux.
- **Credential Injection** — Secrets load from macOS Keychain or the protected Linux secret store and are injected without persisting them in the guest filesystem.
- **Undo & Rollback** — Content-addressed SHA-256 snapshots capture workspace state before every session. Restore, diff, verify, or prune snapshots at any time.
- **Audit Trail** — Merkle-tree-committed session logs with cryptographic integrity verification. Every command, file access, and network connection is recorded in a tamper-evident hash chain.
- **MCP Inspection (eBPF)** — Observe Model Context Protocol JSON-RPC traffic between the agent and its MCP servers at the kernel boundary. Captures both stdio and HTTP/SSE transports, classifies tool calls, and feeds the audit trail. See [docs/mcp-inspection.md](docs/mcp-inspection.md).
- **Supply Chain Provenance** — Ed25519 signing for config and policy files ensures they were authored by trusted identities. Multi-signer support with a configurable trust store.
- **Runtime Supervisor** — Dynamic permission expansion with approval workflows. Agents start restricted and earn broader permissions through supervised interaction (one-time, session-wide, or pattern-based grants).
- **VM Hardening** — Defense-in-depth sysctl lockdown, capability dropping, and seccomp profiles covering all 18 [SandboxEscapeBench](https://arxiv.org/abs/2603.02277) scenarios.
- **Devcontainer Generation** — Export sandbox configurations as [devcontainer](https://containers.dev/) specs for reproducible environments.

## Requirements

| Scope | Dependency | Minimum |
|---|---|---|
| Common | Swift | 6.2 |
| Common | Node.js | 20+ for `copilot-bridge` |
| Apple runtime | macOS | 26 (Tahoe) |
| Apple runtime | Hardware | Apple Silicon |
| Apple runtime | Xcode | 26 |
| Kata runtime | Linux | Bare metal or nested virtualization |
| Kata runtime | Kata Containers | 3.28 |
| Kata runtime | containerd | 1.7 |
| Kata runtime | nerdctl and CNI plugins | Current compatible releases |
| Hyperlight runtime | `hyperlight-unikraft` and KVM | 0.12 |

## Quick Start

### Install

**From releases (prebuilt macOS artifacts):**

Download the latest `.pkg`, `.dmg`, or tarball from [Releases](https://github.com/mbianchidev/sendbox/releases).

```bash
# .pkg — double-click or:
sudo installer -pkg sendbox-*-macos-arm64.pkg -target /

# Tarball:
tar xzf sendbox-*-macos-arm64.tar.gz
sudo cp sendbox-*/sendbox /usr/local/bin/
```

**From source:**

```bash
git clone https://github.com/mbianchidev/sendbox.git
cd sendbox
make install
```

For an interactive runtime preflight and configuration flow:

```bash
./setup.sh
```

Kata installation and containerd configuration are documented in [docs/kata-containers.md](docs/kata-containers.md).

### Running Unsigned macOS Releases

Releases are **not code-signed**. macOS Gatekeeper will block the binary on first run.
Use one of these methods to allow it:

```bash
# Option 1 (recommended) — Remove the quarantine attribute
xattr -dr com.apple.quarantine /usr/local/bin/sendbox

# Option 2 — Right-click the binary in Finder → Open (one-time approval)

# Option 3 — Allow in System Settings
#   System Settings → Privacy & Security → scroll to "sendbox was blocked" → Allow Anyway

# Option 4 (not recommended) — Disable Gatekeeper globally
sudo spctl --master-disable
# Re-enable after:  sudo spctl --master-enable
```

> **Note:** The `.pkg` installer runs `xattr -dr` automatically during post-install, so
> the quarantine attribute is removed for you.

### Configure

Create a `sendbox.yaml` in your project root (see [Configuration](#configuration) below), then:

```bash
sendbox init
sendbox init --runtime kata
```

### Run

```bash
# Launch an agent inside the sandbox
sendbox run --config sendbox.yaml
sendbox run --config sendbox.yaml --runtime kata
```

## Configuration

SendBox is configured through YAML. See [config/example-sandbox.yaml](config/example-sandbox.yaml) for the fully annotated reference.

```yaml
name: my-agent-sandbox
project_path: /home/developer/my-project

runtime:
  provider: auto # auto | apple | kata | hyperlight
  kata:
    executable: nerdctl
    runtime_handler: io.containerd.kata.v2
    namespace: sendbox
  hyperlight:
    kernel_path: /opt/hyperlight/shell-kernel
    initrd_path: /opt/hyperlight/shell.cpio

resources:
  cpus: 2
  memory_mb: 2048
  disk_size_mb: 5120

policy:
  commands:
    default_action: deny
    allowlist: ["git *", "npm *", "swift *"]
    denylist: ["sudo *"]
    log_blocked: true
  network:
    default_action: deny
    allowed_domains: ["github.com", "*.github.com"]
    blocked_domains: []
    allow_dns: true

secrets: [GITHUB_TOKEN]

devcontainer:
  auto_generate: true
  extensions: [github.copilot]

github:
  forward_auth: true
  forward_copilot_auth: true

observability:
  mcp_inspection:
    enabled: false
    transports: [stdio, http]
    capture_payloads: false
    max_payload_bytes: 16384
    log_path: /var/log/sendbox/mcp-trace.log
```

### Configuration Reference

| Section | Key | Description |
|---|---|---|
| `name` | string | Human-readable sandbox name |
| `project_path` | string | Host project directory mounted into the guest |
| `runtime.provider` | enum | `auto`, `apple`, or `kata` |
| `runtime.kata.runtime_handler` | string | Kata containerd runtime v2 handler |
| `runtime.kata.namespace` | string | containerd namespace |
| `runtime.kata.configuration_path` | string | Absolute Kata config path on the containerd host |
| `runtime.hyperlight.kernel_path` | string | Hyperlight-compatible Unikraft shell kernel |
| `runtime.hyperlight.initrd_path` | string | Rootfs CPIO containing the commands or MCP servers to run |
| `resources.cpus` | int | Number of virtual CPUs |
| `resources.memory_mb` | int | Memory allocation in MB |
| `resources.disk_size_mb` | int | Requested writable-layer size |
| `policy.commands` | object | Command allowlist/denylist policy |
| `policy.network` | object | Outbound network policy |
| `secrets` | list | Secret names injected at runtime |
| `devcontainer.auto_generate` | bool | Generate a devcontainer spec |
| `observability.mcp_inspection.enabled` | bool | Enable eBPF MCP call inspection (opt-in) |

## Architecture

```
┌─────────────┐     ┌─────────────────┐
│ sendbox CLI │────▶│ RuntimeProvider │
└─────────────┘     └────────┬────────┘
                    ┌────────┴─────────┐
                    ▼                  ▼
          Apple Containerization   nerdctl/containerd
             (macOS arm64)          + Kata shim (Linux)
                    │                  │
                    └────────┬─────────┘
                             ▼
                  Dedicated Linux guest VM
```

**SendBoxKit** is the core library organized into four modules:

| Module | Responsibility |
|---|---|
| `Config` | Parse and validate YAML configuration |
| `Security` | Enforce command filtering, network rules, and secret injection |
| `Container` | Select and manage Apple or Kata VM runtimes |
| `Agent` | Coordinate agent process execution and I/O |

The **copilot-bridge** is an optional Node.js sidecar that exposes a JSON-RPC interface for IDE integrations.

See [docs/hyperlight.md](docs/hyperlight.md) for Hyperlight setup and limitations.

## Security Model

SendBox follows a **deny-by-default** security posture:

1. **Filesystem** — Only explicitly mounted paths are visible inside the VM. The host filesystem is never exposed wholesale.
2. **Commands** — By default no binaries are available. Use `allowlist` mode to grant access to specific tools, or `denylist` mode to start permissive and lock down selectively.
3. **Network** — Outbound connections are blocked unless a matching `allow` rule exists. DNS resolution is restricted to permitted hosts.
4. **Secrets** — Credentials are injected at container creation and never persisted in the guest filesystem. Host storage uses Keychain on macOS and mode-restricted files on Linux.
5. **Isolation** — Each sandbox runs in its own lightweight VM. A compromised agent cannot affect the host or other sandboxes.

## CLI Reference

```
USAGE: sendbox <subcommand> [options]

SUBCOMMANDS:
  init          Initialize a new sendbox.yaml in the current directory
  run           Start the sandbox and launch the agent
  analyze       Analyze a project and generate a devcontainer spec
  secrets       Add, remove, or list stored secrets
  policy        Show or validate policies
  mcp           Inspect Model Context Protocol calls via eBPF
  completions   Install or print shell completions
  help          Show help for any subcommand
```

### Examples

```bash
# Initialize a new project
sendbox init

# Run with the Kata backend
sendbox run --config sendbox.yaml --runtime kata

# Generate devcontainer spec
sendbox analyze --project . --output .devcontainer/

# Validate a sandbox configuration's policy
sendbox policy validate --config sendbox.yaml

# Print the eBPF program SendBox uses to inspect MCP calls
sendbox mcp script

# Parse a captured trace log and summarise MCP activity
sendbox mcp parse /var/log/sendbox/mcp-trace.log
sendbox mcp report /var/log/sendbox/mcp-trace.log
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Make sure tests pass (`make test`)
4. Lint your code (`make lint`)
5. Open a pull request

For larger changes, please open an issue first to discuss the approach.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
