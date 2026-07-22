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
- **Boundary Enforcement** — Run every agent process under a seccomp-BPF syscall denylist and route stdio MCP servers through a framing-aware tool proxy. eBPF detects direct proxy bypass attempts and records denied syscalls. Enforcement is fail-closed.
- **Supply Chain Provenance** — Ed25519 signing for config and policy files ensures they were authored by trusted identities. Multi-signer support with a configurable trust store.
- **Runtime Supervisor** — Dynamic permission expansion with approval workflows. Agents start restricted and earn broader permissions through supervised interaction (one-time, session-wide, or pattern-based grants).
- **VM Hardening** — Defense-in-depth sysctl lockdown, capability dropping, and seccomp profiles covering all 18 [SandboxEscapeBench](https://arxiv.org/abs/2603.02277) scenarios.
- **Devcontainer Generation** — Export sandbox configurations as [devcontainer](https://containers.dev/) specs for reproducible environments.

## Requirements

| Scope | Dependency | Minimum |
|---|---|---|
| Common | Swift | 6.2 |
| Common | Node.js | 20+ for `copilot-bridge` |
| Experimental validator | Rust | 1.93.1 (pinned by `rust-toolchain.toml`) |
| Apple runtime | macOS | 26 (Tahoe) |
| Apple runtime | Hardware | Apple Silicon |
| Apple runtime | Xcode | 26 |
| Kata runtime | Linux | Bare metal or nested virtualization |
| Kata runtime | Kata Containers | 3.28 |
| Kata runtime | containerd | 1.7 |
| Kata runtime | nerdctl and CNI plugins | Current compatible releases |
| Hyperlight runtime | `hyperlight-unikraft` and KVM | 0.12 |

Production [guest artifact bundles](docs/architecture/guest-artifact-bundles.md)
provide static-musl guest and execution binaries, strict CO-RE BPF objects,
signed manifests, inventory, SBOM metadata, deterministic rootfs tarballs, and
minimal scratch OCI images for Linux x86_64 and arm64. The image contains no
Python, Node.js, compiler, bpftrace, or development headers.

The production BPF programs are cgroup-scoped observation only. Runtime adapter
integration is intentionally not wired yet, and these programs do not claim
exec, syscall, network, or MCP enforcement.

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

### Experimental Rust validator

The parallel Rust foundation builds an experimental `sendbox-rs` binary. In this
phase it only parses and validates configuration and policy; all sandbox runtime
execution remains on the production Swift `sendbox` binary.

The workspace also contains the pre-1.0 `sendbox-protocol` foundation for
bounded, authenticated host/guest communication. `sendbox-runtime` now owns the
transport-neutral channel provisioning contract, and `sendbox-agent` owns the
pure orchestration state machine; neither starts a concrete vendor VM or selects
runtime-specific socket mappings. See
[authenticated guest protocol](docs/architecture/authenticated-guest-protocol.md)
and [agent orchestration](docs/architecture/agent-orchestration.md).

```bash
make rust-build
make rust-test
./target/debug/sendbox-rs --version
./target/debug/sendbox-rs policy validate --config config/example-sandbox.yaml
./target/debug/sendbox-rs policy validate --config config/example-sandbox.yaml --json
```

The JSON form is deterministic and intended for future Swift/Rust differential
tests. Invalid configuration returns exit status `2`; text diagnostics are
written to stderr, while `--json` always writes its result to stdout.

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
# sendbox.yaml
name: my-agent-sandbox
project_path: ./workspace

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
  disk_size_mb: 10240

policy:
  commands:
    default_action: deny
    allowlist:
      - "git *"
      - "npm *"
      - "python3 *"
    denylist:
      - "sudo *"
    log_blocked: true

  network:
    default_action: deny
    allow_dns: true
    # Replace wildcard entries with concrete hostnames when using Hyperlight.
    allowed_domains:
      - github.com
      - "*.github.com"
      - registry.npmjs.org
    blocked_domains: []

  boundaries:
    # Set to false when using Hyperlight.
    enabled: true
    tool_calls:
      transport: stdio       # HTTP/SSE MCP is rejected in boundary mode
      default_action: deny
      allowlist:
        - read_file
        - list_directory
        - search_code
      denylist:
        - "*delete*"
      max_frame_bytes: 1048576
      server_command_patterns:
        - mcp-server
        - "@modelcontextprotocol"
      allowed_server_commands:
        - ["/usr/local/bin/node", "/usr/local/lib/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js", "/workspaces/my-project"]
    syscalls:
      additional_denylist:
        - io_uring_setup
      log_blocked: true
    log_path: /var/log/sendbox/boundary.log

secrets:
  - NPM_TOKEN

devcontainer:
  auto_generate: true
  extensions:
    - github.copilot

github:
  forward_auth: true
  forward_copilot_auth: true
  allow_private_repository_access: false
  branch_protection:
    enabled: true
    protected_branches: [main, master]
    allowed_branch_patterns:
      - "{username}/*"
      - "copilot/*"
      - "feature/*"

observability:
  mcp_inspection:
    enabled: false
    transports: [stdio, http]
    capture_payloads: false
    max_payload_bytes: 16384
    log_path: /var/log/sendbox/mcp-trace.log
```

Copilot authentication is forwarded independently from repository credentials. By default, a
GitHub token may cover the selected repository and public repositories only. Set
`github.allow_private_repository_access` to permit additional private repositories in the
selected repository's organization; cross-organization private access remains blocked.

Selected-repository `git push` and `git pull` operations are branch-protected by default.
`main` and `master` are denied, while `{username}/*`, `copilot/*`, and `feature/*` are
allowed. The username is auto-detected from `gh` or can be configured explicitly. This guard
requires `policy.boundaries.enabled`; keep GitHub server-side branch protection enabled as
defense in depth against direct API ref mutations or alternate Git clients. Disable
`github.branch_protection.enabled` for non-Git projects.

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
| `policy.boundaries.enabled` | bool | Install fail-closed MCP and syscall boundaries |
| `policy.boundaries.tool_calls` | object | Framed stdio MCP tool allow/deny rules |
| `policy.boundaries.syscalls.additional_denylist` | list | Extra syscall names blocked by seccomp |
| `secrets` | list | Secret names injected at runtime |
| `devcontainer.auto_generate` | bool | Generate a devcontainer spec |
| `github.forward_auth` | bool | Forward guarded GitHub credentials for the selected repository |
| `github.forward_copilot_auth` | bool | Forward Copilot authentication independently |
| `github.allow_private_repository_access` | bool | Permit additional same-organization private repositories |
| `github.branch_protection.enabled` | bool | Guard selected-repository pushes and pulls by branch |
| `github.branch_protection.username` | string | Username used to expand `{username}` patterns; auto-detected by default |
| `github.branch_protection.protected_branches` | list | Branch names that push and pull can never target |
| `github.branch_protection.allowed_branch_patterns` | list | Glob patterns allowed for selected-repository push and pull |
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

The **copilot-bridge** is a temporary Node.js migration bridge. New project
analysis and devcontainer generation are native Rust and do not require Node.js
or Copilot.

The Rust workspace contains shared domain/error types, strict configuration and
policy validation, native project analysis, runtime and credential primitives,
and production Linux execution and egress enforcement. See the architecture documents for
[project analysis](docs/architecture/native-project-analysis.md),
[runtime core](docs/architecture/runtime-core.md),
[agent orchestration](docs/architecture/agent-orchestration.md),
[secrets](docs/architecture/secrets-and-credential-broker.md), and
[execution brokerage](docs/architecture/execution-broker.md), plus
[egress enforcement](docs/architecture/egress-enforcement.md).

See [docs/hyperlight.md](docs/hyperlight.md) for Hyperlight setup and limitations.
The isolated Rust proof for Apple's official CLI is documented in
[docs/apple-container-adapter-spike.md](docs/apple-container-adapter-spike.md).

## Security Model

SendBox follows a **deny-by-default** security posture:

1. **Filesystem** — Only explicitly mounted paths are visible inside the VM. The host filesystem is never exposed wholesale.
2. **Commands** — By default no binaries are available. Use `allowlist` mode to grant access to specific tools, or `denylist` mode to start permissive and lock down selectively.
3. **Network** — Outbound connections are blocked unless a matching `allow` rule exists. DNS resolution is restricted to permitted hosts.
4. **Secrets** — Copilot authentication is independent; GitHub credentials are forwarded only when their private-repository scope matches policy. Credentials are never persisted in the guest filesystem. Host storage uses Keychain on macOS and mode-restricted files on Linux.
5. **Isolation** — Each sandbox runs in its own lightweight VM. A compromised agent cannot affect the host or other sandboxes.
6. **Boundaries** — The agent runs as the invoking non-root host UID under seccomp. Stdio MCP tool calls must pass through the root-owned proxy; direct server launches are terminated by eBPF.
7. **Branches** — A root-installed git guard and eBPF bypass detector restrict selected-repository pushes and pulls to configured feature branch patterns.

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
  boundary      Inspect generated proxy, eBPF, seccomp, or bootstrap artifacts
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

# Experimental native analysis with automation JSON
cargo run -p sendbox-cli -- analyze --project . --json

# Experimental native devcontainer generation
cargo run -p sendbox-cli -- devcontainer generate --project . --json

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
