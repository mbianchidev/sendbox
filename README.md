# SendBox

**Authenticated, VM-backed agent sandboxing on macOS and Linux.**

SendBox runs AI agents through a signed, fail-closed runtime plan. Persistent
sessions use Apple's [Containerization](https://github.com/apple/containerization)
on Apple silicon or [Kata Containers](https://katacontainers.io/) through
nerdctl/containerd on Linux. Hyperlight is an explicit Linux/KVM one-shot
provider with a narrower capability set.

---

## Features

- **File Isolation** — Host visibility is limited to explicitly configured
  runtime mounts; state and workspace roots must be disjoint.
- **Command Filtering** — Deny-first semantic policy applies to the brokered
  top-level argv. Descendants inherit kernel containment rather than an
  unprovable recursive shell-policy claim.
- **Network Firewall** — Apple and Kata sessions route DNS and TCP CONNECT
  through loopback brokers backed by cgroup-v2 identity, `SO_MARK`, and atomic
  nftables rules. UDP/QUIC and direct external agent traffic are denied.
- **Runtime Providers** — `auto` selects Apple on macOS arm64 and Kata on Linux.
  Explicit Apple, Kata, and Hyperlight requests never fall back silently.
- **Hyperlight Execution** — Verified one-shot commands run in
  Hyperlight/Unikraft micro-VMs on Linux; unsupported persistent guest, MCP,
  credential, Git-guard, and restrictive-egress features are rejected.
- **Credential Injection** — Secrets and repository-scoped GitHub/Copilot
  credentials use authenticated encrypted host-to-guest envelopes. SSH keys are
  staged only for a trusted SSH child in an owner-only runtime directory and are
  removed afterward.
- **Undo & Rollback** — Descriptor-safe, content-addressed SHA-256 snapshots
  support capture, verify, restore, diff, and prune with versioned formats.
- **Audit Trail** — Lifecycle operations and security decisions are committed to
  versioned hash-chained records with Merkle summaries and externally verifiable
  heads.
- **Native MCP Boundary** — Apple and Kata guests install a root-owned stdio
  broker with bounded framing, strict JSON-RPC validation, deny-first tool
  policy, exact server commands, a cleared environment, and versioned
  observation records. See [docs/mcp-inspection.md](docs/mcp-inspection.md).
- **Boundary Enforcement** — The host signs one immutable runtime plan before
  provider dispatch. The authenticated guest starts mandatory security services
  before workload execution and rejects session, policy, feature, or cgroup
  drift.
- **Supply Chain Provenance** — Boundary plans and reproducible guest bundles
  use Ed25519 signatures, versioned trust metadata, rollback floors, inventory,
  and SBOM evidence. Host archives and installers receive GitHub artifact
  attestations.
- **Runtime Supervisor** — Permission grants use an explicit persisted and
  auditable state machine with one-time, session, pattern, and permanent-deny
  decisions.
- **VM Hardening** — Dedicated service profiles apply no-new-privileges,
  capability removal, resource limits, and architecture-aware TSYNC seccomp.
- **Devcontainer Generation** — Export sandbox configurations as [devcontainer](https://containers.dev/) specs for reproducible environments.

## Requirements

| Scope | Dependency | Minimum |
|---|---|---|
| Source build | Rust | 1.93.1 (pinned by `rust-toolchain.toml`) |
| Linux source build | Native compiler and headers | `build-essential clang cmake libelf-dev libseccomp-dev libzstd-dev pkg-config zlib1g-dev` on Debian/Ubuntu |
| Apple runtime | macOS | 26 (Tahoe) |
| Apple runtime | Hardware | Apple Silicon |
| Apple runtime | Xcode | 26 |
| Apple runtime | Official `container` CLI | 0.10.0, service already registered and running |
| Kata runtime | Linux | Bare metal or nested virtualization |
| Kata runtime | Kata Containers | 3.28 |
| Kata runtime | containerd | 1.7 |
| Kata runtime | nerdctl and CNI plugins | Current compatible releases |
| Linux host binary | libseccomp, libelf, zlib, and zstd runtime libraries | Distribution packages such as `libseccomp2`, `libelf1`, `zlib1g`, and `libzstd1` |
| Hyperlight runtime | Operator-pinned `hyperlight-unikraft`, signed Unikraft bundle, and KVM | See [docs/hyperlight.md](docs/hyperlight.md) |

Production [guest artifact bundles](docs/architecture/guest-artifact-bundles.md)
provide static-musl guest and execution binaries, strict CO-RE BPF objects,
signed manifests, inventory, SBOM metadata, deterministic rootfs tarballs, and
minimal scratch OCI images for Linux x86_64 and arm64. The image contains no
Python, Node.js, compiler, bpftrace, or development headers.

The production BPF programs are cgroup-scoped observation only. The Apple
adapter can mount their signed bundle, but activation remains guest-policy
driven and these programs do not claim exec, syscall, network, or MCP
enforcement.

## Quick Start

### Install

#### Release artifacts

Download the matching artifact from
[Releases](https://github.com/mbianchidev/sendbox/releases):

| Host | Artifacts |
|---|---|
| macOS arm64 | tarball, unsigned `.pkg`, unsigned `.dmg` |
| Linux x86_64 | tarball |
| Linux aarch64 | tarball |

Each host archive and macOS installer contains the production `sendbox` binary,
configuration examples, setup helper, and matching signed guest bundle. The
release also publishes standalone guest-bundle archives.

Verify GitHub provenance before trusting the embedded guest public key, then
verify the adjacent checksum:

```bash
gh attestation verify sendbox-<version>-<platform>.tar.gz \
  -R mbianchidev/sendbox
shasum -a 256 -c sendbox-<version>-<platform>.tar.gz.sha256

# Install a verified tarball into a root-owned runtime location
sudo tar xzf sendbox-<version>-<platform>.tar.gz -C /opt
sudo install -m 0755 /opt/sendbox-<version>-<platform>/sendbox \
  /usr/local/bin/sendbox

# Or install the verified macOS package
sudo installer -pkg sendbox-<version>-macos-arm64.pkg -target /
```

Run `/opt/sendbox-<version>-<platform>/setup.sh` as your normal user. The
root-owned extraction preserves the runtime trust boundary for the bundled guest
artifacts; do not copy them into a user-writable directory before launch.

#### From source

```bash
git clone https://github.com/mbianchidev/sendbox.git
cd sendbox
make install
```

Source installs require a separately attested signed guest bundle and trust root;
tagged host artifacts already include the matching pair.

For an interactive runtime preflight and configuration flow:

```bash
./setup.sh
```

Kata installation and containerd configuration are documented in [docs/kata-containers.md](docs/kata-containers.md).

### Production implementation

The Rust workspace emits the production `sendbox` binary. It implements
`run`, `init`, `analyze`,
`devcontainer`, `policy`, `secrets`, `mcp`, `boundary`, and `completions`.

`sendbox run` resolves and verifies one signed boundary plan before provider
construction or image acquisition. Persistent Apple and Kata sessions bind the
plan digest into authenticated bootstrap, then start egress, MCP, Git,
credential, audit, snapshot, supervisor, and execution controls before the
guest accepts the workload. Hyperlight uses an authenticated one-shot path and
rejects unsupported composition.

See [authenticated guest protocol](docs/architecture/authenticated-guest-protocol.md),
[agent orchestration](docs/architecture/agent-orchestration.md),
[Git branch guard](docs/architecture/git-branch-guard.md), and
[secrets and credential brokering](docs/architecture/secrets-and-credential-broker.md).

```bash
make build
make test
./target/debug/sendbox --version
./target/debug/sendbox init --project .
./target/debug/sendbox policy show --json
./target/debug/sendbox policy validate --config config/example-sandbox.yaml
./target/debug/sendbox policy validate --config config/example-sandbox.yaml --json
./target/debug/sendbox completions print --shell zsh
```

Rust-generated configuration uses deterministic snake_case YAML, validates
before writing, is created atomically with mode `0600`, and refuses to overwrite
an existing `.sendbox.yaml`. JSON results are deterministic. Invalid input or
configuration returns `2`; analysis failures return `3`; write failures and
no-overwrite refusals return `4`. Text diagnostics use stderr, while `--json`
failures use stdout only.

### Unsigned macOS packages

The `.pkg` and `.dmg` are not Apple-signed or notarized. Verify their GitHub
attestation and checksum before installation. If Gatekeeper blocks a verified
download, approve that artifact in Finder or System Settings, or remove only its
quarantine attribute:

```bash
xattr -dr com.apple.quarantine sendbox-<version>-macos-arm64.pkg
```

Do not disable Gatekeeper globally. The package removes quarantine from the
installed `/usr/local/bin/sendbox` only after the installer has been approved.
The DMG `install.sh` replaces the shared payload through a fresh staging
directory, removes stale upgrade files, and enforces root ownership with `0555`
guest executables and `0444` bundle metadata and trust roots.

### Configure

Generate `.sendbox.yaml` in the project root, then edit it as needed using the
[Configuration](#configuration) reference:

```bash
sendbox init --project .
sendbox init --project . --runtime kata
```

### Run

```bash
# Launch one exact argv workload through a verified guest bundle
sendbox run \
  --config .sendbox.yaml \
  --runtime kata \
  --image registry.example/workload@sha256:<digest> \
  --bundle /usr/local/share/sendbox/guest/x86_64/bundle \
  --trust-root /usr/local/share/sendbox/guest/x86_64/release-public.key \
  -- /usr/bin/true
```

Tarball users can point these flags at `guest/<architecture>/` inside the
extracted release directory. A bundled public key is not self-authenticating;
trust it only after verifying the host or standalone guest archive attestation.

### Interactive terminal sessions

`--interactive` runs the workload on a pseudoterminal inside the sandbox and forwards this
terminal's keystrokes and window size to it, which is what terminal agents such as GitHub
Copilot CLI, Claude Code, Codex and Gemini need in order to render and accept input.

```bash
sendbox run --interactive \
  --config .sendbox.yaml \
  --runtime kata \
  --image registry.example/workload@sha256:<digest> \
  --bundle /usr/local/share/sendbox/guest/x86_64/bundle \
  --trust-root /usr/local/share/sendbox/guest/x86_64/release-public.key \
  -- /usr/bin/copilot
```

Keystrokes ride the same authenticated control channel as workload output, so they inherit
its message authentication, replay protection and session binding. No additional port,
socket or privilege is introduced.

Requirements and behaviour:

- Both stdin and stdout must be a terminal and `sendbox` must be in that terminal's
  foreground process group. Otherwise the run fails with a clear error instead of silently
  falling back to a workload with no input.
- `--interactive` cannot be combined with `--json`; machine-readable output and a raw
  terminal are mutually exclusive.
- Only the `apple` and `kata` runtimes provide a terminal. `hyperlight` rejects
  `--interactive` before anything is created or started.
- `Ctrl-C`, `Ctrl-Z` and `Ctrl-D` are delivered to the *workload's* terminal, not to
  `sendbox`. Use the agent's own quit command to end the session.
- The host `TERM` is authoritative for the workload; it replaces any configured `TERM`.
- Terminal output merges the workload's stdout and stderr, because a terminal is a single
  device. Drop `--interactive` when the two streams must stay separate.
- Window size changes are tracked through `SIGWINCH` for as long as the run lasts.

See [interactive terminals](docs/architecture/interactive-terminal.md) for the design,
flow-control rules and qualification evidence.

Troubleshooting:

| Symptom | Cause | Fix |
|---|---|---|
| `--interactive requires a terminal but stdin is not one` | `sendbox` is being piped or run from a job runner | Run it from a terminal, or drop `--interactive` |
| `--interactive requires the foreground process group` | Started with `&` or under a job-control shell in the background | Bring the job to the foreground |
| `the hyperlight runtime cannot provide an interactive terminal` | `--runtime hyperlight` | Use `--runtime apple` or `--runtime kata` |
| `interactive execution needs a controlling terminal, but the command policy denies: ioctl` | `policy.boundaries.syscalls.additional_denylist` blocks terminal syscalls | Remove `ioctl`, `setsid`, `dup2` and `dup3` from the denylist, or run without `--interactive` |
| The agent renders as garbled boxes | The guest image has no terminfo entry for the host `TERM` | Set `TERM=xterm-256color` before running |

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
    transports: [stdio]
    capture_payloads: false
    max_payload_bytes: 16384
    log_path: /var/log/sendbox/mcp-trace.log
```

Copilot authentication is forwarded independently from repository credentials. By default, a
GitHub token may cover the selected repository and public repositories only. Set
`github.allow_private_repository_access` to permit additional private repositories in the
selected repository's organization; cross-organization private access remains blocked.
GitHub repository forwarding currently supports `github.com`. Ordinary HTTPS Git uses a fixed
authenticated askpass helper rather than assuming `GITHUB_TOKEN` is consumed automatically.
`github.ssh_key_path` accepts an owner-only private-key file and routes Git SSH through a trusted
wrapper with strict host-key checking; the guest image must provide trusted SSH host keys.

Selected-repository `git push` and `git pull` operations are branch-protected by default.
`main` and `master` are denied, while `{username}/*`, `copilot/*`, and `feature/*` are
allowed. The username is auto-detected from `gh` or can be configured explicitly. This guard
requires `policy.boundaries.enabled`; keep GitHub server-side branch protection enabled as
defense in depth against direct API ref mutations or alternate Git clients. Disable
`github.branch_protection.enabled` for non-Git projects.

The native Rust admission engine is connected to persistent Apple and Kata `sendbox run`
sessions through authenticated guest bootstrap. It does not replace hosting-provider rulesets
or protect alternate clients and direct GitHub API calls.

Local stdio MCP configuration is validated before launch and must use
`/run/sendbox-boundary/mcp-broker -- <exact-approved-command>`. Apple and Kata guests install the
root-owned broker and signed policy before the agent starts; server children receive a cleared,
signed environment and fixed workspace. Optional stdio observation is written below
`/var/log/sendbox`. HTTP/SSE inspection and Hyperlight MCP composition fail closed.

### Copilot credentials

`github.forward_copilot_auth: true` forwards a Copilot credential independently of
repository-scoped GitHub authentication. The host resolves it from the first variable that
is set, in this order:

| Host variable | Status |
|---|---|
| `COPILOT_GITHUB_TOKEN` | Supported |
| `GITHUB_COPILOT_TOKEN` | Legacy compatibility only |

Only an *absent* variable falls through to the next candidate; a variable that is set but
empty is a hard error rather than a silent fallback. Repository-scoped credentials
(`GH_TOKEN`, `GITHUB_TOKEN`) are never consulted for Copilot.

Whichever host variable supplied the value, the guest receives it as
**`COPILOT_GITHUB_TOKEN`** — the name current GitHub Copilot CLI releases read — so no
wrapper script or duplicated GitHub token is required. Errors name the supported variables
and never print a credential value.

### Configuration Reference

| Section | Key | Description |
|---|---|---|
| `name` | string | Human-readable sandbox name |
| `project_path` | string | Host project directory mounted into the guest |
| `runtime.provider` | enum | `auto`, `apple`, `kata`, or `hyperlight` |
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
| `github.forward_copilot_auth` | bool | Forward Copilot authentication independently as `COPILOT_GITHUB_TOKEN` |
| `github.allow_private_repository_access` | bool | Permit additional same-organization private repositories |
| `github.ssh_key_path` | string | Owner-only SSH private key used by the trusted Git SSH wrapper |
| `github.branch_protection.enabled` | bool | Guard selected-repository pushes and pulls by branch |
| `github.branch_protection.username` | string | Username used to expand `{username}` patterns; auto-detected by default |
| `github.branch_protection.protected_branches` | list | Branch names that push and pull can never target |
| `github.branch_protection.allowed_branch_patterns` | list | Glob patterns allowed for selected-repository push and pull |
| `observability.mcp_inspection.enabled` | bool | Enable authenticated local stdio MCP observation on Apple or Kata |

### Run flags

| Flag | Description |
|---|---|
| `--config PATH` | Sandbox configuration file |
| `--runtime auto\|apple\|kata\|hyperlight` | Runtime provider selection |
| `--image IMAGE@sha256:DIGEST` | Digest-pinned workload image for persistent runtimes |
| `--bundle PATH` | Verified guest bundle directory |
| `--trust-root PATH` | Release public key used to verify the bundle |
| `--json` | Emit machine-readable events instead of raw output |
| `--interactive` | Run the workload on a pseudoterminal; conflicts with `--json` |

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

The Rust workspace separates immutable boundary planning, provider-neutral
orchestration, runtime adapters, authenticated guest services, and
security-record persistence. The CLI depends on native project analysis and
devcontainer generation; no production path requires Node.js or Copilot.

See the architecture documents for
[project analysis](docs/architecture/native-project-analysis.md),
[runtime core](docs/architecture/runtime-core.md),
[agent orchestration](docs/architecture/agent-orchestration.md),
[secrets](docs/architecture/secrets-and-credential-broker.md), and
[session security](docs/architecture/session-security-lifecycle.md),
[execution brokerage](docs/architecture/execution-broker.md),
[interactive terminals](docs/architecture/interactive-terminal.md), plus
[egress enforcement](docs/architecture/egress-enforcement.md).

See [docs/hyperlight.md](docs/hyperlight.md) for Hyperlight setup and limitations.
The production Apple adapter, qualification command, transport design, and
limitations are documented in [docs/apple-runtime.md](docs/apple-runtime.md).
The earlier isolated evidence remains in
[docs/apple-container-adapter-spike.md](docs/apple-container-adapter-spike.md).

## Security Model

SendBox follows a **deny-by-default** security posture:

1. **Filesystem** — Only explicitly configured host paths are mounted into the guest. State and workspace roots cannot overlap.
2. **Commands** — Deny rules win over allow rules for the brokered top-level argv. Descendants are constrained by the guest execution boundary, not recursively reinterpreted as shell text.
3. **Network** — Persistent workloads can reach only the loopback DNS and SOCKS5 brokers. Kernel rules deny direct external agent traffic and unmarked broker traffic.
4. **Secrets** — Copilot authentication is independent; GitHub credentials are forwarded only when repository scope matches policy. Secret values use authenticated envelopes and temporary owner-only guest files where a child process requires a file.5. **Isolation** — Apple and Kata provide persistent Linux VMs; Hyperlight provides explicit Linux/KVM one-shot isolation. Missing host or runtime capabilities are errors, never silent fallbacks.
6. **Boundaries** — Signed guest services must become ready before execution. Local stdio MCP calls must traverse the installed broker; HTTP/SSE, direct project-server configuration, and unsupported transports fail closed.
7. **Branches** — Trusted Git wrappers restrict selected-repository push and pull operations. Alternate clients and direct hosting-provider APIs remain outside this local guard, so server-side rules stay required.

## CLI Reference

The Rust CLI implements the complete supported `sendbox` surface:

```
USAGE: sendbox <subcommand> [options]

SUBCOMMANDS:
  init          Initialize a new sendbox.yaml in the current directory
  run           Start the sandbox and launch the agent
  analyze       Analyze a project and generate a devcontainer spec
  secrets       Add, remove, or list stored secrets
  policy        Show or validate policies
  mcp           Parse and summarize native or legacy MCP observations
  boundary      Inspect the structured native boundary plan
  completions   Install or print shell completions
  help          Show help for any subcommand
```

### Examples

```bash
# Initialize a new project
sendbox init

# Run with the Kata backend
sendbox run --config .sendbox.yaml --runtime kata \
  --image registry.example/workload@sha256:<digest> \
  --bundle /usr/local/share/sendbox/guest/x86_64/bundle \
  --trust-root /usr/local/share/sendbox/guest/x86_64/release-public.key \
  -- /usr/bin/true

# Generate devcontainer spec
sendbox analyze --project . --output .devcontainer/

# Validate a sandbox configuration's policy
sendbox policy validate --config sendbox.yaml

# Show the effective policy as deterministic JSON
sendbox policy show --config sendbox.yaml --json

# Print or install generated shell completions
sendbox completions print --shell zsh
sendbox completions install --shell fish

# Native analysis with automation JSON
cargo run -p sendbox-cli -- analyze --project . --json

# Native devcontainer generation
cargo run -p sendbox-cli -- devcontainer generate --project . --json

# Parse a captured trace log and summarise MCP activity
sendbox mcp parse /var/log/sendbox/mcp-trace.log
sendbox mcp report /var/log/sendbox/mcp-trace.log

# Inspect the structured boundary declaration without generating scripts
sendbox boundary inspect --config .sendbox.yaml --json
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
