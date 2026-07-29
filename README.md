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
- **Package Supply-chain Proxy** — npm metadata and artifacts traverse an
  isolated trusted proxy that verifies, scans, caches, and reports verdicts
  before any package bytes reach the workload.
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
  broker and trusted Streamable HTTP gateway with bounded framing, strict
  JSON-RPC validation, exact server identities, independent deny-first tool
  policies, filtered discovery, and one mandatory redacted audit path. See
  [docs/mcp-inspection.md](docs/mcp-inspection.md).
- **Credential-free Safe Outputs** — An untrusted agent can declare a bounded
  subset of GitHub writes through a root-owned MCP recorder. The host verifies
  the sealed artifact after runtime teardown and only then resolves a dedicated
  write token. See [docs/architecture/safe-outputs.md](docs/architecture/safe-outputs.md).
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
[Releases](https://github.com/mbianchidev/sendbox/releases). Verify its GitHub
attestation and checksum before installing it:

| Host | Artifacts |
|---|---|
| macOS arm64 | tarball, unsigned `.pkg`, unsigned `.dmg` |
| Linux x86_64 | tarball |
| Linux aarch64 | tarball |

```bash
gh attestation verify sendbox-<version>-<platform>.tar.gz \
  -R mbianchidev/sendbox
shasum -a 256 -c sendbox-<version>-<platform>.tar.gz.sha256
```

The [installation guide](docs/installation.md) covers tarball and macOS
installation, release trust, and guest-bundle placement.

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

Kata installation and containerd configuration are documented in the
[Kata Containers guide](docs/kata-containers.md).

### Unsigned macOS packages

The `.pkg` and `.dmg` are not Apple-signed or notarized. Follow the
[macOS package instructions](docs/installation.md#unsigned-macos-packages)
rather than disabling Gatekeeper.

### Configure

Generate `.sendbox.yaml` in the project root, then edit it as needed using the
[configuration guide](docs/configuration.md):

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

`--interactive` runs terminal agents such as GitHub Copilot CLI, Claude Code,
Codex, and Gemini on a pseudoterminal inside the sandbox:

```bash
sendbox run --interactive \
  --config .sendbox.yaml \
  --runtime kata \
  --image registry.example/workload@sha256:<digest> \
  --bundle /usr/local/share/sendbox/guest/x86_64/bundle \
  --trust-root /usr/local/share/sendbox/guest/x86_64/release-public.key \
  -- /usr/bin/copilot
```

See [interactive sessions](docs/interactive-sessions.md) for terminal
requirements, flow control, separate stderr, and troubleshooting.

## Documentation

| Topic | Guide |
|---|---|
| Installation and release verification | [Installation](docs/installation.md) |
| YAML and policy options | [Configuration](docs/configuration.md) |
| Commands and examples | [CLI reference](docs/cli-reference.md) |
| Terminal agents | [Interactive sessions](docs/interactive-sessions.md) |
| Runtime setup | [Apple](docs/apple-runtime.md), [Kata](docs/kata-containers.md), and [Hyperlight](docs/hyperlight.md) |
| Threat model and guarantees | [Security model](docs/security-model.md) |
| Package controls | [Package supply-chain proxy](docs/package-supply-chain.md) |

Browse the [documentation index](docs/README.md) for architecture, qualification,
migration, and implementation-history documents.

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

The [architecture index](docs/README.md#architecture) links to the runtime,
protocol, security-boundary, and agent-tooling design documents.

## Security Model

SendBox follows a **deny-by-default** security posture:

1. **Filesystem** — Only explicitly configured host paths are mounted into the
   guest. State and workspace roots cannot overlap.
2. **Commands** — Deny rules win over allow rules for the brokered top-level
   argv. Descendants inherit the guest execution boundary.
3. **Network** — Persistent workloads can reach only the loopback DNS and SOCKS5
   brokers. Kernel rules deny direct external agent traffic.
4. **Packages** — Configured npm artifacts are quarantined, verified, and
   inspected before release.
5. **Secrets** — Repository, Copilot, MCP gateway, and package registry
   credentials use separate scopes and trusted delivery paths.
6. **Isolation** — Apple and Kata provide persistent Linux VMs; Hyperlight
   provides explicit Linux/KVM one-shot isolation.
7. **Boundaries** — Signed guest services must become ready before execution;
   unsupported transports and authorization fallback fail closed.
8. **Branches** — Trusted Git wrappers restrict selected-repository pushes and
   pulls; server-side rules remain required.

Read the complete [security model](docs/security-model.md) for guarantees,
assumptions, and defense-in-depth analysis.

## CLI Reference

See the [CLI reference](docs/cli-reference.md) for subcommands, run flags, and
common examples. The installed version also provides `sendbox help <subcommand>`.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Run `make lint` (this also compiles every standalone fuzz workspace with
   its committed lockfile)
4. Run `make test`, `make release`, and `make audit`
5. Open a pull request

For larger changes, please open an issue first to discuss the approach.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
