# SendBox

**Give your coding agent a workspace, not your whole machine.**

SendBox is an open-source Rust CLI for running coding agents in dedicated Linux
VMs on **macOS and Linux**. Keep your terminal workflow while explicitly choosing
the files, network destinations, credentials, and MCP tools a session can use.

Use it to try an unfamiliar agent, work on a sensitive repository, or run
headless coding tasks without handing the agent your home directory and host
environment.

[Quick start](#quick-start) |
[Supported agents](#supported-coding-agents) |
[Configuration and commands](#configuration-and-commands) |
[Integrations](#integrations) |
[Similar tools](#similar-tools) |
[Documentation](docs/README.md)

## Why SendBox?

An agent needs to edit code, run commands, and reach its model provider. It does
not need unrestricted access to everything else on your laptop or runner.
SendBox puts that distinction in a reviewable YAML policy, with the same guest
controls across supported CLI agents.

| Feature | What it gives you |
|---|---|
| **VM-backed isolation** | A dedicated guest kernel through Apple Containerization or Kata Containers, rather than a workload sharing the host kernel. |
| **Explicit workspace scope** | Share one project, or deliberately opt into a multi-repository workspace. Your host home and runtime sockets are not mounted automatically. |
| **Controlled execution and networking** | Deny-first rules for the brokered entry command and allowed domains. Guest containment also covers descendants; direct external agent traffic and UDP/QUIC are blocked. |
| **Scoped credentials** | Vault-backed secrets and separate GitHub, Copilot, MCP, and registry credential paths. Known credentials are masked in terminal output and diagnostics. |
| **MCP tool policies** | Admit exact local servers or remote Streamable HTTP endpoints, filter tool discovery, and allow or deny tools per server. |
| **Package checks before delivery** | An optional npm proxy verifies and inspects packages before releasing their bytes, with private registry credentials kept out of the workload. |
| **Snapshots and audit evidence** | Before/after workspace snapshots, diffs, failure rollback, and tamper-evident lifecycle records help you understand what changed. |
| **GitHub write controls** | Guard selected-repository Git branches, or use optional Safe Outputs to declare bounded writes without giving the agent a GitHub write token. |
| **Interactive or automated sessions** | Run terminal agents with `--interactive`, or use headless execution and JSON events from scripts and job runners. |
| **Reproducible tooling** | Bring a digest-pinned Linux tooling image and generate devcontainer configuration from project analysis. |

The host verifies and signs the runtime plan before launch; required guest
controls must be ready before the agent starts. An unavailable provider or
unsupported capability is an error, **not a fallback to running on the host**.

Network grants support explicit subdomain wildcards. On Apple and Kata, an exact
`github.com` grant also includes periodically refreshed official GitHub Meta
domains and IPv4/IPv6 CIDRs, including shared-cloud ranges. See
[network scope, outages, and provenance](docs/configuration.md#network-grants).

## Supported coding agents

| Agent | Init profile | Example guest executable |
|---|---|---|
| **Moguri** | `--agent moguri` | `/usr/local/bin/moguri` |
| **Claude Code** | `--agent claude` | `/usr/local/bin/claude` |
| **OpenAI Codex CLI** | `--agent codex` | `/usr/local/bin/codex` |
| **GitHub Copilot CLI** | `--agent copilot` | `/usr/local/bin/copilot` |
| **Gemini CLI** | `--agent gemini` | `/usr/local/bin/gemini` |
| **OpenCode** | `--agent opencode` | `/usr/local/bin/opencode` |
| **Custom CLI agents and programs** | `--agent custom` | Your explicitly allowed absolute path |

Profiles configure the agent's entry command and initial inference hosts; they
**do not install the agent or log you in**. Your workload image must contain the
Linux agent, its dependencies, certificates, development tools, and `nftables`
for mandatory guest egress enforcement. Use the agent's actual installed
executable path when launching; entrypoint and working-directory paths must not
traverse symlinks.

Only the Copilot profile enables SendBox's Copilot credential forwarding.
Other agents, including Moguri, manage their own authentication. Add any extra
model provider, authentication, package, or plugin endpoints you need explicitly.
The [agent guide](docs/cli-agents.md) covers credentials, native MCP formats,
multi-repo workspaces, and nested agent sandbox settings.

## Quick start

### 1. Install SendBox and a runtime

**Homebrew activation is pending an approved patched stable release.** Published
v0.2.2 predates the TLS fixes for RUSTSEC-2026-0382/0383. The tap bootstrap stays
draft until its formula references verified patched artifacts.

Install the CLI from the existing Homebrew tap:

```bash
brew install mbianchidev/tap/sendbox
```

The formula supports macOS on Apple silicon and Linux on x86_64/aarch64. Follow
the [Homebrew setup](docs/installation.md#homebrew) to stage its signed guest
bundle in a root-owned location before running a VM session. Homebrew does not
provision or start a runtime.

Alternatively, download a matching
[release](https://github.com/mbianchidev/sendbox/releases), verify its attestation
and checksum, and follow the [installation guide](docs/installation.md).
Host release artifacts include the matching signed guest bundle; source builds
need that bundle separately.

| Your host | Session runtime and prerequisites | Setup |
|---|---|---|
| macOS 26+ on Apple silicon | Apple Containerization, Xcode 26, and official `container` CLI **0.10.0** with its service registered and running | [Apple runtime](docs/apple-runtime.md) |
| Linux x86_64 or aarch64 with hardware or nested virtualization | Kata Containers **3.28+**, containerd **1.7+**, nerdctl, CNI plugins, and user access to `/dev/kvm` and containerd | [Kata runtime](docs/kata-containers.md) |

Linux host binaries also need libseccomp, libelf, zlib, and zstd runtime libraries
(on Debian/Ubuntu: `libseccomp2 libelf1 zlib1g libzstd1`). Rust is only required
when building from source.

Run the installed `setup.sh` as your normal user for runtime preflight and
configuration assistance, not `sudo sendbox`. For macOS package/DMG installs,
the helper is `/usr/local/share/sendbox/setup.sh`; for tarballs it is in the
extracted release directory. See [full requirements](docs/installation.md#requirements).
macOS installers are **unsigned and unnotarized**; follow the
[package instructions](docs/installation.md#unsigned-macos-packages).

Confirm the binary is on your `PATH`:

```bash
sendbox --version
sendbox help run
```

#### Build from source instead

Install the pinned Rust **1.93.1** toolchain and the
[native build dependencies](docs/installation.md#requirements), then:

```bash
git clone https://github.com/mbianchidev/sendbox.git
cd sendbox
make install PREFIX="$HOME/.local"
export PATH="$HOME/.local/bin:$PATH"
sendbox --version
```

This builds and installs the host CLI, not a VM runtime, an agent image, or the
signed guest bundle. Obtain the matching verified bundle and trust root
separately before `sendbox run`.

### 2. Configure your project and agent

From your project directory, select a profile. For example, with Claude Code:

```bash
sendbox init --project . --agent claude
sendbox secrets add ANTHROPIC_API_KEY
```

`init` creates a private `.sendbox.yaml` in the project root and refuses to
overwrite an existing one. `secrets add` prompts for the value without putting
it in shell history. Edit the generated file to reference the stored credential,
preserving its other settings:

```yaml
secrets: [ANTHROPIC_API_KEY]
```

Review the generated command and network policy before running. The Claude
profile adds `claude` and `api.anthropic.com`; it is not a minimal network
allowlist, so remove any default development endpoints you do not need.

Generated configurations enable GitHub repository forwarding and branch guards.
For a `github.com` checkout, authenticate the host's `gh` CLI, for example with
`gh auth login`. Private repository access additionally requires
`github.allow_private_repository_access: true`. If no GitHub credential is
needed, set `github.forward_auth: false`; for a non-Git project also set
`github.branch_protection.enabled: false`. Non-Copilot profiles already disable
Copilot token forwarding. See the
[credential guide](docs/cli-agents.md#credentials-and-agent-state); host login
files are not copied into the VM.

Validate and inspect the policy before starting a VM:

```bash
sendbox policy validate --config .sendbox.yaml
sendbox policy show --config .sendbox.yaml --json
```

Validation should exit successfully. It checks configuration and policy, not
runtime readiness, image contents, or whether credentials can be retrieved.

### 3. Start a terminal session

Set `WORKLOAD_IMAGE` to your **digest-pinned image containing Claude Code**.
The image below is a placeholder, not a published agent image.
`GUEST_DIR` below matches a macOS package/DMG installation:

```bash
WORKLOAD_IMAGE='your-registry/agent-tools@sha256:REPLACE_WITH_DIGEST'
GUEST_DIR='/usr/local/share/sendbox/guest/aarch64'

sendbox run --interactive \
  --config .sendbox.yaml \
  --image "$WORKLOAD_IMAGE" \
  --bundle "$GUEST_DIR/bundle" \
  --trust-root "$GUEST_DIR/release-public.key" \
  -- /usr/local/bin/claude
```

For Homebrew installs, use the versioned root-owned `GUEST_DIR` from the
[guest staging guide](docs/installation.md#stage-the-guest-bundle), not the
macOS package path above.

For tarball installs, use `guest/aarch64/` or `guest/x86_64/` under the root-owned
extracted release directory. The workload image and bundle architectures must
match; **ARM guest directories are named `aarch64`, not `arm64`**. Bundle files,
the trust root, and their ancestors must meet the runtime's ownership and
permission checks. Moving only the public key into a trusted location is not
sufficient.

`auto` selects Apple on macOS arm64 and Kata on Linux; you can select a provider
explicitly with `--runtime`. Once authenticated guest services are ready, the
agent starts in the shared project at `/workspace`. A successful zero exit
preserves workspace edits; the session's guest home and login state are discarded.

Drop `--interactive` and supply your agent's headless arguments for automation.
`--json` emits machine-readable events in headless mode and cannot be combined
with `--interactive`; workload output bytes are hex encoded.
See [terminal troubleshooting](docs/interactive-sessions.md) and the
[CLI reference](docs/cli-reference.md) for more options.
For first-request networking failures, use the credential-free
[cold-start DNS diagnostic](docs/dns-cold-start.md), not a warmed retry.

## Configuration and commands

The generated `.sendbox.yaml` is the starting point, not a requirement to use
every integration. Review `project_path` and optional `workspace_path`, CPU and
memory resources, `policy.commands`, `policy.network`, `secrets`, and `github`
for each project. Sharing a parent workspace exposes its sibling repositories
too. Package inspection, Safe Outputs, and syscall tracing are opt-in.

Use the [configuration guide](docs/configuration.md) and
[annotated YAML reference](config/example-sandbox.yaml) for individual settings.
These commands do not launch a VM or require an agent login:

```bash
# Inspect the configured boundary declaration, not a live session
sendbox boundary inspect --config .sendbox.yaml --json

# Analyze a project without writing generated files
sendbox analyze --project . --json

# Write .devcontainer/devcontainer.json from native project analysis
sendbox devcontainer generate --project .

# Install completions for your shell (bash, zsh, or fish)
sendbox completions install --shell zsh
```

Devcontainer generation merges an existing configuration and rewrites it as
JSON; JSONC comments are not preserved. Review the resulting diff. A generated
devcontainer is development-environment configuration, not a replacement for
`sendbox run` or its security services. Use `sendbox help <subcommand>` for
options supported by your installed version.

## Integrations

| Connect it to | How it fits |
|---|---|
| **Local and remote MCP servers** | Broker local stdio tools and remote Streamable HTTP services with separate tool policies and scoped authentication. |
| **GitHub workflows** | Use repository-scoped credentials and branch guards, or stage Safe Outputs for host-side writes after the VM is gone. |
| **Model providers and private registries** | Allow only the inference endpoints you use; optionally route npm traffic through the package inspection proxy. |
| **VS Code and devcontainer tooling** | Generate a standard devcontainer spec for reproducible development setup. The spec alone does not reproduce SendBox's security controls. |
| **CI and custom orchestrators** | Invoke the CLI on a prepared virtualization-capable runner; use headless commands and JSON events. Runner provisioning and scheduling remain yours. |

See [integration recipes and boundaries](docs/integrations.md) for configuration
examples and the distinction between built-in support and workflows you compose.

<a id="how-does-it-compare"></a>

## Similar tools

**Choose SendBox when you want to run CLI agents on infrastructure you control,
with VM isolation and explicit policies across agents.** It is not a hosted
sandbox service or a turnkey fleet scheduler.

| Tool | Deployment and isolation | Strengths and tradeoffs |
|---|---|---|
| [Agent Substrate](https://github.com/agent-substrate/substrate) | Kubernetes; gVisor or Cloud Hypervisor microVMs | Stateful agent fleets, suspend/resume, and credentials injected outside actors. Requires operating a cluster; gVisor and microVMs are different boundaries. |
| [Chainguard Workspaces](https://edu.chainguard.dev/chainguard/workspaces/overview/) | Chainguard-hosted Linux microVMs | Terminal sessions, external credentials, and full-state resume. Currently beta; default sessions reach the public internet unless opened with an egress allowlist. |
| [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) | Local microVMs or a separate managed cloud offering | Local sandboxes include their own Docker Engine and optional private-clone workflow. Local and cloud policies and lifecycles differ. |
| [E2B](https://docs.e2b.dev/) | API/SDK-driven cloud Linux VMs; self-hosting also documented | Code execution, templates, and pause/resume for applications. A platform to integrate, rather than a local CLI session policy wrapper. |
| [Daytona](https://www.daytona.io/docs/en/sandboxes/) | API-first remote platform with container and VM sandbox classes | Programmatic environments, snapshots, and multiple OS options. Select the sandbox class explicitly; do not assume every sandbox is a VM. |
| [microsandbox](https://github.com/superradcompany/microsandbox) | Local microVMs on macOS, Linux, and Windows | Embeddable SDKs, OCI images, and fork/snapshot workflows. Beta, general-purpose execution infrastructure rather than SendBox's integrated session controls. |
| [Dev containers](https://containers.dev/overview) | Environment specification; boundary depends on its runtime and mounts | Reproducible tooling and editor setup. The specification itself is not an agent security boundary. |
| **SendBox** | Self-managed macOS/Apple and Linux/Kata VMs | One policy across CLI agents, with the optional controls below. You prepare the runtime, tooling image, and verified guest bundle; no Windows runtime or fleet scheduler. |

Two distinctive SendBox built-ins, rather than claims of exclusive invention:

| Workflow | SendBox implementation | Comparison |
|---|---|---|
| **Gate npm bytes before delivery** | An opt-in [registry proxy](docs/package-supply-chain.md) quarantines tarballs, verifies integrity and configured signature/provenance requirements, and statically inspects content before allowing delivery. | An equivalent built-in pipeline was not established in the reviewed sources. Chainguard advertises lockfile verification, which is not the same guarantee. |
| **Bound GitHub writes after VM teardown** | A native, partial-conformance [Safe Outputs gateway](docs/architecture/safe-outputs.md) validates bounded requests and stages them or applies them on the host without giving the agent a write token. | Docker Sandboxes can also run under GitHub Agentic Workflows, which supplies Safe Outputs through the external workflow. SendBox integrates this subset into local sessions. |

Both SendBox controls are opt-in and supported on Apple/Kata, not Hyperlight.
VMs, credential mediation, and snapshots are **not unique to SendBox**.
This comparison uses official sources reviewed on October 29, 2026; missing
documentation means unknown, not unsupported. See the
[comparison guide and sources](docs/alternatives.md) for scope and limitations.

## Limitations and security expectations

VM isolation does not make agent-generated changes trustworthy. The shared
workspace is writable, and credentials deliberately delivered to an agent are
available to that agent. Review changes before executing them on your host.

Workspace mounts are live, not an isolated copy waiting to be merged.
Nonzero exits, runtime failures, and normal session cancellation trigger
snapshot rollback of the shared workspace. Avoid concurrent host edits during
a session: they can be included in a rollback. A failed run is not a way to
retain partial agent changes.

Command policy covers the brokered top-level argv, not recursive semantic
inspection of every descendant command. Credential masking is not comprehensive
data-loss prevention, and local Git guards do not replace server-side branch
protection. Optional syscall tracing observes activity; it does not enforce policy.

Agents must honor the configured HTTP/SOCKS proxies to reach allowed external
services. Direct connections and UDP/QUIC remain blocked; a client that ignores
the proxies will fail even if its destination is allowed. See
[agent networking](docs/cli-agents.md#agent-compatible-network-proxy).

Apple and Kata support the full persistent guest-service path.
[Hyperlight](docs/hyperlight.md) is an explicit Linux/KVM **one-shot** provider,
not an interactive agent runtime; it rejects MCP, credential delivery, and
restrictive-egress composition rather than silently downgrading them.

There is no Windows or Intel macOS runtime, Kubernetes backend, or graphical
dashboard. CI sessions require a prepared runner with the selected runtime and
virtualization access; ordinary container-only runners are not enough.

Read the [security model](docs/security-model.md) for guarantees and assumptions,
and the [documentation index](docs/README.md) for configuration, architecture,
and operational guides.

## Contributing

Contributions are welcome. See the [contribution guide](docs/contributing.md)
for source setup, checks, and release procedures. The [roadmap](ROADMAP.md)
includes future proposals and historical designs; use the CLI and runtime
guides above for current behavior.

## License

[Apache License 2.0](LICENSE).
