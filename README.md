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
[Integrations](#integrations) |
[Alternatives](#how-does-it-compare) |
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

## Supported coding agents

| Agent | Init profile | Example guest executable |
|---|---|---|
| **Claude Code** | `--agent claude` | `/usr/local/bin/claude` |
| **OpenAI Codex CLI** | `--agent codex` | `/usr/local/bin/codex` |
| **GitHub Copilot CLI** | `--agent copilot` | `/usr/local/bin/copilot` |
| **Gemini CLI** | `--agent gemini` | `/usr/local/bin/gemini` |
| **OpenCode** | `--agent opencode` | `/usr/local/bin/opencode` |
| **Custom CLI agents and programs** | `--agent custom` | Your explicitly allowed absolute path |

Profiles configure the agent's entry command and initial inference hosts; they
**do not install the agent or log you in**. Your workload image must contain the
Linux agent, its dependencies, certificates, development tools, and `nftables`
for mandatory guest egress enforcement. Use its
actual installed executable path when launching.

Non-Copilot profiles do not require Copilot credentials. Add any extra model
provider, authentication, package, or plugin endpoints you need explicitly.
The [agent guide](docs/cli-agents.md) covers credentials, native MCP formats,
multi-repo workspaces, and nested agent sandbox settings.

## Quick start

### 1. Install SendBox and a runtime

Download a matching [release](https://github.com/mbianchidev/sendbox/releases),
verify its attestation and checksum, and follow the
[installation guide](docs/installation.md). Host release artifacts include the
matching signed guest bundle; source builds need that bundle separately.

| Your host | Session runtime | Setup |
|---|---|---|
| macOS 26+ on Apple silicon | Apple Containerization | [Apple runtime](docs/apple-runtime.md) |
| Linux with hardware or nested virtualization | Kata Containers via nerdctl/containerd | [Kata runtime](docs/kata-containers.md) |

Run the installed `setup.sh` as your normal user for runtime preflight and
configuration assistance. See [full requirements](docs/installation.md#requirements)
for pinned tooling and native libraries. macOS installers are currently unsigned
and unnotarized; follow the [package instructions](docs/installation.md#unsigned-macos-packages).

### 2. Configure your project and agent

From your project directory, select a profile. For example, with Claude Code:

```bash
sendbox init --project . --agent claude
sendbox secrets add ANTHROPIC_API_KEY
```

Edit the generated `.sendbox.yaml` to reference the stored credential:

```yaml
secrets: [ANTHROPIC_API_KEY]
```

Review the generated command and network policy before running. GitHub forwarding
and branch protection are configured independently: set up repository
authentication when using them, or explicitly disable the features you do not
need. The [credential guide](docs/cli-agents.md#credentials-and-agent-state)
explains these settings; host login files are not copied into the VM.

### 3. Start a terminal session

Set `WORKLOAD_IMAGE` to your **digest-pinned image containing Claude Code** and
`GUEST_DIR` to the root-owned guest artifact directory from your verified
installation. These are placeholders, not a published agent image:

```bash
WORKLOAD_IMAGE='your-registry/agent-tools@sha256:REPLACE_WITH_DIGEST'
GUEST_DIR='/usr/local/share/sendbox/guest/x86_64'

sendbox run --interactive \
  --config .sendbox.yaml \
  --image "$WORKLOAD_IMAGE" \
  --bundle "$GUEST_DIR/bundle" \
  --trust-root "$GUEST_DIR/release-public.key" \
  -- /usr/local/bin/claude
```

Use `arm64` instead of `x86_64` for an arm64 guest bundle. For tarball installs,
use `guest/<architecture>/` under the root-owned extracted release directory.
`auto` selects Apple on macOS arm64 and Kata on Linux; you can select a provider
explicitly with `--runtime`.

Drop `--interactive` and supply your agent's headless arguments for automation.
See [terminal troubleshooting](docs/interactive-sessions.md) and the
[CLI reference](docs/cli-reference.md) for more options.

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

## How does it compare?

**Choose SendBox when you want to run CLI agents on infrastructure you control,
with VM isolation and explicit policies across agents.** It is not a hosted
sandbox service or a turnkey fleet scheduler.

Docker Sandboxes is another agent-focused option with local microVMs and a
separate cloud offering. Dev containers focus on reproducible development
environments. E2B and Daytona offer API-first sandbox platforms for applications
and agent workflows.

The [alternatives guide](docs/alternatives.md) compares where each fits, deployment
tradeoffs, and isolation considerations, with links to the projects' own
documentation. There is no universal winner: choose for your trust boundary,
tooling needs, and operational model.

## Security expectations

VM isolation does not make agent-generated changes trustworthy. The shared
workspace is writable, and credentials deliberately delivered to an agent are
available to that agent. Review changes before executing them on your host.

Command policy covers the brokered top-level argv, not recursive semantic
inspection of every descendant command. Credential masking is not comprehensive
data-loss prevention, and local Git guards do not replace server-side branch
protection. Optional syscall tracing observes activity; it does not enforce policy.

Apple and Kata support the full persistent guest-service path.
[Hyperlight](docs/hyperlight.md) is an explicit Linux/KVM **one-shot** provider,
not an interactive agent runtime; it rejects MCP, credential delivery, and
restrictive-egress composition rather than silently downgrading them.

Read the [security model](docs/security-model.md) for guarantees and assumptions,
and the [documentation index](docs/README.md) for configuration, architecture,
and operational guides.

## Contributing

See the [contribution guide](docs/contributing.md) for source setup, checks, and
release procedures. The [roadmap](ROADMAP.md) tracks planned work.

## License

[Apache License 2.0](LICENSE).
