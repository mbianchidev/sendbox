# SendBox documentation

The root [README](../README.md) provides a project overview and the shortest path
to a first run. Use this index for setup, operation, and implementation details.

## Get started

| Guide | Contents |
|---|---|
| [Installation](installation.md) | Host/runtime requirements, workload images, release verification, source builds, and macOS package notes |
| [Configuration](configuration.md) | YAML examples, policy settings, and credential configuration |
| [CLI reference](cli-reference.md) | Commands, run flags, and common examples |
| [Interactive sessions](interactive-sessions.md) | Terminal requirements, behavior, and troubleshooting |
| [CLI agents](cli-agents.md) | Agent profiles, native MCP formats, multi-repo scope, HTTP proxies, and syscall tracing |
| [Integrations](integrations.md) | MCP, GitHub, model providers, private registries, devcontainers, and CI workflows |
| [Similar tools](alternatives.md) | SendBox compared with Agent Substrate, Chainguard Workspaces, Docker Sandboxes, E2B, Daytona, microsandbox, and dev containers |
| [Contributing](contributing.md) | Source setup, checks, documentation conventions, and release procedures |

## Runtime and operations

- [Apple runtime](apple-runtime.md)
- [Cold-start DNS diagnostics](dns-cold-start.md)
- [Kata Containers](kata-containers.md)
- [Hyperlight](hyperlight.md)
- [Package supply-chain proxy](package-supply-chain.md)
- [MCP inspection](mcp-inspection.md)
- [Qualification](qualification.md)

## Security

- [Security model](security-model.md)
- [Egress enforcement trust boundary](security/egress-enforcement-trust-boundary.md)
- [Secrets migration](migration/secrets.md)
- [Security-record migration](migration/security-records.md)

## Architecture

### Runtime and guest

- [Runtime core](architecture/runtime-core.md)
- [Execution broker](architecture/execution-broker.md)
- [Guest supervisor](architecture/guest-supervisor.md)
- [Guest artifact bundles](architecture/guest-artifact-bundles.md)
- [Interactive terminal](architecture/interactive-terminal.md)
- [Kata runtime](architecture/kata-runtime.md)

### Boundaries and policy

- [Authenticated guest protocol](architecture/authenticated-guest-protocol.md)
- [Session security lifecycle](architecture/session-security-lifecycle.md)
- [Egress enforcement](architecture/egress-enforcement.md)
- [MCP broker](architecture/mcp-broker.md)
- [Package registry proxy](architecture/package-registry-proxy.md)
- [Secrets and credential broker](architecture/secrets-and-credential-broker.md)
- [Git branch guard](architecture/git-branch-guard.md)
- [Safe Outputs](architecture/safe-outputs.md)
- [Security records](architecture/security-records.md)

### Agent tooling

- [Agent orchestration](architecture/agent-orchestration.md)
- [Native project analysis](architecture/native-project-analysis.md)
- [Rust CLI parity](architecture/rust-cli-parity.md)

## Research and implementation history

These documents record earlier experiments and are not the primary operator
guides:

- [Apple container adapter spike](apple-container-adapter-spike.md)
- [Egress enforcement spike](egress-enforcement-spike.md)
- [Execution broker phase 1](exec-broker-phase-1.md)
- [Guest BPF spike](guest-bpf-spike.md)

See the project [roadmap](../ROADMAP.md) for planned work.
