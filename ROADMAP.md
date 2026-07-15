# SendBox Roadmap

> Living document tracking planned features, platform expansion, and ecosystem integrations.

---

## Phase 1 — Foundation and Direct VM Runtimes ✅ (Current)

SendBox supports direct hardware-isolated runtimes on macOS and Linux: Apple's [Containerization](https://github.com/apple/containerization) framework on Apple silicon, and [Kata Containers](https://katacontainers.io/) through nerdctl/containerd on Linux.

| Feature | Status |
|---------|--------|
| Lightweight Linux VMs via Virtualization.framework | ✅ Done |
| Kata Containers runtime via nerdctl/containerd | ✅ Done |
| RuntimeProvider abstraction and `--runtime` selection | ✅ Done |
| Command allowlist / denylist engine | ✅ Done |
| Domain-level network firewall (iptables) | ✅ Done |
| macOS Keychain and Linux file-backed secrets management | ✅ Done |
| DevContainer generation via Copilot SDK | ✅ Done |
| YAML-based configuration with presets | ✅ Done |
| CLI (`run`, `init`, `analyze`, `secrets`, `policy`) | ✅ Done |
| Interactive setup script | ✅ Done |

---

## Phase 2 — Kubernetes Orchestration (KinD)

### Goal

Add **Kubernetes in Docker (KinD)** as an orchestrated runtime for Windows, Intel macOS, remote clusters, and multi-sandbox deployments. Linux already has direct Kata Containers support.

### Architecture

```
┌─────────────────────────────────────────────────────┐
│                   sendbox CLI                        │
├──────────────────┬──────────────────────────────────┤
│  RuntimeProvider │  (protocol / trait / interface)   │
├──────────────────┼──────────────────────────────────┤
│ AppleVMRuntime   │ KataRuntime      │ Kubernetes     │
│ (macOS arm64)    │ (Linux)          │ Runtime        │
│ Virtualization   │ nerdctl +        │ KinD +         │
│ .framework       │ containerd       │ containerd     │
└──────────────────┴──────────────────────────────────┘
```

### Approach

1. **Extend the existing `RuntimeProvider` abstraction** with a Kubernetes implementation while keeping sandbox logic runtime-agnostic.

2. **KinD backend** (`KubernetesRuntime`):
   - Requires Docker and [KinD](https://kind.sigs.k8s.io/) installed on the host.
   - Creates a dedicated KinD cluster per sandbox (or reuses one with namespace isolation).
   - Maps SendBox concepts to Kubernetes primitives:

     | SendBox Concept | Kubernetes Primitive |
     |-----------------|---------------------|
     | Container / VM | Pod (single-container) |
     | Command policy | Admission webhook / OPA Gatekeeper policy |
     | Network firewall | NetworkPolicy (Calico/Cilium) |
     | Secrets | Kubernetes Secrets (encrypted at rest) |
     | Filesystem isolation | EmptyDir + InitContainer for workspace copy |
     | DevContainer | Pod spec with devcontainer image + volume mounts |

   - NetworkPolicy replaces iptables — egress rules map allowed/blocked domains to CIDR blocks via DNS resolution at policy-apply time, or use Cilium's FQDN-aware policies.
   - Secrets injected as Kubernetes Secrets mounted at `/run/secrets/` or as environment variables.
   - Command filtering enforced via a sidecar admission proxy or an init script that wraps the shell.

3. **Runtime selection** — auto-detected or user-specified:
   ```yaml
   # .sendbox.yaml
   runtime:
     provider: auto       # auto | apple | kata | kubernetes
   kubernetes:
     provider: kind       # kind | minikube | k3d | remote
     cluster_name: sendbox-cluster
     namespace: sandbox-default
     network_plugin: cilium  # calico | cilium (for FQDN policies)
   ```

4. **CLI changes**:
   ```bash
   sendbox run --runtime kubernetes --project ./my-app
   sendbox cluster create    # Create/manage KinD cluster
   sendbox cluster delete
   sendbox cluster status
   ```

### Tasks

- [x] Define `RuntimeProvider` protocol with create/start/stop/exec/cleanup
- [ ] Implement `KubernetesRuntime` using client-go or kubectl subprocess
- [ ] Generate Kubernetes manifests (Pod, NetworkPolicy, Secret) from SendBox config
- [ ] Implement FQDN-aware NetworkPolicy (Cilium CiliumNetworkPolicy or DNS-to-CIDR resolver)
- [ ] Map command policy to OPA/Gatekeeper constraints or shell wrapper
- [ ] KinD cluster lifecycle management (create, reuse, destroy)
- [x] Add `--runtime` flag to CLI
- [ ] Cross-platform CI (macOS and Linux complete; Windows pending)
- [x] Runtime unit tests on Linux (live Kata tests require nested virtualization)
- [ ] Helm chart for remote Kubernetes clusters (EKS, GKE, AKS)

### Platform Support Matrix

| Platform | Runtime | Status |
|----------|---------|--------|
| macOS arm64 | Apple Virtualization | ✅ Supported |
| Linux x86_64 | Kata Containers | ✅ Supported |
| Linux arm64 | Kata Containers | ✅ Supported |
| macOS arm64 | KinD | 🔲 Planned |
| macOS x86_64 | KinD | 🔲 Planned |
| Linux x86_64 | KinD | 🔲 Planned |
| Linux arm64 | KinD | 🔲 Planned |
| Windows (WSL2) | KinD | 🔲 Planned |
| Remote K8s | kubectl | 🔲 Planned |

---

## Phase 3 — Multi-Agent Tool Compatibility

### Goal

Support **any AI coding agent**, not just GitHub Copilot CLI. The sandbox should be agent-agnostic — the security guarantees (isolation, command filtering, network firewall, secrets) apply regardless of which tool runs inside.

### Supported Agents

| Agent | Integration Approach | Status |
|-------|---------------------|--------|
| **GitHub Copilot CLI** | Native via `@github/copilot-sdk` | ✅ Supported |
| **Claude Code** (Anthropic) | CLI binary + API key injection | 🔲 Planned |
| **Codex CLI** (OpenAI) | CLI binary + API key injection | 🔲 Planned |
| **Gemini CLI** (Google) | CLI binary + API key injection | 🔲 Planned |
| **Aider** | pip install + config | 🔲 Planned |
| **Cline / Roo Code** | VS Code extension (devcontainer) | 🔲 Planned |
| **Cursor Agent** | Not CLI-based (limited support) | 🔲 Investigating |
| **Amazon Q Developer CLI** | CLI binary + AWS credentials | 🔲 Planned |
| **Custom agents** | User-defined command + env | 🔲 Planned |

### Architecture

```
┌─────────────────────────────────────────────────────┐
│                    sendbox CLI                       │
├─────────────────────────────────────────────────────┤
│                  AgentProvider                       │
│            (protocol / interface)                    │
├────────┬─────────┬─────────┬──────────┬─────────────┤
│Copilot │ Claude  │ Codex   │ Gemini   │ Custom      │
│CLI     │ Code    │ CLI     │ CLI      │ (user cmd)  │
├────────┴─────────┴─────────┴──────────┴─────────────┤
│              Agent-Agnostic Sandbox                  │
│  ┌──────────┬───────────┬──────────┬──────────────┐ │
│  │ Command  │ Network   │ Secrets  │ Filesystem   │ │
│  │ Policy   │ Firewall  │ Vault    │ Isolation    │ │
│  └──────────┴───────────┴──────────┴──────────────┘ │
└─────────────────────────────────────────────────────┘
```

### AgentProvider Protocol

Each agent adapter implements:

```
AgentProvider:
  name()           → String               # "claude-code", "codex", etc.
  installCommand() → [String]             # How to install inside container
  runCommand()     → [String]             # How to launch the agent
  requiredSecrets() → [String]            # e.g., ["ANTHROPIC_API_KEY"]
  requiredDomains() → [String]            # e.g., ["api.anthropic.com"]
  healthCheck()    → Bool                 # Verify agent is working
  configFiles()    → [FilePath]           # Agent-specific config to mount
```

### Agent-Specific Details

#### Claude Code (Anthropic)
- **Install**: `npm install -g @anthropic-ai/claude-code`
- **Run**: `claude` (interactive) or `claude -p "prompt"` (headless)
- **Secrets**: `ANTHROPIC_API_KEY`
- **Domains**: `api.anthropic.com`, `*.anthropic.com`
- **Notes**: Supports `--allowedTools` flag for built-in tool restriction. SendBox command policy provides an additional layer.

#### Codex CLI (OpenAI)
- **Install**: `npm install -g @openai/codex`
- **Run**: `codex` (interactive) or `codex -q "prompt"`
- **Secrets**: `OPENAI_API_KEY`
- **Domains**: `api.openai.com`, `*.openai.com`
- **Notes**: Has its own sandbox mode (`--full-auto`). SendBox wraps this for network/filesystem guarantees the built-in sandbox doesn't provide.

#### Gemini CLI (Google)
- **Install**: `npm install -g @anthropic-ai/claude-code` → TBD (check actual package name on release)
- **Run**: `gemini` or via API
- **Secrets**: `GEMINI_API_KEY` or Google Cloud credentials
- **Domains**: `generativelanguage.googleapis.com`, `*.googleapis.com`
- **Notes**: May require Google Cloud auth flow.

#### Aider
- **Install**: `pip install aider-chat`
- **Run**: `aider --model <model>`
- **Secrets**: Model-specific API key (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.)
- **Domains**: Depends on model provider
- **Notes**: Highly configurable. SendBox mounts `.aider.conf.yml` if present.

#### Custom Agent
- **Config**: User provides install/run commands directly
  ```yaml
  agent:
    type: custom
    install: "pip install my-agent"
    command: ["my-agent", "--workspace", "/workspace"]
    secrets:
      - MY_API_KEY
    extra_domains:
      - "api.my-service.com"
  ```

### Configuration Changes

```yaml
# .sendbox.yaml — Phase 3 additions
agent:
  type: claude-code           # copilot | claude-code | codex | gemini | aider | custom
  
  # Auto-resolved per agent type, but overridable:
  # install_command: "npm install -g @anthropic-ai/claude-code"
  # run_command: ["claude", "-p", "Fix all failing tests"]
  
  # Agent-specific options
  options:
    model: claude-sonnet-4-20250514    # For agents that support model selection
    headless: true             # Non-interactive mode
    prompt: "Fix the CI"       # Initial prompt for headless mode
    
  # Custom agent (when type: custom)
  # custom:
  #   install: "pip install my-agent"
  #   command: ["my-agent", "--auto"]
  #   secrets: [MY_API_KEY]
  #   domains: ["api.example.com"]
```

### Tasks

- [ ] Define `AgentProvider` protocol
- [ ] Implement `CopilotAgent` (refactor existing Copilot SDK integration)
- [ ] Implement `ClaudeCodeAgent`
- [ ] Implement `CodexAgent`
- [ ] Implement `GeminiAgent`
- [ ] Implement `AiderAgent`
- [ ] Implement `CustomAgent` (user-defined)
- [ ] Auto-detect agent type from project files (`.claude`, `.codex`, etc.)
- [ ] Agent-specific domain allowlists (merged with user policy)
- [ ] Agent-specific secret requirements (validated before launch)
- [ ] `sendbox run --agent claude-code --project ./my-app`
- [ ] Documentation and examples for each agent

---

## Phase 4 — Advanced Features

Features planned after core platform and agent support is solid.

### Observability & Audit
- [ ] Full audit log of all commands executed, network connections made, files modified
- [x] eBPF inspection of MCP (Model Context Protocol) calls the agent performs
- [ ] Real-time dashboard (TUI) showing agent activity
- [ ] Export audit logs as JSON/CSV for compliance
- [ ] Cost tracking (API calls made by agent, token usage if available)

### Multi-Agent Orchestration
- [ ] Run multiple agents in isolated sandboxes that share a workspace
- [ ] Agent-to-agent communication through controlled channels
- [ ] Supervisor agent that reviews changes from worker agents

### Snapshot & Rollback
- [ ] Filesystem snapshots before/after agent runs
- [ ] Diff view of all changes made by the agent
- [ ] One-click rollback to pre-agent state
- [ ] Git-based change tracking within the sandbox

### CI/CD Integration
- [ ] GitHub Actions action: `sendbox-action`
- [ ] GitLab CI template
- [ ] Pre-commit hook for validating sandbox configs
- [ ] PR review mode: agent runs in sandbox, posts diff as PR comment

### Policy as Code
- [ ] OPA/Rego policy language support for complex rules
- [ ] Policy inheritance (org → team → project)
- [ ] Policy testing framework
- [ ] Community policy library

---

## Timeline

| Phase | Target | Key Milestone |
|-------|--------|---------------|
| Phase 1 | ✅ Complete | Core sandbox on macOS with Copilot SDK |
| Phase 2 | Next | KinD runtime → Linux/Windows support |
| Phase 3 | After Phase 2 | Claude Code, Codex, Gemini CLI support |
| Phase 4 | Ongoing | Audit logs, multi-agent, CI/CD |

---

## Contributing

We welcome contributions, especially for:
- New `AgentProvider` implementations
- New `RuntimeProvider` backends (Podman, Firecracker, gVisor)
- Platform testing on Linux and Windows
- Policy templates for common use cases

See [CONTRIBUTING.md](https://github.com/apple/containerization/blob/main/CONTRIBUTING.md) for guidelines.
