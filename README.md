# SendBox

**Secure, lightweight agent sandboxing on Apple Silicon.**

SendBox provides hardware-isolated execution environments for AI agents using Apple's [Virtualization framework](https://developer.apple.com/documentation/virtualization) and [Containerization](https://github.com/apple/containerization). Every agent runs inside a minimal Linux VM with fine-grained controls over filesystem access, network connectivity, command execution, and secret management.

---

## Features

- **File Isolation** — Mount only the directories an agent needs. Everything else is invisible.
- **Command Filtering** — Allowlist or denylist which binaries an agent may execute inside the sandbox.
- **Network Firewall** — Restrict outbound traffic to specific hosts, ports, or protocols.
- **Secrets Management** — Inject credentials at runtime without persisting them to disk.
- **Devcontainer Generation** — Export sandbox configurations as [devcontainer](https://containers.dev/) specs for reproducible environments.

## Requirements

| Dependency | Minimum Version |
|---|---|
| macOS | 26 (Tahoe) |
| Hardware | Apple Silicon (M1 or later) |
| Xcode | 26 |
| Swift | 6.1 |
| Node.js | 20+ (for copilot-bridge) |

## Quick Start

### Install

```bash
git clone https://github.com/mbianchidev/sendbox.git
cd sendbox
make install
```

### Configure

Create a `sendbox.yaml` in your project root (see [Configuration](#configuration) below), then:

```bash
sendbox init
```

### Run

```bash
# Launch an agent inside the sandbox
sendbox run --config sendbox.yaml

# One-shot command execution
sendbox exec --config sendbox.yaml -- echo "hello from the sandbox"
```

## Configuration

SendBox is configured through a YAML file. Below is a complete example showing all available options:

```yaml
# sendbox.yaml
sandbox:
  name: my-agent-sandbox
  image: ghcr.io/mbianchidev/sendbox-base:latest

resources:
  cpus: 2
  memory: 2048  # MB

filesystem:
  mounts:
    - host: ./workspace
      guest: /home/agent/workspace
      readonly: false
    - host: ~/.ssh/id_ed25519.pub
      guest: /home/agent/.ssh/authorized_keys
      readonly: true

security:
  commands:
    mode: allowlist          # allowlist | denylist
    list:
      - /usr/bin/git
      - /usr/bin/curl
      - /usr/local/bin/node

  network:
    outbound:
      allow:
        - host: api.github.com
          port: 443
        - host: registry.npmjs.org
          port: 443
      deny:
        - host: "*"          # deny everything else

  secrets:
    - name: GITHUB_TOKEN
      source: env            # env | file | keychain
    - name: NPM_TOKEN
      source: file
      path: ~/.secrets/npm

devcontainer:
  generate: true
  output: .devcontainer/devcontainer.json
  features:
    - ghcr.io/devcontainers/features/git:1
    - ghcr.io/devcontainers/features/node:1
```

### Configuration Reference

| Section | Key | Description |
|---|---|---|
| `sandbox.name` | string | Human-readable name for the sandbox instance |
| `sandbox.image` | string | Base container image to use |
| `resources.cpus` | int | Number of virtual CPUs |
| `resources.memory` | int | Memory allocation in MB |
| `filesystem.mounts` | list | Host-to-guest filesystem mounts |
| `security.commands.mode` | string | `allowlist` or `denylist` |
| `security.commands.list` | list | Paths to allowed/denied binaries |
| `security.network.outbound` | object | Outbound network rules |
| `security.secrets` | list | Secrets injected at runtime |
| `devcontainer.generate` | bool | Whether to generate a devcontainer spec |

## Architecture

```
┌──────────────────────────────────────────────────┐
│  Host (macOS)                                    │
│                                                  │
│  ┌─────────┐   ┌──────────────┐                  │
│  │ sendbox  │──▶│ SendBoxKit   │                  │
│  │   CLI    │   │              │                  │
│  └─────────┘   │ ┌──────────┐ │  ┌─────────────┐ │
│                │ │ Config   │ │  │  Copilot     │ │
│                │ ├──────────┤ │  │  Bridge      │ │
│                │ │ Security │ │──│  (Node.js)   │ │
│                │ ├──────────┤ │  └─────────────┘ │
│                │ │Container │ │                   │
│                │ ├──────────┤ │                   │
│                │ │ Agent    │ │                   │
│                │ └──────────┘ │                   │
│                └──────┬───────┘                   │
│                       │ Virtualization.framework  │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┼─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
│                       ▼                           │
│            ┌────────────────────┐                 │
│            │  Lightweight VM    │                 │
│            │  (Linux guest)     │                 │
│            │                    │                 │
│            │  ┌──────────────┐  │                 │
│            │  │ Agent Process│  │                 │
│            │  └──────────────┘  │                 │
│            └────────────────────┘                 │
└──────────────────────────────────────────────────┘
```

**SendBoxKit** is the core library organized into four modules:

| Module | Responsibility |
|---|---|
| `Config` | Parse and validate YAML configuration |
| `Security` | Enforce command filtering, network rules, and secret injection |
| `Container` | Manage VM lifecycle via Apple Containerization / Virtualization |
| `Agent` | Coordinate agent process execution and I/O |

The **copilot-bridge** is an optional Node.js sidecar that exposes a JSON-RPC interface for IDE integrations.

## Security Model

SendBox follows a **deny-by-default** security posture:

1. **Filesystem** — Only explicitly mounted paths are visible inside the VM. The host filesystem is never exposed wholesale.
2. **Commands** — By default no binaries are available. Use `allowlist` mode to grant access to specific tools, or `denylist` mode to start permissive and lock down selectively.
3. **Network** — Outbound connections are blocked unless a matching `allow` rule exists. DNS resolution is restricted to permitted hosts.
4. **Secrets** — Credentials are injected as environment variables at VM boot and are never written to the guest filesystem. Sources include host environment variables, files, and the macOS Keychain.
5. **Isolation** — Each sandbox runs in its own lightweight VM. A compromised agent cannot affect the host or other sandboxes.

## CLI Reference

```
USAGE: sendbox <subcommand> [options]

SUBCOMMANDS:
  init          Initialize a new sendbox.yaml in the current directory
  run           Start the sandbox and launch the agent
  exec          Execute a single command inside the sandbox
  stop          Stop a running sandbox
  status        Show status of active sandboxes
  config        Validate or display resolved configuration
  devcontainer  Generate a devcontainer.json from the current config
  help          Show help for any subcommand
```

### Examples

```bash
# Initialize a new project
sendbox init

# Validate configuration
sendbox config --validate sendbox.yaml

# Run with verbose logging
sendbox run --config sendbox.yaml --log-level debug

# Execute a command and capture output
sendbox exec --config sendbox.yaml -- python3 script.py

# Stop a sandbox by name
sendbox stop my-agent-sandbox

# List running sandboxes
sendbox status

# Generate devcontainer spec
sendbox devcontainer --config sendbox.yaml --output .devcontainer/
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
