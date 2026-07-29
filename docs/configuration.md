# Configuration

SendBox is configured through YAML. Generate `.sendbox.yaml` in the project root
and then edit it for the selected runtime and policy:

```bash
sendbox init --project .
sendbox init --project . --runtime kata
sendbox policy validate --config .sendbox.yaml
```

The fully annotated reference is
[`config/example-sandbox.yaml`](../config/example-sandbox.yaml).

## Example

```yaml
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

  packages:
    enabled: true
    registries:
      - ecosystem: npm
        url: https://registry.npmjs.org/
        allow_insecure_http: false
        signature: if_present
        provenance: if_present
    default_finding_action: deny
    finding_actions:
      - finding: lifecycle_script
        action: deny
    exceptions: []
    limits:
      max_report_bytes: 98304

  boundaries:
    # Set to false when using Hyperlight.
    enabled: true
    tool_calls:
      max_frame_bytes: 1048576
      servers:
        filesystem:
          transport: stdio
          command:
            - /usr/local/bin/node
            - /usr/local/lib/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js
            - /workspaces/my-project
          tools:
            default_action: deny
            allowlist: [read_file, list_directory]
            denylist: ["write_*", "delete_*"]
        github:
          transport: stdio
          command: ["/usr/local/bin/github-mcp-server", "stdio"]
          tools:
            default_action: deny
            allowlist: [search_code, get_file_contents]
            denylist: ["create_*", "update_*", "delete_*"]
        remote-docs:
          transport: streamable_http
          url: https://mcp.example.com/mcp
          tools:
            default_action: deny
            allowlist: [search_docs, get_document]
            denylist: ["create_*", "update_*", "delete_*"]
          http:
            allow_redirects: false
            max_response_bytes: 1048576
            request_timeout_seconds: 30
            authorization:
              bearer_secret: REMOTE_MCP_TOKEN
    syscalls:
      additional_denylist:
        - io_uring_setup
      log_blocked: true
    log_path: /var/log/sendbox/boundary.log

secrets:
  - DATABASE_URL

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
  safe_outputs:
    enabled: false
    mode: staged
    write_token_env: SENDBOX_SAFE_OUTPUTS_GITHUB_TOKEN

observability:
  mcp_inspection:
    enabled: false
    transports: [stdio]
    capture_payloads: false
    max_payload_bytes: 16384
    log_path: /var/log/sendbox/mcp-trace.log
```

Rust-generated configuration uses deterministic snake_case YAML, validates
before writing, is created atomically with mode `0600`, and refuses to overwrite
an existing `.sendbox.yaml`. JSON results are deterministic. Invalid input or
configuration returns `2`; analysis failures return `3`; write failures and
no-overwrite refusals return `4`. Text diagnostics use stderr, while `--json`
failures use stdout only.

## GitHub and MCP boundaries

GitHub repository forwarding currently supports `github.com`. Ordinary HTTPS
Git uses a fixed authenticated askpass helper rather than assuming
`GITHUB_TOKEN` is consumed automatically. `github.ssh_key_path` accepts an
owner-only private-key file and routes Git SSH through a trusted wrapper with
strict host-key checking; the guest image must provide trusted SSH host keys.

Selected-repository `git push` and `git pull` operations are branch-protected by
default. `main` and `master` are denied, while `{username}/*`, `copilot/*`, and
`feature/*` are allowed. The username is auto-detected from `gh` or can be
configured explicitly. This guard requires `policy.boundaries.enabled`; keep
GitHub server-side branch protection enabled as defense in depth against direct
API ref mutations or alternate Git clients. Disable
`github.branch_protection.enabled` for non-Git projects.

The native Rust admission engine is connected to persistent Apple and Kata
`sendbox run` sessions through authenticated guest bootstrap. It does not
replace hosting-provider rulesets or protect alternate clients and direct GitHub
API calls.

Local stdio MCP configuration must use
`/run/sendbox-boundary/mcp-broker -- <exact-approved-command>`. Remote project
definitions must use the deterministic
`http://127.0.0.1:15082/mcp/<server-id>` route and the configured
`streamable-http` or `streamable-http-2025` type; direct upstream URLs and
project-supplied credentials are rejected. Stdio and HTTP share exact server
resolution, deny-first tool policy, `tools/list` filtering, call-time checks,
and a root-owned audit log. The gateway verifies TLS, revalidates DNS and
redirect addresses, pins exact destinations, and keeps bearer credentials out
of the agent environment. Legacy 2024 HTTP+SSE and Hyperlight MCP composition
fail closed.

Safe Outputs is disabled and staged by default. Enabling `github.safe_outputs`
requires Apple or Kata, `policy.boundaries.enabled: true`,
`github.forward_auth: false`, no SSH key forwarding, and exact repository and
operation limits. The trusted guest installs
`/run/sendbox-boundary/safe-outputs-mcp`; configure it behind the native broker.
Apply mode reads `SENDBOX_SAFE_OUTPUTS_GITHUB_TOKEN` only after the guest,
control channel, and secret resolver have been cleaned up. Asset uploads are not
supported. A custom write-token name cannot reuse a forwarded Copilot token
variable. See the [Safe Outputs architecture](architecture/safe-outputs.md).

## Copilot credentials

`github.forward_copilot_auth: true` forwards a Copilot credential independently
of repository-scoped GitHub authentication. The host resolves it from the first
variable that is set, in this order:

| Host variable | Status |
|---|---|
| `COPILOT_GITHUB_TOKEN` | Supported |
| `GITHUB_COPILOT_TOKEN` | Legacy compatibility only |

Only an absent variable falls through to the next candidate; a variable that is
set but empty is a hard error rather than a silent fallback.
Repository-scoped credentials (`GH_TOKEN`, `GITHUB_TOKEN`) are never consulted
for Copilot.

Whichever host variable supplied the value, the guest receives it as
`COPILOT_GITHUB_TOKEN`, the name current GitHub Copilot CLI releases read.
Errors name the supported variables and never print a credential value.

## Package registry credentials

`policy.packages.enabled: true` activates the npm-first proxy on Apple and Kata
persistent guests. The current implementation requires exactly one npm
registry. For private registries, set `registries[].credential_secret` to a
SendBox vault reference. That reference must not also appear in top-level
`secrets`: registry tokens are delivered only to the isolated trusted proxy and
are never exposed to the workload.

The proxy forces npm to its loopback endpoint, disables lifecycle scripts,
denies direct workload access to the configured upstream, and withholds
tarballs until verification and inspection allow them. See the
[package supply-chain proxy](package-supply-chain.md) for setup, policy,
false-positive handling, reports, and future ecosystem adapter contracts.

## Configuration reference

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
| `policy.packages` | object | npm proxy, verification, finding actions, limits, exceptions, and cache policy |
| `policy.packages.registries[].credential_secret` | string | Vault reference isolated from workload secrets |
| `policy.packages.limits.max_report_bytes` | int | Bounded package report size, up to 98304 bytes |
| `policy.boundaries.enabled` | bool | Install fail-closed MCP and syscall boundaries |
| `policy.boundaries.tool_calls` | object | Exact stdio/HTTP MCP servers with independent tool and transport policy |
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
| `github.safe_outputs` | object | Credential-free, sealed GitHub write declarations; disabled and staged by default |
| `github.safe_outputs.mode` | enum | `staged` for preview-only or `apply` for host-only GitHub execution |
| `github.safe_outputs.write_token_env` | string | Host-only environment variable read after runtime teardown |
| `github.safe_outputs.allowed_repositories` | list | Exact `owner/repository` write targets |
| `observability.mcp_inspection.enabled` | bool | Enable authenticated local stdio MCP observation on Apple or Kata |
