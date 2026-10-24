# CLI agents and workspace isolation

SendBox launches an exact guest argv, not a host-side agent wrapper. Moguri,
OpenCode, Claude Code, Codex, Copilot, Gemini, and other CLI programs use the same
signed plan, execution broker, terminal transport, MCP services, egress firewall,
snapshots, Git guard, and optional package analysis.

## Select an agent

```bash
sendbox init --project /projects/my-repo --agent moguri
# Also accepted: --agent opencode, open-code, claude, codex, copilot, gemini, custom.
```

An explicit profile admits the selected entry program and its usual inference
hosts under a default-deny policy. Non-Copilot profiles disable independent
Copilot token forwarding; they do not disable Git protection or repository
credential scoping. Existing `init` calls without `--agent` retain their
configuration defaults.

| Profile | Initially admitted inference hosts |
|---|---|
| `moguri` | `api.githubcopilot.com`, `*.githubcopilot.com` |
| `opencode` | `opencode.ai`, `models.dev` |
| `claude` | `api.anthropic.com` |
| `codex` | `api.openai.com`, `chatgpt.com`, `auth.openai.com` |
| `copilot` | `api.githubcopilot.com`, `*.githubcopilot.com` |
| `gemini` | `generativelanguage.googleapis.com`, `oauth2.googleapis.com`, `cloudcode-pa.googleapis.com` |
| `custom` | None; configure the program and endpoints explicitly |

OpenCode supports multiple model providers. Add the exact provider endpoints you
actually use to `policy.network.allowed_domains`; the profile does not grant
every provider or plugin unrestricted networking. Deny rules still take
precedence. Select additional telemetry, authentication, Git, and package hosts
explicitly rather than changing the policy to allow all traffic.

The workload image must contain the Linux agent binary, its dependencies,
certificates, shell, and development tools. SendBox's signed guest bundle
contains the trusted controls, not Node.js, Bun, or the agents themselves.
Preinstall MCP servers at fixed absolute image paths instead of configuring
shells or package runners such as `npx`.

```bash
sendbox run --interactive \
  --config /projects/my-repo/.sendbox.yaml \
  --image registry.example/agent-tools@sha256:<digest> \
  --bundle /usr/local/share/sendbox/guest/<architecture>/bundle \
  --trust-root /usr/local/share/sendbox/guest/<architecture>/release-public.key \
  -- /usr/local/bin/moguri --project /workspace
```

Moguri's `moguri` executable opens its TUI by default; `moguri tui` is equivalent.
`--project /workspace` selects the shared guest project. The workload image
needs the full CLI, its supported Node.js runtime, native dependencies, and a
Linux Secret Service for Moguri's OS-keyring authentication. Sign in inside the
guest; the `moguri` profile does not enable SendBox's Copilot CLI token forwarding.
For another model provider, explicitly allow its endpoints.

For another agent, replace the final argv with its actual guest executable and
arguments. For headless operation, drop `--interactive` and use the agent's
noninteractive arguments. No executable lookup or shell evaluation happens on
the host. An unavailable provider or guest primitive is an error, not permission
to run the command on the host.

Native agent sandboxes may need adjustment for an already-contained VM.
For example, Codex can be run with `--sandbox danger-full-access` to avoid a
nested sandbox requiring unavailable guest kernel facilities. This is an
explicit agent option, not a SendBox containment bypass; SendBox never adds
agent approval-bypass flags automatically.

## Credentials and agent state

Store an API credential in the SendBox vault and list only the required
workload reference:

```bash
sendbox secrets add ANTHROPIC_API_KEY
```

```yaml
secrets: [ANTHROPIC_API_KEY]
github:
  forward_copilot_auth: false
```

For Codex use `OPENAI_API_KEY`; for another provider use its documented variable.
The host's home, global agent configuration, browser, keychain files, and
runtime sockets are not mounted. Each session gets an owner-only guest home at
`/run/sendbox-workload/<session-id>` and isolated XDG directories. Login state
created there disappears with the VM. Use vault references rather than relying
on host login files being copied implicitly.

GitHub forwarding remains independently configurable. Disable
`github.forward_auth` when no GitHub credential is needed, and disable
`github.branch_protection.enabled` for non-Git projects. Keep server-side branch
protection: local wrappers do not govern alternate clients or direct API writes.

### Credential masking

Credential masking is always enabled for workload stdout and stderr, including
PTY output and JSON/hex CLI output. Values delivered from the vault or session
credential forwarding are registered before the workload can print them.
Gateway and registry credentials are also registered for runtime diagnostics.
Credentials split across chunks are withheld until they can be masked safely;
stdout and stderr have independent state. An ambiguous credential prefix at
stream termination is masked rather than printed.

Recognizable bearer/basic headers, sensitive assignments and JSON fields,
common provider token prefixes, URL userinfo, and private-key blocks are
replaced with `[REDACTED]` even when not registered in the vault. Runtime errors
are masked before failure-audit persistence. Captured MCP payloads are decoded
and masked before truncation or log serialization; decoded JSON escapes cannot
hide a registered value. Safe Outputs human-readable titles, bodies, and
messages use the same masker before sealing. Original authentication values,
envelopes, MCP traffic, and proposed source patches are not rewritten.

Masking is not a data-loss-prevention boundary. Arbitrary encodings,
obfuscation, credentials assembled across separate output streams, newly
created opaque credentials with no recognizable form, repository files, and
source patches are not comprehensively scrubbed. Keep MCP payload capture
disabled unless needed: non-credential private content may still be recorded.
Known values are limited to 512 distinct credentials of at most 64 KiB each;
registration or masking failures stop the affected operation without exposing
the original diagnostic. Output byte counters describe the original guest
bytes, not the replacement text.

## Repository or multi-repository filesystem scope

By default, only `project_path` is shared read/write at `/workspace`.
To share an enclosing multi-repository workspace explicitly:

```bash
sendbox init --project /projects/team/repo-one \
  --workspace /projects/team --agent codex
```

```yaml
project_path: /projects/team/repo-one
workspace_path: /projects/team
```

The only workload host mount becomes `/projects/team -> /workspace`; the
initial cwd and selected Git repository remain `/workspace/repo-one`.
Sibling repositories inside that root are visible. Repositories outside it,
host control sockets, and the host home are not added automatically.

The project must be inside the normalized workspace root. Filesystem-root
mounts, parent traversal, symlinked source components, and overlapping runtime
state are rejected. Snapshots and rollback cover the selected shared root;
Safe Outputs patches still target the selected repository.

MCP configuration is checked in the selected project and its ancestors up to
the shared workspace root, never in host-global configuration. These checks
reject symlinked configuration parents, malformed server containers, and
unapproved launcher/authentication overrides.

## Agent-compatible network proxy

Persistent guests expose two explicit loopback frontends backed by one
authorization cache, DNS guard, connection budget, address-pinning path, and
marked dialer:

| Environment | Guest endpoint |
|---|---|
| `ALL_PROXY`, `all_proxy` | `socks5h://127.0.0.1:15080` |
| `HTTP_PROXY`, `HTTPS_PROXY`, lowercase equivalents | `http://127.0.0.1:15083` |
| `NO_PROXY`, `no_proxy` | `localhost,127.0.0.1,::1` |
| `NODE_USE_ENV_PROXY` | `1` |

The HTTP frontend supports CONNECT tunnels and absolute-form plaintext HTTP
requests. It bounds headers and handshake time, rejects conflicting Host/body
framing and proxy credentials, and validates the endpoint before dialing.
HTTPS certificates remain the client's responsibility inside CONNECT tunnels.
Use a Node.js release supporting `NODE_USE_ENV_PROXY` for native `fetch`
clients; clients that ignore every proxy mechanism fail closed at the firewall.

nftables restricts the agent cgroup and all execution descendants to the exact
loopback broker, gateway, and configured package-proxy ports. Direct outbound
TCP, UDP/QUIC, metadata access, unmarked broker traffic, and unapproved endpoints
remain denied. HTTP and SOCKS share the same connection limit rather than
doubling it. Remote MCP upstreams remain reserved from both public frontends.

## Native MCP configuration

SendBox checks the traditional JSON MCP files plus `opencode.json`,
`opencode.jsonc`, `.codex/config.toml`, and `.gemini/settings.json`.
Each definition must select the exact broker argv or trusted gateway route.

OpenCode:

```json
{
  "mcp": {
    "files": {
      "type": "local",
      "command": ["/run/sendbox-boundary/mcp-broker", "--", "/usr/bin/mcp-server"],
      "enabled": true
    },
    "docs": {
      "type": "remote",
      "url": "http://127.0.0.1:15082/mcp/docs",
      "oauth": false
    }
  }
}
```

Codex:

```toml
[mcp_servers.files]
command = "/run/sendbox-boundary/mcp-broker"
args = ["--", "/usr/bin/mcp-server"]

[mcp_servers.docs]
url = "http://127.0.0.1:15082/mcp/docs"
```

Claude/Copilot JSON uses `mcpServers` or `servers` with the same `command` and
`args`. Gemini uses `mcpServers` and `httpUrl` for Streamable HTTP; legacy SSE is
not admitted. Client tool-selection settings can narrow discovery but cannot
expand signed server/tool policy.

Hierarchical stdio servers receive no workload secrets by default. Explicit
environment authentication selects only named, already-delivered references:

```yaml
policy:
  boundaries:
    tool_calls:
      servers:
        files:
          transport: stdio
          command: [/usr/bin/mcp-server]
          authorization:
            method: environment
            secrets: [MCP_TOKEN]
          tools:
            default_action: deny
            allowlist: [read_file, list_directory]
        docs:
          transport: streamable_http
          url: https://mcp.example.com/mcp
          http:
            allowed_auth_methods: [bearer]
            authorization:
              bearer_secret: REMOTE_MCP_TOKEN
          tools:
            default_action: deny
            allowlist: [search_docs]
secrets: [MCP_TOKEN]
```

The remote bearer reference must not appear in top-level `secrets`; it is
delivered only to the trusted gateway. HTTP authentication supports `none` and
`bearer`; stdio supports no authentication or explicitly selected `environment`
references. OAuth and caller-supplied credential/header helpers are rejected.
Legacy flat stdio policies retain their old global environment compatibility;
use hierarchical policies for per-server credential partitions.

Server identity, authentication choice, exact command, and tool rules are
immutable signed policy. Tool deny rules win, discovery is filtered, and calls
are checked again with mandatory redacted audit. Agent descendants remain
VM-contained even when using built-in tools; recursive descendant argv
authorization is not claimed. See [MCP inspection](mcp-inspection.md).

## Optional guest syscall tracing

```yaml
observability:
  syscall_tracing: true
```

Tracing is disabled by default. When requested, Apple/Kata bootstrap verifies
the signed BPF object and starts a mandatory tracer before execution. The
tracer depends on armed egress, and Exec depends on the tracer; shutdown reverses
that order. A cgroup-array descriptor includes execution leaves and their
descendants without observing unrelated guest processes.

Missing BTF, tracepoints, loading/attachment privileges, artifact verification,
or mandatory tracer readiness fails the session. BPF capabilities are held by
trusted guest services only; agent capabilities remain empty.

The root-only guest log is `/var/log/sendbox/syscalls.jsonl`, capped at 16 MiB.
An authenticated, terminal-only, single-use report is independently verified
and persisted at
`~/.sendbox/run/sessions/<session-id>/syscall-trace-report.json` with mode `0600`.
It contains architecture, syscall counts, up to 256 argument-free samples,
sampling counts, log-limit status, and kernel/userspace/decode loss counters.
It contains no syscall arguments, command argv, paths, payloads, or credentials.

Tracing is observation, not authorization, and bounded sampling is not a
complete forensic transcript. Loss and log limits are explicit. Hyperlight has
no Linux guest kernel or persistent broker composition and rejects tracing,
interactive sessions, MCP, and full egress features rather than downgrading them.
