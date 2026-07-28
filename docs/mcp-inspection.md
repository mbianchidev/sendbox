# MCP brokering and inspection

`sendbox-mcp` is the native Rust library for local stdio MCP authorization,
project configuration validation, and observation processing. Production
`sendbox run` validates configuration on the host, binds the policy digest into
the signed boundary plan, and installs the broker in authenticated Apple and Kata
guests.

## Authorization boundary

Authorization applies only to local stdio MCP servers launched through the
broker:

- Newline and `Content-Length` frames are bounded before body allocation.
- JSON-RPC 2.0 requests, notifications, responses, errors, and IDs are validated
  before forwarding. Batch messages are rejected.
- The exact server argv selects one stable policy ID. Project aliases and
  caller-supplied IDs never select policy.
- Each server has independent deny-first `*`/`?` tool rules. Denylist matches
  win, then allowlist matches, then the server default.
- Correlated `tools/list` responses are filtered before forwarding. Every
  `tools/call` is checked again even if the tool was previously listed.
- Denied requests receive error `-32001` in the request's framing mode. Denied
  notifications are dropped.
- Missing `params.name`, malformed JSON-RPC, oversized frames, child death,
  output saturation, and broker cancellation fail closed.
- The injected process launcher receives one exact approved absolute executable
  and argv vector. Shells, package runners, project-defined environment
  overrides, and project-defined working directories are rejected.
- The Tokio launcher clears its inherited environment before applying the
  administrator-supplied minimal environment.
- Every decision is written first to the root-created JSON-lines boundary audit
  log. Audit failure denies the operation and terminates the broker.

Remote HTTP/SSE MCP is not an authorization or inspection surface. Enabling HTTP
inspection fails closed because the native runtime cannot observe TLS plaintext.

## Project configuration

The validator checks every existing Swift-recognized path:

- `.mcp.json`
- `.vscode/mcp.json`
- `.github/copilot/mcp.json`
- `.cursor/mcp.json`
- `.claude/mcp.json`

It accepts `mcpServers` or `servers` at the root or below `mcp`. A local server
must use `/run/sendbox-boundary/mcp-broker`, `--`, and an exact command from one
`policy.boundaries.tool_calls.servers` stdio entry. The project-local name may
be any alias; exact argv uniquely determines the trusted policy. Remote
transports, unproxied commands, wrapper arguments, policy-ID fields, shells,
package runners, `env`, and `cwd` are rejected.

```yaml
boundaries:
  tool_calls:
    max_frame_bytes: 1048576
    servers:
      github:
        transport: stdio
        command: ["/usr/local/bin/github-mcp-server", "stdio"]
        tools:
          default_action: deny
          allowlist: [search_code, get_file_contents]
          denylist: ["create_*", "update_*", "delete_*"]
      filesystem:
        transport: stdio
        command: ["/usr/local/bin/node", "/opt/mcp/filesystem.js", "/workspace"]
        tools:
          default_action: deny
          allowlist: [read_file, list_directory]
          denylist: ["write_*", "move_*", "delete_*"]
```

Server IDs must match `[a-z][a-z0-9_-]{0,63}`. Commands must be absolute,
non-shell vectors of at most 16 printable parts. Duplicate IDs, duplicate exact
commands, empty allow-by-default policies, and mixed legacy/hierarchical fields
are configuration errors.

## Legacy configuration migration

The former global `allowlist`, `denylist`, `default_action`, and
`allowed_server_commands` fields remain an explicit compatibility mode. Each
legacy exact command receives a deterministic `legacy-<fingerprint>` audit ID.
Legacy and hierarchical fields cannot be mixed. Migrate by moving every command
under a stable `servers.<id>` entry and copying the global tool rules into that
server's `tools` block, then narrow permissions independently.

`sendbox boundary inspect --config <path> [--json]` reports the mode, stable
server IDs, non-reversible command fingerprints, transports, and effective tool
rules without printing command arguments.

## Observation formats

The parser retains compatibility with legacy Swift trace lines:

```text
SENDBOX_MCP<TAB>ts<TAB>pid<TAB>comm<TAB>transport<TAB>direction<TAB>payload
```

The native versioned format is:

```text
SENDBOX_MCP_EVENT<TAB>{"schema_version":1,...}
```

The guest broker emits the native format for wrapper-mediated stdio traffic. The
log is created by the root supervisor and is writable only by the configured
workload group. When payload capture is disabled, arguments and error messages
are removed before the event is written.

Authorization decisions use the separate boundary audit log configured by
`policy.boundaries.log_path`. Records include the server policy ID, command
fingerprint, transport, method, tool, outcome, matching rule, and denial reason.
They never include command arguments or tool arguments.

Both formats support request/response correlation by process and JSON-RPC ID,
method/category classification, payload redaction, deterministic summaries, and
deterministic reports.

## Runtime limits

Only traffic that traverses the installed stdio broker is authorized and
observed. Project configuration that launches a server directly, sets its own
environment or working directory, uses a shell/package runner, or selects a
remote transport is rejected. Separately available binaries and alternate
clients remain outside this wrapper boundary.
