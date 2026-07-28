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
- `tools/call` uses deny-first `*`/`?` glob matching, then allowlist/default
  action.
- Denied requests receive error `-32001` in the request's framing mode. Denied
  notifications are dropped.
- Missing `params.name`, malformed JSON-RPC, oversized frames, child death,
  output saturation, and broker cancellation fail closed.
- The injected process launcher receives one exact approved absolute executable
  and argv vector. Shells, package runners, project-defined environment
  overrides, and project-defined working directories are rejected.
- The Tokio launcher clears its inherited environment before applying the
  administrator-supplied minimal environment.

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
must use `/run/sendbox-boundary/mcp-broker`, `--`, and an exact command from
`policy.boundaries.tool_calls.allowed_server_commands`. Remote transports,
unproxied commands, shells, package runners, `env`, and `cwd` are rejected.

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

Both formats support request/response correlation by process and JSON-RPC ID,
method/category classification, payload redaction, deterministic summaries, and
deterministic reports.

## Runtime limits

Only traffic that traverses the installed stdio broker is authorized and
observed. Project configuration that launches a server directly, sets its own
environment or working directory, uses a shell/package runner, or selects a
remote transport is rejected. Separately available binaries and alternate
clients remain outside this wrapper boundary.
