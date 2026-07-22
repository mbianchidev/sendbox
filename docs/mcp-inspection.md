# MCP brokering and inspection

`sendbox-mcp` is the native Rust library for local stdio MCP authorization,
project configuration validation, and observation processing. This PR provides
the production library boundary only. It does not connect the broker or observer
to a guest/runtime and does not change the CLI.

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

Remote HTTP/SSE MCP is not an authorization surface. It may be represented in
observation records, but this crate makes no remote authorization claim.

## Project configuration

The validator checks every existing Swift-recognized path:

- `.mcp.json`
- `.vscode/mcp.json`
- `.github/copilot/mcp.json`
- `.cursor/mcp.json`
- `.claude/mcp.json`

It accepts `mcpServers` or `servers` at the root or below `mcp`. A local server
must use an exact approved broker/proxy prefix, `--`, and an exact command from
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

`ObservationMetadata` is the ingestion boundary for a future C/libbpf
ring-buffer producer. It contains metadata and captured UTF-8 payload bytes; no
C code, loader, ring-buffer reader, or guest attachment is included here.

Both formats support request/response correlation by process and JSON-RPC ID,
method/category classification, payload redaction, deterministic summaries, and
deterministic reports.

## Native observer artifacts

The old `mcp script` behavior generated executable bpftrace/bootstrap scripts.
The Rust library intentionally does not reproduce that architecture.
`NativeObserverArtifact` instead emits deterministic JSON describing:

- the configured transports and capture limits;
- the future native ring-buffer metadata producer;
- stdio-only authorization semantics;
- the explicit absence of runtime integration.

This artifact is descriptive, not executable, and never claims that a native
observer has been loaded.
