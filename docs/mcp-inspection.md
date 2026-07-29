# MCP boundary and inspection

SendBox provides one fail-closed MCP authorization model for exact stdio
servers and trusted Streamable HTTP upstreams. Optional inspection records are
an observation by-product; they are not an authorization mechanism.

## Configure server and tool policy

`policy.boundaries.tool_calls.servers` maps stable policy IDs to exact transport
identities and independent tool policies:

```yaml
policy:
  boundaries:
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

        remote-docs:
          transport: streamable_http
          url: https://mcp.example.com/mcp
          tools:
            default_action: deny
            allowlist: [search_docs, get_document]
            denylist: ["create_*", "update_*", "delete_*"]
          http:
            allow_redirects: false
            max_request_bytes: 1048576
            max_response_bytes: 1048576
            request_timeout_seconds: 30
            connect_timeout_seconds: 10
            idle_timeout_seconds: 30
            max_events: 1024
            max_concurrent_requests: 32
            authorization:
              bearer_secret: REMOTE_MCP_TOKEN
```

Server IDs are stable policy identities, not caller-provided authorization
claims. Exact stdio argv or an exact deterministic gateway route selects the
policy. Unknown servers, ambiguous identities, changed commands or endpoints,
invalid transport metadata, and audit failures deny.

Tool deny rules win, then allow rules, then `default_action`. Use
`default_action: deny` to require explicit tool admission. SendBox filters every
`tools/list` page and checks `tools/call` again, so discovery is never an
authorization grant.

All policy and configuration structs reject unknown YAML fields. Stdio and HTTP
server entries are tagged by `transport` and cannot mix transport-specific
fields.

## Bind project MCP definitions

SendBox validates `.mcp.json`, `.vscode/mcp.json`,
`.github/copilot/mcp.json`, `.cursor/mcp.json`, and `.claude/mcp.json`.
Project aliases do not affect policy selection and project files cannot select a
SendBox policy ID.

Stdio definitions must invoke the installed broker followed by one exact
approved command:

```json
{
  "mcpServers": {
    "files": {
      "type": "stdio",
      "command": "/run/sendbox-boundary/mcp-broker",
      "args": [
        "--",
        "/usr/local/bin/node",
        "/usr/local/lib/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js",
        "/workspaces/my-project"
      ]
    }
  }
}
```

Remote definitions must select the exact loopback route derived from the server
ID:

```json
{
  "mcpServers": {
    "docs": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:15082/mcp/remote-docs"
    }
  }
}
```

Direct upstream URLs, custom headers or credentials, URL drift, query strings,
fragments, user information, env/cwd overrides, wrapper chains, unknown routes,
and unsupported transports are rejected.

## HTTP transport modes

- `streamable_http` implements modern Streamable HTTP with POST-only,
  request-scoped JSON or SSE responses. Session IDs, GET streams, DELETE, and
  reconnect event IDs are rejected.
- `streamable_http_2025` is an explicit compatibility mode for issued session
  IDs, GET/SSE, DELETE, and validated `Last-Event-ID` reconnects. Sessions and
  observed event IDs are bound to one server and gateway instance.
- Legacy 2024 HTTP+SSE and WebSocket upgrades are unsupported and fail closed.

For either supported HTTP mode, the root-owned gateway:

- accepts only the canonical `/mcp/<server-id>` loopback route;
- validates JSON-RPC, status, content type, protocol metadata, response IDs,
  sizes, concurrency, timeouts, and SSE event limits;
- verifies TLS chains, validity, hostname, and SNI with system roots plus any
  configured PEM roots;
- resolves each connection independently, classifies every address, and dials
  the exact validated address with the egress mark;
- disables redirects by default and permits only exact configured redirect
  targets when enabled;
- strips hop-by-hop, cookie, and unapproved headers;
- has no direct-upstream fallback.

Plaintext HTTP is limited to loopback endpoints with
`allow_plaintext_local: true`. Restricted literal addresses require
`allow_private_networks: true`; metadata addresses remain denied.

Remote MCP forces authenticated egress enforcement. Agent processes can reach
only the loopback gateway route, configured upstream names are reserved from the
normal CONNECT broker, and direct-IP CONNECT is disabled while remote MCP is
active. TLS uprobes remain observation-only and never authorize traffic.

## Gateway credentials

`http.authorization.bearer_secret` names a value in the SendBox vault. Store it
with the normal secret CLI:

```bash
sendbox secrets add REMOTE_MCP_TOKEN
```

Gateway credential names are signed separately from top-level `secrets` and
must not overlap them. Values are resolved by the host, delivered only through
authenticated root-owned bootstrap material, zeroized, and injected only into
the configured upstream request. They never enter the workload environment or
project MCP file.

## Inspect the resolved boundary

Inspect policy without launching a sandbox:

```bash
sendbox boundary inspect --config .sendbox.yaml
sendbox boundary inspect --config .sendbox.yaml --json
```

The output identifies hierarchical versus legacy mode and reports each server's
ID, transport, fingerprint, exact command or normalized endpoint, deterministic
local gateway route, effective tool rules, HTTP limits, TLS settings, redirect
policy, and credential reference names. Secret values are never shown.

## Mandatory audit and optional observation

Stdio and HTTP authorization share a mandatory append-only JSONL audit path:

```text
/var/log/sendbox/mcp-audit.jsonl
```

Records include stable server identity, transport and fingerprint, normalized
endpoint where applicable, method/tool, outcome, rule/reason, status, byte
counts, timing, and hashed session identity. They exclude commands, tool
arguments, payloads, environment values, and credentials. The trusted service
writes a record before an action takes effect; write failure is terminal.

Optional stdio observation can be enabled separately:

```yaml
observability:
  mcp_inspection:
    enabled: true
    transports: [stdio]
    capture_payloads: false
    max_payload_bytes: 16384
    log_path: /var/log/sendbox/mcp-trace.log
```

Inspection requires `policy.boundaries.enabled: true`. Paths outside
`/var/log/sendbox`, duplicate transports, and unsupported transports are
rejected. Payload text is omitted unless capture is explicitly enabled and is
then truncated to the configured bound.

```bash
sendbox mcp parse /var/log/sendbox/mcp-trace.log
sendbox mcp report /var/log/sendbox/mcp-trace.log --json
```

Apple and Kata support MCP composition. Hyperlight rejects it.

## Deprecated flat policy

The old flat stdio fields remain as an explicit compatibility mode:

```yaml
tool_calls:
  allowed_server_commands:
    - [/usr/local/bin/github-mcp-server, stdio]
  default_action: deny
  allowlist: [search_code]
  denylist: ["delete_*"]
```

Flat fields cannot be mixed with `servers`. SendBox synthesizes deterministic
legacy IDs from command fingerprints and exposes the compatibility mode in
boundary inspection. New configurations should use hierarchical `servers`.
