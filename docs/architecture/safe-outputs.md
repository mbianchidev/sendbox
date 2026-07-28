# Native Safe Outputs gateway

SendBox implements a partial-conformance
[GitHub Agentic Workflows Safe Outputs](https://github.github.com/gh-aw/specs/safe-outputs-specification/)
gateway for Apple and Kata sessions. The agent receives no GitHub write
credential. It can only declare bounded operations through a trusted local MCP
server.

## Supported subset

GitHub write tools:

- `create_issue`
- `add_comment`
- `create_pull_request`
- `add_labels`
- `remove_labels`

System reporting tools:

- `noop`
- `missing_tool`
- `missing_data`
- `report_incomplete`

Asset and artifact upload tools are intentionally unsupported because they
would require a separately constrained storage write primitive.

## Configuration

Safe Outputs is disabled and staged by default. A minimal issue-only
configuration is:

```yaml
policy:
  boundaries:
    enabled: true
    tool_calls:
      transport: stdio
      default_action: deny
      allowlist: []
      denylist: []
      max_frame_bytes: 1048576
      server_command_patterns: []
      allowed_server_commands: []

github:
  forward_auth: false
  forward_copilot_auth: true
  allow_private_repository_access: false
  branch_protection:
    enabled: true
    protected_branches: [main, master]
    allowed_branch_patterns: ["copilot/*"]
  safe_outputs:
    enabled: true
    mode: staged
    write_token_env: SENDBOX_SAFE_OUTPUTS_GITHUB_TOKEN
    allowed_repositories: [owner/repository]
    allowed_domains: [github.com]
    allowed_mentions: []
    max_artifact_bytes: 131072
    create_issue:
      enabled: true
      max: 1
      title_prefix: "[sendbox] "
      labels: [triage]
      assignees: []
```

The host compiler auto-admits only the installed Safe Outputs command and the
enabled tool names. An explicit denylist match still fails closed.

Configure the MCP client to launch the gateway through the native broker:

```json
{
  "mcpServers": {
    "safe-outputs": {
      "type": "stdio",
      "command": "/run/sendbox-boundary/mcp-broker",
      "args": ["--", "/run/sendbox-boundary/safe-outputs-mcp"]
    }
  }
}
```

For `mode: apply`, provide a fine-grained token through the host process
environment named by `write_token_env`. Do not place the value in YAML, project
MCP configuration, a forwarded SendBox secret, or guest environment. When
Copilot authentication is forwarded, `write_token_env` also cannot reuse either
host Copilot token variable.

## Trust boundary and lifecycle

1. The host compiles the complete policy into authenticated bootstrap and the
   signed boundary feature admissions.
2. The guest supervisor installs the exact MCP bridge and starts a mandatory,
   health-reported root-owned recorder under
   `/run/sendbox-safe-outputs/<session>`. Gateway mode verifies that the running
   executable is the root-owned, non-writable installed path rather than
   trusting `argv[0]`.
3. The workload bridge can reach only a `0660` writer socket. The recorder
   authenticates the peer UID and GID, performs framing and schema validation,
   sanitizes content, enforces targets and limits, and atomically replaces a
   root-owned `0600` NDJSON artifact.
4. Each accepted record binds the session, boundary-plan digest, policy digest,
   sequence, timestamp, idempotency key, previous hash, operation, and record
   hash.
5. After the execution broker proves descendant cleanup, the guest fences the
   writer, drains complete in-flight frames, and creates an HKDF/HMAC seal over
   the artifact hash, chain head, counts, and provenance before returning the
   terminal result.
6. The host requests the artifact exactly once over the authenticated control
   channel. Missing capability negotiation, malformed collection, duplicate
   collection, foreign provenance, or an invalid seal fails the run.
7. The host tears down the guest, control channel, runtime, and secret resolver.
   It then independently validates and sanitizes the full batch before reading
   the dedicated write-token environment variable.

The supervisor uses an in-process typed control channel, so untrusted bytes
never reach sealing or collection commands.

## Sanitization and authorization

The recorder and host processor both enforce:

- exact `owner/repository` targets;
- per-tool all-or-nothing count limits;
- NFKC normalization and bounded text;
- credential-pattern redaction;
- URL allowlisting;
- instruction and mention neutralization;
- HTML angle escaping;
- allowed labels, assignees, base branches, and pull-request paths;
- deterministic idempotency keys and duplicate rejection.

System reporting operations never enter the token-bearing GitHub writer.

## Staged and apply modes

`staged` writes no GitHub data and does not resolve a token. It persists a
deterministic preview at:

```text
<state>/sessions/<session>/safe-outputs-report.json
```

The report renders each sanitized operation and binds the session,
boundary-plan digest, policy digest, artifact hash, chain head, operation
sequence, tool, idempotency key, status, and any result URL. The signed session
audit records separate verified and processed events with the same batch
provenance.

`apply` persists a private idempotency ledger before each external write:

```text
<state>/sessions/<session>/safe-outputs-ledger.json
```

Create operations carry a hidden provenance marker. A retry reconciles pending
issues, comments, and pull requests against that marker before writing again.
Label APIs are retried through their idempotent forms. GitHub applies a
preflight-validated batch sequentially, so a remote failure can leave earlier
operations applied; the ledger makes that partial state explicit and
recoverable.

## Pull-request transport

Pull requests never mutate the user's index or current ref. The host:

- rejects protected, disallowed, non-UTF-8, non-normalized, symlinked-parent,
  symlink, directory, conflict, file-count, and patch-size cases before any
  GitHub API write;
- snapshots source hashes and rechecks them before copying;
- fetches the configured base into a private temporary repository;
- disables system/global Git configuration, credential helpers, prompts,
  hooks, fsmonitor, external diff/text conversion, redirects, proxies, and
  commit signing;
- creates a deterministic commit on `safe-outputs/<session>-<key>`;
- passes the token only through a private askpass environment;
- pushes one explicit non-force refspec to an HTTPS `github.com` URL;
- verifies an existing retry branch has the expected commit before creating
  the pull request.

Temporary Git state and askpass files are removed after processing. The token
is never placed in argv, URLs, diagnostics, the ledger, the report, or
persistent Git configuration.

## Limitations

- Only GitHub.com REST endpoints are supported.
- Apply is sequential after complete local preflight, not transactionally
  atomic at GitHub.
- Reconciliation scans the newest 100 matching GitHub objects.
- Pull-request changes must be regular files in the mounted repository;
  symlinks and submodule updates are rejected.
- Hyperlight does not support the persistent authenticated gateway.
