# Integrating SendBox into your workflow

SendBox's integration surface is a CLI, YAML policy, and standard agent/MCP
configuration. The controls below are built in; connecting them to your editor,
job runner, or orchestration service is a workflow you compose, not a separate
managed SendBox service.

## Coding agents and model providers

Select a profile when creating project configuration:

```bash
sendbox init --project . --agent codex
```

Profiles exist for Claude Code, Codex CLI, GitHub Copilot CLI, Gemini CLI, and
OpenCode. Custom CLI programs use `--agent custom` and explicit command/network
rules. Install the agent in your digest-pinned Linux workload image, then pass
its absolute guest executable path after `sendbox run ... --`.

Profiles admit initial inference endpoints, not every possible provider or
plugin. For example, an OpenCode session using a separate model provider needs
that provider's exact endpoints in `policy.network.allowed_domains`.
Authentication and telemetry may require additional hosts too.

Store API keys with `sendbox secrets add NAME` and reference only the keys the
workload needs in `secrets`. Copilot credential forwarding is independent of
GitHub repository credentials; selecting another agent disables unrelated
Copilot forwarding.

See [CLI agents](cli-agents.md) for profile endpoints, authentication, proxy
compatibility, and native sandbox settings.

## MCP tools: local servers and remote services

Apple and Kata sessions support both local stdio servers and remote Streamable
HTTP servers. This lets an agent use project tools, documentation search, or
repository services without treating every tool exposed by a server as allowed.

For a preinstalled local server, merge a server definition into your policy:

```yaml
policy:
  boundaries:
    enabled: true
    tool_calls:
      servers:
        files:
          transport: stdio
          command: [/usr/local/bin/project-mcp-server]
          tools:
            default_action: deny
            allowlist: [read_file, list_directory]
```

Replace the example executable and tool names with your server's actual
interface. Configure the agent to launch it through the trusted broker:

```json
{
  "mcpServers": {
    "files": {
      "command": "/run/sendbox-boundary/mcp-broker",
      "args": ["--", "/usr/local/bin/project-mcp-server"]
    }
  }
}
```

The JSON container above fits Claude-style configuration; other agents use
their own native formats. The broker matches exact server identities, filters
discovery, and checks calls against the signed tool policy.

Remote services use a trusted loopback gateway rather than direct upstream
URLs in the agent configuration. Bearer credentials can be delivered only to
the gateway, separate from workload secrets. Legacy HTTP+SSE, OAuth helpers, and
unapproved launchers are not supported fallback paths.

See [native MCP configuration](cli-agents.md#native-mcp-configuration) and
[MCP inspection](mcp-inspection.md) for complete stdio, remote, authentication,
and audit examples.

## GitHub: repository access and bounded writes

For normal Git workflows, SendBox can forward repository-scoped GitHub
credentials through authenticated guest delivery and guard selected-repository
pushes and pulls by branch. SSH uses a trusted wrapper and narrowly staged key
material rather than mounting your host SSH directory.

For automation that should not hold a GitHub write token inside the VM,
**Safe Outputs** provides a different path:

1. The agent declares an allowed write through a trusted MCP recorder.
2. The guest seals the bounded artifact, and the runtime is torn down.
3. The host verifies the artifact; apply mode then resolves a dedicated write
   token and executes only admitted operations.

Safe Outputs is optional, disabled by default, and defaults to staged preview
when enabled. It requires exact repository/operation limits and cannot be
combined with ordinary GitHub credential or SSH forwarding. It is not a general
GitHub API pass-through, and asset uploads are unsupported.

See [GitHub configuration](configuration.md#github-and-mcp-boundaries) and
[Safe Outputs](architecture/safe-outputs.md). Keep GitHub server-side rulesets
enabled; local Git wrappers do not govern alternate clients or direct API writes.

## npm and private registries

Enable `policy.packages.enabled` to route supported npm traffic through a
trusted inspection proxy. It quarantines artifacts, checks identity and
integrity, evaluates configured signature/provenance requirements, and applies
static finding policies before releasing package bytes.

Private registry credentials belong in the vault and are referenced by
`policy.packages.registries[].credential_secret`, not workload `secrets`.
The current implementation supports exactly one npm registry; it is not yet a
universal package-manager firewall. Lifecycle scripts are disabled.

See the [package supply-chain guide](package-supply-chain.md) for registry
configuration, findings, exceptions, caching, and report commands.

## VS Code and devcontainer tooling

Generate a standard devcontainer spec from native project analysis:

```bash
sendbox analyze --project . --json
sendbox devcontainer generate --project .
```

The generated `.devcontainer/devcontainer.json` can be consumed by tools
supporting the [Dev Container Specification](https://containers.dev/overview).
Use it to share tooling setup with teammates or editor workflows.

**A devcontainer spec is not the SendBox runtime boundary.** Opening the
generated configuration in another tool does not automatically install the
signed guest services, enforce SendBox policy, or give each workload a dedicated
kernel. That depends on the runtime used to launch it.

See the [CLI reference](cli-reference.md) for generation options.

## CI, scripts, and custom orchestrators

Use headless `sendbox run` on a runner with a prepared runtime, verified guest
artifacts, and access to the selected virtualization device/control plane.
Do not assume an arbitrary hosted CI runner supports nested virtualization.

```bash
sendbox policy validate --config .sendbox.yaml

# Set these to your prepared image and verified, root-owned guest artifacts.
sendbox run --json \
  --config .sendbox.yaml \
  --image "$WORKLOAD_IMAGE" \
  --bundle "$GUEST_DIR/bundle" \
  --trust-root "$GUEST_DIR/release-public.key" \
  -- /usr/local/bin/your-agent --your-headless-option
```

Replace the executable and headless option with your agent's actual interface,
and admit that command in policy. `--json` emits machine-readable output,
result, and error events; it cannot be combined with `--interactive`. Binary
workload output is hex encoded. Preserve the process exit status when wrapping
the command in a script.

SendBox supplies session isolation and lifecycle controls, not runner
provisioning, a remote execution API, or a multi-tenant scheduler. Your
orchestrator owns scheduling, credentials, artifact collection, and workspace
allocation. Use separate workspaces for concurrent jobs rather than allowing
agents to race on the same writable checkout.

See [CLI reference](cli-reference.md), [qualification](qualification.md), and
[session security lifecycle](architecture/session-security-lifecycle.md).
