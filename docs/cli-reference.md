# CLI reference

The Rust CLI implements the supported `sendbox` command surface:

```text
USAGE: sendbox <subcommand> [options]

SUBCOMMANDS:
  init          Initialize a new sendbox.yaml in the current directory
  run           Start the sandbox and launch the agent
  analyze       Analyze a project and generate a devcontainer spec
  secrets       Add, remove, or list stored secrets
  policy        Show or validate policies
  mcp           Parse and summarize native or legacy MCP observations
  package       Show package verdict status or a complete security report
  boundary      Inspect the structured native boundary plan
  completions   Install or print shell completions
  help          Show help for any subcommand
```

Use `sendbox help` or `sendbox help <subcommand>` for the options supported by
the installed version.

## Run flags

| Flag | Description |
|---|---|
| `--config PATH` | Sandbox configuration file |
| `--runtime auto\|apple\|kata\|hyperlight` | Runtime provider selection |
| `--image IMAGE@sha256:DIGEST` | Digest-pinned workload image for persistent runtimes |
| `--bundle PATH` | Verified guest bundle directory |
| `--trust-root PATH` | Release public key used to verify the bundle |
| `--json` | Emit machine-readable events instead of raw output |
| `--interactive` | Run the workload on a pseudoterminal; conflicts with `--json` |

See [interactive sessions](interactive-sessions.md) for terminal-specific
requirements and [configuration](configuration.md) for the YAML reference.

## Examples

```bash
# Initialize a new project
sendbox init

# Run with the Kata backend
sendbox run --config .sendbox.yaml --runtime kata \
  --image registry.example/workload@sha256:<digest> \
  --bundle /usr/local/share/sendbox/guest/x86_64/bundle \
  --trust-root /usr/local/share/sendbox/guest/x86_64/release-public.key \
  -- /usr/bin/true

# Generate a devcontainer spec
sendbox analyze --project . --output .devcontainer/

# Validate a sandbox configuration's policy
sendbox policy validate --config sendbox.yaml

# Show the effective policy as deterministic JSON
sendbox policy show --config sendbox.yaml --json

# Show the latest package-enabled run and its complete report
sendbox package status
sendbox package report --json

# Print or install generated shell completions
sendbox completions print --shell zsh
sendbox completions install --shell fish

# Native analysis with automation JSON
cargo run -p sendbox-cli -- analyze --project . --json

# Native devcontainer generation
cargo run -p sendbox-cli -- devcontainer generate --project . --json

# Parse a captured trace log and summarize MCP activity
sendbox mcp parse /var/log/sendbox/mcp-trace.log
sendbox mcp report /var/log/sendbox/mcp-trace.log

# Inspect the structured boundary declaration without generating scripts
sendbox boundary inspect --config .sendbox.yaml --json
```
