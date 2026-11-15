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
  governance    Sign, verify, and check operator governance profiles
  completions   Install or print shell completions
  help          Show help for any subcommand
```

Use `sendbox help` or `sendbox help <subcommand>` for the options supported by
the installed version.

## Init profiles and workspace scope

`sendbox init --agent moguri|opencode|claude|codex|copilot|gemini|custom` selects the
entry program and initial inference endpoints; `open-code` is an alias for
`opencode`. Omit `--agent` to preserve the existing defaults.
`--workspace PATH` explicitly shares an enclosing multi-repository root while
`--project PATH` retains the selected repository and initial cwd. See
[CLI agents](cli-agents.md) for credentials, native MCP formats, and examples.

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
| `--governance-config PATH` | Opt-in governance configuration; rejected when a managed configuration names a different file |

See [interactive sessions](interactive-sessions.md) for terminal-specific
requirements and [configuration](configuration.md) for the YAML reference.

JSON workload output events carry `encoding: "hex"`; decode their `data` before
comparing payload bytes. A persistent launch/runtime failure reports its already
credential-masked terminal diagnostic in the result's `message` field and keeps
the existing nonzero exit code. Text mode prints that diagnostic to stderr.
Successful result objects do not add a failure message.

For an exact `github.com` grant, the final JSON result includes
`network_report: {path, sha256}`. The private JSON artifact contains the configured policy
and latest GitHub Meta scope/provenance for each active gateway role. Read its
freshness, failure and expiry fields before interpreting the published grants;
explicit deny and restricted-address rules still apply. It is authenticated
guest evidence whose digest is recorded in session provenance, not a separately
GitHub-signed feed or a complete refresh log.
See [network grants](configuration.md#network-grants).

## Governance

`sendbox governance` manages operator-signed profiles for
[governed sessions](architecture/governed-sessions.md):

| Subcommand | Purpose |
|---|---|
| `keygen --output PATH` | Create an Ed25519 signing key (mode `0600`, never overwritten) and print its public identity |
| `sign PROFILE --key PATH [--append]` | Sign the profile's exact bytes into `PROFILE.sig.json`; `--append` adds a threshold signature |
| `verify [--governance-config PATH]` | Verify the active operator configuration, profile, and signatures |
| `check --config PATH [--governance-config PATH] [--runtime apple\|kata] [--image IMAGE@sha256:DIGEST]` | List every violation of the active profile without starting a session |
| `login [--governance-config PATH] [--identity-token-file PATH] [--ttl-seconds N] [--description TEXT]` | Exchange an identity-provider token (read from the file, stdin, or a prompt) with the configured shared governance service and store the returned service token in the host secret store |

Each subcommand accepts `--json`. A governance failure or a rejected
configuration exits with code `6`. `check` evaluates the local profile only;
with a [shared governance service](architecture/governed-sessions.md#shared-governance-service),
run `sendbox governance login` (or `sendbox secrets add SENDBOX_FLEET_TOKEN`)
before `sendbox run`.

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

# Show configured policy as deterministic JSON (no live metadata retrieval)
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

# Check a project against the active governance profile
sendbox governance check --config .sendbox.yaml --runtime apple
```
