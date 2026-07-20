# Rust CLI parity boundary

The migration binary remains named `sendbox-rs`, but its clap command name,
help, JSON contracts, and generated completions use the final `sendbox` surface.
This keeps Rust and Swift binaries installable side by side without freezing an
experimental name into scripts or completion files.

## Implemented without runtime dependencies

| Surface | Rust behavior |
|---|---|
| `init` | Resolves an existing project directory, selects a policy preset and runtime, validates deterministic v1 YAML, creates `.sendbox.yaml` atomically with mode `0600`, and never overwrites an existing file. |
| `policy show` | Shows the default or configured policy as stable text or deterministic JSON. Configuration input uses strict decoding and policy-only validation. |
| `policy validate` | Retains full sandbox validation, deterministic JSON, diagnostics, and exit `2` for invalid configuration. |
| `completions print` | Generates bash, zsh, or fish output directly from the clap command tree. |
| `completions install` | Detects `SHELL` or accepts `--shell`, falls back to zsh when detection is unavailable, writes to stable per-shell paths with atomic replacement, mode `0644`, and directory mode `0755`. It never launches a shell or respawns the CLI. |
| `analyze` / `devcontainer generate` | Retains the existing native project-analysis subset. |

Exit `2` is reserved for invalid input/configuration, `3` for project analysis
failures, and `4` for output failures or no-overwrite refusals. Text failures go
to stderr. Commands with `--json` emit one deterministic failure object to
stdout and leave stderr empty.

## Configuration persistence

`sendbox-config` accepts current v1 documents with no version key and migration
inputs carrying `schema_version: 1`. Future versions and unknown fields are
rejected. Canonical YAML uses declaration-order snake_case keys, omits absent
optional values, preserves explicit empty collections, and includes documented
defaults. Migration reports distinguish schema changes from formatting
canonicalization.

Writes validate first, open every destination-directory component without
following symlinks, create a temporary file through the opened directory, set
the final mode, sync content, and atomically create or replace the destination.
`init` uses a no-replace rename so a concurrent creator wins without being
modified; explicit migration callers may request replacement.

## Deferred command groups

The Rust CLI intentionally does not expose `run`, secrets commands, MCP
commands, or boundary commands in this phase. Those require concrete runtime,
credential-storage, MCP authorization, or security-listener integration and
remain on Swift until their dependencies and qualification fixtures are ready.
Release installers also continue to package the Swift binary.
