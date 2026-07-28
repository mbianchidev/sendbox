# Rust CLI

Cargo emits the production binary as `sendbox`. Its clap command name, help,
JSON contracts, generated completions, install paths, and release artifacts use
the same name.

## Implemented command groups

| Surface | Rust behavior |
|---|---|
| `init` | Resolves an existing readable/searchable project directory, selects a policy preset and runtime, validates deterministic v1 YAML, creates `.sendbox.yaml` atomically with mode `0600`, and never overwrites an existing file. |
| `policy show` | Shows the default or configured policy as stable text or deterministic JSON. Configuration input uses strict decoding and policy-only validation. |
| `policy validate` | Retains full sandbox validation, deterministic JSON, diagnostics, and exit `2` for invalid configuration. |
| `completions print` | Generates bash, zsh, or fish output directly from the clap command tree. |
| `completions install` | Detects `SHELL` or accepts `--shell`, falls back to zsh when detection is unavailable, writes to stable per-shell paths with atomic replacement, mode `0644`, and directory mode `0755`. It never launches a shell or respawns the CLI. |
| `analyze` / `devcontainer generate` | Retains the existing native project-analysis subset. |
| `secrets` | Adds, lists, and removes versioned secrets through Keychain on macOS or the descriptor-safe protected file store on Linux without printing values. |
| `mcp parse` / `mcp report` | Parses native or legacy observations with optional redaction and deterministic JSON. It does not generate executable inspection scripts. |
| `boundary inspect` | Emits the structured native boundary declaration without scripts or secret values. |
| `run` | Resolves and verifies a signed immutable boundary plan, selects Apple/Kata/Hyperlight without fallback, and dispatches either an authenticated persistent guest session or the explicit authenticated Hyperlight one-shot path. |

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
modified; explicit migration callers may request replacement. Descriptor-based
traversal requires read and search permission on existing destination
directories. Completion setup applies `0755` only to directories it creates and
preserves stricter modes on directories that already exist.

## Runtime contract

`run` requires an absolute guest command plus a verified bundle and trust root.
Persistent Apple and Kata execution waits for authenticated guest readiness and
the required capability set before resolving workload secrets or launching the
command. Hyperlight is explicit-only and rejects every feature its one-shot
boundary cannot enforce. Text errors use stderr; `--json` emits one error or
result object to stdout.
