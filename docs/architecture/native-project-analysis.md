# Native project analysis

`sendbox-project` is the deterministic Rust implementation of project detection
and devcontainer generation. It does not start project processes, evaluate
manifests, run package scripts, or require Node.js or Copilot.

## Scanning

The scanner traverses entries in lexical order and never follows symbolic links.
Regular files are opened only after metadata checks, and Unix file identities are
checked again after opening to detect symlink or rename races. The default limits
are:

| Limit | Default |
|---|---:|
| Directory depth | 12 |
| Files visited | 4,096 |
| Manifest bytes read | 8 MiB |
| Bytes per manifest | 1 MiB |

`sendbox-rs analyze` exposes each limit as a flag. Limit hits, symlinks,
permission failures, files changed during scanning, and malformed manifests are
reported in `scan.skipped` or `scan.errors`; they are not converted into a
success-shaped fallback.

The analyzer safely parses JSON, TOML, XML, and bounded static text for the
languages and tools detected by the temporary TypeScript bridge: Node.js and
TypeScript, Python, Rust, Go, Java and Kotlin, Ruby, C and C++, .NET, PHP,
Elixir, and Swift. `Package.swift`, Gradle files, Gemfiles, and `mix.exs` are
inspected as text only and are never executed.

## Bridge compatibility

The native `ProjectAnalysis` keeps the bridge field names and meanings:

- `language`, `framework`, `packageManager`, `buildSystem`, `runtimeVersion`
- `dependencies`, `devDependencies`
- `hasDockerfile`, `hasDevContainer`, `detectedFiles`
- `suggestedImage`, `suggestedFeatures`, `suggestedExtensions`

Intentional native differences:

- scanning is recursive and bounded instead of unbounded root-only existence
  checks;
- dependencies and development dependencies are sorted and deduplicated;
- native parsing covers additional structured dependency data in `pyproject.toml`,
  `pom.xml`, Composer files, and .NET projects;
- `languages` reports all detected project languages;
- `scan` reports limits, skipped entries, and errors explicitly;
- `refinement.status` is always present and is `not_requested`, `applied`, or
  `failed`.

Checked-in fixtures compare representative native output with expected bridge
JSON without making live model calls.

## Optional refinement

`RefinementProvider` is separate from deterministic analysis. A provider may
return changes to image, features, extensions, framework, or runtime version.
Native analysis remains valid without a provider, and provider failures are
returned as errors while the analysis records that refinement failed. No Node or
Copilot implementation is required by the Rust crate.

## Devcontainer generation

Generation starts with the bridge-compatible image, features, extensions,
settings, ports, remote user, and post-create command. Merge precedence is:

1. generated native defaults;
2. an existing `.devcontainer/devcontainer.json`;
3. typed Rust or CLI overrides.

Objects are merged recursively. Features, settings, and `containerEnv` merge by
key. Extensions and forwarded ports are sorted and deduplicated. Unknown
devcontainer properties are preserved.

Existing files are parsed as JSONC with string-aware line comments, block
comments, and trailing commas. Rewriting produces deterministic JSON, so comments
from the input are intentionally not preserved; JSON output reports
`commentsPreserved: false`.

Output must remain beneath the canonical project directory. Existing output
symlinks are rejected. The parent directory is created with private permissions
on Unix, and a mode `0600` temporary file is flushed, synchronized, and atomically
renamed into place.

## Experimental CLI

```bash
# Human-readable summary
sendbox-rs analyze --project .

# Complete deterministic JSON
sendbox-rs analyze --project . --json

# Generate or merge .devcontainer/devcontainer.json
sendbox-rs devcontainer generate --project . --json

# Apply typed overrides
sendbox-rs devcontainer generate \
  --project . \
  --image mcr.microsoft.com/devcontainers/rust:1-bookworm \
  --feature 'ghcr.io/devcontainers/features/github-cli:1={}' \
  --extension rust-lang.rust-analyzer \
  --container-env RUST_BACKTRACE=1 \
  --json
```

Automation exit codes are scoped to these commands:

| Code | Meaning |
|---:|---|
| 0 | Analysis or generation completed |
| 2 | CLI usage error, or existing `policy validate` validation failure |
| 3 | Project root or analysis failure |
| 4 | Devcontainer parse, merge, or output failure |

The Node `copilot-bridge` remains checked in only for migration and differential
fixtures. Rust analysis and generation do not invoke it.
