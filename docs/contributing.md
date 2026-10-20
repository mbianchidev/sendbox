# Contributing to SendBox

Contributions are welcome. For larger changes, open an issue first to discuss
the approach. The [roadmap](../ROADMAP.md) tracks planned work.

## Source setup

Follow the [source-build requirements](installation.md#requirements), then fork
and clone the repository and create a feature branch:

```bash
git clone https://github.com/YOUR_USERNAME/sendbox.git
cd sendbox
git checkout -b feature/my-change
make build
```

The toolchain is pinned in `rust-toolchain.toml`. Building the host binary does
not provision a runtime or install a signed guest bundle; see
[installation](installation.md) for those steps.

## Checks

Before opening a pull request for code changes, run:

```bash
make lint
make test
make release
make audit
```

`make lint` checks formatting and Clippy and compiles every standalone fuzz
workspace with its committed lockfile. `make audit` requires `cargo-audit`.
Runtime-specific live qualification needs a prepared host; see
[qualification](qualification.md) and the individual runtime guides.

CI runs portable checks and build/install qualification in parallel on macOS
and Linux, with fail-fast matrices. Rust dependency caches are isolated by
toolchain, platform, lockfiles, and job task; every check still runs. Standalone
fuzz workspaces share the root target directory in CI instead of recompiling
their common dependencies into separate target directories. The `cargo-audit`
executable is cached, but every run refreshes and checks the advisory database.

Guest artifact CI runs the two clean builds for each architecture in separate
parallel jobs and compares their outputs before publishing the verified bundle.
See [guest artifact CI](architecture/guest-artifact-bundles.md#continuous-integration)
for cache boundaries and the automatic privileged BPF smoke tests.

For documentation-only changes, check examples, relative links, and heading
anchors. Keep the root README focused on evaluating the project and starting a
session; put detailed operational and architecture material under `docs/` and
link it from the [documentation index](README.md).

## Publishing releases

Maintainers publish tag-triggered releases with:

```bash
./scripts/release.sh VERSION
```

`make release` only builds locally. See
[publishing a release](installation.md#publishing-a-release) for prerequisites,
version-bump review, CI, tags, and recovery behavior.
