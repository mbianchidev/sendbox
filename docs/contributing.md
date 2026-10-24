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
The portable-check jobs also run the credential-free cold-start diagnostic
harness's Python standard-library tests. Live VM qualification remains an
explicit prepared-host check; see [cold-start DNS diagnostics](dns-cold-start.md).
The separate Homebrew updater check uses Python standard-library tests for
stable-release gating, checksum/provenance failures, atomic formula updates,
and preservation of other tap packages. Run it locally without installing or
starting SendBox:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s packaging/homebrew -p 'test_*.py'
```

The CLI integration suite also exercises release creation and same-version
recovery using temporary local Git repositories, offline Cargo fixtures, and
mocked GitHub commands. These tests never publish a release or contact GitHub:

```bash
cargo test --locked -p sendbox-cli --test release_script
```

Hosted Apple, Hyperlight, and qualification checks also cache Rust dependencies;
qualification caches both its standalone workspace and the root CLI workspace.
These caches restore on pull requests but save only on `main`, avoiding another
set of large target caches for every PR.
These jobs explicitly budget three workers on macOS and four on Linux, matching
the standard public runners without reducing their existing CPU parallelism or
changing the prepared self-hosted live gates. The Apple adapter spike, egress
spike, production egress, and production exec workflows share CI's platform-
and version-keyed `cargo-audit` executable cache. Cache hits skip only installing
the audit tool, never the dependency audit or advisory database refresh.

Generic hosted x64 Linux jobs use `ubuntu-latest`; generic Apple-silicon jobs
use `macos-latest`. Matrix `os` values and existing job names remain stable
status-check identifiers; the separate `runner` field selects the current
image. Version strings in those check names are not runner pins.
Native Linux arm64 jobs retain `ubuntu-24.04-arm`, because GitHub has no
documented `ubuntu-latest-arm` alias. Kernel-specific BPF, exec and egress live
proofs keep their qualified Ubuntu 24.04 hosts, and prepared self-hosted gates
keep their hardware labels.

Release CLI builds retain Ubuntu 24.04 for their glibc-linked Linux binaries.
The macOS producer uses `macos-latest` but explicitly retains the existing
`MACOSX_DEPLOYMENT_TARGET=11.0` binary floor and verifies arm64/Mach-O metadata.
This does not change the Apple runtime's macOS 26+ requirement. Packaging and
publication jobs can follow the hosted aliases without relinking these bytes.

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
version-bump review, CI, tags, and recovery behavior. After preflight checks, the
script switches to `main` and pulls fast-forward-only before release operations.
Retry a failed attempt with the same command and version; existing release tags
are not moved or replaced.

Stable releases reuse the published archives to prepare a Homebrew formula
update in the existing tap; they do not compile a separate Homebrew binary.
Release builds cache Rust dependencies by toolchain/platform/lockfile and
reuse each signed guest artifact for the host packages and publication.
Native CLI tests and release builds run alongside the independent signed guest
builds. Packaging waits for both and restores the tested CLI from a same-run,
commit- and platform-specific archive, verifying its checksum and executable
mode rather than compiling it again. These internal CLI archives keep the
repository's default artifact retention for failed-job retries and are not
included in the public `release-*` asset set.
Clean guest-container builds and the existing macOS/Linux checks remain in
place. See [stable Homebrew updates](installation.md#stable-homebrew-updates)
for deploy-key scope, draft PR review, activation, and retry procedures.
