# Installation

Install SendBox through Homebrew or a verified release artifact, or build the
host binary from source when developing the project.

## Requirements

Choose a runtime before installing. Apple and Kata support interactive and
headless agent sessions; Hyperlight is an explicit one-shot provider with a
narrower capability set.

| Scope | Dependency | Required version or setup |
|---|---|---|
| Source build | Rust | 1.93.1 (pinned by `rust-toolchain.toml`) |
| Linux source build | Native compiler and headers | `build-essential clang cmake libelf-dev libseccomp-dev libzstd-dev pkg-config zlib1g-dev` on Debian/Ubuntu |
| Apple runtime | macOS | 26 (Tahoe) or newer |
| Apple runtime | Hardware | Apple silicon |
| Apple runtime | Xcode | 26 |
| Apple runtime | Official `container` CLI | Exactly 0.10.0; service already registered and running |
| Kata runtime | Linux | Bare metal or nested virtualization |
| Kata runtime | Kata Containers | 3.28 or newer |
| Kata runtime | containerd | 1.7 or newer |
| Kata runtime | nerdctl and CNI plugins | Compatible releases; access to KVM and the containerd socket |
| Linux host binary | libseccomp, libelf, zlib, and zstd runtime libraries | Distribution packages such as `libseccomp2`, `libelf1`, `zlib1g`, and `libzstd1` |
| Hyperlight runtime | Operator-pinned `hyperlight-unikraft`, signed Unikraft bundle, and KVM | See [Hyperlight](hyperlight.md) |

The [Apple](apple-runtime.md) and [Kata](kata-containers.md) guides cover runtime
setup and preflight. Run SendBox as your normal user, not with `sudo` to work
around runtime access problems.

### Workload image versus guest bundle

Persistent agent sessions need both:

- A **digest-pinned Linux workload image** for the guest architecture, containing
  your agent, its runtime dependencies, certificates, shell, and development
  tools.
- A **verified signed guest bundle and trust root**, containing SendBox's
  security services. These do not install the agent or its development tools.

Apple and Kata workload images must also provide the `nft` executable and its
shared-library dependencies. Mandatory egress enforcement requires a writable
cgroup v2 root, delegated memory/PID controllers, `CAP_NET_ADMIN`, `SO_MARK`, and
kernel support for nftables `socket cgroupv2`. A plain Alpine image without
`nftables` is not sufficient, even when the network policy denies all traffic.
Missing enforcement prerequisites are errors, not grounds to skip hardening.

The execution broker resolves entrypoint and working-directory paths without
following symlinks. Use a regular executable path and match that exact argv in
the command policy. Alpine's default `/bin/sh` is a BusyBox symlink; a workload
image using that entrypoint must materialize a regular shell executable or
select another regular entrypoint with the corresponding policy. Do not disable
descriptor-resolution checks to accommodate an image.

The production guest image is intentionally minimal: it contains no Python,
Node.js, compiler, bpftrace, or development headers. Keep bundle executables,
metadata, and trust roots in the root-owned locations described below. A public
key shipped beside a bundle is not self-authenticating; verify release
provenance before trusting it.

## Homebrew

The existing [mbianchidev/tap](https://github.com/mbianchidev/homebrew-tap)
distributes a **formula**, not a GUI cask:

```bash
brew install mbianchidev/tap/sendbox
sendbox --version
sendbox --help
```

It reuses verified published host archives for macOS arm64, Linux x86_64, and
Linux aarch64. There is no frontend build, background service, or automatic
runtime installation. Intel Macs are not supported. The Apple runtime still
requires macOS 26+, Apple silicon, and the pinned `container` CLI; Linux needs
the Kata/KVM runtime described above.

The binary is linked into Homebrew's `bin`; the complete release payload,
including `setup.sh`, configuration examples, and signed guest assets, lives
under `$(brew --prefix mbianchidev/tap/sendbox)/libexec`.

### Stage the guest bundle

Homebrew's Cellar is user-owned. **Do not pass the Cellar's guest bundle or
public key directly to `sendbox run`**, change Cellar ownership, or run Homebrew
with `sudo`. SendBox deliberately requires root-owned runtime artifacts and
trusted ancestors. A formula install does not weaken that requirement.

Before trusting the embedded guest key, independently verify the original
archive's provenance:

```bash
brew fetch --formula mbianchidev/tap/sendbox
gh attestation verify "$(brew --cache --formula mbianchidev/tap/sendbox)" \
  --repo mbianchidev/sendbox \
  --signer-workflow mbianchidev/sendbox/.github/workflows/release.yaml
```

Copy the matching payload to a **new, versioned, root-owned location**. The
following commands are an explicit administrator step, not a formula hook.
Stop if the destination already exists and inspect it instead of overwriting
an existing runtime installation:

```bash
prefix="$(brew --prefix mbianchidev/tap/sendbox)"
version="$(sendbox --version | awk '{print $2}')"
case "$(uname -m)" in
  arm64|aarch64) architecture=aarch64 ;;
  x86_64) architecture=x86_64 ;;
  *) printf 'Unsupported architecture\n' >&2; exit 1 ;;
esac
GUEST_DIR="/opt/sendbox/$version/guest/$architecture"
test ! -e "/opt/sendbox/$version" || {
  printf 'Guest destination already exists; inspect it before continuing\n' >&2
  exit 1
}
sudo install -d -o 0 -g 0 -m 0755 /opt/sendbox "$GUEST_DIR"
sudo cp -R "$prefix/libexec/guest/$architecture/bundle" \
  "$prefix/libexec/guest/$architecture/release-public.key" "$GUEST_DIR/"
sudo chown -R 0:0 "/opt/sendbox/$version"
sudo find "/opt/sendbox/$version" -type d -exec chmod 0755 {} +
sudo find "/opt/sendbox/$version" -type f -exec chmod 0444 {} +
sudo find "$GUEST_DIR/bundle/bin" -type f -exec chmod 0555 {} +
```

Ensure `/opt` and `/opt/sendbox` are real root-owned directories, not symlinks,
and are not group/world writable. Launch the CLI as your **normal user**, with
`--bundle "$GUEST_DIR/bundle"` and
`--trust-root "$GUEST_DIR/release-public.key"`. Configure the runtime separately
using the [Apple](apple-runtime.md) or [Kata](kata-containers.md) guide.

### Upgrade and removal

```bash
brew update
brew upgrade mbianchidev/tap/sendbox
brew uninstall mbianchidev/tap/sendbox
```

After upgrading, verify and stage the new version's guest bundle before using
it with the new CLI. Keep old root-owned bundles until no sessions need them;
they are outside the Cellar and are not removed by Homebrew.

Upgrades and removal preserve project `.sendbox.yaml` files, workspace contents,
user state under `~/.sendbox`, and macOS Keychain credentials. No uninstall or
cleanup hook deletes these locations. Remove retained state and versioned
`/opt/sendbox` payloads separately only when you intentionally want to erase
them. Do not mix a manual `/usr/local/bin/sendbox` install with Homebrew or use
`brew link --overwrite`; inspect and migrate the old installation explicitly.

## Release artifacts

Download the matching artifact from
[Releases](https://github.com/mbianchidev/sendbox/releases):

| Host | Artifacts |
|---|---|
| macOS arm64 | tarball, unsigned `.pkg`, unsigned `.dmg` |
| Linux x86_64 | tarball |
| Linux aarch64 | tarball |

Each host archive and macOS installer contains the production `sendbox` binary,
configuration examples, setup helper, and matching signed guest bundle. The
release also publishes standalone guest-bundle archives.

Verify GitHub provenance before trusting the embedded guest public key, then
verify the adjacent checksum:

```bash
gh attestation verify sendbox-<version>-<platform>.tar.gz \
  -R mbianchidev/sendbox
shasum -a 256 -c sendbox-<version>-<platform>.tar.gz.sha256
```

Install a verified tarball into a root-owned runtime location:

```bash
sudo tar xzf sendbox-<version>-<platform>.tar.gz -C /opt
sudo install -m 0755 /opt/sendbox-<version>-<platform>/sendbox \
  /usr/local/bin/sendbox
```

Or install the verified macOS package:

```bash
sudo installer -pkg sendbox-<version>-macos-arm64.pkg -target /
```

Run `/opt/sendbox-<version>-<platform>/setup.sh` as your normal user after
installing a tarball. The root-owned extraction preserves the runtime trust
boundary for the bundled guest artifacts; do not copy them into a user-writable
directory before launch.

Production guest bundles provide static-musl guest and execution binaries,
strict CO-RE BPF objects, signed manifests, inventory, SBOM metadata,
deterministic rootfs tarballs, and minimal scratch OCI images for Linux x86_64
and arm64. See [guest artifact bundles](architecture/guest-artifact-bundles.md)
for details.

## Publishing a release

Releases are triggered by pushing a `vX.Y.Z` tag, not by `make release`, which
only builds locally. From a clean checkout with `origin` pointing to
`mbianchidev/sendbox`, run:

```bash
./scripts/release.sh 0.2.0
```

The script requires Bash, Git, Cargo, Python 3.11 or newer, and an authenticated
GitHub CLI account with permission to push branches and tags and merge PRs.
Pass a stable `X.Y.Z` version greater than the version on `main`; a leading `v`
is also accepted.

It creates an isolated worktree from freshly fetched `origin/main`, updates
`[workspace.package].version` and the CLI version assertion, and refreshes every
committed Cargo lockfile, including standalone fuzz, spike, and qualification
workspaces. Unrelated dependencies are not upgraded.

It then opens a version-bump PR, waits for CI checks to pass, and merges without
bypassing branch protections. An annotated tag is pushed at the PR's merged
`main` commit, after verifying that its Cargo version matches the tag. The
original checkout and branch are unchanged, even if `main` advances meanwhile.

The script watches the [Release workflow](https://github.com/mbianchidev/sendbox/actions/workflows/release.yaml),
which publishes GitHub assets and GHCR artifacts, including macOS installers,
Linux archives, and signed guest bundles. The required release-signing secret
is already configured; no local signing key is needed.

On failure, the script stops and preserves any branch, PR, or tag already
created. Uncommitted release files are retained in the temporary worktree whose
path is printed for recovery. Check registration, merge completion, and release
run discovery each have a ten-minute timeout; existing tags are never replaced.

### Stable Homebrew updates

After the Release workflow publishes and attests its existing build outputs,
it calls `homebrew.yaml`. A human-published stable release also triggers this
workflow. It downloads the three host archives and their checksum files,
recomputes SHA-256, checks GitHub's asset digests, and verifies provenance from
this repository's tag-triggered Release workflow on GitHub-hosted runners.
It does not rebuild the CLI or guest bundles.

Only a published, non-draft, non-prerelease `vX.Y.Z` matching GitHub's latest
stable release can update the formula. Older releases, a newer formula, and a
stable release that supersedes an in-flight verification cannot downgrade it.
Prereleases do not update the stable formula, GitHub's latest release, or the
GHCR `latest` tag.

The dedicated write-enabled SSH deploy key is registered **only** on
`mbianchidev/homebrew-tap`; its private half is stored **only** as the SendBox
Actions secret `SENDBOX_HOMEBREW_TAP_SSH_KEY`. It is separate from other
projects' keys. The workflow authenticates with that identity alone, obtains
GitHub SSH host keys over the authenticated HTTPS API, and removes its
temporary SSH files on exit. Signing keys and SSH credentials are never cached.
Rotate by generating a new key pair, registering its public key on the existing
tap, replacing this secret, verifying access, and then revoking the old deploy
key. Never copy another project's key.

The updater changes only `Formula/sendbox.rb` and pushes
`automation/sendbox-vX.Y.Z`, **never `main`**. Tap CI validates the checked-out
branch and prepares a draft PR. A human must approve and merge it before
`brew update` offers the release. Existing branches are not force-pushed:
identical retries are a no-op, conflicting content requires inspection.

Activation after reviewing the two bootstrap PRs:

1. Merge the tap PR to make the verified initial formula available.
2. Merge the SendBox PR to enable the future release hook.
3. In the tap's Actions settings, enable **Allow GitHub Actions to create and
   approve pull requests** so its scoped workflow token can create update
   drafts. The workflow creates drafts only; it never approves or merges.

No new stable release is required for the initial formula. To retry a failed
update after these changes are on `main`, dispatch **Homebrew stable update**
with the already published latest stable tag, for example:

```bash
gh workflow run homebrew.yaml --repo mbianchidev/sendbox \
  --ref main -f tag=v0.2.2
```

If the formula already matches that verified release, the workflow is a no-op.
If a branch already exists, inspect its tap CI and draft PR; rerun the failed
tap job after fixing permissions rather than replacing the branch. This retry
path never runs `scripts/release.sh`, merges a PR, creates a tag, or republishes
assets.

## Build from source

```bash
git clone https://github.com/mbianchidev/sendbox.git
cd sendbox
make install
```

Source installs require a separately attested signed guest bundle and trust
root; tagged host artifacts already include the matching pair.

For an interactive runtime preflight and configuration flow:

```bash
./setup.sh
```

Kata installation and containerd configuration are documented in the
[Kata Containers guide](kata-containers.md).

## Unsigned macOS packages

The `.pkg` and `.dmg` are not Apple-signed or notarized. Verify their GitHub
attestation and checksum before installation. If Gatekeeper blocks a verified
download, approve that artifact in Finder or System Settings, or remove only its
quarantine attribute:

```bash
xattr -dr com.apple.quarantine sendbox-<version>-macos-arm64.pkg
```

Do not disable Gatekeeper globally. The package removes quarantine from the
installed `/usr/local/bin/sendbox` only after the installer has been approved.
The DMG `install.sh` replaces the shared payload through a fresh staging
directory, removes stale upgrade files, and enforces root ownership with `0555`
guest executables and `0444` bundle metadata and trust roots.

Continue with the [configuration guide](configuration.md) after installation.
