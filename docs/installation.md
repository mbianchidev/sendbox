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
uses a **formula**, not a GUI cask.

**Activation is blocked pending an approved patched stable release.** The
bootstrap PR verifies the immutable v0.2.2 artifacts for isolated lifecycle
qualification, but those binaries predate
[RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382) and
[RUSTSEC-2026-0383](https://rustsec.org/advisories/RUSTSEC-2026-0383).
The source lockfiles update `rustls-webpki` to 0.103.16 and
`webpki-root-certs` to 1.0.10; published binaries cannot inherit source fixes.
Do not merge or activate that formula until a newly approved patched stable
release replaces its URLs/checksums and passes tap CI. The updater rejects
published releases older than v0.2.3. No replacement release is published by
this packaging work.

After activation:

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

The script requires Bash, Git, Python 3.11 or newer, and an authenticated GitHub
CLI account with permission to push branches and tags, merge PRs, and rerun
Actions workflows. Cargo is also required when preparing a new version bump.
For a new release, pass a stable `X.Y.Z` version greater than the version on
`main`; a leading `v` is also accepted.

After its preflight safety checks, the script switches the invoking checkout
to `main` and pulls `origin/main` with `--ff-only` before inspecting or resuming
a release. A failed pull or divergent local `main` stops the script before any
release operations. If `main` is checked out in another Git worktree, run from
that checkout instead; the script never forces a second checkout of `main`.

For a new release, it creates an isolated worktree from updated `origin/main`,
updates `[workspace.package].version` and the CLI version assertion, and
refreshes every committed Cargo lockfile, including standalone fuzz, spike,
and qualification workspaces. Unrelated dependencies are not upgraded.

It then opens a version-bump PR, waits for CI checks to pass, and merges without
bypassing branch protections. An annotated tag is pushed at the PR's merged
`main` commit, after verifying that its Cargo version matches the tag. The
invoking checkout stays on `main` at its startup pull, while the original
feature branch is unchanged and version edits remain in the isolated worktree.

The script watches the [Release workflow](https://github.com/mbianchidev/sendbox/actions/workflows/release.yaml),
which publishes GitHub assets and GHCR artifacts, including macOS installers,
Linux archives, and signed guest bundles. The required release-signing secret
is already configured; no local signing key is needed.

On failure, the script stops and preserves any branch, PR, or tag already
created. Resolve the underlying failure, then run the **same command with the
same version** to resume. It reuses a committed `release/vX.Y.Z` branch and its
open or merged version-bump PR rather than creating duplicates. Uncommitted
release files are retained in the temporary worktree whose path is printed for
recovery; inspect and finish that work before retrying.

If the tag already exists, the script verifies its Cargo version and ancestry
on `origin/main`, then watches its existing Release workflow. Failed runs rerun
only failed jobs and their dependents, retaining successful build outputs.
Cancelled or otherwise unsuccessful completed runs restart the whole workflow.
The script waits for the new attempt before watching it; active runs are only
watched, and successful runs are not restarted. Retries remain subject to
GitHub's rerun window and artifact retention.

A local tag not yet pushed is published unchanged. Existing tags are never
replaced, and conflicting local and remote tags or release branches require
manual inspection. Check registration, merge completion, release run discovery,
and retry registration each have a ten-minute timeout.

### Stable Homebrew updates

After the Release workflow publishes and attests its existing build outputs,
it calls `homebrew.yaml`. A human-published stable release also triggers this
workflow. It downloads the three host archives and their checksum files,
recomputes SHA-256, checks GitHub's asset digests, and verifies provenance from
this repository's tag-triggered Release workflow on GitHub-hosted runners.
It does not rebuild the CLI or guest bundles.

Only a published, non-draft, non-prerelease `vX.Y.Z` matching GitHub's latest
stable release at or above the patched-release floor v0.2.3 can update the
formula. The floor prevents known-affected existing releases from activating.
Older releases, a newer formula, and a
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

Activation after reviewing the two draft PRs:

1. With human approval, merge the SendBox source/security changes. This does not
   publish a release or activate the tap.
2. Separately approve and publish a patched stable release newer than v0.2.2.
   Do not reuse existing v0.2.2 tags, assets, or checksums.
3. Update the still-draft tap bootstrap branch from that release's verified
   artifacts, rerun its isolated CI, then approve and merge it. For example,
   **only after an approved v0.2.3 exists**, run the updater from a SendBox
   checkout against the bootstrap tap checkout:

   ```bash
   python3 packaging/homebrew/update.py --tag v0.2.3 \
     --tap /path/to/bootstrap-tap-checkout
   ```

   Commit/push only that tap feature branch, never `main`. The normal release
   hook requires a formula already on tap `main`, so the first bootstrap update
   is deliberately explicit rather than trusting an unmerged branch.
4. In the tap's Actions settings, enable **Allow GitHub Actions to create and
   approve pull requests** so its scoped workflow token can create update
   drafts. The workflow creates drafts only; it never approves or merges.

To retry a failed update after the patched release and formula are available
on `main`, dispatch **Homebrew stable update** with that published latest
stable tag, for example after v0.2.3 has been approved and published:

```bash
gh workflow run homebrew.yaml --repo mbianchidev/sendbox \
  --ref main -f tag=v0.2.3
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
