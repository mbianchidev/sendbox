# Installation

Install SendBox from a verified release artifact for the simplest setup, or
build the host binary from source when developing the project.

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
