#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SENDBOX="$ROOT_DIR/target/release/sendbox"
RAW_ROOT="$(mktemp -d)"
MOUNT_DEVICE=""
INSTALL_USES_SUDO=0

install_as_root() {
    if [[ "$INSTALL_USES_SUDO" == "1" ]]; then
        sudo -n "$@"
    else
        "$@"
    fi
}

cleanup() {
    if [[ -n "$MOUNT_DEVICE" ]]; then
        hdiutil detach "$MOUNT_DEVICE" >/dev/null
    fi
    if [[ "$INSTALL_USES_SUDO" == "1" ]]; then
        sudo -n rm -rf "$RAW_ROOT"
    else
        rm -rf "$RAW_ROOT"
    fi
}
trap cleanup EXIT HUP INT TERM

TEST_ROOT="$(cd "$RAW_ROOT" && pwd -P)"
test -x "$SENDBOX"
test -x "$ROOT_DIR/setup.sh"
VERSION="$("$SENDBOX" --version | awk '{print $2}')"

case "$(uname -s):$(uname -m)" in
    Darwin:arm64)
        PLATFORM="macos-arm64"
        GUEST_ARCHITECTURE="aarch64"
        ;;
    Linux:x86_64)
        PLATFORM="linux-x86_64"
        GUEST_ARCHITECTURE="x86_64"
        ;;
    Linux:aarch64 | Linux:arm64)
        PLATFORM="linux-aarch64"
        GUEST_ARCHITECTURE="aarch64"
        ;;
    *)
        echo "unsupported release smoke host: $(uname -s) $(uname -m)" >&2
        exit 1
        ;;
esac

PROJECT="$TEST_ROOT/project"
mkdir -m 0700 "$PROJECT"
printf '%s\n%s\n' "$PROJECT" 1 \
    | "$ROOT_DIR/setup.sh" configure >/dev/null
test -f "$PROJECT/.sendbox.yaml"
"$SENDBOX" policy validate --config "$PROJECT/.sendbox.yaml" >/dev/null

printf '\n' | "$ROOT_DIR/setup.sh" build >/dev/null

MAKE_ROOT="$TEST_ROOT/make-install"
make -C "$ROOT_DIR" install DESTDIR="$MAKE_ROOT" PREFIX=/usr/local >/dev/null
test -x "$MAKE_ROOT/usr/local/bin/sendbox"
"$MAKE_ROOT/usr/local/bin/sendbox" --version >/dev/null
if [[ -n "$(find "$MAKE_ROOT" -name 'sendbox-rs' -print -quit)" ]]; then
    echo "legacy sendbox-rs binary was installed" >&2
    exit 1
fi

PAYLOAD="$TEST_ROOT/guest-payload"
mkdir -p "$PAYLOAD/bundle/bin"
printf 'guest\n' >"$PAYLOAD/bundle/bin/sendbox-guest"
printf 'launcher\n' >"$PAYLOAD/bundle/bin/sendbox-exec-launcher"
printf '{}\n' >"$PAYLOAD/bundle/manifest.json"
printf 'signature\n' >"$PAYLOAD/bundle/manifest.sig"
printf '00000000000000000000000000000000' >"$PAYLOAD/release-public.key"
chmod 0555 \
    "$PAYLOAD/bundle/bin/sendbox-guest" \
    "$PAYLOAD/bundle/bin/sendbox-exec-launcher"
chmod 0444 \
    "$PAYLOAD/bundle/manifest.json" \
    "$PAYLOAD/bundle/manifest.sig" \
    "$PAYLOAD/release-public.key"

STAGING="sendbox-${VERSION}-${PLATFORM}"
mkdir -p "$TEST_ROOT/$STAGING/guest/$GUEST_ARCHITECTURE"
cp "$SENDBOX" "$TEST_ROOT/$STAGING/"
cp "$ROOT_DIR/README.md" "$ROOT_DIR/LICENSE" "$ROOT_DIR/ROADMAP.md" \
    "$ROOT_DIR/setup.sh" "$TEST_ROOT/$STAGING/"
cp -R "$ROOT_DIR/config" "$TEST_ROOT/$STAGING/"
cp -R "$PAYLOAD/bundle" \
    "$TEST_ROOT/$STAGING/guest/$GUEST_ARCHITECTURE/"
cp "$PAYLOAD/release-public.key" \
    "$TEST_ROOT/$STAGING/guest/$GUEST_ARCHITECTURE/"

if [[ "$PLATFORM" == macos-* ]]; then
    (
        cd "$TEST_ROOT"
        COPYFILE_DISABLE=1 tar \
            --uid 0 \
            --gid 0 \
            --uname root \
            --gname wheel \
            -czf "${STAGING}.tar.gz" \
            "$STAGING"
        shasum -a 256 "${STAGING}.tar.gz" >"${STAGING}.tar.gz.sha256"
        shasum -a 256 -c "${STAGING}.tar.gz.sha256"
    )

    PKG_ROOT="$TEST_ROOT/pkg-root"
    SCRIPTS_DIR="$TEST_ROOT/pkg-scripts"
    mkdir -p \
        "$PKG_ROOT/usr/local/bin" \
        "$PKG_ROOT/usr/local/share/sendbox/guest/aarch64" \
        "$SCRIPTS_DIR"
    install -m 0755 "$SENDBOX" "$PKG_ROOT/usr/local/bin/sendbox"
    cp "$ROOT_DIR/README.md" "$ROOT_DIR/LICENSE" "$ROOT_DIR/ROADMAP.md" \
        "$ROOT_DIR/setup.sh" "$PKG_ROOT/usr/local/share/sendbox/"
    cp -R "$ROOT_DIR/config" "$PKG_ROOT/usr/local/share/sendbox/"
    cp -R "$PAYLOAD/bundle" \
        "$PKG_ROOT/usr/local/share/sendbox/guest/aarch64/"
    cp "$PAYLOAD/release-public.key" \
        "$PKG_ROOT/usr/local/share/sendbox/guest/aarch64/"
    printf '%s\n' \
        '#!/bin/sh' \
        'set -eu' \
        'xattr -dr com.apple.quarantine /usr/local/bin/sendbox 2>/dev/null || true' \
        >"$SCRIPTS_DIR/postinstall"
    chmod 0755 "$SCRIPTS_DIR/postinstall"
    pkgbuild \
        --root "$PKG_ROOT" \
        --scripts "$SCRIPTS_DIR" \
        --identifier dev.sendbox.cli \
        --version "$VERSION" \
        --install-location / \
        "$TEST_ROOT/${STAGING}.pkg" >/dev/null
    shasum -a 256 "$TEST_ROOT/${STAGING}.pkg" \
        >"$TEST_ROOT/${STAGING}.pkg.sha256"
    (
        cd "$TEST_ROOT"
        shasum -a 256 -c "${STAGING}.pkg.sha256"
    )
    pkgutil --payload-files "$TEST_ROOT/${STAGING}.pkg" \
        >"$TEST_ROOT/pkg-files.txt"
    grep -q 'usr/local/bin/sendbox' "$TEST_ROOT/pkg-files.txt"
    grep -q 'usr/local/share/sendbox/guest/aarch64/release-public.key' \
        "$TEST_ROOT/pkg-files.txt"

    DMG_ROOT="$TEST_ROOT/SendBox"
    mkdir -p "$DMG_ROOT/guest/aarch64"
    cp "$SENDBOX" "$DMG_ROOT/"
    cp "$ROOT_DIR/README.md" "$ROOT_DIR/LICENSE" "$ROOT_DIR/setup.sh" "$DMG_ROOT/"
    cp -R "$ROOT_DIR/config" "$DMG_ROOT/"
    cp -R "$PAYLOAD/bundle" "$DMG_ROOT/guest/aarch64/"
    cp "$PAYLOAD/release-public.key" "$DMG_ROOT/guest/aarch64/"
    cp "$ROOT_DIR/packaging/release/install-macos.sh" "$DMG_ROOT/install.sh"
    chmod 0755 "$DMG_ROOT/install.sh"
    hdiutil create \
        -volname "SendBox ${VERSION}" \
        -srcfolder "$DMG_ROOT" \
        -ov \
        -format UDZO \
        "$TEST_ROOT/${STAGING}.dmg" >/dev/null
    shasum -a 256 "$TEST_ROOT/${STAGING}.dmg" \
        >"$TEST_ROOT/${STAGING}.dmg.sha256"
    (
        cd "$TEST_ROOT"
        shasum -a 256 -c "${STAGING}.dmg.sha256"
    )
    MOUNT_POINT="$TEST_ROOT/mount"
    mkdir "$MOUNT_POINT"
    MOUNT_DEVICE="$(
        hdiutil attach \
            -readonly \
            -nobrowse \
            -mountpoint "$MOUNT_POINT" \
            "$TEST_ROOT/${STAGING}.dmg" \
            | awk '$1 ~ "^/dev/" { print $1; exit }'
    )"
    test -x "$MOUNT_POINT/sendbox"
    test -x "$MOUNT_POINT/setup.sh"
    test -x "$MOUNT_POINT/install.sh"
    test -x "$MOUNT_POINT/guest/aarch64/bundle/bin/sendbox-guest"
    test -r "$MOUNT_POINT/guest/aarch64/release-public.key"

    INSTALL_ROOT="$TEST_ROOT/install-root"
    INSTALL_OWNER="$(id -u)"
    INSTALL_ENV=(env "SENDBOX_INSTALL_ROOT=$INSTALL_ROOT")
    if sudo -n true 2>/dev/null; then
        INSTALL_USES_SUDO=1
        INSTALL_OWNER=0
    elif [[ "${SENDBOX_REQUIRE_SUDO:-0}" == "1" ]]; then
        echo "passwordless sudo is required for the CI installation smoke" >&2
        exit 1
    else
        INSTALL_ENV+=("SENDBOX_INSTALL_NO_SUDO=1")
    fi
    "${INSTALL_ENV[@]}" "$MOUNT_POINT/install.sh" >/dev/null
    INSTALLED_SHARE="$INSTALL_ROOT/usr/local/share/sendbox"
    test -x "$INSTALL_ROOT/usr/local/bin/sendbox"
    "$INSTALL_ROOT/usr/local/bin/sendbox" --version >/dev/null
    test "$(stat -f '%u' "$INSTALLED_SHARE/guest/aarch64/release-public.key")" \
        = "$INSTALL_OWNER"
    test "$(stat -f '%Lp' "$INSTALLED_SHARE/guest/aarch64/release-public.key")" = 444
    test "$(stat -f '%Lp' "$INSTALLED_SHARE/guest/aarch64/bundle/bin/sendbox-guest")" = 555
    test -r "$INSTALLED_SHARE/guest/aarch64/release-public.key"
    PATH="$INSTALL_ROOT/usr/local/bin:$PATH" \
        SENDBOX_INSTALL_PREFIX="$INSTALL_ROOT/usr/local" \
        "$INSTALLED_SHARE/setup.sh" build \
        </dev/null >"$TEST_ROOT/installed-setup.log"
    grep -q 'Binary already installed at' "$TEST_ROOT/installed-setup.log"
    install_as_root chmod 0400 "$INSTALLED_SHARE/guest/aarch64/release-public.key"
    install_as_root chmod 0600 "$INSTALLED_SHARE/setup.sh"
    printf '\nrollback sentinel\n' \
        | install_as_root tee -a \
            "$INSTALL_ROOT/usr/local/bin/sendbox" \
            "$INSTALLED_SHARE/setup.sh" >/dev/null
    ORIGINAL_BINARY_HASH="$(shasum -a 256 "$INSTALL_ROOT/usr/local/bin/sendbox" | awk '{print $1}')"
    ORIGINAL_SETUP_HASH="$(
        install_as_root shasum -a 256 "$INSTALLED_SHARE/setup.sh" | awk '{print $1}'
    )"
    if install_as_root env \
        SENDBOX_INSTALL_ROOT="$INSTALL_ROOT" \
        SENDBOX_INSTALL_NO_SUDO=1 \
        SENDBOX_INSTALL_TEST_FAIL_BINARY_COMMIT=1 \
        "$MOUNT_POINT/install.sh" >"$TEST_ROOT/forced-install.log" 2>&1; then
        echo "forced binary commit failure unexpectedly succeeded" >&2
        exit 1
    fi
    test "$(shasum -a 256 "$INSTALL_ROOT/usr/local/bin/sendbox" | awk '{print $1}')" \
        = "$ORIGINAL_BINARY_HASH"
    test "$(install_as_root shasum -a 256 "$INSTALLED_SHARE/setup.sh" | awk '{print $1}')" \
        = "$ORIGINAL_SETUP_HASH"
    test "$(stat -f '%Lp' "$INSTALLED_SHARE/setup.sh")" = 600
    test -z "$(find "$INSTALL_ROOT/usr/local" \
        \( -name '.sendbox-install.*' -o -name '*.previous.*' \) -print -quit)"

    install_as_root touch "$INSTALLED_SHARE/stale-file"
    "${INSTALL_ENV[@]}" "$MOUNT_POINT/install.sh" >/dev/null
    test "$(stat -f '%Lp' "$INSTALLED_SHARE/guest/aarch64/release-public.key")" = 444
    test ! -e "$INSTALLED_SHARE/stale-file"

    hdiutil detach "$MOUNT_DEVICE" >/dev/null
    MOUNT_DEVICE=""
else
    (
        cd "$TEST_ROOT"
        tar \
            --sort=name \
            --mtime="@0" \
            --owner=0 \
            --group=0 \
            --numeric-owner \
            -czf "${STAGING}.tar.gz" \
            "$STAGING"
        sha256sum "${STAGING}.tar.gz" >"${STAGING}.tar.gz.sha256"
        sha256sum -c "${STAGING}.tar.gz.sha256"
    )
fi

EXTRACTED="$TEST_ROOT/extracted"
mkdir "$EXTRACTED"
tar -xzf "$TEST_ROOT/${STAGING}.tar.gz" -C "$EXTRACTED"
test -x "$EXTRACTED/$STAGING/sendbox"
test -x "$EXTRACTED/$STAGING/setup.sh"
test -x \
    "$EXTRACTED/$STAGING/guest/$GUEST_ARCHITECTURE/bundle/bin/sendbox-guest"
test -r \
    "$EXTRACTED/$STAGING/guest/$GUEST_ARCHITECTURE/release-public.key"
test ! -e "$EXTRACTED/$STAGING/Package.swift"
test ! -e "$EXTRACTED/$STAGING/Sources"
test ! -e "$EXTRACTED/$STAGING/copilot-bridge"
