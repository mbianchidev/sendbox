#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
INSTALL_ROOT="${SENDBOX_INSTALL_ROOT:-}"
INSTALL_NO_SUDO="${SENDBOX_INSTALL_NO_SUDO:-0}"
STAGING=""
BINARY_STAGING=""
SHARE_BACKUP=""
BINARY_BACKUP=""
SHARE_ROOT=""
BINARY_PATH=""
SHARE_OLD_MOVED=0
BINARY_OLD_MOVED=0
SHARE_NEW_MOVED=0
BINARY_NEW_MOVED=0
INSTALL_COMPLETE=0

case "$INSTALL_ROOT" in
    "" | /*) ;;
    *)
        echo "SENDBOX_INSTALL_ROOT must be absolute" >&2
        exit 2
        ;;
esac
case "$INSTALL_NO_SUDO" in
    0 | 1) ;;
    *)
        echo "SENDBOX_INSTALL_NO_SUDO must be 0 or 1" >&2
        exit 2
        ;;
esac
if [[ "$INSTALL_NO_SUDO" == "1" && -z "$INSTALL_ROOT" ]]; then
    echo "SENDBOX_INSTALL_NO_SUDO requires SENDBOX_INSTALL_ROOT" >&2
    exit 2
fi
INSTALL_UID=0
INSTALL_GID=0
if [[ "$INSTALL_NO_SUDO" == "1" ]]; then
    INSTALL_UID="$(id -u)"
    INSTALL_GID="$(id -g)"
fi

as_root() {
    if [[ "$(id -u)" -eq 0 || "$INSTALL_NO_SUDO" == "1" ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

cleanup() {
    if [[ -n "$STAGING" ]]; then
        as_root rm -rf "$STAGING"
    fi
    if [[ -n "$BINARY_STAGING" ]]; then
        as_root rm -f "$BINARY_STAGING"
    fi
    if [[ "$INSTALL_COMPLETE" == "0" ]]; then
        if [[ "$SHARE_NEW_MOVED" == "1" && ( -e "$SHARE_ROOT" || -L "$SHARE_ROOT" ) ]]; then
            as_root rm -rf "$SHARE_ROOT"
        fi
        if [[ "$SHARE_OLD_MOVED" == "1" && ( -e "$SHARE_BACKUP" || -L "$SHARE_BACKUP" ) ]]; then
            as_root mv "$SHARE_BACKUP" "$SHARE_ROOT"
        fi
        if [[ "$BINARY_NEW_MOVED" == "1" && ( -e "$BINARY_PATH" || -L "$BINARY_PATH" ) ]]; then
            as_root rm -f "$BINARY_PATH"
        fi
        if [[ "$BINARY_OLD_MOVED" == "1" && ( -e "$BINARY_BACKUP" || -L "$BINARY_BACKUP" ) ]]; then
            as_root mv "$BINARY_BACKUP" "$BINARY_PATH"
        fi
    else
        if [[ -n "$SHARE_BACKUP" && ( -e "$SHARE_BACKUP" || -L "$SHARE_BACKUP" ) ]]; then
            as_root rm -rf "$SHARE_BACKUP"
        fi
        if [[ -n "$BINARY_BACKUP" && ( -e "$BINARY_BACKUP" || -L "$BINARY_BACKUP" ) ]]; then
            as_root rm -f "$BINARY_BACKUP"
        fi
    fi
}
trap cleanup EXIT HUP INT TERM

for required in sendbox setup.sh config guest; do
    if [[ ! -e "$SOURCE_DIR/$required" ]]; then
        echo "missing installer payload: $required" >&2
        exit 1
    fi
done

PREFIX="$INSTALL_ROOT/usr/local"
SHARE_PARENT="$PREFIX/share"
SHARE_ROOT="$SHARE_PARENT/sendbox"
BINARY_PATH="$PREFIX/bin/sendbox"

as_root install -d -m 0755 "$PREFIX/bin" "$SHARE_PARENT"
STAGING="$(as_root mktemp -d "$SHARE_PARENT/.sendbox-install.XXXXXX")"
BINARY_STAGING="$(as_root mktemp "$PREFIX/bin/.sendbox-install.XXXXXX")"
as_root install -d -m 0755 "$STAGING"
as_root cp -R "$SOURCE_DIR/config" "$SOURCE_DIR/guest" "$STAGING/"
as_root install -m 0755 "$SOURCE_DIR/setup.sh" "$STAGING/setup.sh"
if [[ -f "$SOURCE_DIR/README.md" ]]; then
    as_root install -m 0444 "$SOURCE_DIR/README.md" "$STAGING/README.md"
fi
if [[ -f "$SOURCE_DIR/LICENSE" ]]; then
    as_root install -m 0444 "$SOURCE_DIR/LICENSE" "$STAGING/LICENSE"
fi

as_root chown -R "$INSTALL_UID:$INSTALL_GID" "$STAGING"
as_root find "$STAGING" -type d -exec chmod 0755 {} +
as_root find "$STAGING" -type f -exec chmod 0444 {} +
as_root chmod 0755 "$STAGING/setup.sh"
as_root find "$STAGING/guest" -type f -path '*/bundle/bin/*' -exec chmod 0555 {} +
as_root install -m 0755 "$SOURCE_DIR/sendbox" "$BINARY_STAGING"
as_root chown "$INSTALL_UID:$INSTALL_GID" "$BINARY_STAGING"

if [[ -L "$SHARE_ROOT" ]]; then
    echo "refusing to replace symlinked install root: $SHARE_ROOT" >&2
    exit 1
fi
if [[ -L "$BINARY_PATH" ]]; then
    echo "refusing to replace symlinked binary: $BINARY_PATH" >&2
    exit 1
fi
if [[ -e "$SHARE_ROOT" ]]; then
    SHARE_BACKUP="${SHARE_ROOT}.previous.$$"
    if [[ -e "$SHARE_BACKUP" || -L "$SHARE_BACKUP" ]]; then
        echo "installer backup path already exists: $SHARE_BACKUP" >&2
        exit 1
    fi
fi
if [[ -e "$BINARY_PATH" ]]; then
    BINARY_BACKUP="${BINARY_PATH}.previous.$$"
    if [[ -e "$BINARY_BACKUP" || -L "$BINARY_BACKUP" ]]; then
        echo "installer backup path already exists: $BINARY_BACKUP" >&2
        exit 1
    fi
fi

trap '' HUP INT TERM
if [[ -n "$SHARE_BACKUP" ]]; then
    if ! as_root mv "$SHARE_ROOT" "$SHARE_BACKUP"; then
        exit 1
    fi
    SHARE_OLD_MOVED=1
fi
if [[ -n "$BINARY_BACKUP" ]]; then
    if ! as_root mv "$BINARY_PATH" "$BINARY_BACKUP"; then
        exit 1
    fi
    BINARY_OLD_MOVED=1
fi
if ! as_root mv "$STAGING" "$SHARE_ROOT"; then
    exit 1
fi
STAGING=""
SHARE_NEW_MOVED=1
if [[ "${SENDBOX_INSTALL_TEST_FAIL_BINARY_COMMIT:-0}" == "1" ]]; then
    if [[ -z "$INSTALL_ROOT" ]]; then
        echo "the binary commit failure hook requires a redirected test install" >&2
        exit 2
    fi
    echo "forced binary commit failure" >&2
    exit 1
fi
if ! as_root mv "$BINARY_STAGING" "$BINARY_PATH"; then
    exit 1
fi
BINARY_STAGING=""
BINARY_NEW_MOVED=1
INSTALL_COMPLETE=1
trap cleanup EXIT HUP INT TERM
cleanup
SHARE_BACKUP=""
BINARY_BACKUP=""

as_root xattr -dr com.apple.quarantine "$BINARY_PATH" 2>/dev/null || true

echo "SendBox installed to $PREFIX/bin/sendbox"
