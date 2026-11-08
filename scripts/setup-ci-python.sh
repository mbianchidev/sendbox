#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'ci-python: %s\n' "$*" >&2
    exit 1
}

if [[ $# -ne 1 ]]; then
    printf 'Usage: %s VERSION\n' "${0##*/}" >&2
    exit 2
fi
VERSION="$1"
[[ "$VERSION" == 3.15.1 ]] || fail "update the pinned assets before using Python $VERSION"
[[ "${GITHUB_ACTIONS:-}" == true && -n "${RUNNER_TOOL_CACHE:-}" && -n "${RUNNER_TEMP:-}" ]] \
    || fail "the GitHub Actions tool-cache environment is required"

PLATFORM="$(uname -s):$(uname -m)"
CHECKSUM_COMMAND=(sha256sum --check)
case "$PLATFORM" in
    Darwin:arm64)
        ARCH=arm64
        ASSET_ID=662872898
        SHA256=e1a49acab28b4a180ee9819663f9e01d0e56ed49f78b1e370dedea8863301a3a
        CHECKSUM_COMMAND=(shasum -a 256 --check)
        ;;
    Linux:x86_64)
        ARCH=x64
        [[ "$(lsb_release -is)" == Ubuntu ]] || fail "only Ubuntu Linux assets are configured"
        DISTRIBUTION_VERSION="$(lsb_release -rs)"
        case "$DISTRIBUTION_VERSION" in
            22.04)
                ASSET_ID=662873037
                SHA256=d5089a4a7ab6cea9664fb26cdae5c6379f880edc368a5be81999455c25cda556
                ;;
            24.04)
                ASSET_ID=662872932
                SHA256=9809d583ffee9af685f33c8746da541d7102c30a7baa7aacf0a30a1f04731a56
                ;;
            26.04)
                ASSET_ID=662873040
                SHA256=0aa6f845c6f40c4a88a99e92a46374889ab9170fde378f1168e2e936b34d1218
                ;;
            *) fail "no pinned Python asset is configured for Ubuntu $DISTRIBUTION_VERSION" ;;
        esac
        ;;
    *) fail "no pinned Python asset is configured for $PLATFORM" ;;
esac

cache="$RUNNER_TOOL_CACHE/Python/$VERSION/$ARCH"
if [[ -f "$cache.complete" ]]; then
    printf 'Python %s (%s) is already cached\n' "$VERSION" "$ARCH"
else
    directory="$(mktemp -d "$RUNNER_TEMP/python-api.XXXXXX")"
    trap 'rm -rf "$directory"' EXIT
    archive="$directory/python.tar.gz"
    curl -fsSL --retry 5 --retry-max-time 600 --connect-timeout 10 --max-time 600 \
        --header 'Accept: application/octet-stream' \
        "https://api.github.com/repos/actions/python-versions/releases/assets/$ASSET_ID" \
        --output "$archive"
    printf '%s  %s\n' "$SHA256" "$archive" | "${CHECKSUM_COMMAND[@]}"
    tar -xzf "$archive" -C "$directory"
    rm "$archive"
    cd "$directory"
    if [[ "$PLATFORM" == Linux:* ]]; then
        export LD_LIBRARY_PATH="$directory/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    fi
    AGENT_TOOLSDIRECTORY="$RUNNER_TOOL_CACHE" bash ./setup.sh
fi

installed_version="$("$cache/bin/python3" --version)"
[[ "$installed_version" == "Python $VERSION" ]] \
    || fail "cached version $installed_version does not match Python $VERSION"
printf 'Using %s (%s)\n' "$installed_version" "$ARCH"
