#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf 'Usage: %s VERSION\nMerge a version-bump PR, push its release tag, and watch publishing.\n' \
        "${0##*/}"
}

fail() {
    printf 'release: %s\n' "$*" >&2
    exit 1
}

if [[ $# -eq 1 && ( "$1" == --help || "$1" == -h ) ]]; then
    usage
    exit 0
fi
if [[ $# -ne 1 ]]; then
    usage >&2
    exit 2
fi

VERSION="${1#v}"
if [[ ! "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    printf 'release: version must be X.Y.Z (for example, 0.2.0)\n' >&2
    exit 2
fi

for tool in git cargo gh python3; do
    command -v "$tool" >/dev/null || fail "required command not found: $tool"
done
python3 -c 'import tomllib' || fail "Python 3.11 or newer is required"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
REPOSITORY="mbianchidev/sendbox"
TAG="v$VERSION"
BRANCH="release/$TAG"
TEMP_DIR=""
WORKTREE=""

workspace_version() {
    python3 -c 'import sys, tomllib; print(tomllib.loads(sys.stdin.read())["workspace"]["package"]["version"])'
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ -n "$TEMP_DIR" ]]; then
        if [[ -d "$WORKTREE" ]] && ! git -C "$ROOT_DIR" worktree remove "$WORKTREE"; then
            printf 'release: worktree retained for recovery: %s\n' "$WORKTREE" >&2
            if [[ "$status" -eq 0 ]]; then
                status=1
            fi
        elif ! rmdir "$TEMP_DIR"; then
            printf 'release: could not remove temporary directory: %s\n' "$TEMP_DIR" >&2
            status=1
        fi
    fi
    if [[ "$status" -ne 0 ]]; then
        printf 'release: stopped; any created branch, PR, or tag is kept. Inspect it before retrying.\n' >&2
    fi
    exit "$status"
}

cd "$ROOT_DIR"
[[ -z "$(git status --porcelain --untracked-files=all)" ]] \
    || fail "a clean checkout is required; commit or stash your changes first"
gh auth status --hostname github.com >/dev/null
ORIGIN="$(git remote get-url origin)"
ORIGIN_REPOSITORY="$(gh repo view "$ORIGIN" --json nameWithOwner --jq '.nameWithOwner')"
[[ "$ORIGIN_REPOSITORY" == "$REPOSITORY" ]] \
    || fail "origin must point to $REPOSITORY, not $ORIGIN_REPOSITORY"
PUSH_ORIGIN="$(git remote get-url --push --all origin)"
[[ "$PUSH_ORIGIN" != *$'\n'* ]] || fail "origin must have exactly one push URL"
if [[ "$PUSH_ORIGIN" != "$ORIGIN" ]]; then
    PUSH_REPOSITORY="$(gh repo view "$PUSH_ORIGIN" --json nameWithOwner --jq '.nameWithOwner')"
    [[ "$PUSH_REPOSITORY" == "$REPOSITORY" ]] \
        || fail "origin's push URL must point to $REPOSITORY"
fi

EXISTING_LOCAL="$(git for-each-ref --format='%(refname)' "refs/tags/$TAG" "refs/heads/$BRANCH")"
EXISTING_REMOTE="$(git ls-remote origin "refs/tags/$TAG" "refs/heads/$BRANCH")"
[[ -z "$EXISTING_LOCAL" && -z "$EXISTING_REMOTE" ]] \
    || fail "$TAG or $BRANCH already exists; inspect the previous release attempt"
git fetch --no-tags origin refs/heads/main:refs/remotes/origin/main
CURRENT_VERSION="$(git show origin/main:Cargo.toml | workspace_version)"
python3 - "$CURRENT_VERSION" "$VERSION" <<'PY'
import re
import sys

current, requested = sys.argv[1:]
if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", current):
    sys.exit(f"release: main's Cargo version is not X.Y.Z: {current}")
if tuple(map(int, requested.split("."))) <= tuple(map(int, current.split("."))):
    sys.exit(f"release: version must be greater than main's Cargo version {current}")
PY

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sendbox-release.XXXXXX")"
WORKTREE="$TEMP_DIR/checkout"
git worktree add -b "$BRANCH" "$WORKTREE" origin/main
cd "$WORKTREE"

python3 - "$VERSION" <<'PY'
from pathlib import Path
import re
import sys
import tomllib

version = sys.argv[1]
manifest = Path("Cargo.toml")
text = manifest.read_text(encoding="utf-8")
current = tomllib.loads(text)["workspace"]["package"]["version"]
section = re.search(r"(?ms)^\[workspace\.package\][ \t]*(?:#[^\n]*)?\n.*?(?=^\[|\Z)", text)
if section is None:
    sys.exit("release: [workspace.package] section not found")
replacement, count = re.subn(
    r'(?m)^([ \t]*version[ \t]*=[ \t]*)"' + re.escape(current) + r'"',
    r'\g<1>"' + version + '"',
    section.group(),
)
if count != 1:
    sys.exit("release: expected one [workspace.package].version entry")

tests = Path("crates/sendbox-cli/tests/cli.rs")
test_text = tests.read_text(encoding="utf-8")
expected = f'"sendbox {current}\\n"'
if test_text.count(expected) != 1:
    sys.exit("release: expected one CLI version assertion matching the Cargo version")

manifest.write_text(text[:section.start()] + replacement + text[section.end():], encoding="utf-8")
tests.write_text(test_text.replace(expected, f'"sendbox {version}\\n"'), encoding="utf-8")
PY

FILES=(Cargo.toml crates/sendbox-cli/tests/cli.rs)
git ls-files --error-unmatch Cargo.lock >/dev/null
while IFS= read -r -d '' lockfile; do
    manifest="${lockfile%Cargo.lock}Cargo.toml"
    [[ -f "$manifest" ]] || fail "manifest not found for $lockfile"
    cargo update --workspace --manifest-path "$manifest"
    cargo metadata --locked --format-version 1 --manifest-path "$manifest" >/dev/null
    FILES+=("$lockfile")
done < <(git ls-files -z -- 'Cargo.lock' '*/Cargo.lock')
CLI_VERSION="$(
    cargo metadata --locked --no-deps --format-version 1 \
        | python3 -c 'import json, sys; packages = json.load(sys.stdin)["packages"]; print(next(p["version"] for p in packages if p["name"] == "sendbox-cli"))'
)"
[[ "$CLI_VERSION" == "$VERSION" ]] \
    || fail "sendbox-cli version $CLI_VERSION does not match $TAG"

git add -- "${FILES[@]}"
git diff --cached --check
git commit --no-gpg-sign -m "Bump version to $VERSION"
HEAD_COMMIT="$(git rev-parse HEAD)"
git push --set-upstream origin "$BRANCH"
PR_URL="$(
    gh pr create --repo "$REPOSITORY" --base main --head "$BRANCH" \
        --title "Release $TAG" \
        --body "Bump the workspace and CLI version to $VERSION and refresh all committed Cargo lockfiles.

After CI passes, scripts/release.sh merges this PR and tags its merged main commit. The tag-triggered Release workflow publishes GitHub assets and GHCR artifacts."
)"
printf 'Version-bump PR: %s\n' "$PR_URL"

CHECK_COUNT=0
for attempt in {1..60}; do
    CHECK_COUNT="$(gh pr view "$PR_URL" --repo "$REPOSITORY" \
        --json statusCheckRollup --jq '.statusCheckRollup | length')"
    [[ "$CHECK_COUNT" =~ ^[0-9]+$ ]] || fail "could not read PR checks"
    if [[ "$CHECK_COUNT" -gt 0 ]]; then
        break
    fi
    sleep 10
done
[[ "$CHECK_COUNT" -gt 0 ]] || fail "no PR checks appeared within 10 minutes; the PR is left open"
gh pr checks "$PR_URL" --repo "$REPOSITORY" --watch --fail-fast --interval 10
CHECKED_HEAD="$(gh pr view "$PR_URL" --repo "$REPOSITORY" --json headRefOid --jq '.headRefOid')"
[[ "$CHECKED_HEAD" == "$HEAD_COMMIT" ]] || fail "PR head changed while waiting for CI; refusing to merge"
gh pr merge "$PR_URL" --repo "$REPOSITORY" --squash --match-head-commit "$HEAD_COMMIT"

STATE=""
MERGE_COMMIT=""
for attempt in {1..60}; do
    DETAILS="$(gh pr view "$PR_URL" --repo "$REPOSITORY" \
        --json state,headRefOid,mergeCommit \
        --jq '[.state, .headRefOid, (.mergeCommit.oid // "")] | @tsv')"
    IFS=$'\t' read -r STATE MERGED_HEAD MERGE_COMMIT <<<"$DETAILS"
    [[ "$MERGED_HEAD" == "$HEAD_COMMIT" ]] || fail "PR head changed before merging; refusing to tag"
    case "$STATE" in
        MERGED) break ;;
        OPEN) sleep 10 ;;
        *) fail "PR is not open or merged: $STATE" ;;
    esac
done
[[ "$STATE" == MERGED && -n "$MERGE_COMMIT" ]] \
    || fail "PR did not merge within 10 minutes; refusing to tag"

git fetch --no-tags origin refs/heads/main:refs/remotes/origin/main
git merge-base --is-ancestor "$MERGE_COMMIT" origin/main \
    || fail "PR merge commit is not on origin/main"
MERGED_VERSION="$(git show "$MERGE_COMMIT:Cargo.toml" | workspace_version)"
[[ "$MERGED_VERSION" == "$VERSION" ]] \
    || fail "merged Cargo version $MERGED_VERSION does not match $TAG"
git -c tag.gpgSign=false tag -a "$TAG" "$MERGE_COMMIT" -m "Release $TAG"
git push origin "$TAG"

RUN_ID=""
for attempt in {1..60}; do
    RUN_ID="$(gh run list --repo "$REPOSITORY" --workflow release.yaml \
        --event push --branch "$TAG" --commit "$MERGE_COMMIT" --limit 1 \
        --json databaseId --jq '.[0].databaseId // empty')"
    if [[ -n "$RUN_ID" ]]; then
        break
    fi
    sleep 10
done
[[ -n "$RUN_ID" ]] \
    || fail "Release workflow did not appear within 10 minutes; $TAG is already pushed"
gh run watch "$RUN_ID" --repo "$REPOSITORY" --exit-status --interval 10
gh release view "$TAG" --repo "$REPOSITORY" --json url --jq '.url'
