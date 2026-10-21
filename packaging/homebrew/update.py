#!/usr/bin/env python3
"""Prepare a tap formula update using verified, published stable artifacts."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


REPOSITORY = "mbianchidev/sendbox"
PLATFORMS = ("macos-arm64", "linux-x86_64", "linux-aarch64")
STABLE_VERSION = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
FORMULA_VERSION = re.compile(r'^  version "(' + STABLE_VERSION + r')"$', re.MULTILINE)


class UpdateError(Exception):
    """A release or formula does not satisfy the publication contract."""


def stable_version(tag):
    if re.fullmatch("v" + STABLE_VERSION, tag) is None:
        raise UpdateError(f"expected a stable vX.Y.Z tag, got {tag!r}")
    return tuple(map(int, tag[1:].split(".")))


def github_json(endpoint):
    result = subprocess.run(
        ["gh", "api", "--hostname", "github.com", endpoint],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return json.loads(result.stdout)


def validate_release(release, tag):
    if (
        release.get("tag_name") != tag
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or not release.get("published_at")
    ):
        raise UpdateError(f"{tag} is not a published stable release")


def formula_version(formula):
    matches = list(FORMULA_VERSION.finditer(formula))
    if len(matches) != 1:
        raise UpdateError("expected exactly one stable formula version")
    return stable_version("v" + matches[0].group(1))


def render_formula(formula, tag, checksums):
    stable_version(tag)
    formula_version(formula)
    updated = FORMULA_VERSION.sub(f'  version "{tag[1:]}"', formula)
    for platform in PLATFORMS:
        digest = checksums[platform]
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise UpdateError(f"invalid SHA-256 for {platform}")
        url = (
            f"https://github.com/{REPOSITORY}/releases/download/"
            "v#{version}/sendbox-#{version}-" + platform + ".tar.gz"
        )
        pattern = re.compile(
            r'(^[ \t]*url "' + re.escape(url) + r'"\n[ \t]*sha256 ")[0-9a-f]{64}("$)',
            re.MULTILINE,
        )
        updated, count = pattern.subn(lambda match: match[1] + digest + match[2], updated)
        if count != 1:
            raise UpdateError(f"expected exactly one canonical {platform} URL/checksum pair")
    return updated


def asset_digest(assets, name, tag):
    matches = [asset for asset in assets if asset.get("name") == name]
    if len(matches) != 1:
        raise UpdateError(f"expected exactly one published asset named {name}")
    asset = matches[0]
    expected_url = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"
    digest = asset.get("digest", "")
    if (
        asset.get("browser_download_url") != expected_url
        or not isinstance(digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        or not isinstance(asset.get("size"), int)
        or asset["size"] <= 0
    ):
        raise UpdateError(f"missing or invalid published asset identity for {name}")
    return digest.removeprefix("sha256:")


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verified_checksums(release, tag, destination):
    assets = release.get("assets", [])
    command = ["gh", "release", "download", tag, "--repo", REPOSITORY, "--dir", str(destination)]
    expected = {}
    for platform in PLATFORMS:
        name = f"sendbox-{tag[1:]}-{platform}.tar.gz"
        for filename in (name, name + ".sha256"):
            expected[filename] = asset_digest(assets, filename, tag)
            command.extend(["--pattern", filename])
    subprocess.run(command, check=True, stdout=sys.stderr)

    checksums = {}
    for platform in PLATFORMS:
        name = f"sendbox-{tag[1:]}-{platform}.tar.gz"
        archive = destination / name
        checksum = destination / (name + ".sha256")
        for path in (archive, checksum):
            if file_digest(path) != expected[path.name]:
                raise UpdateError(f"GitHub asset digest mismatch for {path.name}")
        match = re.fullmatch(
            r"([0-9a-f]{64}) [ *]" + re.escape(name) + r"\n?",
            checksum.read_text(encoding="utf-8"),
        )
        if match is None or match[1] != expected[name]:
            raise UpdateError(f"adjacent checksum mismatch for {name}")
        subprocess.run(
            [
                "gh", "attestation", "verify", str(archive),
                "--repo", REPOSITORY,
                "--signer-workflow", f"{REPOSITORY}/.github/workflows/release.yaml",
                "--source-ref", f"refs/tags/{tag}",
                "--deny-self-hosted-runners",
            ],
            check=True,
            stdout=sys.stderr,
        )
        checksums[platform] = expected[name]
    return checksums


def prepare_update(tap, tag):
    requested_version = stable_version(tag)
    release = github_json(f"repos/{REPOSITORY}/releases/tags/{tag}")
    validate_release(release, tag)
    latest = github_json(f"repos/{REPOSITORY}/releases/latest")
    latest_tag = latest.get("tag_name", "")
    stable_version(latest_tag)
    validate_release(latest, latest_tag)
    result = {"updated": False, "version": tag[1:], "branch": f"automation/sendbox-{tag}"}
    if latest_tag != tag:
        return result | {"reason": f"{tag} is not the latest stable release ({latest_tag})"}

    path = tap / "Formula/sendbox.rb"
    if path.is_symlink() or not path.is_file():
        raise UpdateError("Formula/sendbox.rb must exist as a regular file; merge the tap bootstrap PR first")
    original = path.read_text(encoding="utf-8")
    if requested_version < formula_version(original):
        return result | {"reason": "refusing to downgrade the formula"}

    with tempfile.TemporaryDirectory(prefix="sendbox-homebrew-") as directory:
        checksums = verified_checksums(release, tag, Path(directory))
    updated = render_formula(original, tag, checksums)
    if updated == original:
        return result | {"reason": "formula already matches the verified stable release"}

    # Recheck after verification so a newly published stable cannot be overwritten.
    if github_json(f"repos/{REPOSITORY}/releases/latest").get("tag_name") != tag:
        return result | {"reason": "a newer stable release appeared during verification"}
    if path.is_symlink() or path.read_text(encoding="utf-8") != original:
        raise UpdateError("formula changed during verification; retry from a clean checkout")

    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", prefix=".sendbox-", dir=path.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(updated)
        temporary.chmod(path.stat().st_mode & 0o777)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return result | {"updated": True, "reason": "all release checksums and provenance verified"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="Published stable tag, for example v0.2.2")
    parser.add_argument("--tap", required=True, type=Path, help="Clean checkout of mbianchidev/homebrew-tap")
    arguments = parser.parse_args()
    try:
        result = prepare_update(arguments.tap, arguments.tag)
    except (UpdateError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"homebrew update: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
