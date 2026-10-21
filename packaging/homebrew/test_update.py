import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import update


def formula(version="0.2.1"):
    sections = []
    for platform in update.PLATFORMS:
        digest = hashlib.sha256(("previous-" + platform).encode()).hexdigest()
        sections.append(
            '    url "https://github.com/mbianchidev/sendbox/releases/download/'
            f'v#{{version}}/sendbox-#{{version}}-{platform}.tar.gz"\n'
            f'    sha256 "{digest}"'
        )
    return (
        f'class Sendbox < Formula\n  version "{version}"\n'
        + "\n".join(sections)
        + '\n  def install\n    bin.install "sendbox"\n  end\nend\n'
    )


def published_release(tag="v0.2.2"):
    return {"tag_name": tag, "draft": False, "prerelease": False, "published_at": "2026-01-01T00:00:00Z"}


class FormulaTests(unittest.TestCase):
    def test_only_stable_semver_tags_are_accepted(self):
        self.assertEqual(update.stable_version("v10.20.30"), (10, 20, 30))
        for tag in ("0.2.2", "v0.2", "v0.2.2-rc.1", "v0.2.2+build", "v01.2.3", "v0.2.2\n", "$(id)"):
            with self.subTest(tag=tag), self.assertRaises(update.UpdateError):
                update.stable_version(tag)

    def test_updates_only_version_and_platform_hashes(self):
        checksums = {platform: hashlib.sha256(platform.encode()).hexdigest() for platform in update.PLATFORMS}
        original = formula()
        rendered = update.render_formula(original, "v0.2.2", checksums)
        self.assertIn('  version "0.2.2"', rendered)
        for digest in checksums.values():
            self.assertIn(f'sha256 "{digest}"', rendered)
        self.assertEqual(original.split("  def install")[1], rendered.split("  def install")[1])
        self.assertEqual(rendered.count("#{version}"), 6)
        self.assertEqual(update.render_formula(rendered, "v0.2.2", checksums), rendered)

    def test_missing_or_duplicate_platform_and_version_fail_closed(self):
        original = formula()
        checksums = {platform: hashlib.sha256(platform.encode()).hexdigest() for platform in update.PLATFORMS}
        for invalid in (
            original.replace("macos-arm64", "macos-intel"),
            original + original,
            original.replace('  version "0.2.1"\n', ""),
            original.replace('  version "0.2.1"', '  version "0.2.1-rc.1"'),
        ):
            with self.subTest(formula=invalid), self.assertRaises(update.UpdateError):
                update.render_formula(invalid, "v0.2.2", checksums)

    def test_invalid_hash_is_rejected(self):
        checksums = dict.fromkeys(update.PLATFORMS, "not-a-checksum")
        with self.assertRaisesRegex(update.UpdateError, "invalid SHA-256"):
            update.render_formula(formula(), "v0.2.2", checksums)

    def test_release_must_be_published_stable_and_match_tag(self):
        for invalid in (
            published_release() | {"draft": True},
            published_release() | {"prerelease": True},
            published_release() | {"published_at": None},
            published_release("v0.2.1"),
            {"tag_name": "v0.2.2", "published_at": "2026-01-01"},
        ):
            with self.subTest(release=invalid), self.assertRaises(update.UpdateError):
                update.validate_release(invalid, "v0.2.2")


class AssetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.destination = Path(self.temporary.name)
        self.release = published_release() | {"assets": []}
        self.checksums = {}
        for platform in update.PLATFORMS:
            name = f"sendbox-0.2.2-{platform}.tar.gz"
            payload = ("mock artifact for " + platform).encode()
            digest = hashlib.sha256(payload).hexdigest()
            self.checksums[platform] = digest
            for filename, content in (
                (name, payload),
                (name + ".sha256", f"{digest}  {name}\n".encode()),
            ):
                (self.destination / filename).write_bytes(content)
                self.release["assets"].append({
                    "name": filename,
                    "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
                    "size": len(content),
                    "browser_download_url": (
                        "https://github.com/mbianchidev/sendbox/releases/download/v0.2.2/" + filename
                    ),
                })

    def verify(self):
        return update.verified_checksums(self.release, "v0.2.2", self.destination)

    @patch("update.subprocess.run")
    def test_verifies_every_archive_checksum_and_attestation(self, run):
        self.assertEqual(self.verify(), self.checksums)
        self.assertEqual(run.call_count, 4)
        download = run.call_args_list[0].args[0]
        self.assertEqual(download.count("--pattern"), 6)
        for call in run.call_args_list[1:]:
            command = call.args[0]
            self.assertIn("--deny-self-hosted-runners", command)
            self.assertEqual(command[command.index("--source-ref") + 1], "refs/tags/v0.2.2")
            self.assertEqual(
                command[command.index("--signer-workflow") + 1],
                "mbianchidev/sendbox/.github/workflows/release.yaml",
            )

    @patch("update.subprocess.run")
    def test_modified_download_is_rejected(self, run):
        archive = self.destination / "sendbox-0.2.2-macos-arm64.tar.gz"
        archive.write_bytes(b"corrupted mock artifact")
        with self.assertRaisesRegex(update.UpdateError, "digest mismatch"):
            self.verify()
        self.assertEqual(run.call_count, 1)

    @patch("update.subprocess.run")
    def test_adjacent_checksum_cannot_name_another_file(self, run):
        name = "sendbox-0.2.2-macos-arm64.tar.gz.sha256"
        content = f'{self.checksums["macos-arm64"]}  another-file\n'.encode()
        (self.destination / name).write_bytes(content)
        next(asset for asset in self.release["assets"] if asset["name"] == name)["digest"] = (
            "sha256:" + hashlib.sha256(content).hexdigest()
        )
        with self.assertRaisesRegex(update.UpdateError, "adjacent checksum mismatch"):
            self.verify()

    @patch("update.subprocess.run")
    def test_missing_duplicate_or_unidentified_assets_are_rejected_before_download(self, run):
        original = self.release["assets"].copy()
        for assets in (
            original[1:],
            original + [original[0]],
            [original[0] | {"digest": None}] + original[1:],
            [original[0] | {"browser_download_url": "https://example.invalid/asset"}] + original[1:],
        ):
            self.release["assets"] = assets
            with self.subTest(assets=assets), self.assertRaises(update.UpdateError):
                self.verify()
        run.assert_not_called()

    @patch("update.subprocess.run", side_effect=subprocess.CalledProcessError(1, "gh"))
    def test_download_failure_is_not_hidden(self, run):
        with self.assertRaises(subprocess.CalledProcessError):
            self.verify()


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.tap = Path(self.temporary.name)
        (self.tap / "Formula").mkdir()
        self.path = self.tap / "Formula/sendbox.rb"
        self.original = formula("0.2.2")
        self.path.write_text(self.original)
        (self.tap / "Formula/another-package.rb").write_text("preserve other packages\n")
        self.checksums = {platform: hashlib.sha256(platform.encode()).hexdigest() for platform in update.PLATFORMS}
        self.api = patch("update.github_json", return_value=published_release("v0.2.3")).start()
        self.addCleanup(patch.stopall)
        self.verify = patch("update.verified_checksums", return_value=self.checksums).start()

    def test_update_is_atomic_and_preserves_other_packages(self):
        result = update.prepare_update(self.tap, "v0.2.3")
        self.assertTrue(result["updated"])
        self.assertEqual(result["branch"], "automation/sendbox-v0.2.3")
        self.assertIn('version "0.2.3"', self.path.read_text())
        self.assertEqual((self.tap / "Formula/another-package.rb").read_text(), "preserve other packages\n")
        self.assertEqual(sorted(path.name for path in self.path.parent.iterdir()), ["another-package.rb", "sendbox.rb"])
        self.assertFalse(update.prepare_update(self.tap, "v0.2.3")["updated"])

    def test_obsolete_release_cannot_replace_latest_stable(self):
        self.api.side_effect = [published_release("v0.2.3"), published_release("v0.2.4")]
        self.assertFalse(update.prepare_update(self.tap, "v0.2.3")["updated"])
        self.verify.assert_not_called()
        self.assertEqual(self.path.read_text(), self.original)

    def test_never_downgrades_a_newer_formula(self):
        self.path.write_text(formula("1.0.0"))
        self.assertFalse(update.prepare_update(self.tap, "v0.2.3")["updated"])
        self.verify.assert_not_called()
        self.assertEqual(update.formula_version(self.path.read_text()), (1, 0, 0))

    def test_prerelease_is_rejected_before_api_calls(self):
        with self.assertRaises(update.UpdateError):
            update.prepare_update(self.tap, "v0.3.0-rc.1")
        self.api.assert_not_called()
        self.verify.assert_not_called()

    def test_known_affected_stable_releases_cannot_activate(self):
        for tag in ("v0.0.2", "v0.1.0", "v0.2.1", "v0.2.2"):
            with self.subTest(tag=tag), self.assertRaisesRegex(update.UpdateError, "patched stable"):
                update.prepare_update(self.tap, tag)
        self.api.assert_not_called()
        self.verify.assert_not_called()
        self.assertEqual(self.path.read_text(), self.original)

    def test_flagged_prerelease_is_rejected_even_with_stable_tag(self):
        self.api.return_value = published_release("v0.2.3") | {"prerelease": True}
        with self.assertRaises(update.UpdateError):
            update.prepare_update(self.tap, "v0.2.3")
        self.verify.assert_not_called()
        self.assertEqual(self.path.read_text(), self.original)

    def test_failed_attestation_leaves_formula_unchanged(self):
        self.verify.side_effect = subprocess.CalledProcessError(1, "gh attestation verify")
        with self.assertRaises(subprocess.CalledProcessError):
            update.prepare_update(self.tap, "v0.2.3")
        self.assertEqual(self.path.read_text(), self.original)

    def test_new_stable_during_verification_leaves_formula_unchanged(self):
        self.api.side_effect = [
            published_release("v0.2.3"), published_release("v0.2.3"), published_release("v0.2.4")
        ]
        self.assertFalse(update.prepare_update(self.tap, "v0.2.3")["updated"])
        self.assertEqual(self.path.read_text(), self.original)

    def test_concurrent_formula_edits_are_not_overwritten(self):
        changed = self.original + "# concurrent maintainer edit\n"

        def verify(*_):
            self.path.write_text(changed)
            return self.checksums

        self.verify.side_effect = verify
        with self.assertRaisesRegex(update.UpdateError, "formula changed"):
            update.prepare_update(self.tap, "v0.2.3")
        self.assertEqual(self.path.read_text(), changed)

    def test_missing_formula_requires_bootstrap_not_placeholder(self):
        self.path.unlink()
        with self.assertRaisesRegex(update.UpdateError, "bootstrap PR"):
            update.prepare_update(self.tap, "v0.2.3")
        self.verify.assert_not_called()

    def test_symlink_formula_is_rejected(self):
        other = self.tap / "Formula/another-package.rb"
        self.path.unlink()
        self.path.symlink_to(other)
        with self.assertRaisesRegex(update.UpdateError, "regular file"):
            update.prepare_update(self.tap, "v0.2.3")
        self.assertEqual(other.read_text(), "preserve other packages\n")


if __name__ == "__main__":
    unittest.main()
