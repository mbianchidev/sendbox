import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERSION = "0.2.0"
TAG = f"v{VERSION}"
BRANCH = f"release/{TAG}"
PR_URL = "https://github.com/mbianchidev/sendbox/pull/1"

MOCK_TOOL = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
state_path = Path(os.environ["RELEASE_TEST_STATE"])
state = json.loads(state_path.read_text())
with Path(os.environ["RELEASE_TEST_LOG"]).open("a") as log:
    log.write(json.dumps([tool, *args]) + "\n")

def finish(output="", status=0):
    state_path.write_text(json.dumps(state))
    if output:
        print(output, file=sys.stderr if status else sys.stdout)
    sys.exit(status)

def remote_git(*arguments):
    return subprocess.check_output(
        ["git", "--git-dir", os.environ["RELEASE_TEST_REMOTE"], *arguments], text=True
    ).strip()

if tool == "sleep":
    finish()
if tool == "cargo":
    manifest = Path(args[args.index("--manifest-path") + 1]) if "--manifest-path" in args else Path("Cargo.toml")
    version = tomllib.loads(manifest.read_text())["workspace"]["package"]["version"]
    if args[0] == "update":
        if state.get("fail_cargo"):
            finish("mock Cargo update failed", 1)
        manifest.with_name("Cargo.lock").write_text(
            f'version = 4\n[[package]]\nname = "sendbox-cli"\nversion = "{version}"\n'
        )
        finish()
    if args[0] == "metadata":
        finish(json.dumps({"packages": [{"name": "sendbox-cli", "version": version}]}))
if tool == "gh":
    command = args[:2]
    if command == ["auth", "status"]:
        finish()
    if command == ["repo", "view"]:
        finish("mbianchidev/sendbox")
    if command == ["pr", "list"]:
        prs = state.get("prs", [])
        if len(prs) > 1:
            finish("multiple release PRs; inspect the previous release attempts", 1)
        if prs:
            pr = prs[0]
            finish("\t".join([
                pr["url"], pr["state"], pr["headRefOid"],
                str(pr.get("isCrossRepository", False)).lower(),
                pr.get("mergeCommit", ""),
            ]))
        finish()
    if command == ["pr", "create"]:
        branch = args[args.index("--head") + 1]
        pr = {
            "url": "https://github.com/mbianchidev/sendbox/pull/1",
            "state": "OPEN",
            "headRefOid": remote_git("rev-parse", f"refs/heads/{branch}"),
        }
        state["prs"] = [pr]
        finish(pr["url"])
    if command == ["pr", "view"]:
        pr = state["prs"][0]
        fields = args[args.index("--json") + 1]
        if fields == "statusCheckRollup":
            finish("1")
        if fields == "headRefOid":
            finish(state.get("checked_head", pr["headRefOid"]))
        if fields == "state,headRefOid,mergeCommit":
            finish("\t".join([pr["state"], pr["headRefOid"], pr.get("mergeCommit", "")]))
    if command == ["pr", "checks"]:
        if state.pop("fail_checks_once", False):
            finish("mock PR checks failed", 1)
        finish()
    if command == ["pr", "merge"]:
        pr = state["prs"][0]
        pr.update(state="MERGED", mergeCommit=pr["headRefOid"])
        remote_git("update-ref", "refs/heads/main", pr["mergeCommit"])
        finish()
    if command == ["run", "list"]:
        if state.get("missing_run"):
            finish()
        state.setdefault("run", {"attempt": 1, "status": "in_progress", "conclusion": ""})
        finish("12345")
    if command == ["run", "view"]:
        run = state["run"]
        if "pending_attempt_polls" in state:
            if state["pending_attempt_polls"] > 0:
                state["pending_attempt_polls"] -= 1
            elif not state.get("rerun_never_starts"):
                run.update(attempt=run["attempt"] + 1, status="queued", conclusion="")
                del state["pending_attempt_polls"]
        fields = args[args.index("--json") + 1]
        if fields == "attempt":
            finish(str(run["attempt"]))
        if fields == "attempt,status,conclusion":
            finish(f'{run["attempt"]}\t{run["status"]}\t{run["conclusion"]}')
    if command == ["run", "rerun"]:
        if state.get("fail_rerun"):
            finish("mock rerun permission denied", 1)
        state["pending_attempt_polls"] = state.get("rerun_delay", 0)
        finish()
    if command == ["run", "watch"]:
        if "pending_attempt_polls" in state:
            finish("watch observed the old attempt", 1)
        failed = state.pop("fail_watch_once", False)
        state["run"].update(status="completed", conclusion="failure" if failed else "success")
        finish("mock publishing failed" if failed else "", int(failed))
    if command == ["release", "view"]:
        finish(f"https://github.com/mbianchidev/sendbox/releases/tag/{args[2]}")
finish(f"unexpected mock command: {tool} {args}", 2)
'''


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="sendbox-release-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.repo = self.root / "repo"
        self.remote = self.root / "origin.git"
        self.bin = self.root / "bin"
        self.state_path = self.root / "state.json"
        self.log_path = self.root / "commands.jsonl"
        self.repo.mkdir()
        self.bin.mkdir()
        (self.root / "tmp").mkdir()
        self.environment = os.environ | {
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "Release Fixture",
            "GIT_AUTHOR_EMAIL": "release-fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Release Fixture",
            "GIT_COMMITTER_EMAIL": "release-fixture@example.invalid",
            "RELEASE_TEST_STATE": str(self.state_path),
            "RELEASE_TEST_LOG": str(self.log_path),
            "RELEASE_TEST_REMOTE": str(self.remote),
            "TMPDIR": str(self.root / "tmp"),
        }
        for tool in ("gh", "cargo", "sleep"):
            path = self.bin / tool
            path.write_text(MOCK_TOOL)
            path.chmod(0o755)
        self.set_state()
        self.git("init", "--quiet", "--bare", "--initial-branch=main", str(self.remote))
        self.git("init", "--quiet", "--initial-branch=main")
        (self.repo / "scripts").mkdir()
        shutil.copyfile(ROOT / "scripts/release.sh", self.repo / "scripts/release.sh")
        (self.repo / "crates/sendbox-cli/tests").mkdir(parents=True)
        self.write_version("0.1.0")
        self.git("add", ".")
        self.git("commit", "--quiet", "--no-gpg-sign", "-m", "Initial fixture")
        self.git("remote", "add", "origin", str(self.remote))
        self.git("push", "--quiet", "--set-upstream", "origin", "main")

    def git(self, *arguments, cwd=None):
        location = ["--git-dir", str(self.remote)] if cwd == self.remote else ["-C", str(self.repo)]
        return subprocess.check_output(
            ["git", *location, *arguments],
            env=self.environment, text=True, stderr=subprocess.PIPE,
        ).strip()

    def write_version(self, version):
        (self.repo / "Cargo.toml").write_text(
            f'[workspace]\n[workspace.package]\nversion = "{version}"\n'
        )
        (self.repo / "Cargo.lock").write_text(
            f'version = 4\n[[package]]\nname = "sendbox-cli"\nversion = "{version}"\n'
        )
        (self.repo / "crates/sendbox-cli/tests/cli.rs").write_text(
            f'assert_eq!(output, "sendbox {version}\\n");\n'
        )

    def set_state(self, **state):
        self.state_path.write_text(json.dumps(state))

    def state(self):
        return json.loads(self.state_path.read_text())

    def calls(self, *prefix):
        if not self.log_path.exists():
            return []
        calls = [json.loads(line) for line in self.log_path.read_text().splitlines()]
        return [call for call in calls if call[:len(prefix)] == list(prefix)]

    def run_release(self, version=VERSION):
        return subprocess.run(
            ["/bin/bash", str(self.repo / "scripts/release.sh"), version],
            cwd=self.repo, env=self.environment, text=True, capture_output=True, timeout=30,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def release_branch(self, push=True):
        self.git("switch", "--quiet", "-c", BRANCH)
        self.write_version(VERSION)
        self.git("add", "Cargo.toml", "Cargo.lock", "crates/sendbox-cli/tests/cli.rs")
        self.git("commit", "--quiet", "--no-gpg-sign", "-m", f"Release {TAG}")
        commit = self.git("rev-parse", "HEAD")
        self.git("switch", "--quiet", "main")
        if push:
            self.git("push", "--quiet", "origin", BRANCH)
        return commit

    def merged_release(self, tag=True, push_tag=True):
        commit = self.release_branch()
        self.git("merge", "--quiet", "--ff-only", BRANCH)
        self.git("push", "--quiet", "origin", "main")
        if tag:
            self.git("-c", "tag.gpgSign=false", "tag", "-a", TAG, commit, "-m", f"Release {TAG}")
            if push_tag:
                self.git("push", "--quiet", "origin", TAG)
        return commit

    def pr(self, commit, state="OPEN"):
        return {
            "url": PR_URL, "state": state, "headRefOid": commit,
            "mergeCommit": commit if state == "MERGED" else "",
        }

    def test_new_release_keeps_version_bump_and_publication_flow(self):
        self.assert_success(self.run_release())
        commit = self.git("rev-parse", f"{TAG}^{{commit}}")
        self.assertEqual(self.git("rev-parse", "main", cwd=self.remote), commit)
        self.assertIn(f'version = "{VERSION}"', self.git("show", f"{TAG}:Cargo.lock"))
        self.assertIn(f"sendbox {VERSION}\\n", self.git("show", f"{TAG}:crates/sendbox-cli/tests/cli.rs"))
        self.assertEqual(self.git("cat-file", "-t", f"refs/tags/{TAG}"), "tag")
        self.assertEqual(len(self.calls("gh", "pr", "create")), 1)
        self.assertEqual(len(self.calls("gh", "pr", "merge")), 1)
        self.assertEqual(self.calls("gh", "run", "rerun"), [])
        self.assertEqual(self.git("status", "--porcelain"), "")
        self.assertEqual(list((self.root / "tmp").iterdir()), [])

    def test_failed_publication_retries_same_tag_without_another_bump_or_pr(self):
        self.set_state(fail_watch_once=True)
        self.assertNotEqual(self.run_release().returncode, 0)
        tag = self.git("rev-parse", f"refs/tags/{TAG}", cwd=self.remote)
        cargo_calls = len(self.calls("cargo"))
        self.assert_success(self.run_release("v" + VERSION))
        self.assertEqual(self.git("rev-parse", f"refs/tags/{TAG}", cwd=self.remote), tag)
        self.assertEqual(len(self.calls("cargo")), cargo_calls)
        self.assertEqual(len(self.calls("gh", "pr", "create")), 1)
        self.assertEqual(len(self.calls("gh", "pr", "merge")), 1)
        self.assertIn("--failed", self.calls("gh", "run", "rerun")[0])
        self.assertEqual(self.state()["run"]["attempt"], 2)

    def test_existing_remote_tag_is_fetched_even_when_main_has_advanced(self):
        commit = self.merged_release()
        tag = self.git("rev-parse", f"refs/tags/{TAG}")
        self.git("tag", "-d", TAG)
        self.write_version("0.3.0")
        self.git("add", ".")
        self.git("commit", "--quiet", "--no-gpg-sign", "-m", "Later fixture release")
        self.git("push", "--quiet", "origin", "main")
        self.set_state(run={"attempt": 1, "status": "completed", "conclusion": "failure"})
        self.assert_success(self.run_release())
        self.assertEqual(self.git("rev-parse", f"{TAG}^{{commit}}"), commit)
        self.assertEqual(self.git("rev-parse", f"refs/tags/{TAG}"), tag)
        self.assertEqual(self.calls("gh", "pr"), [])
        self.assertEqual(self.calls("cargo"), [])

    def test_active_and_successful_runs_are_not_restarted(self):
        self.merged_release()
        for status, conclusion in (("in_progress", ""), ("completed", "success")):
            with self.subTest(status=status):
                self.set_state(run={"attempt": 1, "status": status, "conclusion": conclusion})
                self.assert_success(self.run_release())
        self.assertEqual(self.calls("gh", "run", "rerun"), [])

    def test_cancelled_and_timed_out_runs_can_be_retried(self):
        self.merged_release()
        for conclusion in ("cancelled", "timed_out"):
            with self.subTest(conclusion=conclusion):
                self.set_state(run={"attempt": 1, "status": "completed", "conclusion": conclusion})
                self.assert_success(self.run_release())
                self.assertEqual(self.state()["run"]["attempt"], 2)

    def test_rerun_waits_for_new_attempt_before_watching(self):
        self.merged_release()
        self.set_state(
            run={"attempt": 3, "status": "completed", "conclusion": "failure"},
            rerun_delay=2,
        )
        self.assert_success(self.run_release())
        self.assertEqual(self.state()["run"]["attempt"], 4)
        self.assertGreaterEqual(len(self.calls("gh", "run", "view")), 4)

    def test_rerun_errors_are_not_hidden(self):
        self.merged_release()
        self.set_state(
            run={"attempt": 1, "status": "completed", "conclusion": "failure"},
            fail_rerun=True,
        )
        result = self.run_release()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mock rerun permission denied", result.stderr)
        self.assertEqual(self.calls("gh", "run", "watch"), [])

    def test_missing_run_and_unregistered_retry_time_out_without_changing_tag(self):
        self.merged_release()
        tag = self.git("rev-parse", f"refs/tags/{TAG}")
        for state in (
            {"missing_run": True},
            {
                "run": {"attempt": 1, "status": "completed", "conclusion": "failure"},
                "rerun_never_starts": True,
            },
        ):
            with self.subTest(state=state):
                self.set_state(**state)
                result = self.run_release()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("within 10 minutes", result.stderr)
                self.assertEqual(self.git("rev-parse", f"refs/tags/{TAG}"), tag)
                self.assertEqual(self.git("rev-parse", f"refs/tags/{TAG}", cwd=self.remote), tag)
        self.assertEqual(self.calls("gh", "run", "watch"), [])

    def test_failed_retry_stops_after_one_attempt(self):
        self.merged_release()
        self.set_state(
            run={"attempt": 1, "status": "completed", "conclusion": "failure"},
            fail_watch_once=True,
        )
        result = self.run_release()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.calls("gh", "run", "rerun")), 1)
        self.assertEqual(self.state()["run"]["conclusion"], "failure")

    def test_local_tag_is_pushed_without_recreating_it(self):
        self.merged_release(push_tag=False)
        tag = self.git("rev-parse", f"refs/tags/{TAG}")
        self.assert_success(self.run_release())
        self.assertEqual(self.git("rev-parse", f"refs/tags/{TAG}", cwd=self.remote), tag)

    def test_divergent_tags_are_not_overwritten(self):
        self.merged_release()
        remote_tag = self.git("rev-parse", f"refs/tags/{TAG}", cwd=self.remote)
        self.git("tag", "-d", TAG)
        self.git("tag", TAG)
        local_tag = self.git("rev-parse", f"refs/tags/{TAG}")
        result = self.run_release()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match", result.stderr)
        self.assertEqual(self.git("rev-parse", f"refs/tags/{TAG}", cwd=self.remote), remote_tag)
        self.assertEqual(self.git("rev-parse", f"refs/tags/{TAG}"), local_tag)
        self.assertEqual(self.calls("gh", "run"), [])

    def test_tagged_commit_must_be_on_main_with_matching_version(self):
        self.git("tag", TAG)
        result = self.run_release()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match", result.stderr)
        self.git("tag", "-d", TAG)
        commit = self.release_branch()
        self.git("tag", TAG, commit)
        result = self.run_release()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not on origin/main", result.stderr)
        self.assertEqual(self.calls("gh", "run"), [])

    def test_existing_merged_pr_is_tagged_at_its_merge_commit(self):
        commit = self.merged_release(tag=False)
        self.write_version("0.3.0")
        self.git("add", ".")
        self.git("commit", "--quiet", "--no-gpg-sign", "-m", "Later fixture release")
        self.git("push", "--quiet", "origin", "main")
        self.set_state(prs=[self.pr(commit, "MERGED")])
        self.assert_success(self.run_release())
        self.assertEqual(self.git("rev-parse", f"{TAG}^{{commit}}"), commit)
        self.assertEqual(self.calls("gh", "pr", "create"), [])
        self.assertEqual(self.calls("gh", "pr", "merge"), [])

    def test_failed_pr_checks_resume_the_existing_pr(self):
        self.set_state(fail_checks_once=True)
        self.assertNotEqual(self.run_release().returncode, 0)
        self.assert_success(self.run_release())
        self.assertEqual(len(self.calls("gh", "pr", "create")), 1)
        self.assertEqual(len(self.calls("gh", "pr", "merge")), 1)

    def test_committed_local_branch_without_pr_is_reused(self):
        commit = self.release_branch(push=False)
        self.assert_success(self.run_release())
        self.assertEqual(self.git("rev-parse", f"{TAG}^{{commit}}"), commit)
        self.assertEqual(self.calls("cargo"), [])

    def test_remote_branch_without_pr_is_reused(self):
        commit = self.release_branch()
        self.git("branch", "--delete", "--force", BRANCH)
        self.assert_success(self.run_release())
        self.assertEqual(self.git("rev-parse", f"{TAG}^{{commit}}"), commit)
        self.assertEqual(self.calls("cargo"), [])

    def test_divergent_release_branch_is_not_pushed_or_merged(self):
        self.release_branch()
        self.git("switch", "--quiet", BRANCH)
        self.git("commit", "--quiet", "--no-gpg-sign", "--allow-empty", "-m", "Unpushed fixture change")
        self.git("switch", "--quiet", "main")
        remote_commit = self.git("rev-parse", f"refs/heads/{BRANCH}", cwd=self.remote)
        result = self.run_release()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match origin", result.stderr)
        self.assertEqual(self.git("rev-parse", f"refs/heads/{BRANCH}", cwd=self.remote), remote_commit)
        self.assertEqual(self.calls("gh", "pr", "create"), [])

    def test_uncommitted_release_files_are_retained_for_recovery(self):
        self.set_state(fail_cargo=True)
        result = self.run_release()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("worktree retained for recovery", result.stderr)
        worktrees = list((self.root / "tmp").glob("sendbox-release.*/checkout"))
        self.assertEqual(len(worktrees), 1)
        self.assertIn(f'version = "{VERSION}"', (worktrees[0] / "Cargo.toml").read_text())
        result = self.run_release()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("inspect the recovery worktree", result.stderr)
        self.assertEqual(self.calls("gh", "pr", "create"), [])

    def test_closed_ambiguous_or_foreign_pr_is_not_merged(self):
        commit = self.release_branch()
        for prs in (
            [self.pr(commit, "CLOSED")],
            [self.pr(commit), self.pr(commit)],
            [self.pr(commit) | {"isCrossRepository": True}],
        ):
            with self.subTest(prs=prs):
                self.set_state(prs=prs)
                self.assertNotEqual(self.run_release().returncode, 0)
        self.assertEqual(self.calls("gh", "pr", "merge"), [])
        self.assertEqual(self.calls("gh", "run"), [])

    def test_pr_head_changes_are_not_merged(self):
        commit = self.release_branch()
        self.set_state(prs=[self.pr(commit)], checked_head="a" * 40)
        result = self.run_release()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PR head changed", result.stderr)
        self.assertEqual(self.calls("gh", "pr", "merge"), [])


if __name__ == "__main__":
    unittest.main()
