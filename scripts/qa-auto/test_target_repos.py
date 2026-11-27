import hashlib, json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "target_repos.py"
TD = "cli/internal/extract/crdversions/"
KEYS = "cli/knowledge/trust/web-approval-keys.json"
BATCH = "cli/knowledge/onboarding/ob-20261125-2.json"
NOW = "2026-11-26T00:00:00Z"

# a stand-in for prufyx-maintainer: the real signature verifier is Go; here only its CLI contract is exercised
FAKE = """#!/usr/bin/env python3
import os, sys
a = sys.argv[1:]
if a[:2] == ["approval", "keys-digest"]:
    print("sha256:" + "0" * 64); sys.exit(0)
if a[:2] == ["approval", "verify"] and "--onboarding-signature" in a:
    if os.environ.get("FAKE_REFUSE"):
        print("onboarding batch signature REFUSED: x"); sys.exit(1)
    print(open(os.environ["FAKE_REPORT"]).read().strip()); sys.exit(0)
sys.exit(9)
"""


def target(repo):
    return json.dumps({"target": {"repo": "github.com/" + repo}}).encode()


def sha(b):
    return "sha256:" + hashlib.sha256(b).hexdigest()


class Repo:
    def __init__(self, tmp):
        self.src = os.path.join(tmp, "src")
        self.tmp = tmp
        self.git("init", "-q", self.src)

    def git(self, *a):
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
        r = subprocess.run(["git", "-C", self.src] + list(a) if a[0] != "init" else ["git"] + list(a), capture_output=True, env=env)
        assert r.returncode == 0, r.stderr
        return r.stdout.decode().strip()

    def write(self, path, data):
        p = Path(self.src, path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "c")
        return self.git("rev-parse", "HEAD")


class Case(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.r = Repo(self.td.name)
        self.r.write(TD + "target-a.json", target("o/a"))
        self.r.write(KEYS, b"{}")
        self.base = self.r.commit()
        self.fake = os.path.join(self.td.name, "fake")
        Path(self.fake).write_text(FAKE)
        os.chmod(self.fake, 0o755)
        self.report = os.path.join(self.td.name, "report.json")

    def run_script(self, changed, maint=False, refuse=False, report=None, env=None):
        ch = os.path.join(self.td.name, "changed")
        Path(ch).write_text("\n".join(changed) + "\n")
        cmd = [sys.executable, "-I", str(SCRIPT), "--src", self.r.src, "--base", self.base, "--changed", ch]
        e = {"PATH": os.environ["PATH"], "FAKE_REPORT": self.report}
        if refuse:
            e["FAKE_REFUSE"] = "1"
        if env:
            e.update(env)
        if report is not None:
            Path(self.report).write_text(json.dumps(report))
        if maint:
            cmd += ["--maintainer", self.fake, "--now", NOW]
        p = subprocess.run(cmd, capture_output=True, env=e)
        return p.returncode, p.stdout.decode().strip()

    def add_head(self, repo="o/new", batch=True):
        t = target(repo)
        self.r.write(TD + "target-new.json", t)
        changed = [TD + "target-new.json"]
        if batch:
            self.r.write(BATCH, b"{}")
            changed.append(BATCH)
        self.r.commit()
        return changed, sha(t)

    def test_known_repo_and_unchanged_pass(self):
        self.r.write(TD + "target-b.json", target("o/a"))  # same repo as a base target: known
        self.r.commit()
        self.assertEqual(self.run_script([TD + "target-b.json"])[0], 0)

    # every encoding json.loads would accept from bytes but strict UTF-8 without a byte-order mark must not
    BAD_ENCODINGS = ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be")

    def encoded(self, repo, enc):
        return target(repo).decode().encode(enc)

    def assert_unreadable(self, got):
        rc, out = got
        self.assertEqual(rc, 1, out)
        self.assertIn("target check failed", out)

    def test_encoded_new_target_for_known_repo_refused(self):
        for enc in self.BAD_ENCODINGS:
            with self.subTest(enc=enc):
                self.r.write(TD + "target-b.json", self.encoded("o/a", enc))
                self.r.commit()
                self.assert_unreadable(self.run_script([TD + "target-b.json"]))

    def test_encoded_rewrite_of_base_target_same_repo_refused(self):
        for enc in self.BAD_ENCODINGS:
            with self.subTest(enc=enc):
                self.r.write(TD + "target-a.json", self.encoded("o/a", enc))
                self.r.commit()
                self.assert_unreadable(self.run_script([TD + "target-a.json"]))

    def test_encoded_new_repo_refused_before_maintainer(self):
        for enc in self.BAD_ENCODINGS:
            with self.subTest(enc=enc):
                self.r.write(TD + "target-new.json", self.encoded("o/new", enc))
                self.r.commit()
                ch = [TD + "target-new.json"]
                self.assert_unreadable(self.run_script(ch))  # never exit 4
                self.assert_unreadable(self.run_script(ch, env={"QA_GATE_REPOS": "o/new"}))

    def test_encoded_new_repo_refused_even_when_signed(self):
        self.r.write(BATCH, b"{}")
        for enc in self.BAD_ENCODINGS:
            with self.subTest(enc=enc):
                t = self.encoded("o/new", enc)
                self.r.write(TD + "target-new.json", t)
                self.r.commit()
                rep = {"batchId": "b", "schema": "x", "artifacts": [{"path": TD + "target-new.json", "digest": sha(t)}]}
                self.assert_unreadable(self.run_script([TD + "target-new.json", BATCH], maint=True, report=rep))

    def test_encoded_base_target_refused(self):
        for enc in self.BAD_ENCODINGS:
            with self.subTest(enc=enc):
                self.r.write(TD + "target-a.json", self.encoded("o/a", enc))
                self.base = self.r.commit()
                self.r.write(TD + "target-b.json", target("o/a") + b"\n" * (1 + self.BAD_ENCODINGS.index(enc)))
                self.r.commit()
                self.assert_unreadable(self.run_script([TD + "target-b.json"]))

    def test_repo_change_refused(self):
        self.r.write(TD + "target-a.json", target("o/other"))
        self.r.commit()
        rc, out = self.run_script([TD + "target-a.json"])
        self.assertEqual(rc, 1)
        self.assertIn("repo changed", out)

    def test_new_repo_needs_maintainer_pass(self):
        ch, _ = self.add_head()
        self.assertEqual(self.run_script(ch)[0], 4)

    def test_env_list_still_works(self):
        ch, _ = self.add_head()
        self.assertEqual(self.run_script(ch, env={"QA_GATE_REPOS": "o/new"})[0], 0)

    def test_signed_batch_lists_target(self):
        ch, dg = self.add_head()
        rep = {"batchId": "ob-20261125-2", "schema": "x", "artifacts": [{"path": TD + "target-new.json", "digest": dg}]}
        self.assertEqual(self.run_script(ch, maint=True, report=rep), (0, ""))

    def test_digest_mismatch_refused(self):
        ch, dg = self.add_head()
        rep = {"batchId": "b", "schema": "x", "artifacts": [{"path": TD + "target-new.json", "digest": "sha256:" + "1" * 64}]}
        rc, out = self.run_script(ch, maint=True, report=rep)
        self.assertEqual(rc, 1)
        self.assertIn("not in a signed onboarding batch", out)

    def test_path_not_listed_refused(self):
        ch, dg = self.add_head()
        rep = {"batchId": "b", "schema": "x", "artifacts": [{"path": TD + "target-other.json", "digest": dg}]}
        self.assertEqual(self.run_script(ch, maint=True, report=rep)[0], 1)

    def test_signature_refused(self):
        ch, dg = self.add_head()
        rep = {"batchId": "b", "schema": "x", "artifacts": [{"path": TD + "target-new.json", "digest": dg}]}
        rc, out = self.run_script(ch, maint=True, refuse=True, report=rep)
        self.assertEqual(rc, 1)
        self.assertIn("signature refused", out)

    def test_no_batch_added_refused(self):
        ch, dg = self.add_head(batch=False)
        rep = {"batchId": "b", "schema": "x", "artifacts": [{"path": TD + "target-new.json", "digest": dg}]}
        rc, out = self.run_script(ch, maint=True, report=rep)
        self.assertEqual(rc, 1)
        self.assertIn("no single signed onboarding batch", out)

    def test_two_batches_refused(self):
        ch, dg = self.add_head()
        self.r.write("cli/knowledge/onboarding/ob-20261125-3.json", b"{}")
        self.r.commit()
        ch.append("cli/knowledge/onboarding/ob-20261125-3.json")
        rep = {"batchId": "b", "schema": "x", "artifacts": [{"path": TD + "target-new.json", "digest": dg}]}
        self.assertEqual(self.run_script(ch, maint=True, report=rep)[0], 1)

    def test_garbage_report_refused(self):
        ch, _ = self.add_head()
        Path(self.report).write_text("not json")
        self.assertEqual(self.run_script(ch, maint=True)[0], 1)

    def test_maintainer_without_now_refused(self):
        ch, _ = self.add_head()
        e = {"PATH": os.environ["PATH"]}
        c = os.path.join(self.td.name, "ch")
        Path(c).write_text("\n".join(ch))
        p = subprocess.run([sys.executable, "-I", str(SCRIPT), "--src", self.r.src, "--base", self.base, "--changed", c,
                            "--maintainer", self.fake], capture_output=True, env=e)
        self.assertEqual(p.returncode, 1)


if __name__ == "__main__":
    unittest.main()
