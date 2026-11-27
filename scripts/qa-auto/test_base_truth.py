"""Base truth for the gate: no base target may disappear, and the gate base must be the main tip (real Git, stubbed suites)."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import qa_batch_scope as batch
import qalib
from seeded_support import install_stub_seeds
from test_oracle_box import COMPANION, DEVBOX, KIND
import test_seeds  # module import: its test classes must not be collected a second time from here

HERE = Path(__file__).resolve().parent
TD = "cli/internal/extract/crdversions/"
A, B = TD + "target-a.json", TD + "target-b.json"
TABLE = "cli/internal/customresources/table.json"
KEYS = "cli/knowledge/trust/web-approval-keys.json"
RUN_ID = "0123456789abcdef0123456789abcdef"
REMOVED = "base target removed or not a regular file"

# a git on PATH that fails (or interferes with) exactly one kind of call and otherwise is the real one
SHIM = """#!/usr/bin/env python3
import os, subprocess, sys
a = sys.argv[1:]
real, mode = os.environ["REAL_GIT"], os.environ.get("SHIM", "")
sub = a[2] if a[:1] == ["-C"] else a[0]
if mode in ("ls-remote", "fetch", "merge-base") and sub == mode:
    sys.exit(128)
if mode == "move-main" and sub == "fetch":
    subprocess.check_call([real, "-C", os.environ["SHIM_REMOTE"], "update-ref", "refs/heads/main", os.environ["SHIM_TO"]])
if mode == "shallow" and "--is-shallow-repository" in a:
    print("true")
    sys.exit(0)
if mode == "show-head" and sub == "show" and a[-1].startswith("HEAD:cli/internal/extract/crdversions/"):
    sys.exit(128)
if mode.startswith("ls-tree:") and sub == "ls-tree" and "-z" in a and os.environ["SHIM_REV"] in a:
    sys.exit(128)
os.execv(real, [real] + a)
"""


def script(path, text):
    path.write_text(text)
    path.chmod(0o700)
    return str(path)


class Repo:
    def __init__(self, path):
        self.path = path
        path.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Spas Atanasov")
        self.git("config", "user.email", "11156623+airstand@users.noreply.github.com")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.path), *args], text=True, stderr=subprocess.PIPE).strip()

    def write(self, name, text):
        path = self.path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self, message="Synthetic"):
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")


def shim_env(root, mode, **extra):
    bin_dir = root / "shim"
    bin_dir.mkdir(exist_ok=True)
    script(bin_dir / "git", SHIM)
    return dict(PATH=f"{bin_dir}:{os.environ['PATH']}", REAL_GIT=shutil.which("git"), SHIM=mode, **extra)


def target(repo, **more):
    return json.dumps({"target": dict(repo=repo, **more)})


class RemovedTargets(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.repo = Repo(self.root / "src")
        self.repo.write(A, target("o/a"))
        self.repo.write(B, target("o/b"))
        self.repo.write(TABLE, "{}")
        self.repo.write(KEYS, "{}")
        self.base = self.first = self.repo.commit()

    def head(self):
        head = self.repo.commit("Head")
        self.repo.git("update-ref", batch.BASE_REF, self.base)
        self.repo.git("update-ref", batch.HEAD_REF, head)
        return head

    def mutate(self, mode):
        path = self.repo.path / B
        if mode in ("delete", "delete-and-table", "unreadable-component"):
            path.unlink()
            if mode == "delete-and-table":
                self.repo.write(TABLE, '{"changed":true}')
        elif mode == "delete-all":
            path.unlink()
            (self.repo.path / A).unlink()
        elif mode == "rename":
            path.rename(path.with_name("target-renamed.json"))
        elif mode == "rename-out":
            self.repo.write("cli/docs/target-b.json", path.read_text())
            path.unlink()
        elif mode == "executable":
            path.chmod(0o755)
        elif mode == "symlink":
            path.unlink()
            path.symlink_to("target-a.json")
        elif mode == "directory":
            path.unlink()
            self.repo.write(B + "/inner.json", target("o/b"))

    MODES = ("delete", "delete-and-table", "delete-all", "rename", "rename-out", "executable", "symlink", "directory",
             "unreadable-component")

    def changed(self, head):
        return self.repo.git("diff", "--name-only", "--no-renames", self.base, head).splitlines()

    def target_repos(self, changed, env=None, maintainer=None):
        listed = self.root / "changed"
        listed.write_text("".join(p + "\n" for p in changed))
        cmd = [sys.executable, "-I", str(HERE / "target_repos.py"), "--src", str(self.repo.path), "--base", self.base,
               "--changed", str(listed)]
        if maintainer:
            cmd += ["--maintainer", maintainer, "--runner", "/usr/bin/env", "--now", "2026-11-26T00:00:00Z"]
        return subprocess.run(cmd, capture_output=True, text=True, env=dict(os.environ, **(env or {})), timeout=60)

    def select(self, head, env=None):
        listed = self.root / "changed"
        listed.write_text("".join(p + "\n" for p in self.changed(head)))
        full = dict(os.environ, QA_BASE=self.base, QA_SHA=head, QA_RUN_ID=RUN_ID, QA_SCOPE_BASE_REF=batch.BASE_REF,
                    QA_SCOPE_HEAD_REF=batch.HEAD_REF, **(env or {}))
        return subprocess.run([sys.executable, "-I", str(HERE / "select_projects.py"), "--changed", str(listed),
                               "--src", str(self.repo.path)], env=full, capture_output=True, text=True, timeout=60)

    def prepare(self, mode):
        """A fresh head for one removal mode, on a base reset for it; returns the head."""
        self.repo.git("reset", "-q", "--hard", self.first)
        self.repo.git("clean", "-qfdx")
        self.base = self.first
        if mode == "unreadable-component":
            # two base targets bind one component: every file loads, the component map does not
            self.repo.write(A, target("o/a", component="pkg:x"))
            self.repo.write(B, target("o/b", component="pkg:x"))
            self.base = self.repo.commit("Unreadable component")
            with self.assertRaises(ValueError):
                batch.base_components(self.repo.path, self.base)
        self.mutate(mode)
        return self.head()

    def test_target_repos_refuses_every_removal(self):
        for mode in self.MODES:
            with self.subTest(mode=mode):
                result = self.target_repos(self.changed(self.prepare(mode)))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(REMOVED, result.stdout)

    def test_target_repos_refuses_removal_left_out_of_the_changed_list(self):
        for mode in self.MODES:
            for changed in ([], [TABLE]):
                with self.subTest(mode=mode, changed=changed):
                    self.prepare(mode)
                    result = self.target_repos(changed)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn(REMOVED, result.stdout)

    def test_signed_batch_and_repo_list_do_not_admit_a_removal(self):
        self.mutate("delete")
        self.repo.write("cli/knowledge/onboarding/ob-20261125-2.json", "{}")
        head = self.head()
        maintainer = script(self.root / "maintainer", "#!/usr/bin/env python3\nimport sys\n"
                            "print('sha256:' + '0' * 64 if 'keys-digest' in sys.argv else '{\"artifacts\": []}')\n")
        result = self.target_repos(self.changed(head), env={"QA_GATE_REPOS": "o/a,o/b"}, maintainer=maintainer)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(B + ": " + REMOVED, result.stdout)

    def test_removal_with_a_new_unknown_repo_never_asks_for_the_maintainer(self):
        self.mutate("delete")
        self.repo.write(TD + "target-new.json", target("o/new"))
        head = self.head()
        result = self.target_repos(self.changed(head))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(REMOVED, result.stdout)

    def test_freeze_and_selection_refuse_every_removal(self):
        for mode in self.MODES:
            with self.subTest(mode=mode):
                head = self.prepare(mode)
                with self.assertRaisesRegex(ValueError, r"UNSUPPORTED_SCOPE: .*\(base target\)"):
                    batch.freeze(self.repo.path, head, self.base, RUN_ID)
                result = self.select(head)
                self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
                self.assertIn("(base target)", result.stderr)

    def test_control_edits_additions_and_table_changes_stay_admitted(self):
        self.repo.write(A, target("o/a", name="edited"))
        self.repo.write(TD + "target-c.json", target("o/b"))
        self.repo.write(TABLE, '{"changed":true}')
        head = self.head()
        result = self.target_repos(self.changed(head))
        self.assertEqual((result.returncode, result.stdout.strip()), (0, ""), result.stderr)
        self.assertEqual(batch.freeze(self.repo.path, head, self.base, RUN_ID)["mode"], "full")
        self.assertEqual(self.select(head).returncode, 0)

    def test_unreadable_changed_target_is_not_a_deletion(self):
        self.repo.write(A, target("o/a", name="edited"))
        head = self.head()
        for changed, env in (([A], shim_env(self.root, "show-head")), ([TD + "target-absent.json"], None)):
            with self.subTest(changed=changed):
                result = self.target_repos(changed, env=env)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("target check failed", result.stdout)
        self.assertEqual(self.target_repos(self.changed(head)).returncode, 0)  # control

    def test_failed_listing_refuses(self):
        self.repo.write(TABLE, '{"changed":true}')
        head = self.head()
        for side in ("base", "head"):
            with self.subTest(side=side, script="target_repos"):
                rev = self.base if side == "base" else "HEAD"
                result = self.target_repos([TABLE], env=shim_env(self.root, "ls-tree:", SHIM_REV=rev))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("target check failed", result.stdout)
            with self.subTest(side=side, script="select_projects"):
                result = self.select(head, env=shim_env(self.root, "ls-tree:", SHIM_REV=self.base if side == "base" else head))
                self.assertEqual(result.returncode, 3, result.stdout + result.stderr)

    def test_unreadable_base_target_refuses(self):
        self.repo.write(A, "")
        self.base = self.repo.commit("Empty base target")
        self.repo.write(TABLE, '{"changed":true}')
        head = self.head()
        result = self.target_repos(self.changed(head))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("target check failed", result.stdout)


class Inventory(unittest.TestCase):
    OID = b"0" * 40

    def entry(self, path, mode=b"100644", kind=b"blob"):
        return mode + b" " + kind + b" " + self.OID + b"\t" + path + b"\0"

    def test_malformed_listing_raises(self):
        import crd_inventory
        good = self.entry(A.encode())
        for raw in (good[:-1], good + b"\0", b"garbage\0", good + good, good.decode(), None,
                    self.entry(A.encode(), mode=b"10064"), self.entry(A.encode(), kind=b"link")):
            with self.subTest(raw=raw):
                for pair in ((raw, good), (good, raw)):
                    with self.assertRaises(ValueError):
                        crd_inventory.removed_targets(*pair)

    def test_removed_targets(self):
        import crd_inventory
        base = self.entry(A.encode()) + self.entry(B.encode()) + self.entry((TD + "other.go").encode())
        self.assertEqual(crd_inventory.removed_targets(base, base), [])
        self.assertEqual(crd_inventory.removed_targets(base, b""), [A, B])
        self.assertEqual(crd_inventory.removed_targets(base, self.entry(A.encode()) + self.entry(B.encode(), mode=b"100755")), [B])
        self.assertEqual(crd_inventory.removed_targets(b"", base), [])

    def test_module_is_part_of_the_oracle_digest(self):
        self.assertIn("crd_inventory.py", qalib.ORACLE_FILES)


class GateBase(unittest.TestCase):
    """main: root - tip. side: head on top of tip."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.remote = Repo(self.root / "remote")
        self.remote.write(A, target("o/a"))
        self.old = self.remote.commit("Root")
        self.remote.write("README.md", "tip\n")
        self.tip = self.remote.commit("Tip")
        self.head = self.branch("side", self.tip, "head\n")
        self.marker = self.root / "ran"
        fake = test_seeds.fake_runner(self.root, test_seeds.GateVerdictLine.OK)
        self.runner = script(self.root / "wrapper", '#!/bin/sh\ntouch "%s"\n'
                             '[ -z "${MID_RUN_MAIN:-}" ] || git -C "%s" update-ref refs/heads/main "$MID_RUN_MAIN"\n'
                             'exec "%s"\n' % (self.marker, self.remote.path, fake))
        self.fake = self.root / "fake"
        self.fake.mkdir()
        (self.fake / "gh").mkdir()
        script(self.fake / "gh" / "gh", '#!/bin/sh\ncase "$1 $2" in\n  "pr list") cat "$FAKE_DIR/prs.json" ;;\n'
               '  "api repos/prufyx/prufyx/commits/"*) cat "$FAKE_DIR/pulls.json" ;;\n  *) exit 1 ;;\nesac\n')
        self.count = 0

    def branch(self, name, start, text, name_file="CHANGE.md"):
        self.remote.git("checkout", "-q", "-B", name, start)
        self.remote.write(name_file, text)
        commit = self.remote.commit(name)
        self.remote.git("checkout", "-q", "main")
        return commit

    def gate(self, head, args, shim="", state=None, **extra):
        self.count += 1
        state = state or self.root / ("state%d" % self.count)
        (self.fake / "prs.json").write_text(json.dumps([{
            "number": 7, "headRefOid": head, "headRefName": "bot/data", "labels": [], "isCrossRepository": False,
            "headRepositoryOwner": {"login": "prufyx"}, "author": {"login": "prufyx-bot"}}]))
        (self.fake / "pulls.json").write_text(json.dumps([{
            "state": "open", "head": {"sha": head, "repo": {"full_name": "prufyx/prufyx"}}, "user": {"login": "prufyx-bot"}}]))
        env = {k: v for k, v in os.environ.items() if not k.startswith("QA_")}
        env.update(shim_env(self.root, shim, SHIM_REMOTE=str(self.remote.path)))
        env["PATH"] = f"{self.fake / 'gh'}:{env['PATH']}"
        env.update(FAKE_DIR=str(self.fake), QA_STATE=str(state), QA_REPO_URL=str(self.remote.path),
                   QA_GATE_RUN=self.runner, QA_GATE_TRIES="1", QA_GATE_AUTHORS="prufyx-bot", HTTPS_PROXY="http://127.0.0.1:9",
                   https_proxy="http://127.0.0.1:9")
        env.update(extra)
        self.marker.unlink(missing_ok=True)
        result = subprocess.run([str(HERE / "batch_gate.sh"), *args], env=env, capture_output=True, text=True, timeout=60)
        return result, state

    def record(self, state, head):
        path = state / "gate" / (head + ".json")
        return json.loads(path.read_text()) if path.exists() else None

    def forms(self, head, base):
        """Every way of choosing the base: explicit and default, with and without --trust-operator, and poll."""
        explicit = [["--trust-operator", head, base], [head, base]]
        return explicit + [["--trust-operator", head], [head], ["--poll"]]

    def assert_refused(self, head, args, **kw):
        result, state = self.gate(head, args, **kw)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 3, output)
        self.assertIn("STRICT_BASE", result.stderr, output)
        self.assertFalse(self.marker.exists(), "run.sh was called: " + output)
        self.assertEqual(list((state / "gate").glob("*")), [], "something was recorded: " + output)
        self.assertEqual(list(state.glob("scope-parent.*")), [])
        self.assertNotIn("WRONGPASS=", result.stdout)

    def test_control_head_on_the_tip_is_green_in_every_form(self):
        for args in self.forms(self.head, self.tip):
            with self.subTest(args=args):
                result, state = self.gate(self.head, args)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue(self.marker.exists())
                record = self.record(state, self.head)
                self.assertEqual((record["state"], record["base"], record["main"]), ("GREEN", self.tip, self.tip))

    def test_control_long_branch_needs_the_full_history(self):
        self.remote.git("checkout", "-q", "side")
        for i in range(70):
            self.remote.commit("Step %d" % i)
        head = self.remote.git("rev-parse", "HEAD")
        self.remote.git("checkout", "-q", "main")
        result, state = self.gate(head, ["--trust-operator", head])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.record(state, head)["base"], self.tip)

    def test_explicit_base_other_than_the_tip_merge_base(self):
        self.remote.git("checkout", "-q", "side")
        second = self.remote.commit("Second")
        self.remote.git("checkout", "-q", "main")
        behind = self.branch("behind", self.old, "behind\n", "BEHIND.md")
        for name, head, base in (("branch commit", second, self.head), ("older ancestor", second, self.old),
                                 ("tip is not the merge base", behind, self.tip), ("merge base is not the tip", behind, self.old),
                                 ("unrelated", self.head, behind), ("base equals head", self.head, self.head),
                                 ("tip against itself", self.tip, self.tip)):
            for args in (["--trust-operator", head, base], [head, base]):
                with self.subTest(case=name, args=args):
                    self.assert_refused(head, args)

    def test_head_behind_main_or_already_main_is_refused_in_every_form(self):
        behind = self.branch("behind", self.old, "behind\n", "BEHIND.md")
        for name, head, base in (("behind", behind, self.old), ("head is the tip", self.tip, self.tip),
                                 ("head inside main", self.old, self.old)):
            for args in self.forms(head, base):
                with self.subTest(case=name, args=args):
                    self.assert_refused(head, args)

    def test_two_merge_bases(self):
        left = self.branch("left", self.tip, "left\n", "LEFT.md")
        right = self.branch("right", self.tip, "right\n", "RIGHT.md")
        tree = self.remote.git("rev-parse", self.tip + "^{tree}")
        main = self.remote.git("commit-tree", tree, "-p", left, "-p", right, "-m", "one")
        head = self.remote.git("commit-tree", tree, "-p", right, "-p", left, "-m", "two")
        self.remote.git("update-ref", "refs/heads/main", main)
        self.remote.git("update-ref", "refs/heads/cross", head)
        for args in self.forms(head, left):
            with self.subTest(args=args):
                self.assert_refused(head, args)

    def test_failed_lookup_fetch_merge_base_and_shallow_history(self):
        for shim in ("ls-remote", "fetch", "merge-base", "shallow"):
            for args in self.forms(self.head, self.tip):
                with self.subTest(shim=shim, args=args):
                    self.assert_refused(self.head, args, shim=shim)

    def test_main_moved_between_lookup_and_fetch(self):
        later = self.branch("later", self.tip, "later\n", "LATER.md")
        for args in self.forms(self.head, self.tip):
            with self.subTest(args=args):
                self.remote.git("update-ref", "refs/heads/main", self.tip)
                self.assert_refused(self.head, args, shim="move-main", SHIM_TO=later)

    def test_only_exactly_one_line_for_exactly_main_is_accepted(self):
        self.remote.git("update-ref", "refs/other/refs/heads/main", self.tip)
        for args in self.forms(self.head, self.tip):
            with self.subTest(case="two lines", args=args):
                self.assert_refused(self.head, args)
        self.remote.git("checkout", "-q", "--detach", self.tip)
        self.remote.git("update-ref", "-d", "refs/heads/main")
        with self.subTest(case="only a look-alike ref"):
            self.assert_refused(self.head, ["--trust-operator", self.head])
        self.remote.git("update-ref", "-d", "refs/other/refs/heads/main")
        with self.subTest(case="no ref"):
            self.assert_refused(self.head, ["--trust-operator", self.head])

    def test_main_moved_during_the_run_makes_the_record_stale(self):
        later = self.branch("later", self.tip, "later\n", "LATER.md")
        result, state = self.gate(self.head, ["--trust-operator", self.head], MID_RUN_MAIN=later)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.remote.git("rev-parse", "refs/heads/main"), later)
        self.assertEqual(self.record(state, self.head)["main"], self.tip)
        result, _ = self.gate(self.head, ["--poll"], state=state)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertFalse(self.marker.exists())
        record = self.record(state, self.head)
        self.assertEqual((record["state"], record["exit"]), ("STALE", 3))

    def stale(self, shim="", **changes):
        state = self.root / ("stale%d" % self.count)
        (state / "gate").mkdir(parents=True)
        record = dict(sha=self.head, base=self.tip, main=self.tip, exit=0, state="GREEN", line="GATE synthetic")
        record.update(changes)
        record = {k: v for k, v in record.items() if v is not None}
        (state / "gate" / (self.head + ".json")).write_text(json.dumps(record))
        result, _ = self.gate(self.head, ["--poll"], state=state, shim=shim)
        return result, self.record(state, self.head)

    # records whose main is not the tip, and an unreadable tip, were already stale before this rule: they stay as controls
    def test_poll_keeps_only_a_green_record_that_satisfies_the_base_rule(self):
        result, record = self.stale()  # control
        self.assertEqual((result.returncode, record["state"]), (0, "GREEN"), result.stderr)
        for name, kw in (("older base, current main", dict(base=self.old)), ("no base", dict(base=None)),
                         ("no main", dict(main=None)), ("older main", dict(main=self.old, base=self.old)),
                         ("base is the head", dict(base=self.head, main=self.head)), ("tip unreadable", dict(shim="ls-remote"))):
            with self.subTest(case=name):
                result, record = self.stale(**kw)
                self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
                self.assertEqual((record["state"], record["exit"]), ("STALE", 3))

    def test_no_base_is_taken_from_a_hosting_api(self):
        text = (HERE / "batch_gate.sh").read_text()
        self.assertNotIn("/compare/", text)


class NightlyListing(unittest.TestCase):
    def run_nightly(self, change):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        repo = Repo(root / "source")
        repo.write(A, target("o/a", name="x" * 200))
        repo.write("cli/internal/cncfcheck/data/rules.json", '{"entries":[]}')
        base = repo.commit()
        change(repo)
        repo.commit("Change")
        installed = root / "installed"
        installed.mkdir()
        for name in ("run.sh", "select_projects.py", "summarize.py", "qalib.py", "qa_scope.py", "qa_batch_scope.py",
                     "crd_inventory.py", "target_json.py", "target_repos.py", "crdgvk.go"):
            if name not in ("crd_inventory.py", "target_json.py") or (HERE / name).exists():  # absent in a red run
                shutil.copy2(HERE / name, installed / name)
        for name in ("crd_oracle.py", "k8s_oracle.py", "bp325.py", "review_cases.py", "rules_oracle.py"):
            (installed / name).write_text(COMPANION)
        install_stub_seeds(installed)
        (installed / "kind_probe.py").write_text(KIND)
        state = root / "state"
        state.mkdir()
        (state / "last_green").write_text(base + "\n")
        (state / "last_full").write_text("%d\n" % time.time())
        env = {k: v for k, v in os.environ.items() if not k.startswith("QA_")}
        env.update(QA_REPO_URL=str(repo.path), QA_STATE=str(state), QA_WORK_ROOT=str(root / "work"),
                   QA_DEVBOX=script(root / "devbox", DEVBOX), QA_MAXLOAD="999")
        result = subprocess.run([str(installed / "run.sh")], env=env, capture_output=True, text=True, timeout=60)
        selected = [json.loads(p.read_text()) for p in state.glob("results/*/select.json")]
        self.assertEqual(len(selected), 1, result.stdout + result.stderr)
        return result, selected[0], (state / "last_green").read_text().strip() == base

    def test_target_renamed_into_an_ignored_path_is_not_mode_none(self):
        def change(repo):
            (repo.path / "cli/docs").mkdir(parents=True)
            repo.git("mv", A, "cli/docs/target-a.json")
        result, selected, unmoved = self.run_nightly(change)
        self.assertNotEqual(selected["mode"], "none", result.stderr)
        self.assertNotIn("nothing relevant changed", result.stderr)
        self.assertTrue(unmoved, "last_green moved without an oracle run")

    def test_control_ignored_path_only_stays_mode_none(self):
        result, selected, unmoved = self.run_nightly(lambda repo: repo.write("cli/docs/note.json", "{}"))
        self.assertEqual(selected["mode"], "none", result.stderr)
        self.assertFalse(unmoved)


if __name__ == "__main__":
    unittest.main()
