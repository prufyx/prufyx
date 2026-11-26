"""Stored count baselines and the stored oracle digest move only on a green full run with nothing skipped; actual summarize.py and run.sh."""
import json, os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path

import qalib
import test_support
from seeded_support import install_stub_seeds

HERE = Path(__file__).resolve().parent
SHA = "a" * 40
KEPT = ("design_unknown_whole_crd_baseline", "unowned_removal_unknown_baseline", "oracle_digest")
OLD = "0" * 64


def cases(design, unowned, *extra):
    out = [qalib.case("crd", "d%d" % i, status="DESIGN_UNKNOWN_WHOLE_CRD_REMOVAL") for i in range(design)]
    out.append(qalib.case("crd", "u", status="UNOWNED_REMOVAL_UNKNOWN", unownedRemoved=["g/v/k%d" % i for i in range(unowned)]))
    return out + list(extra)


WRONGPASS = qalib.case("crd", "wp", wrongpass=True)
MISMATCH = qalib.case("crd", "mm", mismatch=True)
ERROR = qalib.case("crd", "er", error=True)


def summarize(state, found, mode="full", skipped=()):
    with tempfile.TemporaryDirectory() as d:
        Path(d, "crd.cases.json").write_text(json.dumps(found))
        test_support.complete_full_run(d, SHA)
        Path(d, "skipped.json").write_text(json.dumps(list(skipped)))
        r = subprocess.run([sys.executable, str(HERE / "summarize.py"), "--dir", d, "--state", str(state), "--sha", SHA, "--mode", mode],
                           capture_output=True, text=True)
    return r.returncode, json.loads(Path(state, "status.json").read_text())


def kept(status):
    return tuple(status.get(k) for k in KEPT)


class BaselinesMoveOnlyOnGreenFullRun(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.state = Path(td.name)

    def stored(self, digest=None):
        """A state after a green full run (design 42, unowned 10) with an empty mismatch baseline."""
        rc, st = summarize(self.state, cases(42, 10))
        self.assertEqual((rc, kept(st)), (0, (42, 10, qalib.oracle_digest())))
        if digest:
            st["oracle_digest"] = digest
            Path(self.state, "status.json").write_text(json.dumps(st))
        return kept(st)

    def check_kept(self, extra, want_rc, digest=None, **kw):
        before = self.stored(digest)
        for design, unowned in ((26, 8), (45, 11)):  # lower and higher counts, both inside the rise thresholds
            rc, st = summarize(self.state, cases(design, unowned, *extra), **kw)
            self.assertEqual((rc, kept(st)), (want_rc, before), (design, unowned))
            summ_counts = (st["design_unknown_whole_crd_removal"], st["unowned_removal_unknown"])
            self.assertEqual(summ_counts, (design, unowned))  # the counts themselves are still reported

    def test_wrongpass_alarm_keeps_baselines_and_digest(self):
        self.check_kept([WRONGPASS], 2)

    def test_new_mismatch_alarm_keeps_baselines_and_digest(self):
        self.check_kept([MISMATCH], 2)

    def test_alarm_with_changed_oracle_keeps_old_digest(self):
        self.check_kept([MISMATCH], 2, digest=OLD)

    def test_alarm_with_errors_keeps_baselines_and_digest(self):
        self.check_kept([MISMATCH, ERROR], 2, digest=OLD)

    def test_skipped_suite_keeps_baselines_and_digest(self):
        self.check_kept([], 4, skipped=["kind"])

    def test_skipped_suite_with_changed_oracle_keeps_old_digest(self):
        self.check_kept([], 4, digest=OLD, skipped=["kind"])

    def test_inconclusive_keeps_baselines_and_digest(self):
        self.check_kept([ERROR], 3, digest=OLD)

    def test_non_full_green_run_keeps_baselines_and_digest(self):
        self.check_kept([], 0, digest=OLD, mode="incremental")

    def test_green_full_run_moves_baselines_and_digest(self):
        self.stored(OLD)
        rc, st = summarize(self.state, cases(26, 8))
        self.assertEqual((rc, kept(st)), (0, (26, 8, qalib.oracle_digest())))

    def test_first_run_without_status_stores_only_when_green_and_full(self):
        for extra, kw, want_rc in (([WRONGPASS], {}, 2), ([], {"skipped": ["kind"]}, 4), ([ERROR], {}, 3),
                                   ([], {"mode": "incremental"}, 0)):
            with self.subTest(extra=extra, kw=kw):
                Path(self.state, "status.json").unlink(missing_ok=True)
                rc, st = summarize(self.state, cases(42, 10, *extra), **kw)
                self.assertEqual((rc, kept(st)), (want_rc, (None, None, None)))
        rc, st = summarize(self.state, cases(42, 10))
        self.assertEqual((rc, kept(st)), (0, (42, 10, qalib.oracle_digest())))


class NothingRelevantChanged(unittest.TestCase):
    """run.sh, mode none: last_checked moves only for the exit codes that move it after a full run."""

    def run_none(self, gaps):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        src, inst, state = root / "source", root / "installed", root / "state"
        for d in (src, inst, state):
            d.mkdir()

        def git(*a):
            return subprocess.run(["git", "-C", str(src)] + list(a), check=True, capture_output=True, text=True).stdout.strip()
        git("init", "-q", "-b", "main")
        git("config", "user.name", "Synthetic")
        git("config", "user.email", "synthetic@example.invalid")
        (src / "README").write_text("x")
        git("add", ".")
        git("commit", "-qm", "Synthetic")
        sha = git("rev-parse", "HEAD")
        for source in [HERE / "run.sh", *HERE.glob("*.py")]:  # mode none runs no suite; the oracle digest reads their files
            shutil.copy2(source, inst / source.name)
        (inst / "select_projects.py").write_text('print(\'{"mode":"none","projects":[],"db":false}\')\n')
        install_stub_seeds(inst)
        (state / "known-gaps.json").write_text(json.dumps(
            [{"key": "crd|k%02d" % i, "reason": "r", "owner": "o", "sig": "x"} for i in range(gaps)]))
        (state / "last_checked").write_text(OLD[:40] + "\n")
        env = {k: v for k, v in os.environ.items() if not k.startswith("QA_")}
        env.update(QA_REPO_URL=str(src), QA_STATE=str(state), QA_WORK_ROOT=str(root / "work"), QA_MAXLOAD="999",
                   QA_MODE="incremental", QA_DEVBOX="true")
        r = subprocess.run([str(inst / "run.sh")], env=env, capture_output=True, text=True, timeout=60)
        green = state / "last_green"
        return r, sha, (state / "last_checked").read_text().strip(), green.read_text().strip() if green.exists() else None

    def test_inconclusive_does_not_mark_the_sha_checked(self):
        r, _, checked, green = self.run_none(gaps=11)  # more new gap entries than one run may register
        self.assertEqual((r.returncode, checked, green), (3, OLD[:40], None), r.stdout + r.stderr)
        self.assertIn("mode=none INCONCLUSIVE", r.stdout)

    def test_green_marks_the_sha_checked_and_green(self):
        r, sha, checked, green = self.run_none(gaps=0)
        self.assertEqual((r.returncode, checked, green), (0, sha, sha), r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
