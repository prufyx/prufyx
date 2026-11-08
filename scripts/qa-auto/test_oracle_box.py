"""QA_ORACLE_BOX: optional wrapper around the nightly rules suite only; actual run.sh with stubbed companions."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent

COMPANION = '''import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).stem
suite = {'crd_oracle':'crd','k8s_oracle':'k8s','bp325':'bp325','review_cases':'review','rules_oracle':'rules'}[name]
flag = '--cases' if name == 'bp325' else '--out'
out = Path(sys.argv[sys.argv.index(flag)+1])
if name == 'rules_oracle':
    out.with_name('rules.argv.json').write_text(json.dumps(sys.argv))
    if os.environ.get('RULES_FAIL'):
        sys.exit(1)
cases = [dict(suite=suite, key='synthetic', wrongpass=False, mismatch=False, error=False, detail={})]
if name == 'rules_oracle':
    cases.append(dict(suite='rules', key='summary', wrongpass=False, mismatch=False, error=False,
                      detail=dict(entries=1, controls_block=1)))
out.write_text(json.dumps(cases))
'''
KIND = "import sys\nsys.exit(0)\n"
# the stubbed companions leave other suites incomplete: the baseline verdict (no box) is the reference
BASE_RC = 3
BASE_ERR = "ERR=2 "  # crd/k8s scope stubs; a crashed rules suite adds one
DEVBOX = "#!/bin/sh\nexit 0\n"


GOOD = json.dumps([dict(suite="rules", key="synthetic", wrongpass=False, mismatch=False, error=False, detail={}),
                   dict(suite="rules", key="summary", wrongpass=False, mismatch=False, error=False,
                        detail=dict(entries=1, controls_block=1))])
ALLOWLIST = {"PATH", "HOME", "LANG", "LC_ALL", "QA_JOBS", "QA_NOW", "QA_SRC", "QA_TMP", "QA_BIN", "QA_CRDGVK",
             "QA_CACHE", "QA_STATE", "QA_SCAN_TIMEOUT"}


def SUMMARY_BAD(entries, controls, extra_summary=False, nrr=False):
    def c(key, **d):
        return dict(suite="rules", key=key, wrongpass=False, mismatch=False, error=False, detail=d)
    out = [c("summary", entries=entries, controls_block=controls)]
    if extra_summary:
        out.append(c("summary", entries=entries, controls_block=controls))
    if nrr:
        out.append(c("no-reachable-rule"))
    return json.dumps(out)


def box_script(body, path):
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o700)
    return str(path)


class OracleBoxTests(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)
        self.addCleanup(self._td.cleanup)
        # wrapper path parents must not be group/world-writable, so not under /tmp: use a private dir under HOME
        self.bd = Path(tempfile.mkdtemp(dir=str(Path.home())))
        os.chmod(self.bd, 0o700)
        self.addCleanup(shutil.rmtree, str(self.bd), True)
        src = self.root / "source"
        src.mkdir()
        def git(*a):
            subprocess.run(["git", "-C", str(src)] + list(a), check=True, capture_output=True)
        git("init", "-q", "-b", "main")
        git("config", "user.name", "Spas Atanasov")
        git("config", "user.email", "11156623+airstand@users.noreply.github.com")
        (src / "cli/internal/cncfcheck/data").mkdir(parents=True)
        (src / "cli/internal/cncfcheck/data/rules.json").write_text(json.dumps({"entries": [
            {"project": "a", "rule": {"id": "a.1", "operator": "forbid_set_member"}},
            {"project": "b", "rule": {"id": "b.1", "operator": "other"}}]}))
        (src / "README").write_text("x")
        git("add", ".")
        git("commit", "-qm", "Synthetic")
        self.src = src
        self.inst = self.root / "installed"
        self.inst.mkdir()
        for name in ("run.sh", "select_projects.py", "summarize.py", "qalib.py", "qa_scope.py", "qa_batch_scope.py", "crdgvk.go"):
            shutil.copy2(HERE / name, self.inst / name)
        for name in ("crd_oracle.py", "k8s_oracle.py", "bp325.py", "review_cases.py", "rules_oracle.py"):
            (self.inst / name).write_text(COMPANION)
        (self.inst / "kind_probe.py").write_text(KIND)
        self.devbox = self.root / "devbox"
        self.devbox.write_text(DEVBOX)
        self.devbox.chmod(0o700)
        self.n = 0

    def run_sh(self, **extra):
        self.n += 1
        env = {k: v for k, v in os.environ.items() if not k.startswith("QA_")}
        env.update(QA_REPO_URL=str(self.src), QA_STATE=str(self.root / ("state%d" % self.n)),
                   QA_WORK_ROOT=str(self.root / ("work%d" % self.n)), QA_DEVBOX=str(self.devbox),
                   QA_MAXLOAD="999")
        env.update(extra)
        return subprocess.run([str(self.inst / "run.sh")], env=env, capture_output=True, text=True, timeout=60), env

    def ran(self):
        return list(self.root.glob("state*/results/*/rules.argv.json"))

    def rules_cases(self, env):
        files = list(Path(env["QA_STATE"], "results").glob("*/rules.cases.json"))
        return json.loads(files[0].read_text()) if files else None

    EXPECT = ["python3", "-X", "utf8", "rules_oracle.py"]

    def check_argv(self, argv):
        self.assertEqual(argv[:4], self.EXPECT)
        self.assertEqual(argv[4], "--out")
        self.assertTrue(argv[5].endswith("/rules.cases.json"))
        self.assertEqual(argv[6], "--allow")
        self.assertTrue(argv[7].endswith("/rules-allow.json"))
        self.assertEqual(len(argv), 8)

    def test_unset_and_empty_run_directly(self):
        for extra in ({}, {"QA_ORACLE_BOX": ""}):
            r, env = self.run_sh(**extra)
            self.assertEqual(r.returncode, BASE_RC, r.stdout + r.stderr)
            self.assertEqual(self.rules_cases(env)[0]["key"], "synthetic")
            self.assertIn(BASE_ERR, r.stdout)
            argv = json.loads(self.ran()[-1].read_text())
            self.assertEqual(argv[0], "rules_oracle.py")
            self.assertEqual(len(argv), 5)
            self.assertEqual((argv[1], argv[3]), ("--out", "--allow"))
            self.assertTrue(argv[2].endswith("/rules.cases.json") and argv[4].endswith("/rules-allow.json"))

    def test_box_invoked_with_exact_argv_and_ok(self):
        box = box_script('printf "%%s\\n" "$@" >"%s"\nexec "$@"\n' % (self.root / "boxlog"), self.bd / "box")
        r, env = self.run_sh(QA_ORACLE_BOX=box)
        self.assertEqual(r.returncode, BASE_RC, r.stdout + r.stderr)
        args = (self.root / "boxlog").read_text().split("\n")[:-1]
        self.check_argv(args)
        self.assertEqual(self.rules_cases(env)[0]["key"], "synthetic")
        self.assertIn(BASE_ERR, r.stdout)

    def test_refusals(self):
        r, _ = self.run_sh(QA_ORACLE_BOX="relative-box")
        self.assertEqual(r.returncode, 3, r.stderr)
        r, _ = self.run_sh(QA_ORACLE_BOX=str(self.root / "missing"))
        self.assertEqual(r.returncode, 3)
        plain = self.bd / "plain"
        plain.write_text("#!/bin/sh\nexec \"$@\"\n")
        plain.chmod(0o600)
        r, _ = self.run_sh(QA_ORACLE_BOX=str(plain))
        self.assertEqual(r.returncode, 3, "not executable")
        r, _ = self.run_sh(QA_ORACLE_BOX=str(self.root))
        self.assertEqual(r.returncode, 3, "directory")
        for mode in (0o722, 0o702, 0o775):
            b = box_script('exec "$@"\n', self.bd / ("w%o" % mode))
            os.chmod(b, mode)
            r, _ = self.run_sh(QA_ORACLE_BOX=b)
            self.assertEqual(r.returncode, 3, oct(mode))
            self.assertIn("refusing", r.stderr)
        self.assertEqual(self.ran(), [])

    def test_refused_in_gate_adhoc_and_runbox_modes(self):
        box = box_script('exec "$@"\n', self.bd / "ok")
        for extra in ({"QA_BASE": "0" * 40}, {"QA_RUNBOX": "/x"}, {"QA_PROJECTS": "a"}, {"QA_NO_KIND": "1"},
                      {"QA_SHA": "0" * 40}, {"QA_PRE_BUILD": "1"}):
            with self.subTest(extra=extra):
                r, _ = self.run_sh(QA_ORACLE_BOX=box, **extra)
                self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
                self.assertIn("only honored", r.stderr)
        self.assertEqual(self.ran(), [])

    def test_poll_mode_honors_box(self):
        box = box_script('exec "$@"\n', self.bd / "ok")
        r, _ = self.run_sh(QA_ORACLE_BOX=box, QA_POLL="1")
        self.assertEqual(r.returncode, BASE_RC, r.stdout + r.stderr)
        self.assertEqual(len(self.ran()), 1)

    def assert_err(self, r, env):
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        cases = self.rules_cases(env)
        self.assertEqual([(c["key"], c["error"]) for c in cases], [("suite-crashed", True)])
        self.assertIn("ERR=3 ", r.stdout)

    def test_box_failing_without_cases_is_err(self):
        box = box_script("exit 7\n", self.bd / "fail")
        r, env = self.run_sh(QA_ORACLE_BOX=box)
        self.assert_err(r, env)

    def test_box_exit_zero_without_cases_is_err(self):
        box = box_script("exit 0\n", self.bd / "nothing")
        r, env = self.run_sh(QA_ORACLE_BOX=box)
        self.assert_err(r, env)

    def test_box_empty_or_malformed_cases_is_err(self):
        for i, body in enumerate(("", "not json", "[]", '[{"suite":"rules"}]', '{"suite":"rules"}',
                                  '[{"suite":"other","key":"k","wrongpass":false,"mismatch":false,"error":false}]',
                                  '[{"suite":"rules","key":"k","wrongpass":"no","mismatch":false,"error":false}]',
                                  # forged all-green, well formed but no summary case
                                  '[{"suite":"rules","key":"x","wrongpass":false,"mismatch":false,"error":false,"detail":{}}]',
                                  # summary entries do not match the rule-entry count (1)
                                  SUMMARY_BAD(2, 1), SUMMARY_BAD(0, 1), SUMMARY_BAD(True, 1), SUMMARY_BAD(1, 0), SUMMARY_BAD("1", 1),
                                  SUMMARY_BAD(1, 1, extra_summary=True),
                                  SUMMARY_BAD(1, 1, nrr=True))):
            with self.subTest(body=body):
                f = self.root / ("body%d" % i)
                f.write_text(body)
                box = box_script('while [ "$1" != --out ]; do shift; done\ncat "%s" >"$2"\nexit 0\n' % f, self.bd / ("junk%d" % i))
                r, env = self.run_sh(QA_ORACLE_BOX=box)
                self.assert_err(r, env)

    def test_refused_when_parent_directory_writable_or_foreign(self):
        sub = self.bd / "sub"
        sub.mkdir()
        b = box_script('exec "$@"\n', sub / "box")
        for mode in (0o777, 0o770, 0o707):
            os.chmod(sub, mode)
            r, _ = self.run_sh(QA_ORACLE_BOX=b)
            self.assertEqual(r.returncode, 3, oct(mode))
            self.assertIn("parent directories", r.stderr)
        os.chmod(sub, 0o700)
        # a symlink into a writable directory is judged by its resolved path
        link = self.bd / "link"
        wd = self.root / "wd"  # under /tmp: world-writable parent
        wd.mkdir()
        tgt = box_script('exec "$@"\n', wd / "box")
        link.symlink_to(tgt)
        r, _ = self.run_sh(QA_ORACLE_BOX=str(link))
        self.assertEqual(r.returncode, 3)
        self.assertEqual(self.ran(), [])
        r, _ = self.run_sh(QA_ORACLE_BOX=b)
        self.assertEqual(r.returncode, BASE_RC, r.stderr)

    def test_checked_again_before_exec(self):
        # becomes group-writable after the startup check (a companion flips it): the second check refuses
        sub = self.bd / "late"
        sub.mkdir()
        b = box_script('exec "$@"\n', sub / "box")
        (self.inst / "review_cases.py").write_text(COMPANION + "\nos.chmod(%r, 0o770)\n" % str(sub))
        r, env = self.run_sh(QA_ORACLE_BOX=b)
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertEqual(self.ran(), [])

    def test_wrapper_environment_is_allowlisted(self):
        box = box_script('env >"%s"\nexec "$@"\n' % (self.root / "envout"), self.bd / "envbox")
        r, env = self.run_sh(QA_ORACLE_BOX=box, QA_ALARM_HOOK="/x",
                             SECRET_TOKEN="s3cret", QA_ORACLE_BOX_TIMEOUT="900", QA_DB_SUITE="/y", SSH_AUTH_SOCK="/z")
        self.assertEqual(r.returncode, BASE_RC, r.stdout + r.stderr)
        got = {l.split("=", 1)[0] for l in (self.root / "envout").read_text().splitlines() if "=" in l}
        got -= {"PWD", "OLDPWD", "SHLVL", "_"}
        self.assertTrue(got <= ALLOWLIST, got - ALLOWLIST)
        for k in ("PATH", "HOME", "QA_STATE", "QA_SRC", "QA_TMP", "QA_NOW", "QA_JOBS"):
            self.assertIn(k, got)

    def test_orphan_child_does_not_hold_run_lock(self):
        import fcntl
        pidf = self.root / "orphan.pid"
        box = box_script('sleep 60 </dev/null >/dev/null 2>&1 &\necho $! >"%s"\nexec "$@"\n' % pidf, self.bd / "orphan")
        r, env = self.run_sh(QA_ORACLE_BOX=box)
        try:
            self.assertEqual(r.returncode, BASE_RC, r.stdout + r.stderr)
            pid = int(pidf.read_text())
            os.kill(pid, 0)  # the orphan is still alive
            with open(Path(env["QA_STATE"]) / "lock", "w") as fh:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)  # raises if the orphan inherited the lock
        finally:
            try:
                os.kill(int(pidf.read_text()), 15)
            except Exception:
                pass

    def test_timeout_is_err_even_with_fresh_cases(self):
        box = box_script('while [ "$1" != --out ]; do shift; done\nprintf %s \'' + GOOD + '\' >"$2"\nsleep 30\n', self.bd / "slow")
        r, env = self.run_sh(QA_ORACLE_BOX=box, QA_ORACLE_BOX_TIMEOUT="1")
        self.assert_err(r, env)
        self.assertIn("timed out", r.stderr)

    def test_bad_timeout_value_refused(self):
        box = box_script('exec "$@"\n', self.bd / "ok")
        for v in ("0", "-1", "abc", "1.5", "100000", "010"):
            r, _ = self.run_sh(QA_ORACLE_BOX=box, QA_ORACLE_BOX_TIMEOUT=v)
            self.assertEqual(r.returncode, 3, v)

    def test_box_stale_cases_is_err(self):
        good = self.root / "good.json"
        good.write_text(GOOD)
        os.utime(good, (1000000000, 1000000000))
        box = box_script('while [ "$1" != --out ]; do shift; done\ncp -p "%s" "$2"\nexit 0\n' % good, self.bd / "stale")
        r, env = self.run_sh(QA_ORACLE_BOX=box)
        self.assert_err(r, env)

    def test_box_findings_exit_nonzero_with_fresh_cases_keeps_cases(self):
        bad = self.root / "bad.json"
        bad.write_text(json.dumps([dict(suite="rules", key="r1", wrongpass=True, mismatch=True, error=False, detail={}),
                                   json.loads(GOOD)[1]]))
        box = box_script('while [ "$1" != --out ]; do shift; done\ncat "%s" >"$2"\nexit 1\n' % bad, self.bd / "finds")
        r, env = self.run_sh(QA_ORACLE_BOX=box)
        self.assertEqual(self.rules_cases(env)[0]["key"], "r1")
        self.assertIn("WRONGPASS=1", r.stdout)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
