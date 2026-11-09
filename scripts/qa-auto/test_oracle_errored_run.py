"""An errored run never moves the design baseline; the tag fetch retries only transient network failures, bounded, fail closed."""
import json, os, subprocess, sys, tempfile, unittest
from types import SimpleNamespace
from unittest.mock import patch

import crd_oracle as crd
import qalib
import test_support

HERE = os.path.dirname(os.path.abspath(__file__))
D = "DESIGN_UNKNOWN_WHOLE_CRD_REMOVAL"


def design(n):
    return [qalib.case("crd", f"k{i}", status=D) for i in range(n)]


def summarize(state, cases, mode="full", clean=True, adhoc=False, extra_cases=None):
    d = tempfile.mkdtemp()
    json.dump(cases, open(d + "/crd.cases.json", "w"))
    if clean:
        test_support.complete_full_run(d, "a" * 40)
    cmd = [sys.executable, os.path.join(HERE, "summarize.py"), "--dir", d, "--state", state, "--sha", "a" * 40, "--mode", mode]
    if adhoc:
        cmd.append("--adhoc")
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r, json.load(open(d + "/summary.json"))


def baseline(state):
    return json.load(open(state + "/status.json"))["design_unknown_whole_crd_baseline"]


class ErroredRunBaseline(unittest.TestCase):
    def errored(self, n):
        return design(n) + [qalib.case("crd", "proj", error=True, why="fetch tags failed")]

    def test_clean_full_run_stores(self):
        s = tempfile.mkdtemp()
        r, summ = summarize(s, design(42))
        self.assertEqual((summ["errors"], r.returncode, baseline(s)), (0, 0, 42))

    def test_errored_run_keeps_previous_baseline(self):
        s = tempfile.mkdtemp()
        summarize(s, design(42))
        r, summ = summarize(s, self.errored(31))
        self.assertEqual((summ["errors"], summ["state"]), (1, "INCONCLUSIVE"))
        self.assertEqual((baseline(s), summ["design_unknown_whole_crd_baseline"]), (42, 42))

    def test_clean_run_after_errored_run_is_not_a_rise(self):
        s = tempfile.mkdtemp()
        summarize(s, design(42))
        summarize(s, self.errored(31))
        r, summ = summarize(s, design(42))
        first = r.stdout.splitlines()[0]
        for flag in (" RISE", " CAP", "ALARM"):
            self.assertNotIn(flag, first)
        self.assertEqual((summ["state"], r.returncode, baseline(s)), ("GREEN", 0, 42))

    def test_errored_first_run_stores_nothing(self):
        s = tempfile.mkdtemp()
        r, summ = summarize(s, self.errored(31))
        self.assertIsNone(baseline(s))
        r, summ = summarize(s, design(42))
        self.assertEqual(baseline(s), 42)

    def test_errored_run_does_not_lower_baseline_when_oracle_changed(self):
        s = tempfile.mkdtemp()
        summarize(s, design(42))
        st = json.load(open(s + "/status.json"))
        st["oracle_digest"] = "0" * 64
        json.dump(st, open(s + "/status.json", "w"))
        r, summ = summarize(s, self.errored(31))
        self.assertIn("ORACLE_CHANGED", r.stdout.splitlines()[0])
        self.assertEqual(baseline(s), 42)
        self.assertEqual(json.load(open(s + "/status.json"))["oracle_digest"], "0" * 64)  # digest kept too: the reset still applies next run

    def test_errored_run_can_still_raise_cap(self):
        s = tempfile.mkdtemp()
        summarize(s, design(40))
        r, summ = summarize(s, self.errored(70))
        self.assertTrue(summ["design_unknown_whole_crd_cap_breach"])
        self.assertEqual(baseline(s), 40)

    def test_missing_suite_counts_as_errored(self):
        s = tempfile.mkdtemp()
        summarize(s, design(42))
        r, summ = summarize(s, design(30), clean=False)  # other mandatory suites absent: error cases
        self.assertGreater(summ["errors"], 0)
        self.assertEqual(baseline(s), 42)

    def test_non_full_and_adhoc_do_not_store(self):
        s = tempfile.mkdtemp()
        summarize(s, design(42))
        summarize(s, design(30), mode="incremental")
        self.assertEqual(baseline(s), 42)
        summarize(s, design(30), adhoc=True)
        self.assertEqual(baseline(s), 42)

    def test_errored_run_resolves_no_gap_of_its_errored_key(self):
        s = tempfile.mkdtemp()
        json.dump([{"key": "crd|proj", "reason": "r", "owner": "o", "since": "2026-11-07", "ref": "#1", "sig": "x"}], open(s + "/known-gaps.json", "w"))
        r, summ = summarize(s, self.errored(3))
        self.assertEqual(summ["resolved_gaps"], [])


def result(code, err=""):
    return SimpleNamespace(returncode=code, stdout="", stderr=err)


class FetchRetry(unittest.TestCase):
    def run_fetch(self, outcomes):
        calls, sleeps = [], []
        it = iter(outcomes)

        def fake_sh(*argv, **kw):
            calls.append(argv)
            return next(it)
        crd.FETCH_RETRIES.clear()
        with patch.object(crd, "sh", fake_sh), patch.object(crd.time, "sleep", sleeps.append):
            r = crd.fetch_tags("p", "gd")
        return r, len(calls), sleeps

    NET = "fatal: unable to access 'https://x/': Could not resolve host: github.com"

    def test_ok_after_two_failures(self):
        r, n, sleeps = self.run_fetch([result(128, self.NET), result(128, self.NET), result(0)])
        self.assertEqual((r.returncode, n, sleeps, crd.FETCH_RETRIES["p"]), (0, 3, [2, 5], 2))

    def test_three_failures_fail_closed(self):
        r, n, sleeps = self.run_fetch([result(128, self.NET)] * 3)
        self.assertEqual((r.returncode, n, crd.FETCH_RETRIES["p"]), (128, 3, 2))

    def test_non_network_failure_not_retried(self):
        r, n, sleeps = self.run_fetch([result(128, "fatal: not a git repository")])
        self.assertEqual((r.returncode, n, sleeps, crd.FETCH_RETRIES.get("p")), (128, 1, [], None))

    def test_first_try_no_retry(self):
        r, n, sleeps = self.run_fetch([result(0)])
        self.assertEqual((n, sleeps, crd.FETCH_RETRIES.get("p")), (1, [], None))

    def prep(self, outcomes):
        it = iter(outcomes)
        tj = {"repo": "o/p", "tagPrefixes": ["v"]}
        crd.FETCH_RETRIES.clear()
        with tempfile.TemporaryDirectory() as td, patch.object(crd, "GITROOT", td), patch.object(crd, "validate_target", lambda t: ("o/p", "")), \
                patch.object(crd.os.path, "isdir", lambda p: True), patch.object(crd, "sh", lambda *a, **k: next(it)), patch.object(crd.time, "sleep", lambda s: None):
            plan = crd.new_plan()
            plan["binding"] = {"target": {"spec": tj}}
            with patch.object(crd, "checked", side_effect=AssertionError("past the fetch")):
                try:
                    crd.prepare("p", [], plan)
                except ValueError as e:
                    return str(e)
                except AssertionError:
                    return "past"

    def test_prepare_error_text_unchanged_when_all_attempts_fail(self):
        msg = self.prep([result(128, self.NET)] * 3)
        self.assertTrue(msg.startswith("fetch tags failed"), msg)

    def test_prepare_non_network_failure_exact_text(self):
        self.assertEqual(self.prep([result(128, "fatal: bad object")]), "fetch tags failed")

    def test_prepare_succeeds_after_retries(self):
        self.assertEqual(self.prep([result(128, self.NET), result(0)]), "past")
        self.assertEqual(crd.FETCH_RETRIES["p"], 1)


class SummaryField(unittest.TestCase):
    def test_sum_and_log_not_in_verdict(self):
        s = tempfile.mkdtemp()
        a = qalib.case("crd", "a", status=D)
        a["detail"]["fetch_retries"] = 2
        b = qalib.case("crd", "b", error=True, why="fetch tags failed (after 2 retries)")
        b["detail"]["fetch_retries"] = 2
        r, summ = summarize(s, [a, b])
        self.assertEqual(summ["fetch_retries"], 4)
        self.assertIn("fetch_retries=4", r.stdout.splitlines()[1:])
        self.assertNotIn("fetch_retries", r.stdout.splitlines()[0])

    def test_zero_by_default(self):
        r, summ = summarize(tempfile.mkdtemp(), design(1))
        self.assertEqual(summ["fetch_retries"], 0)
        self.assertNotIn("fetch_retries", r.stdout)


if __name__ == "__main__":
    unittest.main()
