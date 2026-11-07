"""Whole-CRD removal class: documented-design UNKNOWN is its own status; every other outcome stays fail-closed."""
import json, os, subprocess, sys, tempfile, unittest

import crd_oracle as crd
import qalib

W1 = ("a.example", "v1", "Gone")
W2 = ("a.example", "v1", "AlsoGone")
V1 = ("b.example", "v1beta1", "Old")
P = "proj"
FAM = "crd.custom_resource_versions"


def unknown(findings=(), gaps=None):
    gaps = [{"component": P, "reason": "COMPONENT_NOT_COVERED"}] if gaps is None else gaps
    paths = [{"component": P, "hops": [{"status": "NO_DATA", "reasons": ["COMPONENT_NOT_COVERED"]}]}]
    return {"verdict": "UNKNOWN", "findings": list(findings), "paths": paths, "gaps": gaps}


class Classify(unittest.TestCase):
    def test_whole_crd_absent_vs_version_inside_present_crd(self):
        defined = {("b.example", "Old")}
        self.assertEqual(crd.whole_removed([W1, V1], defined), [W1])
        self.assertEqual(crd.whole_removed([W1], None), [])

    def test_whole_unknown_exit11_no_findings_is_design(self):
        self.assertEqual(crd.crd_verdict(11, unknown(), [W1, W2], [W1, W2], P), (False, False, [], [], True))

    def test_whole_pass_is_wrongpass(self):
        for code, rep in ((0, {"verdict": "PASS", "findings": []}), (0, {"verdict": "SCOPE_COMPLETE_PASS"}),
                          (11, {"verdict": "UNKNOWN", "findings": [], "paths": [{"component": P, "hops": [
                              {"families": [{"family": FAM, "status": "PASS"}]}]}]})):
            wp, mm, _, _, design = crd.crd_verdict(code, rep, [W1], [W1], P)
            self.assertEqual((wp, mm, design), (True, False, False))

    def test_whole_blocked_or_other_exit_or_findings_is_mismatch(self):
        for code, rep in ((10, {"verdict": "BLOCKED", "findings": []}),
                          (11, {"verdict": "BLOCKED", "findings": []}),
                          (12, unknown()),
                          (11, unknown([{"component": "other"}])),
                          (11, {"verdict": None})):
            wp, mm, missing, _, design = crd.crd_verdict(code, rep, [W1, W2], [W1, W2], P)
            self.assertEqual((wp, mm, design), (False, True, False), (code, rep))
            self.assertTrue(missing)

    def test_generic_unknown_is_not_excused(self):
        for rep in (unknown(gaps=[]),
                    unknown(gaps=[{"component": P, "reason": "VERSION_NOT_DETECTED"}]),
                    unknown(gaps=[{"component": P, "reason": "COMPONENT_NOT_COVERED"}, {"component": P, "reason": "DECLARATION_MISSING"}]),
                    dict(unknown(), paths=[{"component": P, "hops": [{"status": "UNKNOWN", "reasons": ["COMPONENT_NOT_COVERED"]}]}]),
                    dict(unknown(), paths=[]),
                    unknown(gaps=[{"component": "other", "reason": "COMPONENT_NOT_COVERED"}]),
                    unknown(gaps=["x"]),
                    dict(unknown(), unsupported=[{"x": 1}]),
                    dict(unknown(), omitted=[{"x": 1}])):
            wp, mm, _, _, design = crd.crd_verdict(11, rep, [W1], [W1], P)
            self.assertEqual((wp, mm, design), (False, True, False), rep)

    def test_partial_blocked_stays_mismatch(self):
        # four expected, scanner blocked with a smaller set of findings: not attributable
        rep = {"verdict": "BLOCKED", "findings": [{"component": P}, {"component": P}]}
        self.assertTrue(crd.crd_verdict(10, rep, [W1, W2, V1, ("c", "v1", "X")], [W1, W2], P)[1])

    def test_whole_marked_but_not_in_expected_is_ignored(self):
        # whole set must be a subset of the expected set; a stray entry cannot excuse anything
        self.assertEqual(crd.crd_verdict(11, unknown(), [V1], [W1], P)[4], False)
        self.assertTrue(crd.crd_verdict(11, unknown(), [V1], [W1], P)[1])

    def test_mixed_unknown_misses_version_part(self):
        wp, mm, missing, _, design = crd.crd_verdict(11, unknown(), [W1, V1], [W1], P)
        self.assertEqual((wp, mm, design), (False, True, False))
        self.assertEqual(missing, ["/".join(V1)])

    def test_mixed_pass_is_wrongpass_and_non_unknown_does_not_excuse(self):
        self.assertTrue(crd.crd_verdict(0, {"verdict": "PASS"}, [W1, V1], [W1], P)[0])
        wp, mm, missing, _, design = crd.crd_verdict(10, {"verdict": "BLOCKED", "findings": []}, [W1, V1], [W1], P)
        self.assertEqual((wp, mm, design), (False, True, False))
        self.assertIn("/".join(W1), missing)

    def test_no_whole_set_is_unchanged(self):
        self.assertEqual(crd.crd_verdict(11, unknown(), [V1], [], P)[:4],
                         qalib.scoped_result(11, unknown(), [V1], P, FAM))


class LaterTagRead(unittest.TestCase):
    def test_failed_or_empty_later_read_is_no_whole_classification(self):
        from unittest.mock import patch
        removed = [W1, V1]
        with patch.object(crd, "defined_kinds", side_effect=ValueError("blob unreadable")):
            self.assertEqual(crd.classify_whole({}, "gd", "v2", removed, {}), [])
        with patch.object(crd, "defined_kinds", return_value=set()):
            self.assertEqual(crd.classify_whole({}, "gd", "v2", removed, {}), [])
        with patch.object(crd, "defined_kinds", return_value={("b.example", "Old")}):
            self.assertEqual(crd.classify_whole({}, "gd", "v2", removed, {}), [W1])
        self.assertEqual(crd.classify_whole({}, "gd", "v2", [], {}), [])

    def test_failed_read_leaves_version_level_mismatch(self):
        wp, mm, _, _, design = crd.crd_verdict(11, unknown(), [W1], [], P)
        self.assertEqual((wp, mm, design), (False, True, False))


class Counters(unittest.TestCase):
    def cases(self, n):
        return [qalib.case("crd", f"k{i}", status="DESIGN_UNKNOWN_WHOLE_CRD_REMOVAL") for i in range(n)] + [qalib.case("crd", "z")]

    def test_error_design_case_not_counted(self):
        c = qalib.case("crd", "e", error=True, status="DESIGN_UNKNOWN_WHOLE_CRD_REMOVAL")
        self.assertNotIn("design_unknown_whole_crd_removal", qalib.counts([c]))

    def test_counts(self):
        self.assertEqual(qalib.counts(self.cases(2)), {"wrongpass": 0, "mismatch": 0, "error": 0, "design_unknown_whole_crd_removal": 2})
        self.assertNotIn("design_unknown_whole_crd_removal", qalib.counts(self.cases(0)))

    def run_summary(self, state, cases, mode="none"):
        d = tempfile.mkdtemp()
        json.dump(cases, open(d + "/crd.cases.json", "w"))
        r = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "summarize.py"),
                            "--dir", d, "--state", state, "--sha", "a" * 40, "--mode", mode], capture_output=True, text=True)
        return r, json.load(open(d + "/summary.json"))

    def full(self, state, cases):
        # mode full also adds a no-cases error for the other mandatory suites: only the design fields matter here
        return self.run_summary(state, cases, "full")

    def test_summary_count_and_first_run_not_flagged(self):
        s = tempfile.mkdtemp()
        r, summ = self.run_summary(s, self.cases(2))
        self.assertEqual(summ["design_unknown_whole_crd_removal"], 2)
        self.assertFalse(summ["design_unknown_whole_crd_rise"])
        self.assertFalse(summ["design_unknown_whole_crd_cap_breach"])
        self.assertIn("DESIGN_UNKNOWN_WHOLE_CRD=2", r.stdout)
        self.assertEqual(summ["mismatch"], 0)

    def test_hard_cap_is_inconclusive(self):
        r, summ = self.run_summary(tempfile.mkdtemp(), self.cases(81))
        self.assertTrue(summ["design_unknown_whole_crd_cap_breach"])
        self.assertEqual((summ["state"], r.returncode), ("INCONCLUSIVE", 3))
        self.assertIn("CAP", r.stdout)

    def test_growth_beyond_twenty_percent_is_inconclusive_and_baseline_kept(self):
        s = tempfile.mkdtemp()
        r, summ = self.full(s, self.cases(40))
        self.assertEqual(summ["design_unknown_whole_crd_baseline"], 40)
        r, summ = self.full(s, self.cases(46))  # within +20% (8): rise, no breach
        self.assertTrue(summ["design_unknown_whole_crd_rise"])
        self.assertFalse(summ["design_unknown_whole_crd_cap_breach"])
        base = summ["design_unknown_whole_crd_baseline"]
        self.assertEqual(base, 46)
        r, summ = self.full(s, self.cases(70))
        self.assertTrue(summ["design_unknown_whole_crd_cap_breach"])
        self.assertEqual(summ["state"], "INCONCLUSIVE")
        self.assertEqual(summ["design_unknown_whole_crd_baseline"], 46)  # a regression never becomes the new normal
        self.assertEqual(json.load(open(s + "/status.json"))["design_unknown_whole_crd_baseline"], 46)

    def test_large_drop_is_informational(self):
        s = tempfile.mkdtemp()
        self.full(s, self.cases(40))
        r, summ = self.full(s, self.cases(10))
        self.assertTrue(summ["design_unknown_whole_crd_drop"])
        self.assertFalse(summ["design_unknown_whole_crd_cap_breach"])
        self.assertIn("DROP", r.stdout)

    def test_baseline_does_not_excuse_design_candidate_regression(self):
        s = tempfile.mkdtemp()
        json.dump(["crd|k0", "crd|plain"], open(s + "/known-mismatch.json", "w"))
        cand = qalib.case("crd", "k0", mismatch=True, wholeCrdCandidate=True)
        plain = qalib.case("crd", "plain", mismatch=True)
        r, summ = self.run_summary(s, [cand, plain])
        self.assertEqual((summ["mismatch"], summ["new_mismatch"], r.returncode), (2, 1, 2))
        self.assertEqual([c["key"] for c in summ["new_mismatch_cases"]], ["k0"])


if __name__ == "__main__":
    unittest.main()
