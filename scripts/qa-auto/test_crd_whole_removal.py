"""Whole-CRD removal class: documented-design UNKNOWN is its own status; every other outcome stays fail-closed."""
import json, os, subprocess, sys, tempfile, unittest

import crd_oracle as crd
import qalib

W1 = ("a.example", "v1", "Gone")
W2 = ("a.example", "v1", "AlsoGone")
V1 = ("b.example", "v1beta1", "Old")
P = "proj"
FAM = "crd.custom_resource_versions"


def unknown(findings=()):
    return {"verdict": "UNKNOWN", "findings": list(findings), "paths": []}


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


class Counters(unittest.TestCase):
    def cases(self, n):
        return [qalib.case("crd", f"k{i}", status="DESIGN_UNKNOWN_WHOLE_CRD_REMOVAL") for i in range(n)] + [qalib.case("crd", "z")]

    def test_counts(self):
        self.assertEqual(qalib.counts(self.cases(2)), {"wrongpass": 0, "mismatch": 0, "error": 0, "design_unknown_whole_crd_removal": 2})
        self.assertNotIn("design_unknown_whole_crd_removal", qalib.counts(self.cases(0)))

    def run_summary(self, state, cases):
        d = tempfile.mkdtemp()
        json.dump(cases, open(d + "/crd.cases.json", "w"))
        r = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "summarize.py"),
                            "--dir", d, "--state", state, "--sha", "a" * 40, "--mode", "none"], capture_output=True, text=True)
        return r, json.load(open(d + "/summary.json"))

    def test_summary_count_and_rise_flag(self):
        s = tempfile.mkdtemp()
        r, summ = self.run_summary(s, self.cases(2))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(summ["design_unknown_whole_crd_removal"], 2)
        self.assertTrue(summ["design_unknown_whole_crd_rise"])
        self.assertIn("DESIGN_UNKNOWN_WHOLE_CRD=2 RISE", r.stdout)
        self.assertEqual(summ["mismatch"], 0)
        r, summ = self.run_summary(s, self.cases(2))
        self.assertFalse(summ["design_unknown_whole_crd_rise"])
        self.assertNotIn("RISE", r.stdout)
        r, summ = self.run_summary(s, self.cases(3))
        self.assertTrue(summ["design_unknown_whole_crd_rise"])
        self.assertEqual(json.load(open(s + "/status.json"))["design_unknown_whole_crd_removal"], 3)


if __name__ == "__main__":
    unittest.main()
