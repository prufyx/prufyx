"""Mutation tests for the fail-open defects of the CRD wrong-PASS oracle. Stdlib only, no network, no git, no binaries.

run: python3 -I -m unittest discover -s scripts/qa-auto -p 'test_oracle_failopen.py'
"""
import json, os, sys, tempfile, types, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ["QA_TMP"] = tempfile.mkdtemp(prefix="qa-oracle-test-")
import crd_oracle as co  # noqa: E402
from qalib import doc_name  # noqa: E402

A = ("g.io", "v1alpha1", "Foo")
B = ("g.io", "v1alpha1", "Bar")


def loc(gvk):
    return {"file": "f.yaml", "document": 0, "item": 0, "kind": gvk[2], "name": doc_name(*gvk)}


def scan(verdict="UNKNOWN", findings=(), fam=("PASS",)):
    return {"verdict": verdict, "findings": [{"ruleId": "r", "locations": [loc(g)]} for g in findings],
            "paths": [{"hops": [{"families": [{"family": "crd.custom_resource_versions", "status": s} for s in fam]}]}]}


class Judge(unittest.TestCase):
    def test_two_removed_one_unrelated_finding_family_pass_is_wrongpass(self):
        # counterexample: two GVKs removed, the scan reports one unrelated finding and a family PASS, aggregate UNKNOWN
        wp, mm, d = co.judge(1, scan(findings=[("g.io", "v1", "Other")]), [A, B])
        self.assertTrue(wp)
        self.assertFalse(mm)
        self.assertEqual(d["uncovered"], ["g.io/v1alpha1/Foo", "g.io/v1alpha1/Bar"])

    def test_one_of_two_covered_other_family_pass_is_wrongpass(self):
        wp, _, d = co.judge(2, scan("BLOCKED", findings=[A]), [A, B])
        self.assertTrue(wp)
        self.assertEqual(d["uncovered"], ["g.io/v1alpha1/Bar"])

    def test_all_covered_blocked_is_ok(self):
        wp, mm, _ = co.judge(2, scan("BLOCKED", findings=[A, B], fam=("BLOCKED",)), [A, B])
        self.assertFalse(wp)
        self.assertFalse(mm)

    def test_unmatched_without_pass_claim_is_mismatch_not_wrongpass(self):
        wp, mm, _ = co.judge(1, scan("UNKNOWN", findings=[A], fam=("BLOCKED",)), [A, B])
        self.assertFalse(wp)
        self.assertTrue(mm)

    def test_no_findings_unknown_is_mismatch(self):
        wp, mm, _ = co.judge(1, scan("UNKNOWN", fam=()), [A])
        self.assertFalse(wp)
        self.assertTrue(mm)

    def test_exit_zero_or_pass_verdict_is_wrongpass_even_with_findings(self):
        self.assertTrue(co.judge(0, scan("UNKNOWN", findings=[A], fam=()), [A])[0])
        self.assertTrue(co.judge(1, scan("SCOPE_COMPLETE_PASS", findings=[A], fam=()), [A])[0])

    def test_finding_for_other_kind_with_same_name_does_not_cover(self):
        j = scan("BLOCKED", findings=[A], fam=("PASS",))
        j["findings"][0]["locations"][0]["kind"] = "Baz"
        self.assertTrue(co.judge(2, j, [A])[0])

    def test_malformed_scan_is_not_covered(self):
        for j in ({}, {"findings": "x", "paths": 3}, {"findings": [None, {"locations": [None, 1]}]}):
            wp, mm, _ = co.judge(1, j, [A])
            self.assertFalse(wp)
            self.assertTrue(mm)

    def test_nothing_removed_unchanged(self):
        self.assertEqual(co.judge(0, scan(fam=("PASS",)), [])[:2], (False, False))
        self.assertEqual(co.judge(1, scan("BLOCKED", findings=[A], fam=()), [])[:2], (False, True))
        self.assertEqual(co.judge(1, scan("UNKNOWN", fam=("BLOCKED",)), [])[:2], (False, True))


def proc(rc=0, out="", err=""):
    return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)


TARGET = {"paths": [{"path": "crds", "directory": True, "match": r"\.yaml$"}]}
OK_JSON = json.dumps([{"G": "g.io", "V": "v1", "K": "Foo", "Served": True, "Store": True}]) + "\n"


class FakeSh:
    """Replaces crd_oracle.sh: scripted git ls-tree / git show / crdgvk answers."""
    def __init__(self, tree=None, show=None, gvk=None):
        self.tree = tree or proc(0, "crds/a.yaml\n")
        self.show = show or proc(0, "kind: CustomResourceDefinition\n")
        self.gvk = gvk or proc(0, OK_JSON)

    def __call__(self, *a, inp=None, cwd=None):
        if a[0] == "git":
            return self.tree if "ls-tree" in a else self.show
        return self.gvk


class ExpectedSet(unittest.TestCase):
    def setUp(self):
        self._sh = co.sh

    def tearDown(self):
        co.sh = self._sh

    def served(self, **kw):
        co.sh = FakeSh(**kw)
        return co.served_set(TARGET, "gd", "v1.0.0")

    def test_baseline_reads(self):
        self.assertEqual(self.served(), {("g.io", "v1", "Foo")})

    def test_git_show_failure_raises(self):
        with self.assertRaises(co.ExpectedSetError):
            self.served(show=proc(128, "", "fatal: bad object"))

    def test_git_ls_tree_failure_raises(self):
        with self.assertRaises(co.ExpectedSetError):
            self.served(tree=proc(128, "", "fatal: not a tree"))

    def test_empty_show_raises(self):
        with self.assertRaises(co.ExpectedSetError):
            self.served(show=proc(0, "  \n"))

    def test_fixed_path_absent_at_tag_is_a_fact_but_failing_lookup_is_not(self):
        global TARGET
        old, TARGET = TARGET, {"paths": [{"path": "config/x.yaml"}]}
        try:
            self.assertEqual(self.served(tree=proc(0, ""), gvk=proc(0, "[]\n")), set())
            with self.assertRaises(co.ExpectedSetError):
                self.served(tree=proc(128, "", "fatal"))
        finally:
            TARGET = old

    def test_truncated_crdgvk_output_raises(self):
        with self.assertRaises(co.ExpectedSetError):
            self.served(gvk=proc(0, OK_JSON[:30]))

    def test_crdgvk_nonzero_exit_raises_even_with_json(self):
        with self.assertRaises(co.ExpectedSetError):
            self.served(gvk=proc(1, OK_JSON, "crdgvk: yaml: boom"))

    def test_crdgvk_empty_list_for_crd_text_raises(self):
        with self.assertRaises(co.ExpectedSetError):
            self.served(gvk=proc(0, "[]\n"))

    def test_crdgvk_wrong_shape_raises(self):
        for out in ('{"G":"x"}\n', '[{"G":"x"}]\n', "null\n", ""):
            with self.assertRaises(co.ExpectedSetError):
                self.served(gvk=proc(0, out))

    def test_failing_git_show_becomes_error_case_not_shrunk_set(self):
        co.sh = FakeSh(show=proc(128, "", "fatal"))
        lines = {(1, 0): ["v1.0.0"], (1, 1): ["v1.1.0"]}
        called = []
        real = co.prufyx
        co.prufyx = lambda *a, **k: called.append(a) or (0, {}, "")
        try:
            out = co.compare_pairs("p", TARGET, "gd", "v", lines, [{"from": "1.0", "to": "1.1"}])
        finally:
            co.prufyx = real
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0]["error"])
        self.assertFalse(out[0]["wrongpass"] or out[0]["mismatch"])
        self.assertEqual(called, [], "no scan may run against an unknown expected set")


if __name__ == "__main__":
    unittest.main()
