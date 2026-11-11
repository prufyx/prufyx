"""Removals of CRDs no reviewed project owns: the product cannot attribute them, so the pair is UNOWNED_REMOVAL_UNKNOWN
(counted on its own, capped), never a mismatch; any finding naming one, or any PASS, stays a mismatch or WRONGPASS."""
import json, os, subprocess, sys, tempfile, unittest
from unittest.mock import patch

import crd_oracle as crd
import qalib
import test_support

HERE = os.path.dirname(os.path.abspath(__file__))
P = "rook"
S = "UNOWNED_REMOVAL_UNKNOWN"
LISTED = {"ceph.rook.io": None}
OWNED = [("ceph.rook.io", "v1", "CephCluster")]
UNOWNED = [("csi.ceph.io", "v1alpha1", k) for k in ("CephConnection", "ClientProfile", "ClientProfileMapping", "Driver", "OperatorConfig")]
FAM = "crd.custom_resource_versions"


def finding(item, component=P):
    g, v, k = item
    return {"component": component, "ruleId": "r", "locations": [{"kind": k, "name": crd.object_name(g, v, k)}]}


def gap(n):
    return {"component": P, "reason": "DOCUMENTS_NOT_EVALUATED",
            "detail": f"{n} manifest(s) use custom-resource groups that no reviewed project owns, so no custom-resource set is complete"}


def unknown(findings=(), gaps=None):
    return {"verdict": "UNKNOWN", "findings": list(findings), "gaps": [gap(5)] if gaps is None else gaps, "paths": []}


def blocked(findings):
    return {"verdict": "BLOCKED", "findings": list(findings), "gaps": [],
            "paths": [{"component": P, "hops": [{"status": "BLOCKED", "families": [{"family": FAM, "status": "BLOCKED"}]}]}]}


class Classify(unittest.TestCase):
    def setUp(self):
        for mod in (crd, qalib):
            p = patch.object(mod, "removal_claim", lambda *a: True)
            p.start()
            self.addCleanup(p.stop)

    def pair(self, code, rep, removed, whole=(), listed=LISTED, served=None):
        served = set(OWNED + UNOWNED) if served is None else served
        return crd.classify_pair(code, rep, list(removed), list(whole), P, served=served, listed=listed)

    def test_all_unowned_unknown_is_own_status_no_mismatch(self):
        wp, mm, missing, _, design, clause = self.pair(11, unknown(), UNOWNED)
        self.assertEqual((wp, mm, missing, design, clause), (False, False, [], False, "UNOWNED_UNKNOWN"))

    def test_unknown_without_the_unowned_gap_is_mismatch(self):
        for gaps in ([], [gap(4)], [gap(6)], [gap(5), gap(5)], [{"component": P, "reason": "COMPONENT_NOT_COVERED"}],
                     [dict(gap(5), component="other")]):
            r = self.pair(11, unknown(gaps=gaps), UNOWNED)
            self.assertEqual((r[0], r[1], r[5]), (False, True, "UNOWNED_GAP"), gaps)
        r = crd.classify_pair(11, unknown(), UNOWNED, [], P, served=None, listed=LISTED)
        self.assertEqual((r[1], r[5]), (True, "UNOWNED_GAP"))

    def test_ruleid_naming_unowned_is_attribution(self):
        f = {"component": P, "ruleId": "x/" + "/".join(UNOWNED[0]), "locations": []}
        self.assertEqual(self.pair(10, blocked([f]), UNOWNED)[5], "UNOWNED_ATTRIBUTED")

    def test_group_listed_with_kinds_owns_only_those(self):
        listed = {"csi.ceph.io": {"Driver"}, "ceph.rook.io": None}
        self.assertEqual(crd.split_unowned(UNOWNED, listed)[1], [x for x in UNOWNED if x[2] != "Driver"])
        r = self.pair(11, unknown(gaps=[gap(4)]), UNOWNED[:2], listed=listed, served=set(UNOWNED))
        self.assertEqual((r[1], r[5]), (False, "UNOWNED_UNKNOWN"))
        r = self.pair(11, unknown(), UNOWNED, listed={"csi.ceph.io": []}, served=set(UNOWNED))
        self.assertEqual(r[5], "UNOWNED_UNKNOWN")
        self.assertEqual(crd.split_unowned(UNOWNED, {"csi.ceph.io": None}), (UNOWNED, []))

    def test_old_behaviour_without_ownership_is_mismatch(self):
        self.assertTrue(self.pair(11, unknown(), UNOWNED, listed=None)[1])

    def test_unreadable_table_is_no_reclassification(self):
        r = self.pair(11, unknown(), UNOWNED, listed=None)
        self.assertEqual((r[1], r[5]) , (True, "NO_WHOLE"))
        self.assertEqual(sorted(r[2]), sorted("/".join(x) for x in UNOWNED))
        self.assertEqual(crd.split_unowned(UNOWNED, None), (UNOWNED, []))

    def test_unowned_must_not_be_excused_into_pass(self):
        for code, rep in ((0, {"verdict": "PASS", "findings": []}), (0, {"verdict": "SCOPE_COMPLETE_PASS"}),
                          (11, {"verdict": "UNKNOWN", "findings": [], "paths": [{"component": P, "hops": [
                              {"families": [{"family": FAM, "status": "PASS"}]}]}]})):
            r = self.pair(code, rep, UNOWNED)
            self.assertEqual((r[0], r[1]), (True, False), rep)

    def test_finding_naming_unowned_is_mismatch(self):
        r = self.pair(10, blocked([finding(UNOWNED[0])]), UNOWNED)
        self.assertEqual((r[0], r[1], r[5]), (False, True, "UNOWNED_ATTRIBUTED"))
        self.assertIn("/".join(UNOWNED[0]), r[2])

    def test_unowned_with_other_verdict_or_exit_is_mismatch(self):
        for code, rep in ((10, blocked([])), (12, unknown()), (11, {"verdict": "BLOCKED", "findings": []}), (11, unknown([{"component": P}]))):
            r = self.pair(code, rep, UNOWNED)
            self.assertTrue(r[1] and not r[0], (code, rep))

    def test_mixed_owned_reported_unowned_silent_is_ok(self):
        r = self.pair(10, blocked([finding(OWNED[0])]), OWNED + UNOWNED)
        self.assertEqual((r[0], r[1], r[5]), (False, False, "UNOWNED_UNKNOWN"))

    def test_mixed_missing_owned_finding_is_mismatch(self):
        r = self.pair(10, blocked([]), OWNED + UNOWNED)
        self.assertEqual((r[0], r[1]), (False, True))
        self.assertEqual(r[2], ["/".join(OWNED[0])])
        r = self.pair(11, unknown(), OWNED + UNOWNED)
        self.assertTrue(r[1])

    def test_mixed_pass_is_wrongpass(self):
        self.assertTrue(self.pair(0, {"verdict": "PASS"}, OWNED + UNOWNED)[0])

    def test_mixed_finding_naming_unowned_is_mismatch(self):
        r = self.pair(10, blocked([finding(OWNED[0]), finding(UNOWNED[1])]), OWNED + UNOWNED)
        self.assertEqual((r[0], r[1], r[5]), (False, True, "UNOWNED_ATTRIBUTED"))

    def test_whole_crd_removals_keep_their_own_class(self):
        self.assertEqual(crd.split_unowned(UNOWNED, LISTED, set(UNOWNED[:2])), (UNOWNED[:2], UNOWNED[2:]))

    def test_whole_crd_plus_unowned_keeps_old_shape(self):
        whole = [("a.example", "v1", "Gone")]
        for code, rep in ((11, unknown()), (11, unknown(gaps=[{"component": P, "reason": "COMPONENT_NOT_COVERED"}]))):
            new = crd.classify_pair(code, rep, whole + UNOWNED, whole, P, {"b.example"}, set(whole + UNOWNED), LISTED)
            old = crd.classify_owned(code, rep, whole + UNOWNED, whole, P, {"b.example"}, set(whole + UNOWNED), LISTED)
            self.assertEqual(new, old)
            self.assertNotEqual(new[5], "UNOWNED_UNKNOWN")

    def test_unowned_served_never_excuses_unseen_removal(self):
        # invariant: a removal the scanner cannot see is never excused by the unowned-group gap count
        served = {("x.example", "v1", "Foreign")}
        self.assertEqual(crd.unowned_served(served, UNOWNED, LISTED), set())
        self.assertEqual(crd.unowned_served(served, OWNED, LISTED), served)


class Execute(unittest.TestCase):
    def test_case_status_and_detail(self):
        sf = set(OWNED + UNOWNED)
        plan = dict(proj=P, pref="v", metadata=set(), excluded=[], later_groups={},
                    jobs=[("crd|rook|v1|v2", "v1", "v2", sf, sorted(UNOWNED), [])])
        rep = dict(unknown(), summary={"documentsRead": len(sf), "documentsOmitted": 0}, omitted=[])
        with patch.object(crd, "prufyx", return_value=(11, rep, "")), patch.object(crd, "write_private"), patch.object(os, "remove"), \
                patch.object(crd, "listed_groups", return_value=LISTED):
            out, _, _ = crd.execute(plan)
        d = out[0]["detail"]
        self.assertEqual((out[0]["mismatch"], out[0]["wrongpass"], out[0]["error"], d["status"]), (False, False, False, S))
        self.assertEqual(sorted(d["unownedRemoved"]), sorted("/".join(x) for x in UNOWNED))
        self.assertEqual(qalib.counts(out)["unowned_removal_unknown"], 5)


class RealShape(unittest.TestCase):
    """Real scanner output (rook v1.17.0 -> v1.18.0, 24 documents) captured from the built command."""
    def load(self):
        with open(os.path.join(HERE, "testdata", "rook_unowned_removal_scan.json")) as f:
            d = json.load(f)
        t = lambda xs: [tuple(x.split("/")) for x in xs]
        return d["report"], t(d["removed"]), set(t(d["served"]))

    def test_real_report_is_unowned_unknown(self):
        rep, removed, served = self.load()
        r = crd.classify_pair(11, rep, removed, [], "rook", served=served, listed=crd.listed_groups())
        self.assertEqual((r[0], r[1], r[5]), (False, False, "UNOWNED_UNKNOWN"))

    def test_real_report_fail_closed(self):
        rep, removed, served = self.load()
        L = crd.listed_groups()
        self.assertEqual(crd.classify_pair(0, dict(rep, verdict="PASS", gaps=[]), removed, [], "rook", served=served, listed=L)[0], True)
        self.assertEqual(crd.classify_pair(11, dict(rep, gaps=rep["gaps"][:1]), removed, [], "rook", served=served, listed=L)[5], "UNOWNED_GAP")
        f = {"component": "rook", "ruleId": "r", "locations": [{"kind": removed[0][2], "name": crd.object_name(*removed[0])}]}
        self.assertEqual(crd.classify_pair(10, dict(rep, verdict="BLOCKED", findings=[f]), removed, [], "rook", served=served, listed=L)[5], "UNOWNED_ATTRIBUTED")

    def test_case_detail_carries_clause(self):
        rep, removed, served = self.load()
        plan = dict(proj="rook", pref="v", metadata=set(), excluded=[], later_groups={}, jobs=[("crd|rook|a|b", "a", "b", served, removed, [])])
        for code, report, clause in ((11, rep, "UNOWNED_UNKNOWN"), (11, dict(rep, gaps=[]), "UNOWNED_GAP")):
            with patch.object(crd, "prufyx", return_value=(code, report, "")), patch.object(crd, "write_private"), patch.object(os, "remove"):
                out, _, _ = crd.execute(plan)
            self.assertEqual(out[0]["detail"]["clause"], clause)


class Summary(unittest.TestCase):
    def cases(self, pairs):
        return [qalib.case("crd", f"p{i}", status=S, unownedRemoved=["g/v/k%d" % j for j in range(5)]) for i in range(pairs)]

    def run_summary(self, state, cases, mode="full"):
        d = tempfile.mkdtemp()
        json.dump(cases, open(d + "/crd.cases.json", "w"))
        if mode == "full":
            test_support.complete_full_run(d, "a" * 40)
        r = subprocess.run([sys.executable, os.path.join(HERE, "summarize.py"), "--dir", d, "--state", state, "--sha", "a" * 40, "--mode", mode],
                           capture_output=True, text=True)
        return r, json.load(open(d + "/summary.json"))

    def test_counted_in_own_field_not_mismatch(self):
        r, summ = self.run_summary(tempfile.mkdtemp(), self.cases(4))
        self.assertEqual((summ["unowned_removal_unknown"], summ["mismatch"], summ["unowned_removal_unknown_cap_breach"]), (20, 0, False))
        self.assertIn("UNOWNED_REMOVAL_UNKNOWN=20", r.stdout)
        self.assertEqual(summ["unowned_removal_unknown_baseline"], 20)

    def test_baseline_rise_is_inconclusive_and_baseline_kept(self):
        s = tempfile.mkdtemp()
        self.run_summary(s, self.cases(4))
        r, summ = self.run_summary(s, self.cases(5))
        self.assertTrue(summ["unowned_removal_unknown_rise"])
        self.assertTrue(summ["unowned_removal_unknown_cap_breach"])
        self.assertEqual((summ["state"], r.returncode), ("INCONCLUSIVE", 3))
        self.assertIn("UNOWNED_CAP", r.stdout)
        self.assertEqual(json.load(open(s + "/status.json"))["unowned_removal_unknown_baseline"], 20)

    def test_equal_count_is_green_of_this_field(self):
        s = tempfile.mkdtemp()
        self.run_summary(s, self.cases(4))
        r, summ = self.run_summary(s, self.cases(4))
        self.assertFalse(summ["unowned_removal_unknown_rise"])
        self.assertFalse(summ["unowned_removal_unknown_cap_breach"])

    def test_zero_is_kept_as_baseline_and_drop_noted(self):
        s = tempfile.mkdtemp()
        self.run_summary(s, self.cases(4))
        r, summ = self.run_summary(s, [qalib.case("crd", "z")])
        self.assertEqual((summ["unowned_removal_unknown_baseline"], summ["unowned_removal_unknown_drop"]), (0, True))
        self.assertIn("UNOWNED_DROP", r.stdout)
        self.assertEqual(json.load(open(s + "/status.json"))["unowned_removal_unknown_baseline"], 0)
        r, summ = self.run_summary(s, self.cases(2))  # from a zero baseline any growth past +5 is a breach; below is a rise
        self.assertTrue(summ["unowned_removal_unknown_rise"])
        r, summ = self.run_summary(s, self.cases(2))
        self.assertTrue(summ["unowned_removal_unknown_cap_breach"])  # 10 > 0 + 5
        self.assertEqual(summ["unowned_removal_unknown_baseline"], 0)

    def test_errored_run_does_not_store_baseline(self):
        s = tempfile.mkdtemp()
        self.run_summary(s, self.cases(4))
        r, summ = self.run_summary(s, self.cases(1) + [qalib.case("crd", "e", error=True)])
        self.assertEqual(summ["unowned_removal_unknown_baseline"], 20)
        self.assertEqual(json.load(open(s + "/status.json"))["unowned_removal_unknown_baseline"], 20)

    def test_oracle_digest_reset_keeps_the_hard_cap(self):
        s = tempfile.mkdtemp()
        self.run_summary(s, self.cases(4))
        st = json.load(open(s + "/status.json"))
        st["oracle_digest"] = "0" * 64
        json.dump(st, open(s + "/status.json", "w"))
        r, summ = self.run_summary(s, self.cases(5))
        self.assertTrue(summ["unowned_removal_unknown_cap_breach"])
        self.assertEqual((summ["state"], r.returncode), ("INCONCLUSIVE", 3))
        self.assertEqual(json.load(open(s + "/status.json"))["unowned_removal_unknown_baseline"], 20)

    def test_error_case_not_counted(self):
        c = qalib.case("crd", "e", error=True, status=S, unownedRemoved=["g/v/k"])
        self.assertNotIn("unowned_removal_unknown", qalib.counts([c]))


if __name__ == "__main__":
    unittest.main()
