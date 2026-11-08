"""Mixed whole-CRD signature, persisted diagnostics, explained-gap registry and oracle-change rise reset."""
import json, os, subprocess, sys, tempfile, unittest
from unittest.mock import patch

import crd_oracle as crd
import qalib

HERE = os.path.dirname(os.path.abspath(__file__))
P = "proj"
W = ("a.example", "v1", "Gone")
V1 = ("b.example", "v1alpha2", "Old")
V2 = ("b.example", "v1alpha2", "Older")
D = "DESIGN_UNKNOWN_WHOLE_CRD_REMOVAL"


def finding(item, component=P):
    g, v, k = item
    return {"component": component, "ruleId": "r", "locations": [{"kind": k, "name": crd.object_name(g, v, k)}]}


def blocked(findings, gaps=(), **extra):
    rep = {"verdict": "BLOCKED", "findings": list(findings), "gaps": list(gaps),
           "paths": [{"component": P, "hops": [{"status": "BLOCKED", "reasons": [], "families": [{"family": crd.FAMILY if hasattr(crd, "FAMILY") else "crd.custom_resource_versions", "status": "BLOCKED"}]}]}]}
    rep.update(extra)
    return rep


GAP = {"component": P, "reason": "COMPONENT_NOT_COVERED"}


class Mixed(unittest.TestCase):
    def setUp(self):
        for mod in (crd, qalib):
            p = patch.object(mod, "removal_claim", lambda *a: True)
            p.start()
            self.addCleanup(p.stop)

    def verdict(self, code, rep, removed=(W, V1, V2), whole=(W,)):
        return crd.crd_verdict(code, rep, list(removed), list(whole), P)

    def test_exact_version_findings_blocked_is_design(self):
        r = self.verdict(10, blocked([finding(V1), finding(V2)], [GAP]))
        self.assertEqual((r[0], r[1], r[2], r[4]), (False, False, [], True))

    def test_exact_with_no_gap_is_not_design(self):
        rep = blocked([finding(V1), finding(V2)])
        r = crd.classify_pair(10, rep, [W, V1, V2], [W], P)
        self.assertEqual((r[1], r[4], r[5]), (True, False, "NO_GAP"))

    def test_non_dict_finding_is_mismatch(self):
        for bad in ("x", None, 3):
            r = self.verdict(10, blocked([finding(V1), finding(V2), bad], [GAP]))
            self.assertEqual((r[1], r[4]), (True, False), bad)

    def test_missing_version_finding_is_mismatch(self):
        r = self.verdict(10, blocked([finding(V1)], [GAP]))
        self.assertEqual((r[0], r[1], r[4]), (False, True, False))
        self.assertIn("/".join(V2), r[2])

    def test_extra_finding_is_mismatch(self):
        extra = finding(("c.example", "v1", "Stray"))
        r = self.verdict(10, blocked([finding(V1), finding(V2), extra], [GAP]))
        self.assertEqual((r[1], r[4]), (True, False))
        r = self.verdict(10, blocked([finding(V1), finding(V2), finding(V1, "other")], [GAP]))
        self.assertEqual((r[1], r[4]), (True, False))

    def test_foreign_gap_reason_or_component_is_mismatch(self):
        for gaps in ([{"component": P, "reason": "VERSION_NOT_DETECTED"}], [GAP, {"component": "o", "reason": "COMPONENT_NOT_COVERED"}], ["x"]):
            r = self.verdict(10, blocked([finding(V1), finding(V2)], gaps))
            self.assertEqual((r[1], r[4]), (True, False), gaps)

    def test_unsupported_or_omitted_is_mismatch(self):
        for extra in ({"unsupported": [{"x": 1}]}, {"omitted": [{"x": 1}]}):
            r = self.verdict(10, blocked([finding(V1), finding(V2)], [GAP], **extra))
            self.assertEqual((r[1], r[4]), (True, False))

    def test_other_exit_or_verdict_is_mismatch(self):
        rep = blocked([finding(V1), finding(V2)], [GAP])
        for code, r_ in ((11, dict(rep, verdict="UNKNOWN")), (12, rep), (10, dict(rep, verdict="UNKNOWN")), (11, rep)):
            r = self.verdict(code, r_)
            self.assertEqual((r[1], r[4]), (True, False), (code, r_["verdict"]))

    def test_pass_is_wrongpass(self):
        r = self.verdict(0, {"verdict": "PASS", "findings": []})
        self.assertEqual((r[0], r[4]), (True, False))
        rep = blocked([finding(V1), finding(V2)], [GAP])
        rep["paths"][0]["hops"][0]["families"][0]["status"] = "PASS"
        r = self.verdict(10, rep)
        self.assertEqual((r[0], r[4]), (True, False))


def unowned(n, component=P):
    return {"component": component, "reason": "DOCUMENTS_NOT_EVALUATED",
            "detail": f"{n} manifest(s) use custom-resource groups that no reviewed project owns, so no custom-resource set is complete"}


def unknown_only(gaps):
    return {"verdict": "UNKNOWN", "findings": [], "gaps": list(gaps),
            "paths": [{"component": P, "hops": [{"status": "NO_DATA", "reasons": ["COMPONENT_NOT_COVERED"]}]}]}


LG = {"b.example"}  # groups with a CRD left at the later release: the whole-removed group a.example is gone


class UnownedGroupGap(unittest.TestCase):
    """The scanner also reports how many manifests belong to a group no project owns (a CRD gone at the target): design only when
    that count is exactly the number of whole-CRD removals."""
    def setUp(self):
        for mod in (crd, qalib):
            p = patch.object(mod, "removal_claim", lambda *a: True)
            p.start()
            self.addCleanup(p.stop)

    def mixed(self, gaps, findings=(V1, V2), whole=(W,), code=10, **extra):
        rep = blocked([finding(x) for x in findings], gaps, **extra)
        return crd.classify_pair(code, rep, [*whole, V1, V2], list(whole), P, LG)

    def test_mixed_with_matching_count_is_design(self):
        r = self.mixed([GAP, unowned(1)])
        self.assertEqual((r[0], r[1], r[2], r[4], r[5]), (False, False, [], True, "OK"))
        r = self.mixed([unowned(2), GAP], whole=(W, ("a.example", "v1", "Gone2")))
        self.assertEqual((r[1], r[4]), (False, True))

    def test_whole_only_with_matching_count_is_design(self):
        r = crd.classify_pair(11, unknown_only([GAP, unowned(1)]), [W], [W], P, LG)
        self.assertEqual((r[0], r[1], r[4], r[5]), (False, False, True, "OK"))
        w2, w3 = ("c.example", "v1", "Gone2"), ("d.example", "v1", "Gone3")
        r = crd.classify_pair(11, unknown_only([GAP, unowned(3)]), [W, w2, w3], [W, w2, w3], P, LG)
        self.assertEqual((r[1], r[4]), (False, True))

    def test_count_must_equal_the_whole_removals(self):
        for n in (0, 2, 3, 99):
            r = self.mixed([GAP, unowned(n)])
            self.assertEqual((r[1], r[4], r[5]), (True, False, "GAP_UNOWNED"), n)
            r = crd.classify_pair(11, unknown_only([GAP, unowned(n)]), [W], [W], P, LG)
            self.assertEqual((r[1], r[4], r[5]), (True, False, "GAP_UNOWNED"), n)

    def test_malformed_or_repeated_unowned_gap_is_mismatch(self):
        for bad in ({"component": P, "reason": "DOCUMENTS_NOT_EVALUATED"},
                    {"component": P, "reason": "DOCUMENTS_NOT_EVALUATED", "detail": 1},
                    {"component": P, "reason": "DOCUMENTS_NOT_EVALUATED", "detail": "1 manifest(s) use something else"},
                    {"component": P, "reason": "DOCUMENTS_NOT_EVALUATED", "detail": "x1 manifest(s) use custom-resource groups that no reviewed project owns"},
                    unowned(1, "other")):
            r = self.mixed([GAP, bad])
            self.assertEqual((r[1], r[4]), (True, False), bad)
        r = self.mixed([GAP, unowned(1), unowned(1)])
        self.assertEqual((r[1], r[4], r[5]), (True, False, "GAP_UNOWNED"))

    def test_unowned_gap_without_the_design_gap_is_mismatch(self):
        r = self.mixed([unowned(1)])
        self.assertEqual((r[1], r[4], r[5]), (True, False, "NO_GAP"))

    def test_unowned_gap_never_hides_extra_or_missing_findings(self):
        r = self.mixed([GAP, unowned(1)], findings=(V1, V2, ("c.example", "v1", "Stray")))
        self.assertEqual((r[1], r[4], r[5]), (True, False, "EXTRA_FINDING"))
        r = self.mixed([GAP, unowned(1)], findings=(V1,))
        self.assertEqual((r[1], r[4], r[5]), (True, False, "VERSION_MISSING"))
        self.assertIn("/".join(V2), r[2])
        r = self.mixed([GAP, unowned(1)], findings=(V1, V2), unsupported=[{"x": 1}])
        self.assertEqual((r[1], r[4], r[5]), (True, False, "UNSUPPORTED"))

    def test_other_exit_or_verdict_with_unowned_gap_is_mismatch(self):
        r = crd.classify_pair(10, unknown_only([GAP, unowned(1)]), [W], [W], P, LG)
        self.assertEqual((r[1], r[4]), (True, False))
        r = crd.classify_pair(11, dict(unknown_only([GAP, unowned(1)]), verdict="BLOCKED"), [W], [W], P, LG)
        self.assertEqual((r[1], r[4]), (True, False))
        rep = unknown_only([GAP, unowned(1)])
        rep["paths"][0]["hops"][0]["reasons"] = ["DOCUMENTS_NOT_EVALUATED"]
        self.assertEqual(crd.classify_pair(11, rep, [W], [W], P, LG)[5], "HOP_REASON")

    def test_pass_with_unowned_gap_stays_wrongpass(self):
        rep = {"verdict": "PASS", "findings": [], "gaps": [GAP, unowned(1)]}
        for removed in ([W], [W, V1, V2]):
            r = crd.classify_pair(0, rep, removed, [W], P, LG)
            self.assertEqual((r[0], r[4]), (True, False), removed)
        rep = blocked([finding(V1), finding(V2)], [GAP, unowned(1)])
        rep["paths"][0]["hops"][0]["families"][0]["status"] = "PASS"
        r = crd.classify_pair(10, rep, [W, V1, V2], [W], P, LG)
        self.assertEqual((r[0], r[4]), (True, False))

    def test_group_still_defined_or_unread_is_not_accepted(self):
        # the removed kind sits in a group that still has CRDs at the later release (the under-report shape): no allowance
        for groups in ({"a.example"}, {"a.example", "b.example"}, None):
            r = crd.classify_pair(11, unknown_only([GAP, unowned(1)]), [W], [W], P, groups)
            self.assertEqual((r[1], r[4], r[5]), (True, False, "GAP_UNOWNED"), groups)
            r = crd.classify_pair(10, blocked([finding(V1), finding(V2)], [GAP, unowned(1)]), [W, V1, V2], [W], P, groups)
            self.assertEqual((r[1], r[4], r[5]), (True, False, "GAP_UNOWNED"), groups)
        # two whole removals, only one of them from a vanished group: refused as a whole
        w2 = ("c.example", "v1", "Gone2")
        r = crd.classify_pair(11, unknown_only([GAP, unowned(1)]), [W, w2], [W, w2], P, {"c.example"})
        self.assertEqual((r[1], r[4], r[5]), (True, False, "GAP_UNOWNED"))
        r = crd.classify_pair(11, unknown_only([GAP, unowned(2)]), [W, w2], [W, w2], P, {"c.example"})
        self.assertEqual((r[1], r[4], r[5]), (True, False, "GAP_UNOWNED"))

    def test_no_whole_removal_means_no_unowned_allowance(self):
        self.assertEqual(crd.whole_signal_clause(unknown_only([GAP, unowned(1)]), P, 0), "GAP_UNOWNED")


class WholeFixture(unittest.TestCase):
    """Fixed fixture: version-level removals inside still-defined CRDs must never be classified as whole-CRD removals."""
    REMOVED = [("core.oam.dev", "v1alpha2", "Application"), ("core.oam.dev", "v1alpha2", "ApplicationRevision"),
               ("pkg.example", "v1alpha1", "ControllerConfig")]
    DEFINED = {("core.oam.dev", "Application"), ("core.oam.dev", "ApplicationRevision")}

    def test_only_absent_kind_is_whole(self):
        self.assertEqual(crd.whole_removed(self.REMOVED, self.DEFINED), [("pkg.example", "v1alpha1", "ControllerConfig")])

    def test_classify_whole_through_defined_kinds(self):
        with patch.object(crd, "defined_kinds", return_value=self.DEFINED):
            self.assertEqual(crd.classify_whole({}, "gd", "v2", self.REMOVED, {}), [("pkg.example", "v1alpha1", "ControllerConfig")])
        with patch.object(crd, "defined_kinds", return_value=self.DEFINED | {("pkg.example", "ControllerConfig")}):
            self.assertEqual(crd.classify_whole({}, "gd", "v2", self.REMOVED, {}), [])

    def test_version_level_miss_is_not_excused_as_design(self):
        # scanner missed the Application removals while the CRD is still defined: nothing whole, so UNKNOWN stays a mismatch
        whole = crd.whole_removed(self.REMOVED[:2], self.DEFINED)
        self.assertEqual(whole, [])
        rep = {"verdict": "UNKNOWN", "findings": [], "gaps": [GAP],
               "paths": [{"component": P, "hops": [{"status": "NO_DATA", "reasons": ["COMPONENT_NOT_COVERED"]}]}]}
        r = crd.crd_verdict(11, rep, self.REMOVED[:2], whole, P)
        self.assertEqual((r[1], r[4]), (True, False))


class Diagnostics(unittest.TestCase):
    def test_clause_codes(self):
        d = crd.whole_diagnostics(11, {"verdict": "UNKNOWN", "findings": [{"component": P}], "gaps": [GAP], "paths": []}, P, True)
        self.assertEqual((d["scanExit"], d["verdict"], d["nFindings"], d["gapReasons"], d["clause"]), (11, "UNKNOWN", 1, ["COMPONENT_NOT_COVERED"], "FINDINGS"))
        rep = {"verdict": "UNKNOWN", "findings": [], "gaps": [GAP], "paths": [{"component": P, "hops": [{"status": "NO_DATA", "reasons": ["COMPONENT_NOT_COVERED"]}]}]}
        d = crd.whole_diagnostics(11, rep, P, True)
        self.assertEqual((d["clause"], d["hopStatuses"]), ("OK", ["NO_DATA"]))
        rep["gaps"] = [{"component": P, "reason": "X"}]
        self.assertEqual(crd.whole_diagnostics(11, rep, P, True)["clause"], "GAP_REASON")
        rep["gaps"] = [GAP]
        rep["paths"][0]["hops"][0]["status"] = "UNKNOWN"
        d = crd.whole_diagnostics(11, rep, P, True)
        self.assertEqual((d["clause"], d["hopStatuses"]), ("HOP_STATUS", ["UNKNOWN"]))
        self.assertEqual(crd.whole_diagnostics(11, {"verdict": "UNKNOWN", "unsupported": [1]}, P, True)["clause"], "UNSUPPORTED")

    def test_persisted_for_whole_candidates_only(self):
        rep = {"verdict": "UNKNOWN", "findings": [], "gaps": [GAP], "summary": {"documentsRead": 1, "documentsOmitted": 0}, "omitted": [],
               "paths": [{"component": P, "hops": [{"status": "NO_DATA", "reasons": ["COMPONENT_NOT_COVERED"]}]}]}
        plan = dict(proj=P, pref="v", metadata=set(), excluded=[], jobs=[("t", "v1", "v2", {W}, [W], [W])], proof_pairs={})
        with patch.object(crd, "prufyx", return_value=(11, rep, "")), patch.object(crd, "write_private"), patch.object(crd.os, "remove"):
            out = crd.execute(plan)[0]
        d = out[0]["detail"]
        self.assertEqual(d["status"], D)
        self.assertEqual(d["whole"]["clause"], "OK")
        plan["jobs"] = [("t", "v1", "v2", {W}, [W], [])]
        with patch.object(crd, "prufyx", return_value=(11, rep, "")), patch.object(crd, "write_private"), patch.object(crd.os, "remove"):
            out = crd.execute(plan)[0]
        self.assertNotIn("whole", out[0]["detail"])


def run_summary(state, cases, mode="none", env=None, skipped=None):
    d = tempfile.mkdtemp()
    json.dump(cases, open(d + "/crd.cases.json", "w"))
    if skipped is not None:
        json.dump(skipped, open(d + "/skipped.json", "w"))
    e = dict(os.environ, **(env or {}))
    r = subprocess.run([sys.executable, os.path.join(HERE, "summarize.py"), "--dir", d, "--state", state, "--sha", "a" * 40, "--mode", mode],
                       capture_output=True, text=True, env=e)
    return r, json.load(open(d + "/summary.json"))


def entry(key, **kw):
    e = dict(key=key, reason="scanner lacks the v1alpha2 rule", owner="coverage", since="2026-11-07", ref="#1")
    e.update(kw)
    return e


def mm(key, **detail):
    return qalib.case("crd", key, mismatch=True, **detail)


def signed(key, **detail):
    """Registry entry for the plain mismatch `key` (without the suite prefix) carrying the exact sig of that case."""
    return entry("crd|" + key, sig=qalib.case_sig(mm(key, **detail)))


class Registry(unittest.TestCase):
    def setUp(self):
        self.s = tempfile.mkdtemp()

    def gaps(self, *entries):
        json.dump(list(entries), open(self.s + "/known-gaps.json", "w"))

    def test_registered_mismatch_is_known_gap_not_alarm(self):
        self.gaps(signed("k1"))
        r, summ = run_summary(self.s, [mm("k1")])
        self.assertEqual((summ["mismatch"], summ["new_mismatch"], summ["known_gap"], r.returncode), (1, 0, 1, 0))
        self.assertIn("KNOWN_GAP=1", r.stdout)
        self.assertEqual(json.load(open(self.s + "/status.json"))["known_gap_cases"], ["crd|k1"])

    def test_unregistered_stays_new(self):
        self.gaps(signed("k1"))
        r, summ = run_summary(self.s, [mm("k1"), mm("k2")])
        self.assertEqual((summ["new_mismatch"], summ["known_gap"], r.returncode), (1, 1, 2))

    def test_missing_reason_or_owner_is_ignored(self):
        sig = qalib.case_sig(mm("k1"))
        for bad in (entry("crd|k1", reason="", sig=sig), entry("crd|k1", reason="  ", sig=sig), entry("crd|k1", owner="", sig=sig),
                    {"key": "crd|k1", "owner": "o", "sig": sig}, {"key": "crd|k1", "reason": "r", "sig": sig}, "crd|k1"):
            self.gaps(bad)
            r, summ = run_summary(self.s, [mm("k1")])
            self.assertEqual((summ["new_mismatch"], summ["known_gap"], r.returncode), (1, 0, 2), bad)

    def test_sig_matches_covers_and_changed_nature_alarms(self):
        c = mm("k1", missing=["g/v/K"], exit=11, verdict="UNKNOWN")
        self.gaps(entry("crd|k1", sig=qalib.case_sig(c)))
        r, summ = run_summary(self.s, [c])
        self.assertEqual((summ["known_gap"], summ["new_mismatch"], summ["known_gap_nosig"], r.returncode), (1, 0, [], 0))
        for changed in (mm("k1", missing=["g/v/K", "g/v/L"], exit=11, verdict="UNKNOWN"), mm("k1", missing=["g/v/K"], exit=10, verdict="BLOCKED"),
                        mm("k1", missing=["g/v/K"], exit=11, verdict="UNKNOWN", status="X")):
            r, summ = run_summary(self.s, [changed])
            self.assertEqual((summ["known_gap"], summ["new_mismatch"], r.returncode), (0, 1, 2))

    def test_wrong_or_non_string_sig_never_covers(self):
        for sig in ("0" * 64, 5, ["x"]):
            self.gaps(entry("crd|k1", sig=sig))
            r, summ = run_summary(self.s, [mm("k1")])
            self.assertEqual((summ["known_gap"], summ["new_mismatch"]), (0, 1), sig)

    def test_no_sig_covers_nothing_and_is_reported(self):
        for e in (entry("crd|k1"), entry("crd|k1", sig=""), entry("crd|k1", sig=None)):
            self.gaps(e)
            r, summ = run_summary(self.s, [mm("k1")])
            self.assertEqual((summ["known_gap"], summ["new_mismatch"], summ["known_gap_nosig"], r.returncode), (0, 1, ["crd|k1"], 2), e)
        self.assertIn("known-gap entry crd|k1 has no sig", r.stdout)
        self.assertEqual(json.load(open(self.s + "/status.json"))["known_gap_nosig"], ["crd|k1"])

    def test_sig_cli_prints_sig_of_the_mismatch(self):
        c = mm("k1", missing=["g/v/K"], exit=11, verdict="UNKNOWN")
        d = tempfile.mkdtemp()
        json.dump([c], open(d + "/crd.cases.json", "w"))
        r = subprocess.run([sys.executable, os.path.join(HERE, "qalib.py"), "sig", d, "crd|k1"], capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), qalib.case_sig(c))
        r = subprocess.run([sys.executable, os.path.join(HERE, "qalib.py"), "sig", d, "crd|nope"], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)

    def many(self, n):
        return [signed(f"k{i:02d}") for i in range(n)], [mm(f"k{i:02d}") for i in range(n)]

    def test_registry_over_cap_with_missing_or_corrupt_status_alarms(self):
        entries, cases = self.many(11)
        self.gaps(*entries)
        r, summ = run_summary(self.s, cases)
        self.assertEqual((summ["known_gap"], summ["new_mismatch"], r.returncode), (10, 1, 2))
        self.gaps(*entries)
        open(self.s + "/status.json", "w").write("{corrupt")
        r, summ = run_summary(self.s, cases, "full")
        self.assertEqual((summ["state"], summ["known_gap"], summ["new_mismatch"], r.returncode), ("ALARM", 10, 1, 2))

    def test_malformed_file_is_ignored(self):
        open(self.s + "/known-gaps.json", "w").write("{not json")
        r, summ = run_summary(self.s, [mm("k1")])
        self.assertEqual((summ["new_mismatch"], r.returncode), (1, 2))

    def test_whole_candidate_regression_not_excused_by_registry(self):
        self.gaps(signed("k1", wholeCrdCandidate=True))
        r, summ = run_summary(self.s, [mm("k1", wholeCrdCandidate=True)])
        self.assertEqual((summ["new_mismatch"], summ["known_gap"], r.returncode), (1, 0, 2))

    def test_wrongpass_key_in_registry_ignored(self):
        self.gaps(entry("crd|k1"))
        r, summ = run_summary(self.s, [qalib.case("crd", "k1", wrongpass=True)], "full")
        self.assertEqual((summ["wrongpass"], summ["known_gap"], r.returncode), (1, 0, 2))
        self.assertNotIn("crd|k1", [x for x in summ["resolved_gaps"]])

    def test_resolved_gap_reported_on_full_run(self):
        self.gaps(signed("k1"))
        r, summ = run_summary(self.s, [qalib.case("crd", "k1"), qalib.case("crd", "other")], "full")
        self.assertEqual(summ["resolved_gaps"], ["crd|k1"])
        self.assertIn("RESOLVED_GAP=crd|k1", r.stdout)
        r, summ = run_summary(self.s, [qalib.case("crd", "k1")], "none")
        self.assertEqual(summ["resolved_gaps"], [])

    def test_skipped_suite_error_or_absent_suite_is_not_resolved(self):
        self.gaps(signed("k1"), entry("kind|k2", sig="x" * 64), entry("rules|k3", sig="x" * 64))
        cases = [qalib.case("crd", "k1", error=True), qalib.case("kind", "other"), qalib.case("rules", "other")]
        for skipped in ([], ["kind"], ["rules(absent)"]):
            r, summ = run_summary(self.s, cases, "full", skipped=skipped)
            self.assertNotIn("crd|k1", summ["resolved_gaps"], "errored case")
            self.assertEqual("kind|k2" in summ["resolved_gaps"], "kind" not in skipped, skipped)
            self.assertEqual("rules|k3" in summ["resolved_gaps"], "rules(absent)" not in skipped, skipped)
        r, summ = run_summary(self.s, [qalib.case("crd", "other")], "full")
        self.assertEqual(summ["resolved_gaps"], ["crd|k1"])  # crd ran cleanly; kind and rules produced nothing at all

    def test_mass_registration_over_cap_alarms_and_excess_cover_nothing(self):
        entries, cases = self.many(11)
        self.gaps(*entries)
        json.dump([f"crd|k{i:02d}" for i in range(11)], open(self.s + "/known-mismatch.json", "w"))  # the baseline must not excuse them
        r, summ = run_summary(self.s, cases)
        self.assertEqual((summ["state"], r.returncode, summ["known_gap"], summ["new_mismatch"]), ("ALARM", 2, 10, 1))
        self.assertEqual([c["key"] for c in summ["new_mismatch_cases"]], ["k10"])
        self.assertTrue(summ["known_gap_registration_breach"])
        self.assertIn("registry", r.stderr)

    def test_cap_allows_ten_then_counts_only_new(self):
        entries, cases = self.many(31)
        self.gaps(*entries[:10])
        r, summ = run_summary(self.s, cases[:20], "full")
        self.assertFalse(summ["known_gap_registration_breach"])
        self.gaps(*entries[:20])
        r, summ = run_summary(self.s, cases[:20], "full")  # 10 new relative to the stored accepted set
        self.assertFalse(summ["known_gap_registration_breach"])
        self.gaps(*entries)
        r, summ = run_summary(self.s, cases, "full")
        self.assertTrue(summ["known_gap_registration_breach"])
        self.assertEqual((summ["known_gap"], summ["new_mismatch"]), (20 + 10, 1))

    def test_cap_env_override_and_breach_does_not_advance_stored_set(self):
        self.gaps(signed("k1"), signed("k2"))
        r, summ = run_summary(self.s, [mm("k1"), mm("k2")], "full", {"QA_GAPS_MAX_NEW": "1"})
        self.assertTrue(summ["known_gap_registration_breach"])
        self.assertEqual((summ["known_gap"], summ["new_mismatch"]), (1, 1))
        self.assertEqual(json.load(open(self.s + "/status.json"))["known_gap_keys"], [])

    def test_cap_env_is_clamped_to_documented_upper_bound(self):
        entries, cases = self.many(31)
        self.gaps(*entries)
        r, summ = run_summary(self.s, cases, "full", {"QA_GAPS_MAX_NEW": "1000"})
        self.assertEqual((summ["known_gap"], summ["new_mismatch"], r.returncode), (25, 6, 2))
        for bad in ("-3", "x"):
            r, summ = run_summary(self.s, cases, "full", {"QA_GAPS_MAX_NEW": bad})
            self.assertEqual(summ["known_gap"], 0 if bad == "-3" else 10, bad)


class DigestReset(unittest.TestCase):
    def design(self, n):
        return [qalib.case("crd", f"k{i}", status=D) for i in range(n)]

    def community(self, n):
        return [qalib.case("crd", f"c{i}", status="UNSUPPORTED_COMMUNITY") for i in range(n)]

    def test_unchanged_digest_rise_still_fires(self):
        s = tempfile.mkdtemp()
        run_summary(s, self.community(2) + self.design(40), "full")
        r, summ = run_summary(s, self.community(5) + self.design(46), "full")
        self.assertTrue(summ["unsupported_community_rise"])
        self.assertTrue(summ["design_unknown_whole_crd_rise"])
        r, summ = run_summary(s, self.design(70), "full")
        self.assertTrue(summ["design_unknown_whole_crd_cap_breach"])

    def test_changed_digest_skips_rise_and_pct_cap_resets_baseline(self):
        s = tempfile.mkdtemp()
        run_summary(s, self.community(2) + self.design(40), "full")
        st = json.load(open(s + "/status.json"))
        st["oracle_digest"] = "0" * 64
        json.dump(st, open(s + "/status.json", "w"))
        r, summ = run_summary(s, self.community(9) + self.design(44), "full")  # +4 is within the rise threshold
        self.assertFalse(summ["unsupported_community_rise"] or False)
        self.assertFalse(summ["design_unknown_whole_crd_rise"])
        self.assertFalse(summ["design_unknown_whole_crd_cap_breach"])
        self.assertIn("oracle changed: rise baseline reset", r.stderr)
        self.assertEqual(json.load(open(s + "/status.json"))["design_unknown_whole_crd_baseline"], 44)
        # new baseline stored: same digest now, so a later rise fires again
        r, summ = run_summary(s, self.design(49), "full")
        self.assertTrue(summ["design_unknown_whole_crd_rise"])

    def test_legacy_status_without_digest_skips_rise_once(self):
        s = tempfile.mkdtemp()
        json.dump({"mode": "full", "unsupported_community": 1, "design_unknown_whole_crd_baseline": 10}, open(s + "/status.json", "w"))
        r, summ = run_summary(s, self.community(3) + self.design(12), "full")
        self.assertIsNone(summ["unsupported_community_rise"])
        self.assertFalse(summ["design_unknown_whole_crd_cap_breach"])
        self.assertEqual(json.load(open(s + "/status.json"))["oracle_digest"], qalib.oracle_digest())

    def test_changed_digest_with_percent_cap_growth_is_reset_not_flagged_but_marked(self):
        s = tempfile.mkdtemp()
        run_summary(s, self.design(20), "full")
        st = json.load(open(s + "/status.json"))
        st["oracle_digest"] = "0" * 64
        json.dump(st, open(s + "/status.json", "w"))
        r, summ = run_summary(s, self.design(25), "full")  # +5 is exactly the threshold: reset, no CAP, no RISE
        self.assertFalse(summ["design_unknown_whole_crd_cap_breach"])
        self.assertIn("ORACLE_CHANGED design=20->25", r.stdout.splitlines()[0])
        self.assertNotIn("ORACLE_RISE", r.stdout)
        self.assertEqual(json.load(open(s + "/status.json"))["design_unknown_whole_crd_baseline"], 25)
        r, summ = run_summary(s, self.design(26), "full")
        self.assertNotIn("ORACLE_CHANGED", r.stdout.splitlines()[0])

    def test_changed_digest_with_rise_over_threshold_is_inconclusive_and_keeps_baseline(self):
        for before, after in ((20, 26), (100 // 4, 31), (10, 16)):
            s = tempfile.mkdtemp()
            run_summary(s, self.design(before), "full")
            st = json.load(open(s + "/status.json"))
            st["oracle_digest"] = "0" * 64
            json.dump(st, open(s + "/status.json", "w"))
            r, summ = run_summary(s, self.design(after), "full")
            self.assertEqual((summ["state"], r.returncode, summ["design_unknown_whole_crd_oracle_rise"]), ("INCONCLUSIVE", 3, True), (before, after))
            self.assertIn(f"ORACLE_CHANGED design={before}->{after} ORACLE_RISE", r.stdout.splitlines()[0])
            st = json.load(open(s + "/status.json"))
            self.assertEqual((st["design_unknown_whole_crd_baseline"], st["oracle_digest"]), (before, "0" * 64))
        # a partial run never judges the count; a drop is never a rise
        for mode, count in (("none", 90 // 3), ("full", 12)):
            s = tempfile.mkdtemp()
            run_summary(s, self.design(20), "full")
            st = json.load(open(s + "/status.json"))
            st["oracle_digest"] = "0" * 64
            json.dump(st, open(s + "/status.json", "w"))
            r, summ = run_summary(s, self.design(count), mode)
            self.assertFalse(summ["design_unknown_whole_crd_oracle_rise"], mode)

    def test_digest_covers_scope_modules(self):
        import hashlib
        self.assertIn("qa_scope.py", open(os.path.join(HERE, "qalib.py")).read())
        self.assertIn("qa_batch_scope.py", open(os.path.join(HERE, "qalib.py")).read())

    def test_changed_digest_hard_cap_still_applies_and_baseline_not_stored(self):
        s = tempfile.mkdtemp()
        run_summary(s, self.design(40), "full")
        st = json.load(open(s + "/status.json"))
        st["oracle_digest"] = "0" * 64
        json.dump(st, open(s + "/status.json", "w"))
        r, summ = run_summary(s, self.design(81), "full")
        self.assertTrue(summ["design_unknown_whole_crd_cap_breach"])
        st = json.load(open(s + "/status.json"))
        self.assertEqual((st["design_unknown_whole_crd_baseline"], st["oracle_digest"]), (40, "0" * 64))

    def test_changed_digest_partial_run_keeps_old_digest(self):
        s = tempfile.mkdtemp()
        run_summary(s, self.design(40), "full")
        st = json.load(open(s + "/status.json"))
        st["oracle_digest"] = "0" * 64
        json.dump(st, open(s + "/status.json", "w"))
        run_summary(s, self.design(41), "none")
        self.assertEqual(json.load(open(s + "/status.json"))["oracle_digest"], "0" * 64)


LISTED = {"a.example", "b.example"}  # groups the reviewed table attributes to some project
F1 = ("f.example", "v1", "Foreign")  # served group no project lists: always one unowned manifest
F2 = ("f.example", "v1", "Foreign2")
KEPT = ("a.example", "v1", "Kept")   # defined at both releases


class ForeignServedGroup(unittest.TestCase):
    """A served document of a group no project lists is unowned in every scan of the input, not a sign of a hidden removal:
    design only when the count is exactly those documents plus the vanished-group removals, the gap is present, and no
    expected removal lies in an unlisted group."""
    def setUp(self):
        for mod in (crd, qalib):
            p = patch.object(mod, "removal_claim", lambda *a: True)
            p.start()
            self.addCleanup(p.stop)
        self.served = {W, KEPT, V1, F1}

    def whole(self, gaps, removed=(W,), served=None, listed=LISTED, later=None, code=11, rep=None):
        rep = rep or unknown_only(gaps)
        return crd.classify_pair(code, rep, list(removed), [W], P, {"a.example"} if later is None else later,
                                 self.served if served is None else served, listed)

    def test_group_still_defined_kind_removed_with_one_foreign_doc_is_design(self):
        r = self.whole([GAP, unowned(1)], removed=(W,), later={"a.example"}, served={W, KEPT, F1})
        self.assertEqual((r[1], r[4], r[5]), (False, True, "OK"))

    def test_foreign_and_vanished_group_counts_add_up(self):
        r = self.whole([GAP, unowned(2)], later={"b.example"}, served={W, KEPT, F1})
        self.assertEqual((r[1], r[4], r[5]), (False, True, "OK"))
        r = self.whole([GAP, unowned(1)], later={"b.example"}, served={W, KEPT, F1})
        self.assertEqual((r[1], r[4], r[5]), (True, False, "GAP_UNOWNED"))

    def test_count_mismatch_is_mismatch(self):
        for n in (0, 2, 3):
            r = self.whole([GAP, unowned(n)], later={"a.example"}, served={W, KEPT, F1})
            self.assertEqual((r[1], r[4], r[5]), (True, False, "GAP_UNOWNED"), n)
        r = self.whole([GAP, unowned(1)], later={"a.example"}, served={W, KEPT, F1, F2})
        self.assertEqual((r[1], r[4], r[5]), (True, False, "GAP_UNOWNED"))

    def test_missing_unowned_gap_is_mismatch(self):
        r = self.whole([GAP], later={"a.example"}, served={W, KEPT, F1})
        self.assertEqual((r[1], r[4], r[5]), (True, False, "GAP_UNOWNED_MISSING"))

    def test_nothing_derived_without_table_or_served_set(self):
        for kw in ({"listed": None}, {"served": set()}):
            r = self.whole([GAP, unowned(1)], later={"a.example"}, **kw) if "served" not in kw else \
                crd.classify_pair(11, unknown_only([GAP, unowned(1)]), [W], [W], P, {"a.example"}, None, LISTED)
            self.assertEqual((r[1], r[4], r[5]), (True, False, "GAP_UNOWNED"), kw)

    def test_removal_inside_unlisted_group_is_never_excused(self):
        hidden = ("f.example", "v1beta1", "Hidden")
        r = crd.classify_pair(11, unknown_only([GAP, unowned(2)]), [hidden, W], [W], P, {"a.example"}, {W, hidden, F1}, LISTED)
        self.assertEqual((r[1], r[4]), (True, False))
        r = crd.classify_pair(10, blocked([], [GAP, unowned(2)]), [hidden, W], [W], P, {"a.example"}, {W, hidden, F1}, LISTED)
        self.assertEqual((r[1], r[4]), (True, False))

    def test_pass_stays_wrongpass(self):
        r = self.whole([], code=0, rep={"verdict": "PASS", "findings": []}, later={"a.example"}, served={W, KEPT, F1})
        self.assertEqual((r[0], r[1], r[4]), (True, False, False))

    def test_extra_or_missing_findings_stay_mismatch(self):
        served = {W, KEPT, V1, F1}
        extra = blocked([finding(V1), finding(("c.example", "v1", "Stray"))], [GAP, unowned(1)])
        r = crd.classify_pair(10, extra, [W, V1], [W], P, {"a.example", "b.example"}, served, LISTED)
        self.assertEqual((r[1], r[4], r[5]), (True, False, "EXTRA_FINDING"))
        miss = blocked([], [GAP, unowned(1)])
        r = crd.classify_pair(10, miss, [W, V1], [W], P, {"a.example", "b.example"}, served, LISTED)
        self.assertEqual((r[1], r[4], r[5]), (True, False, "VERSION_MISSING"))
        ok = blocked([finding(V1)], [GAP, unowned(1)])
        r = crd.classify_pair(10, ok, [W, V1], [W], P, {"a.example", "b.example"}, served, LISTED)
        self.assertEqual((r[1], r[4], r[5]), (False, True, "OK"))

    def test_findings_on_a_whole_only_pair_stay_mismatch(self):
        rep = dict(unknown_only([GAP, unowned(1)]), findings=[finding(V1)])
        r = self.whole([], rep=rep, later={"a.example"}, served={W, KEPT, F1})
        self.assertEqual((r[1], r[4], r[5]), (True, False, "FINDINGS"))

    def test_listed_groups_reads_table_and_fails_closed(self):
        groups = crd.listed_groups()
        self.assertIn("core.oam.dev", groups)
        with patch.object(crd, "SRC", "/nonexistent"):
            self.assertIsNone(crd.listed_groups())


if __name__ == "__main__":
    unittest.main()
