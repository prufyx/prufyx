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

    def test_exact_with_no_gap_is_design_too(self):
        self.assertTrue(self.verdict(10, blocked([finding(V1), finding(V2)]))[4])

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


def run_summary(state, cases, mode="none", env=None):
    d = tempfile.mkdtemp()
    json.dump(cases, open(d + "/crd.cases.json", "w"))
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


class Registry(unittest.TestCase):
    def setUp(self):
        self.s = tempfile.mkdtemp()

    def gaps(self, *entries):
        json.dump(list(entries), open(self.s + "/known-gaps.json", "w"))

    def test_registered_mismatch_is_known_gap_not_alarm(self):
        self.gaps(entry("crd|k1"))
        r, summ = run_summary(self.s, [mm("k1")])
        self.assertEqual((summ["mismatch"], summ["new_mismatch"], summ["known_gap"], r.returncode), (1, 0, 1, 0))
        self.assertIn("KNOWN_GAP=1", r.stdout)
        self.assertEqual(json.load(open(self.s + "/status.json"))["known_gap_cases"], ["crd|k1"])

    def test_unregistered_stays_new(self):
        self.gaps(entry("crd|k1"))
        r, summ = run_summary(self.s, [mm("k1"), mm("k2")])
        self.assertEqual((summ["new_mismatch"], summ["known_gap"], r.returncode), (1, 1, 2))

    def test_missing_reason_or_owner_is_ignored(self):
        for bad in (entry("crd|k1", reason=""), entry("crd|k1", reason="  "), entry("crd|k1", owner=""),
                    {"key": "crd|k1", "owner": "o"}, {"key": "crd|k1", "reason": "r"}, "crd|k1"):
            self.gaps(bad)
            r, summ = run_summary(self.s, [mm("k1")])
            self.assertEqual((summ["new_mismatch"], summ["known_gap"], r.returncode), (1, 0, 2), bad)

    def test_malformed_file_is_ignored(self):
        open(self.s + "/known-gaps.json", "w").write("{not json")
        r, summ = run_summary(self.s, [mm("k1")])
        self.assertEqual((summ["new_mismatch"], r.returncode), (1, 2))

    def test_whole_candidate_regression_not_excused_by_registry(self):
        self.gaps(entry("crd|k1"))
        r, summ = run_summary(self.s, [mm("k1", wholeCrdCandidate=True)])
        self.assertEqual((summ["new_mismatch"], summ["known_gap"], r.returncode), (1, 0, 2))

    def test_wrongpass_key_in_registry_ignored(self):
        self.gaps(entry("crd|k1"))
        r, summ = run_summary(self.s, [qalib.case("crd", "k1", wrongpass=True)], "full")
        self.assertEqual((summ["wrongpass"], summ["known_gap"], r.returncode), (1, 0, 2))
        self.assertNotIn("crd|k1", [x for x in summ["resolved_gaps"]])

    def test_resolved_gap_reported_on_full_run(self):
        self.gaps(entry("crd|k1"))
        r, summ = run_summary(self.s, [qalib.case("crd", "k1")], "full")
        self.assertEqual(summ["resolved_gaps"], ["crd|k1"])
        self.assertIn("RESOLVED_GAP=crd|k1", r.stdout)
        r, summ = run_summary(self.s, [qalib.case("crd", "k1")], "none")
        self.assertEqual(summ["resolved_gaps"], [])

    def test_mass_registration_cap_is_inconclusive(self):
        self.gaps(*[entry(f"crd|k{i}") for i in range(11)])
        r, summ = run_summary(self.s, [mm(f"k{i}") for i in range(11)])
        self.assertEqual((summ["state"], r.returncode), ("INCONCLUSIVE", 3))
        self.assertTrue(summ["known_gap_registration_breach"])
        self.assertIn("registry", r.stderr)

    def test_cap_allows_ten_then_counts_only_new(self):
        self.gaps(*[entry(f"crd|k{i}") for i in range(10)])
        cases = [mm(f"k{i}") for i in range(20)]
        r, summ = run_summary(self.s, cases, "full")
        self.assertFalse(summ["known_gap_registration_breach"])
        self.gaps(*[entry(f"crd|k{i}") for i in range(20)])
        r, summ = run_summary(self.s, cases, "full")  # 10 new relative to the stored accepted set
        self.assertFalse(summ["known_gap_registration_breach"])
        self.gaps(*[entry(f"crd|k{i}") for i in range(31)])
        r, summ = run_summary(self.s, cases + [mm(f"k{i}") for i in range(20, 31)], "full")
        self.assertTrue(summ["known_gap_registration_breach"])

    def test_cap_env_override_and_breach_does_not_advance_stored_set(self):
        self.gaps(entry("crd|k1"), entry("crd|k2"))
        r, summ = run_summary(self.s, [mm("k1"), mm("k2")], "full", {"QA_GAPS_MAX_NEW": "1"})
        self.assertTrue(summ["known_gap_registration_breach"])
        self.assertEqual(json.load(open(self.s + "/status.json"))["known_gap_keys"], [])


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
        r, summ = run_summary(s, self.community(9) + self.design(70), "full")
        self.assertFalse(summ["unsupported_community_rise"] or False)
        self.assertFalse(summ["design_unknown_whole_crd_rise"])
        self.assertFalse(summ["design_unknown_whole_crd_cap_breach"])
        self.assertIn("oracle changed: rise baseline reset", r.stderr)
        self.assertEqual(json.load(open(s + "/status.json"))["design_unknown_whole_crd_baseline"], 70)
        # new baseline stored: same digest now, so a later rise fires again
        r, summ = run_summary(s, self.design(75), "full")
        self.assertTrue(summ["design_unknown_whole_crd_rise"])

    def test_legacy_status_without_digest_skips_rise_once(self):
        s = tempfile.mkdtemp()
        json.dump({"mode": "full", "unsupported_community": 1, "design_unknown_whole_crd_baseline": 10}, open(s + "/status.json", "w"))
        r, summ = run_summary(s, self.community(3) + self.design(30), "full")
        self.assertIsNone(summ["unsupported_community_rise"])
        self.assertFalse(summ["design_unknown_whole_crd_cap_breach"])
        self.assertEqual(json.load(open(s + "/status.json"))["oracle_digest"], qalib.oracle_digest())

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


if __name__ == "__main__":
    unittest.main()
