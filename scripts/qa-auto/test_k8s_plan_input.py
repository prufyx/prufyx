"""k8s-plan oracle: per-hop plan input (plan_hop_input) and the window runner built on it."""
import unittest
from unittest.mock import patch

import k8s_oracle as k8s
import qalib

A = ("example.io", "v1", "A")   # removed by hop 1.21 -> 1.22
B = ("example.io", "v1", "B")   # removed by hop 1.23 -> 1.24
C = ("example.io", "v1", "C")   # served throughout
D = ("example.io", "v1", "D")   # removed by hop 1.22 -> 1.23
ALPHA = ("example.io", "v1alpha1", "Z")
LATE = ("example.io", "v1", "Late")  # introduced after the window start, never in the input
SETS = {20: {A, B, C, D, ALPHA}, 21: {A, B, C, D, ALPHA}, 22: {B, C, D, LATE}, 23: {B, C, LATE}, 24: {C, LATE}}


def sw(minor):
    return SETS[minor]


class HopInput(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(k8s, "swagger", side_effect=sw)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_window_input_is_start_set_without_alpha(self):
        self.assertEqual(k8s.plan_window_input(20), {A, B, C, D})

    def test_later_removed_and_earlier_removed_are_dropped(self):
        self.assertEqual(k8s.plan_hop_input(20, 24, 20), {C})
        self.assertEqual(k8s.plan_hop_input(20, 24, 22), {C, D})

    def test_gvk_removed_by_this_very_hop_stays(self):
        self.assertEqual(k8s.plan_hop_input(20, 24, 21), {A, C})
        self.assertEqual(k8s.plan_hop_input(20, 24, 23), {B, C})

    def test_single_hop_window_equals_window_input(self):
        self.assertEqual(k8s.plan_hop_input(23, 24, 23), k8s.plan_window_input(23))

    def test_empty_intersection(self):
        with patch.object(k8s, "swagger", side_effect=lambda m: {("g", "v1", "X")} if m < 3 else {("g", "v1", "Y")}):
            self.assertEqual(k8s.plan_hop_input(1, 3, 1), set())

    def test_deterministic_and_inputs_never_mutated(self):
        before = {m: set(s) for m, s in SETS.items()}
        first = [k8s.plan_hop_input(20, 24, m) for m in range(20, 24)]
        second = [k8s.plan_hop_input(20, 24, m) for m in range(20, 24)]
        self.assertEqual(first, second)
        self.assertEqual(SETS, before)

    def test_real_removal_never_disappears_from_expectations(self):
        for lo, h in ((20, 24), (21, 23), (22, 24), (20, 22)):
            window = k8s.plan_window_input(lo)
            with patch.object(k8s, "swagger", side_effect=sw):
                for m in range(lo, h):
                    expected = {x for x in (sw(m) - sw(m + 1)) if x in window}
                    self.assertTrue(expected <= k8s.plan_hop_input(lo, h, m), (lo, h, m))
                    self.assertTrue(k8s.plan_hop_input(lo, h, m) <= window)
                union = set().union(*({x for x in (sw(m) - sw(m + 1)) if x in window} for m in range(lo, h)))
                kept = set().union(*(k8s.plan_hop_input(lo, h, m) & (sw(m) - sw(m + 1)) for m in range(lo, h)))
                self.assertEqual(union, kept)

    def test_hop_stage_needs_exactly_one_match(self):
        report = {"stages": [{"from": "1.20.0", "to": "1.21"}, {"from": "1.21", "to": "1.22"}]}
        self.assertEqual(k8s.hop_stage(report, 21)["to"], "1.22")
        self.assertEqual(k8s.hop_stage(report, 20)["from"], "1.20.0")
        self.assertIsNone(k8s.hop_stage(report, 22))
        self.assertIsNone(k8s.hop_stage({"stages": report["stages"] * 2}, 21))
        self.assertIsNone(k8s.hop_stage(None, 21))


class Fake:
    """Stands in for the binary: a plan that reports a PARTIAL hop whenever the input holds a GVK that is not
    cleanly decidable for that hop (gone before it, or removed only later), and removal findings otherwise."""

    def __init__(self, lo, h, drop_findings=False, pass_on_removal=False):
        self.lo, self.h, self.sets = lo, h, {}
        self.drop_findings, self.pass_on_removal = drop_findings, pass_on_removal
        self.plans = []

    def inp(self, gvks, name):
        self.sets[name] = set(gvks)
        return name

    def removed_at(self, m, gvks):
        return sorted(x for x in gvks if x in sw(m) and x not in sw(m + 1))

    def prufyx(self, cmd, path, frm, to):
        gvks = self.sets[path]
        base = {"provenance": {"inputDigest": "d:" + path}}
        if cmd == "scan":
            findings = []
            for m in range(self.lo, self.h):
                if self.drop_findings:
                    break
                for g, v, kind in self.removed_at(m, gvks):
                    findings.append({"ruleId": "r", "component": "kubernetes",
                                     "hop": {"from": self.stage_name(m, "from"), "to": self.stage_name(m, "to")},
                                     "locations": [{"kind": kind, "name": qalib.object_name(g, v, kind)}]})
            code = 10 if findings else 11
            return code, dict(base, findings=findings, paths=[],
                              summary={"documentsRead": len(gvks), "documentsOmitted": 0}, omitted=[]), ""
        self.plans.append(path)
        stages = []
        for m in range(self.lo, self.h):
            removed = self.removed_at(m, gvks)
            foreign = any(x not in sw(m) or (x in sw(m + 1) and x not in sw(self.h)) for x in gvks)
            verdict = "BLOCKED" if removed else "UNKNOWN"
            if removed and self.pass_on_removal:
                verdict = "SCOPE_COMPLETE_PASS"
            stages.append({"index": m - self.lo + 1, "component": "kubernetes", "from": self.stage_name(m, "from"),
                           "to": self.stage_name(m, "to"), "verdict": verdict, "unsupported": [],
                           "hopStatus": "BLOCKED" if removed else ("PARTIAL" if foreign else "COVERED"),
                           "gaps": [{"reason": "API_VERSION_NOT_REVIEWED"}] + ([{"reason": "LINE_NOT_ATTESTED"}] if foreign else []),
                           "findings": [{"ruleId": "r"}] if removed else []})
        anyremoved = any(self.removed_at(m, gvks) for m in range(self.lo, self.h))
        return (10 if anyremoved else 11), dict(base, verdict="BLOCKED" if anyremoved else "UNKNOWN", stages=stages), ""

    def stage_name(self, m, side):
        if side == "from":
            return f"1.{m}.0" if m == self.lo else f"1.{m}"
        return f"1.{m+1}.0" if m + 1 == self.h else f"1.{m+1}"


class RunWindow(unittest.TestCase):
    def run_window(self, fake, hop_input=None):
        executed = set()
        patches = [patch.object(k8s, "swagger", side_effect=sw), patch.object(k8s, "inp", side_effect=fake.inp),
                   patch.object(k8s, "prufyx", side_effect=fake.prufyx),
                   patch.object(qalib, "removal_claim", return_value=True)]
        if hop_input:
            patches.append(patch.object(k8s, "plan_hop_input", side_effect=hop_input))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return k8s.run_plan_window(fake.lo, fake.h, executed), executed

    def stages(self, cases):
        return {c["key"].rsplit("stage ", 1)[1]: c for c in cases if "stage" in c["key"]}

    def test_every_hop_is_judged_on_its_own_clean_input_and_removals_stay_blocked(self):
        cases, executed = self.run_window(Fake(20, 24))
        stages = self.stages(cases)
        self.assertEqual(len(stages), 4)
        self.assertEqual({s: c["detail"]["verdict"] for s, c in stages.items()},
                         {"1.20.0->1.21": "UNKNOWN", "1.21->1.22": "BLOCKED", "1.22->1.23": "BLOCKED", "1.23->1.24.0": "BLOCKED"})
        self.assertEqual({s: c["detail"]["hopStatus"] for s, c in stages.items()},
                         {"1.20.0->1.21": "COVERED", "1.21->1.22": "BLOCKED", "1.22->1.23": "BLOCKED", "1.23->1.24.0": "BLOCKED"})
        self.assertFalse(any(c["error"] or c["wrongpass"] or c["mismatch"] for c in cases))
        self.assertEqual(len(executed), 5)
        self.assertIn("k8s-plan|1.20->1.24 overall", executed)

    def test_whole_window_plan_still_uses_the_unnarrowed_input(self):
        fake = Fake(20, 24)
        self.run_window(fake)
        self.assertEqual(fake.sets["plan"], {A, B, C, D})
        self.assertEqual(fake.sets["plan-hop-20-24-21"], {A, C})

    def test_removed_gvk_without_a_finding_is_a_failure_not_covered(self):
        cases, executed = self.run_window(Fake(20, 24, drop_findings=True))
        stage = self.stages(cases)["1.21->1.22"]
        self.assertTrue(stage["error"] or stage["mismatch"])
        self.assertNotIn("k8s-plan|1.20->1.24 stage 1.21.0->1.22.0", executed)
        self.assertNotIn("k8s-plan|1.20->1.24 overall", executed)

    def test_pass_on_a_removed_gvk_is_a_wrongpass(self):
        cases, executed = self.run_window(Fake(20, 24, pass_on_removal=True))
        self.assertTrue(self.stages(cases)["1.21->1.22"]["wrongpass"])
        self.assertNotIn("k8s-plan|1.20->1.24 overall", executed)

    def test_hop_input_that_loses_an_expected_removal_fails_closed(self):
        real = k8s.plan_hop_input

        def broken(lo, h, m):
            return set() if m == 21 else real(lo, h, m)
        fake = Fake(20, 24)
        cases, executed = self.run_window(fake, hop_input=broken)
        stage = self.stages(cases)["1.21->1.22"]
        self.assertTrue(stage["error"])
        self.assertIn("preserve the expected removals", stage["detail"]["why"])
        self.assertNotIn("k8s-plan|1.20->1.24 stage 1.21.0->1.22.0", executed)
        self.assertNotIn("k8s-plan|1.20->1.24 overall", executed)
        self.assertNotIn("plan-hop-20-24-21", fake.sets)

    def test_hop_input_wider_than_the_window_input_fails_closed(self):
        extra = ("example.io", "v1", "Extra")
        cases, executed = self.run_window(Fake(20, 24), hop_input=lambda lo, h, m: {C, extra})
        self.assertTrue(all(c["error"] for c in self.stages(cases).values()))
        self.assertEqual(executed, set())

    def test_hop_plan_missing_its_stage_fails_closed(self):
        fake = Fake(20, 24)
        original = fake.prufyx

        def prufyx(cmd, path, frm, to):
            code, report, tail = original(cmd, path, frm, to)
            if cmd == "plan" and path.startswith("plan-hop"):
                report = dict(report, stages=[])
            return code, report, tail
        fake.prufyx = prufyx
        cases, executed = self.run_window(fake)
        self.assertTrue(all(c["error"] for c in self.stages(cases).values()))
        self.assertNotIn("k8s-plan|1.20->1.24 overall", executed)

    def test_hop_scan_digest_mismatch_or_omission_is_not_complete(self):
        fake = Fake(20, 24)
        original = fake.prufyx

        def prufyx(cmd, path, frm, to):
            code, report, tail = original(cmd, path, frm, to)
            if cmd == "scan" and path.startswith("plan-hop"):
                report = dict(report, provenance={"inputDigest": "other"})
            return code, report, tail
        fake.prufyx = prufyx
        cases, executed = self.run_window(fake)
        self.assertTrue(all(c["error"] for c in self.stages(cases).values()))
        self.assertNotIn("k8s-plan|1.20->1.24 overall", executed)

    def test_failed_window_plan_is_one_error_case(self):
        fake = Fake(20, 24)
        original = fake.prufyx
        fake.prufyx = lambda cmd, *a: (124, None, "TimeoutExpired") if cmd == "plan" else original(cmd, *a)
        cases, executed = self.run_window(fake)
        self.assertEqual(len(cases), 1)
        self.assertTrue(cases[0]["error"])
        self.assertEqual(executed, set())


if __name__ == "__main__":
    unittest.main()
