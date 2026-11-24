"""Exact-anchor removal rule (cilium 1.19.0 -> 1.20.0, no range): the oracle expects BLOCKED at the anchor and UNKNOWN at another patch of the line.
Report shapes are the real scanner outputs of cilium 1.19.0 -> 1.20.0 (exit 10) and 1.19.11 -> 1.20.0 (exit 11)."""
import json, os, tempfile, unittest
from unittest.mock import patch

import crd_oracle as crd
import qalib

P = "cilium"
ITEM = ("cilium.io", "v2alpha1", "CiliumNodeConfig")
GAP = {"component": P, "reason": "COMPONENT_NOT_COVERED"}


def rule(frm="1.19.0", to="1.20.0", members=("cilium.io/v2alpha1/CiliumNodeConfig",), **extra):
    r = {"id": "cilium.crd-version-removal.x." + frm + to, "operator": "forbid_set_member",
         "setCondition": {"factId": "f", "members": list(members)}, "subject": {"component": "c", "from": frm, "to": to}}
    r.update(extra)
    return {"project": "cilium", "rule": r}


def unknown_report(**over):
    rep = {"verdict": "UNKNOWN", "findings": [], "gaps": [GAP],
           "paths": [{"component": P, "hops": [{"status": "NO_DATA", "reasons": ["COMPONENT_NOT_COVERED"]}]}]}
    rep.update(over)
    return rep


def blocked_report():
    return {"verdict": "BLOCKED", "gaps": [GAP],
            "findings": [{"component": P, "ruleId": "r", "locations": [{"kind": ITEM[2], "name": crd.object_name(*ITEM)}]}],
            "paths": [{"component": P, "hops": [{"status": "BLOCKED", "reasons": ["COMPONENT_NOT_COVERED"],
                                                "families": [{"family": crd.FAMILY, "status": "BLOCKED"}]}]}]}


class Anchor(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        for mod in (crd, qalib):
            p = patch.object(mod, "removal_claim", lambda *a: True)
            p.start()
            self.addCleanup(p.stop)
        self.rules([rule()])

    def rules(self, entries):
        path = os.path.join(self.dir.name, "cli/internal/cncfcheck/data")
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, "rules.json"), "w") as f:
            json.dump({"entries": entries}, f)
        patcher = patch.object(crd, "SRC", self.dir.name)
        patcher.start()
        self.addCleanup(patcher.stop)

    def classify(self, code, rep, frm, to="v1.20.0"):
        return crd.classify_pair(code, rep, [ITEM], [], P, None, None, None, False, (frm, to))

    def test_covered_anchor_expects_blocked(self):
        r = self.classify(10, blocked_report(), "v1.19.0")
        self.assertEqual((r[0], r[1], r[2]), (False, False, []))
        r = self.classify(11, unknown_report(), "v1.19.0")  # the anchor itself must be found: UNKNOWN there stays a mismatch
        self.assertEqual((r[0], r[1]), (False, True))

    def test_uncovered_patch_expects_unknown(self):
        r = self.classify(11, unknown_report(), "v1.19.11")
        self.assertEqual((r[0], r[1], r[2], r[5]), (False, False, [], crd.ANCHOR_STATUS))

    def test_uncovered_patch_with_blocked_is_not_excused_unknown(self):
        r = self.classify(10, blocked_report(), "v1.19.11")
        self.assertEqual((r[1], r[5]), (False, "NO_WHOLE"))  # a real finding is fine, judged as before

    def test_pass_on_uncovered_patch_is_wrongpass(self):
        rep = {"verdict": "PASS", "findings": [], "gaps": [], "paths": []}
        r = self.classify(0, rep, "v1.19.11")
        self.assertTrue(r[0])

    def test_unknown_with_extra_gap_or_hop_reason_stays_mismatch(self):
        rep = unknown_report(gaps=[GAP, {"component": P, "reason": "VERSION_NOT_DETECTED"}])
        self.assertTrue(self.classify(11, rep, "v1.19.11")[1])
        rep = unknown_report()
        rep["paths"][0]["hops"][0]["reasons"] = ["COMPONENT_NOT_COVERED", "OTHER"]
        self.assertTrue(self.classify(11, rep, "v1.19.11")[1])
        rep = unknown_report(gaps=[])
        self.assertTrue(self.classify(11, rep, "v1.19.11")[1])

    def test_unknown_with_a_finding_stays_judged_by_findings(self):
        rep = unknown_report(findings=[{"component": P, "ruleId": "r", "locations": []}])
        self.assertTrue(self.classify(11, rep, "v1.19.11")[1])

    def test_ranged_rule_is_not_anchor_only(self):
        self.rules([rule(range={"from": {"gte": "1.19.0"}})])
        self.assertTrue(self.classify(11, unknown_report(), "v1.19.11")[1])
        entry = rule()
        entry["rule"]["subject"]["range"] = {"from": {"gte": "1.19.0"}}
        self.rules([entry])
        self.assertTrue(self.classify(11, unknown_report(), "v1.19.11")[1])

    def test_other_line_target_or_member_is_not_covered(self):
        self.assertTrue(self.classify(11, unknown_report(), "v1.18.4")[1])
        self.assertTrue(self.classify(11, unknown_report(), "v1.19.11", "v1.20.1")[1])
        self.rules([rule(members=("cilium.io/v2alpha1/Other",))])
        self.assertTrue(self.classify(11, unknown_report(), "v1.19.11")[1])
        self.rules([rule(frm="1.18.0")])
        self.assertTrue(self.classify(11, unknown_report(), "v1.19.11")[1])

    def test_unreadable_rules_or_versions_fail_closed(self):
        with patch.object(crd, "SRC", "/nonexistent"):
            self.assertTrue(self.classify(11, unknown_report(), "v1.19.11")[1])
        for frm, to in (("main", "v1.20.0"), ("v1.19.11", "next"), ("", "v1.20.0")):
            self.assertTrue(self.classify(11, unknown_report(), frm, to)[1], (frm, to))
        r = crd.classify_pair(11, unknown_report(), [ITEM], [], P)  # no versions given
        self.assertTrue(r[1])

    def test_other_project_rule_does_not_cover(self):
        entry = rule()
        entry["project"] = "other"
        self.rules([entry])
        self.assertTrue(self.classify(11, unknown_report(), "v1.19.11")[1])

    def test_real_cilium_rule_table(self):
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        with patch.object(crd, "SRC", root):
            self.assertTrue(crd.anchor_only_rule_covers(P, "1.19.11", "1.20.0", [ITEM]))
            self.assertFalse(crd.anchor_only_rule_covers(P, "1.19.0", "1.20.0", [ITEM]))


if __name__ == "__main__":
    unittest.main()
