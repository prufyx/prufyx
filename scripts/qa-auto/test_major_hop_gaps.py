"""Structural major-line gaps (MAJOR_HOP_NOT_COVERED, LINES_NOT_LISTED, LINE_NOT_ATTESTED) in the whole-CRD design shapes.
Shapes follow the real scanner outputs of crossplane (mixed, BLOCKED), kuma (whole-only, UNKNOWN) and strimzi (mixed, BLOCKED)."""
import unittest
from unittest.mock import patch

import crd_oracle as crd
import qalib

P = "proj"
W = ("a.example", "v1", "Gone")
V1 = ("b.example", "v1alpha2", "Old")
V2 = ("b.example", "v1alpha2", "Older")
LG = {"b.example"}
FAM = "crd.custom_resource_versions"


def gap(reason):
    return {"component": P, "reason": reason}


def finding(item):
    g, v, k = item
    return {"component": P, "ruleId": "r", "locations": [{"kind": k, "name": crd.object_name(g, v, k)}]}


def mixed(reasons, hop_reasons=()):
    return {"verdict": "BLOCKED", "findings": [finding(V1), finding(V2)], "gaps": [gap(r) for r in reasons],
            "paths": [{"component": P, "hops": [{"status": "BLOCKED", "reasons": list(hop_reasons), "families": [{"family": FAM, "status": "BLOCKED"}]}]}]}


def whole_only(gaps, hop_reasons, status="NO_DATA"):
    return {"verdict": "UNKNOWN", "findings": [], "gaps": [gap(r) for r in gaps],
            "paths": [{"component": P, "hops": [{"status": status, "reasons": list(hop_reasons)}]}]}


CROSSPLANE = ["COMPONENT_NOT_COVERED", "LINES_NOT_LISTED"]
KUMA = ["COMPONENT_NOT_COVERED", "LINES_NOT_LISTED", "LINE_NOT_ATTESTED", "MAJOR_HOP_NOT_COVERED"]


class Base(unittest.TestCase):
    def setUp(self):
        for mod in (crd, qalib):
            p = patch.object(mod, "removal_claim", lambda *a: True)
            p.start()
            self.addCleanup(p.stop)

    def mixed(self, rep, major, code=10):
        return crd.classify_pair(code, rep, [W, V1, V2], [W], P, LG, None, None, major)

    def whole(self, rep, major, code=11):
        return crd.classify_pair(code, rep, [W], [W], P, LG, None, None, major)


class MajorLine(unittest.TestCase):
    def test_major_line_changes(self):
        self.assertTrue(crd.major_line_changes("v1.20.0", "v2.0.0"))
        self.assertTrue(crd.major_line_changes("0.51.0", "1.0.0"))
        self.assertFalse(crd.major_line_changes("v2.14.0", "v2.14.7"))
        for bad in ("", None, "main", "release-1", "x.1.0"):
            self.assertFalse(crd.major_line_changes(bad, "v2.0.0"), bad)
            self.assertFalse(crd.major_line_changes("v1.0.0", bad), bad)


class Mixed(Base):
    def test_crossplane_shape_major_change_is_design(self):
        r = self.mixed(mixed(CROSSPLANE), True)
        self.assertEqual((r[0], r[1], r[2], r[4], r[5]), (False, False, [], True, "OK"))

    def test_strimzi_shape_major_change_is_design(self):
        rep = mixed(["COMPONENT_NOT_COVERED", "LINES_NOT_LISTED"])
        r = self.mixed(rep, True)
        self.assertEqual((r[1], r[4]), (False, True))

    def test_same_major_with_lines_not_listed_still_fails(self):
        r = self.mixed(mixed(CROSSPLANE), False)
        self.assertEqual((r[0], r[1], r[4], r[5]), (False, True, False, "GAP_REASON"))

    def test_mixed_never_accepts_line_not_attested(self):
        r = self.mixed(mixed(CROSSPLANE + ["LINE_NOT_ATTESTED"]), True)
        self.assertEqual((r[1], r[4], r[5]), (True, False, "GAP_REASON"))

    def test_unknown_reason_still_fails_on_major_change(self):
        r = self.mixed(mixed(CROSSPLANE + ["SOMETHING_ELSE"]), True)
        self.assertEqual((r[1], r[4], r[5]), (True, False, "GAP_REASON"))

    def test_only_structural_gaps_without_design_gap_fails(self):
        r = self.mixed(mixed(["LINES_NOT_LISTED"]), True)
        self.assertEqual((r[1], r[4], r[5]), (True, False, "NO_GAP"))

    def test_pass_with_whole_removal_is_still_wrongpass(self):
        for major in (True, False):
            rep = {"verdict": "PASS", "findings": [], "gaps": [], "paths": []}
            r = crd.classify_pair(0, rep, [W, V1, V2], [W], P, LG, None, None, major)
            self.assertEqual((r[0], r[4]), (True, False), major)


class WholeOnly(Base):
    def test_kuma_shape_major_change_is_design(self):
        r = self.whole(whole_only(KUMA, KUMA), True)
        self.assertEqual((r[0], r[1], r[2], r[4], r[5]), (False, False, [], True, "OK"))

    def test_kuma_shape_same_major_fails(self):
        r = self.whole(whole_only(KUMA, KUMA), False)
        self.assertEqual((r[1], r[4], r[5]), (True, False, "GAP_REASON"))

    def test_line_not_attested_in_hop_only_fails_on_other_status(self):
        r = self.whole(whole_only(KUMA, KUMA, status="BLOCKED"), True)
        self.assertEqual((r[1], r[4], r[5]), (True, False, "HOP_STATUS"))

    def test_hop_reason_outside_accepted_fails(self):
        r = self.whole(whole_only(KUMA, KUMA + ["OTHER"]), True)
        self.assertEqual((r[1], r[4], r[5]), (True, False, "HOP_REASON"))

    def test_findings_in_whole_only_shape_fail(self):
        rep = whole_only(KUMA, KUMA)
        rep["findings"] = [finding(V1)]
        r = self.whole(rep, True)
        self.assertEqual((r[1], r[4]), (True, False))

    def test_pass_on_whole_removal_is_wrongpass(self):
        rep = {"verdict": "PASS", "findings": [], "gaps": [], "paths": []}
        for major in (True, False):
            r = crd.classify_pair(0, rep, [W], [W], P, LG, None, None, major)
            self.assertEqual((r[0], r[4]), (True, False), major)

    def test_whole_removal_is_never_expected_as_finding(self):
        r = self.whole(whole_only(KUMA, KUMA), True)
        self.assertEqual(r[2], [])


if __name__ == "__main__":
    unittest.main()
