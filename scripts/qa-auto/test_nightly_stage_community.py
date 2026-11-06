"""Nightly harness proofs: community-catalog refusals and plan stages limited only by uncovered areas."""
import unittest

import crd_oracle as crd
import k8s_oracle as k8s

REFUSAL = ('prufyx: "moco" is in the community catalog (not in the embedded CNCF landscape catalog; '
           'no CNCF status asserted): scan does not check community projects yet; see docs/custom-resources.md')


class CommunityRefusal(unittest.TestCase):
    def test_only_community_target_with_documented_message(self):
        self.assertTrue(crd.community_refusal("community", REFUSAL))
        self.assertFalse(crd.community_refusal("", REFUSAL))
        self.assertFalse(crd.community_refusal("community", "scan crashed"))
        self.assertFalse(crd.community_refusal("community", "is in the community catalog"))


class MinFrom(unittest.TestCase):
    def test_lines_below_min_from_are_dropped(self):
        lines = [(0, 13), (0, 35), (0, 36), (1, 0)]
        self.assertEqual(crd.lines_from(lines, "0.36"), [(0, 36), (1, 0)])
        self.assertEqual(crd.lines_from(lines, ""), lines)
        self.assertEqual(crd.lines_from(lines, None), lines)


class Counts(unittest.TestCase):
    def test_unsupported_community_is_counted_not_an_error(self):
        import qalib
        cases = [qalib.case("crd", "a", status="UNSUPPORTED_COMMUNITY"), qalib.case("crd", "b")]
        self.assertEqual(qalib.counts(cases), {"wrongpass": 0, "mismatch": 0, "error": 0, "unsupported_community": 1})


class StageCompleteness(unittest.TestCase):
    kube = {"component": "kubernetes"}
    uncovered = {"component": "kubernetes", "gaps": [{"reason": "COMPONENT_NOT_COVERED"}]}

    def call(self, stage, got, exp, ok=True, missing=(), wp=False, mm=False):
        return k8s.stage_is_complete(stage, got, exp, ok, list(missing), wp, mm)

    def test_blocked_stage_with_scope_gap_is_complete(self):
        self.assertTrue(self.call(self.uncovered, "BLOCKED", True))

    def test_api_version_not_reviewed_gap_is_scope_limit(self):
        stage = {"component": "kubernetes", "gaps": [{"reason": "API_VERSION_NOT_REVIEWED"}]}
        self.assertTrue(self.call(stage, "UNKNOWN", False))

    def test_unknown_without_removals_from_uncovered_areas_is_complete(self):
        self.assertTrue(self.call(self.uncovered, "UNKNOWN", False))

    def test_unknown_when_removals_expected_is_not_complete(self):
        self.assertFalse(self.call(self.uncovered, "UNKNOWN", True))

    def test_pass_when_removals_expected_is_not_complete(self):
        self.assertFalse(self.call(self.kube, "SCOPE_COMPLETE_PASS", True))

    def test_other_gap_unsupported_missing_or_incomplete_input_stay_errors(self):
        self.assertFalse(self.call({"component": "kubernetes", "gaps": [{"reason": "DOCUMENTS_NOT_EVALUATED"}]}, "BLOCKED", True))
        self.assertFalse(self.call({"component": "kubernetes", "unsupported": [{"x": 1}]}, "BLOCKED", True))
        self.assertFalse(self.call(self.kube, "BLOCKED", True, missing=["a/v1/K"]))
        self.assertFalse(self.call(self.kube, "BLOCKED", True, ok=False))
        self.assertFalse(self.call(self.kube, "BLOCKED", True, wp=True))


if __name__ == "__main__":
    unittest.main()
