"""Nightly harness proofs: community-catalog refusals and plan stages limited only by uncovered areas."""
import json
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

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

    def test_dropped_pair_count_includes_boundary_pair(self):
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            pairs = crd.adjacent_pairs([(0, 13), (0, 35), (0, 36), (1, 0)], "0.36", "sample")
        self.assertEqual(pairs, [{"from": "0.36", "to": "1.0"}])
        self.assertIn("dropped_pairs=2", output.getvalue())


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

    def test_scope_gaps_do_not_hide_missed_removal(self):
        for reason in ("DECLARATION_MISSING", "INTERMEDIATE_LINE_NOT_COVERED_BY_RANGE"):
            stage = {"component": "kubernetes", "gaps": [{"reason": reason}]}
            for verdict, code, expected in (("SCOPE_COMPLETE_PASS", 0, "wrongpass"), ("BLOCKED", 10, "mismatch")):
                with self.subTest(reason=reason, verdict=verdict):
                    report = {"verdict": verdict, "paths": [], "findings": []}
                    wp, mm, missing, _ = k8s.scoped_result(code, report, [("example.io", "v1", "Widget")],
                                                            "kubernetes", "kubernetes.removed_served_gvk")
                    self.assertTrue(wp if expected == "wrongpass" else mm)
                    self.assertEqual(missing, ["example.io/v1/Widget"])
                    self.assertFalse(self.call(stage, verdict, True, missing=missing, wp=wp, mm=mm))


class SummaryRise(unittest.TestCase):
    def test_comparable_previous_run_and_adhoc_preserves_status(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            out, state = root / "out", root / "state"
            out.mkdir()
            state.mkdir()
            status = state / "status.json"
            status.write_text(json.dumps({"mode": "incremental", "unsupported_community": 1}))
            cases = [{"suite": "crd", "key": str(i), "wrongpass": False, "mismatch": False,
                      "error": False, "detail": {"status": "UNSUPPORTED_COMMUNITY"}} for i in range(2)]
            (out / "crd.cases.json").write_text(json.dumps(cases))
            cmd = [sys.executable, str(Path(__file__).with_name("summarize.py")), "--dir", str(out),
                   "--state", str(state), "--sha", "a" * 40, "--mode", "incremental", "--adhoc"]
            result = subprocess.run(cmd, text=True, capture_output=True)
            self.assertIn("UNSUPPORTED_COMMUNITY_RISE=1->2", result.stdout)
            self.assertTrue(json.loads((out / "summary.json").read_text())["unsupported_community_rise"])
            self.assertEqual(json.loads(status.read_text())["unsupported_community"], 1)
            status.write_text(json.dumps({"mode": "full", "unsupported_community": 1}))
            subprocess.run(cmd, text=True, capture_output=True, check=False)
            self.assertIsNone(json.loads((out / "summary.json").read_text())["unsupported_community_rise"])


if __name__ == "__main__":
    unittest.main()
