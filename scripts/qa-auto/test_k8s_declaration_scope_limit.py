"""A plan stage left PARTIAL only by the undeclared kubelet version is a recorded scope limit, nothing else is."""
import unittest

import k8s_oracle as k8s
import qa_scope

KUBELET = "rule kubernetes.kubelet-version-skew.1-32-0-to-1-33-0 applies to this hop but the lowest kubelet is not declared"
STAGE = "k8s-plan|1.24->1.37 stage 1.32.0->1.33.0"


def stage(**change):
    base = {"component": "kubernetes", "hopStatus": "PARTIAL", "findings": [], "unsupported": [],
            "reasons": ["HOP_NOT_COVERED", "COMPONENT_GAP", "HOP_ACTIONS_NOT_CHECKED", "NODE_ROLLS_NOT_PLANNED"],
            "gaps": [{"reason": "API_VERSION_NOT_REVIEWED", "detail": "x"},
                     {"reason": "DECLARATION_MISSING", "detail": KUBELET}]}
    base.update(change)
    return base


def limit(s, got="UNKNOWN", exp=False, ok=True, missing=(), wp=False, mm=False):
    return k8s.stage_scope_limit(s, got, exp, ok, list(missing), wp, mm)


class StageScopeLimit(unittest.TestCase):
    def test_only_declaration_missing_is_scope_limit(self):
        self.assertTrue(limit(stage()))
        self.assertTrue(limit(stage(gaps=[{"reason": "DECLARATION_MISSING", "detail": KUBELET}])))

    def test_declaration_missing_with_another_cause_is_not_a_limit(self):
        for extra in ("LINE_NOT_ATTESTED", "HOP_NOT_COVERED", "INTERMEDIATE_LINE_NOT_COVERED_BY_RANGE", "WHATEVER"):
            with self.subTest(extra=extra):
                gaps = stage()["gaps"] + [{"reason": extra, "detail": "y"}]
                self.assertFalse(limit(stage(gaps=gaps)))
        self.assertFalse(limit(stage(reasons=["HOP_NOT_COVERED", "BLOCKED_BY_EARLIER_FINDING"])))
        self.assertFalse(limit(stage(findings=[{"ruleId": "r"}])))
        self.assertFalse(limit(stage(unsupported=[{"ruleId": "r"}])))

    def test_declaration_gap_of_another_rule_family_is_not_a_limit(self):
        other = [{"reason": "DECLARATION_MISSING", "detail": "rule kubernetes.dockershim.x applies"}]
        self.assertFalse(limit(stage(gaps=other)))
        self.assertFalse(limit(stage(gaps=[{"reason": "DECLARATION_MISSING"}])))

    def test_no_declaration_gap_or_other_status_is_not_a_limit(self):
        self.assertFalse(limit(stage(gaps=[{"reason": "API_VERSION_NOT_REVIEWED"}])))
        for status in ("COVERED", "NO_DATA", "BLOCKED", None):
            self.assertFalse(limit(stage(hopStatus=status)))

    def test_blocked_stays_blocked_and_pass_stays_wrongpass(self):
        self.assertFalse(limit(stage(), got="BLOCKED", exp=True))
        self.assertFalse(limit(stage(), got="BLOCKED"))
        for verdict in ("PASS", "SCOPE_COMPLETE_PASS"):
            self.assertFalse(limit(stage(), got=verdict, exp=True))
            self.assertFalse(limit(stage(), got=verdict))
        self.assertFalse(limit(stage(), exp=True))  # a missed removal (UNKNOWN) is not hidden
        self.assertFalse(limit(stage(), wp=True))
        self.assertFalse(limit(stage(), mm=True))
        self.assertFalse(limit(stage(), missing=["a/v1/K"]))
        self.assertFalse(limit(stage(), ok=False))
        self.assertFalse(limit(stage(component="other")))

    def test_wrongpass_on_expected_removal_still_detected(self):
        report = {"verdict": "SCOPE_COMPLETE_PASS", "paths": [], "findings": []}
        wp, mm, missing, _ = k8s.scoped_result(0, report, [("example.io", "v1", "Widget")],
                                               "kubernetes", "kubernetes.removed_served_gvk")
        self.assertTrue(wp)
        self.assertFalse(limit(stage(), got="SCOPE_COMPLETE_PASS", exp=True, missing=missing, wp=wp, mm=mm))


class RecordedScopeLimit(unittest.TestCase):
    def scope(self, limits):
        value = qa_scope.declare("h", "b", "r", [STAGE], [], [])
        value.update(executed=[STAGE], state="COMPLETE", scope_limits=limits)
        return value

    def good(self):
        return dict(target=STAGE, reason=k8s.KUBELET_LIMIT, next_test=k8s.KUBELET_NEXT_TEST)

    def test_entry_carries_reason_and_next_test(self):
        entry = self.good()
        self.assertEqual(entry["reason"], "kubelet-version-declaration-not-supplied")
        self.assertTrue(entry["next_test"])
        self.assertEqual(qa_scope.errors(self.scope([entry]), "h", "b", "r"), [])
        self.assertEqual(qa_scope.errors(self.scope([]), "h", "b", "r"), [])

    def test_malformed_limits_fail_closed(self):
        bad = [dict(self.good(), reason=""), dict(self.good(), reason="anything"), dict(self.good(), next_test=""),
               dict(self.good(), next_test="  "), dict(self.good(), target="k8s-plan|1.24->1.37 overall"),
               dict(self.good(), target="k8s-plan|1.24->1.37 stage 1.33.0->1.34.0"),
               dict(self.good(), extra=1), {"target": STAGE, "reason": k8s.KUBELET_LIMIT}]
        for entry in bad:
            with self.subTest(entry=entry):
                self.assertTrue(qa_scope.errors(self.scope([entry]), "h", "b", "r"))
        self.assertTrue(qa_scope.errors(self.scope([self.good(), self.good()]), "h", "b", "r"))
        self.assertTrue(qa_scope.errors(self.scope("x"), "h", "b", "r"))
        self.assertTrue(qa_scope.errors(self.scope(["x"]), "h", "b", "r"))


if __name__ == "__main__":
    unittest.main()
