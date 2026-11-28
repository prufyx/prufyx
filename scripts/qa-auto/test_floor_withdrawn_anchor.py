"""A recorded floor withdrawal of an exact-anchor removal rule (cilium 1.19.0 -> 1.20.0): the oracle expects UNKNOWN naming
the withdrawn rule at the anchor, and nothing else. The report shape is the real scanner output for that pair."""
import copy, json, os, tempfile, unittest
from unittest.mock import patch

import crd_oracle as crd

P = "cilium"
C = "pkg:github/cilium/cilium"
ITEM = ("cilium.io", "v2alpha1", "CiliumNodeConfig")
OTHER = ("cilium.io", "v2alpha1", "CiliumOther")
RID = "cilium.crd-version-removal.ciliumnodeconfigs-cilium-io.1-19-0-to-1-20-0"
VERSIONS = ("1.19.0", "1.20.0")


def entry(state="withdrawn"):
    return {"project": P, "rule": {
        "id": RID, "operator": "forbid_set_member", "evidence": {"state": state},
        "subject": {"component": C, "from": "1.19.0", "to": "1.20.0"},
        "setCondition": {"component": C, "factId": "component.cilium.custom_resource_versions_set",
                         "members": ["cilium.io/v2alpha1/CiliumNodeConfig"], "side": "proposed"}}}


def report():
    hop = {"index": 1, "from": "1.19.0", "to": "1.20.0"}
    return {"verdict": "UNKNOWN", "findings": [], "unsupported": [], "omitted": [],
            "summary": {"blockers": 0, "passes": 0, "gaps": 2},
            "gaps": [{"component": P, "reason": "COMPONENT_NOT_COVERED"},
                     {"component": P, "hop": hop, "reason": "EVIDENCE_EXPIRED",
                      "detail": "the review of rule %s is not current (withdrawn)" % RID}],
            "paths": [{"component": P, "hops": [{"status": "PARTIAL", "from": {"version": "1.19.0"},
                                                "to": {"version": "1.20.0"},
                                                "reasons": ["COMPONENT_NOT_COVERED", "EVIDENCE_EXPIRED"]}]}]}


class Withdrawn(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        patcher = patch.object(crd, "SRC", self.dir.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.rules([entry()])

    def rules(self, entries):
        path = os.path.join(self.dir.name, "cli/internal/cncfcheck/data")
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, "rules.json"), "w") as f:
            json.dump({"entries": entries}, f)

    def classify(self, code=11, rep=None, removed=(ITEM,), versions=VERSIONS, component=P):
        return crd.classify_pair(code, report() if rep is None else rep, list(removed), [], component,
                                 None, None, None, False, versions)

    def refused(self, label, **kw):
        r = self.classify(**kw)
        self.assertTrue(r[0] or r[1], (label, r))
        self.assertNotEqual(r[5], crd.WITHDRAWN_STATUS, label)

    def mutated(self, change):
        rep = report()
        change(rep)
        return rep

    def test_recorded_withdrawal_expects_unknown(self):
        r = self.classify()
        self.assertEqual((r[0], r[1], r[2], r[4], r[5]), (False, False, [], False, crd.WITHDRAWN_STATUS))

    def test_any_pass_is_still_wrongpass(self):
        for code, verdict in ((0, "UNKNOWN"), (0, "PASS"), (11, "PASS"), (11, "SCOPE_COMPLETE_PASS")):
            rep = dict(report(), verdict=verdict)
            r = self.classify(code, rep)
            self.assertTrue(r[0], (code, verdict, r))

    def test_other_exit_or_verdict_is_refused(self):
        for code in (2, 3, 10, 15):
            self.refused(code, code=code)
        self.refused("blocked", code=10, rep=dict(report(), verdict="BLOCKED"))

    def test_rule_not_withdrawn_is_refused(self):
        for state in ("active", "stale", "WITHDRAWN", "", None):
            self.rules([entry(state)])
            self.refused(state)
        e = entry()
        del e["rule"]["evidence"]
        self.rules([e])
        self.refused("no evidence")

    def test_changed_missing_or_repeated_rule_is_refused(self):
        changes = {
            "id": lambda e: e["rule"].update(id=RID + "x"),
            "project": lambda e: e.update(project="other"),
            "operator": lambda e: e["rule"].update(operator="forbid_predicate_value"),
            "range": lambda e: e["rule"].update(range={}),
            "subject range": lambda e: e["rule"]["subject"].update(range={}),
            "from": lambda e: e["rule"]["subject"].update({"from": "1.19.1"}),
            "to": lambda e: e["rule"]["subject"].update(to="1.20.1"),
            "component": lambda e: e["rule"]["subject"].update(component="pkg:github/x/y"),
            "members": lambda e: e["rule"]["setCondition"]["members"].append("cilium.io/v2/CiliumOther"),
            "fact": lambda e: e["rule"]["setCondition"].update(factId="f"),
            "side": lambda e: e["rule"]["setCondition"].update(side="current"),
        }
        for label, change in changes.items():
            e = entry()
            change(e)
            self.rules([e])
            self.refused(label)
        self.rules([])
        self.refused("removed from the table")
        self.rules([entry(), entry("active")])
        self.refused("repeated id")
        self.rules(["x"])
        self.refused("malformed table")
        with patch.object(crd, "SRC", "/nonexistent"):
            self.refused("unreadable table")

    def test_unrecorded_rule_pair_or_removals_are_refused(self):
        with patch.object(crd, "FLOOR_WITHDRAWN", ()):
            self.refused("not recorded")
        for reason in ("", "OTHER"):
            with patch.object(crd, "FLOOR_WITHDRAWN", (dict(crd.FLOOR_WITHDRAWN[0], reason=reason),)):
                self.refused(reason)
        for versions in (("1.18.0", "1.20.0"), ("1.19.0", "1.20.1"), ("v1.19.0", "v1.20.0"), None):
            self.refused(versions, versions=versions)
        self.refused("extra removal", removed=(ITEM, OTHER))
        self.refused("other removal", removed=(OTHER,))
        self.refused("other project", component="other")

    def test_other_report_shapes_are_refused(self):
        changes = {
            "finding": lambda r: r.update(findings=[{"component": P, "ruleId": RID, "locations": []}]),
            "foreign finding": lambda r: r.update(findings=[{"component": "x"}]),
            "unsupported": lambda r: r.update(unsupported=["x"]),
            "omitted": lambda r: r.update(omitted=["x"]),
            "no omitted": lambda r: r.pop("omitted"),
            "blockers": lambda r: r["summary"].update(blockers=1),
            "passes": lambda r: r["summary"].update(passes=1),
            "no summary": lambda r: r.pop("summary"),
            "no withdrawn gap": lambda r: r["gaps"].pop(),
            "no design gap": lambda r: r["gaps"].pop(0),
            "foreign gap": lambda r: r["gaps"].append({"component": P, "reason": "VERSION_NOT_DETECTED"}),
            "second withdrawn gap": lambda r: r["gaps"].append(copy.deepcopy(r["gaps"][1])),
            "gap component": lambda r: r["gaps"][0].update(component="x"),
            "expired": lambda r: r["gaps"][1].update(
                detail="the review of rule %s is not current (expired)" % RID),
            "other rule": lambda r: r["gaps"][1].update(detail="the review of rule x is not current (withdrawn)"),
            "no gap hop": lambda r: r["gaps"][1].pop("hop"),
            "gap hop": lambda r: r["gaps"][1]["hop"].update({"from": "1.19.1"}),
            "no paths": lambda r: r.update(paths=[]),
            "two paths": lambda r: r["paths"].append(copy.deepcopy(r["paths"][0])),
            "path component": lambda r: r["paths"][0].update(component="x"),
            "no hop": lambda r: r["paths"][0].update(hops=[]),
            "hop status": lambda r: r["paths"][0]["hops"][0].update(status="PASS_SCOPED"),
            "hop reasons": lambda r: r["paths"][0]["hops"][0]["reasons"].append("OTHER"),
            "hop families": lambda r: r["paths"][0]["hops"][0].update(families=[{"family": crd.FAMILY, "status": "UNKNOWN"}]),
            "hop version": lambda r: r["paths"][0]["hops"][0].update(to={"version": "1.20.1"}),
        }
        for label, change in changes.items():
            self.refused(label, rep=self.mutated(change))

    def test_records_match_the_shipped_rule_table(self):
        """Every record names a shipped rule with exactly its scope, whatever its state."""
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        with open(os.path.join(root, "cli/internal/cncfcheck/data/rules.json")) as f:
            shipped = {e["rule"]["id"]: e for e in json.load(f)["entries"]}
        for record in crd.FLOOR_WITHDRAWN:
            rule = shipped[record["rule"]]["rule"]
            self.assertEqual(shipped[record["rule"]]["project"], record["project"])
            self.assertEqual(rule["subject"], {k: record[k] for k in ("component", "from", "to")})
            self.assertEqual(rule["setCondition"]["members"], list(record["members"]))
            self.assertEqual(rule["setCondition"]["factId"], record["factId"])


if __name__ == "__main__":
    unittest.main()
