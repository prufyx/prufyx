"""Pull-request mode: every changed rule the head still ships is reached by its own claim, else an error case."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import corpus
import qalib

HERE = Path(__file__).resolve().parent
WITHDRAWN = ("UNKNOWN", "RULE_EVIDENCE_WITHDRAWN")


def component(rid):
    return "pkg:github/synthetic/" + rid


def forbid(rid):
    return dict(project="sample", rule=dict(
        id=rid, operator="forbid_predicate_value", subject=dict(component=component(rid), **{"from": "1.0.0", "to": "2.0.0"}),
        condition=dict(side="current", component=component(rid), factId="component.sample.removed", value=True)))


def other(rid, operator, comparison="gte", bound="3.2.0", dependency=None):
    entry = forbid(rid)
    rule = entry["rule"]
    rule["operator"] = operator
    del rule["condition"]
    if operator == "require_component_version":
        rule["dependency"] = dict(side="proposed", component=dependency or component(rid + "-dependency"),
                                  comparison=comparison, version=bound)
    return entry


def withdrawn(entry):
    entry["rule"]["evidence"] = {"state": "withdrawn"}
    return entry


class RulesReachTests(unittest.TestCase):
    def run_oracle(self, entries, ids, codes=None, base="b" * 40, allow=None, projects="", claims=None, every="0",
                   raw=None, variants=None):
        """codes: rule id -> exit code of every run of that rule (default 10). claims: rule id -> the claims list of its
        report as (rule id, status, reason) tuples (default: its own BLOCKED claim on exit 10, none otherwise)."""
        codes, claims = codes or {}, claims or {}
        self.inputs = {}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rules = root / "src/cli/internal/cncfcheck/data/rules.json"
            rules.parent.mkdir(parents=True)
            rules.write_text(raw if raw is not None else json.dumps({"entries": entries}))
            (root / "allow.json").write_text(json.dumps(allow or {}))

            def command(args, **kwargs):
                document = json.loads(Path(args[args.index("--input") + 1]).read_text())
                present = {c["component"] for c in document["current"]["components"]}
                rid = next(e["rule"]["id"] for e in entries if e["rule"]["subject"]["component"] in present)
                self.inputs[rid] = document
                code = codes.get(rid, 10)
                if code == "hang":
                    raise subprocess.TimeoutExpired(args, 20)
                found = claims.get(rid, [(rid, "BLOCKED", "R")] if code == 10 else [])
                report = {"check": {"claims": [dict(ruleId=i, status=s, reasonCode=r) for i, s, r in found]}}
                return subprocess.CompletedProcess(args, code, json.dumps(report), "")

            out = root / "rules.cases.json"
            env = {"QA_RULES_IDS": ids, "QA_BASE": base, "QA_PROJECTS": projects, "QA_RULES_ALL": every}
            with patch.dict(os.environ, env), patch.object(qalib, "SRC", str(root / "src")), patch.object(
                    qalib, "TMP", str(root / "tmp")), patch.object(corpus, "variants", return_value=[]) as corpus_calls, patch.object(
                    subprocess, "run", side_effect=command), patch(
                    "sys.argv", ["rules_oracle.py", "--out", str(out), "--allow", str(root / "allow.json")]):
                try:
                    runpy.run_path(str(HERE / "rules_oracle.py"), run_name="__main__")
                except SystemExit as stop:
                    self.assertEqual(stop.code, 0)
                self.corpus_calls = corpus_calls.call_count
            return json.loads(out.read_text())

    def bad(self, cases):
        return {c["key"]: c for c in cases if c["error"] or c["mismatch"] or c["wrongpass"]}

    def assert_error(self, cases, *keys):
        bad = self.bad(cases)
        self.assertEqual(sorted(bad), sorted(keys))
        self.assertTrue(all(c["error"] for c in bad.values()), bad)

    def test_unreachable_changed_rule_is_an_error_beside_a_blocking_one(self):
        for code in (11, 2, 3, 15):
            with self.subTest(code=code):
                cases = self.run_oracle([forbid("good"), forbid("gone")], "good,gone", {"gone": code})
                self.assert_error(cases, "not-reached:gone")
                self.assertEqual(self.bad(cases)["not-reached:gone"]["detail"]["exit"], code)

    def test_exit_10_without_the_rules_own_blocked_claim_reaches_nothing(self):
        for found in ([], [("neighbour", "BLOCKED", "R")], [("gone", "UNKNOWN", "R"), ("neighbour", "BLOCKED", "R")],
                      [("gone", "PASS", "R")], [("gone", "blocked", "R")], [("gone", "BLOCKED", "R")] * 2):
            for ids, base in (("good,gone", "b" * 40), ("", "")):
                with self.subTest(found=found, ids=ids):
                    cases = self.run_oracle([forbid("good"), forbid("gone")], ids, base=base, claims={"gone": found})
                    self.assert_error(cases, "control-unclaimed:gone")
                    self.assertEqual(self.corpus_calls, 1)

    def test_report_without_claims_reaches_nothing(self):
        cases = self.run_oracle([forbid("gone")], "gone", claims={"gone": []})
        self.assert_error(cases, "control-unclaimed:gone", "no-reachable-rule")

    def test_blocked_claim_with_another_exit_reaches_nothing(self):
        cases = self.run_oracle([forbid("good"), forbid("gone")], "good,gone", {"gone": 11},
                                claims={"gone": [("gone", "BLOCKED", "R")]})
        self.assert_error(cases, "not-reached:gone")

    def test_all_requires_every_head_id(self):
        entries = [forbid("good"), forbid("gone"), other("bound", "require_intermediate_version"), other("odd", "unknown_op")]
        cases = self.run_oracle(entries, "", {"gone": 11}, every="1")
        self.assert_error(cases, "not-reached:gone", "not-reached:odd")
        self.assertIn("bound", self.inputs)

    def test_all_with_every_rule_reached_is_clean(self):
        entries = [forbid("good"), other("a", "require_intermediate_version"), other("b", "forbid_target_version"),
                   other("c", "require_component_version")]
        self.assertEqual(self.bad(self.run_oracle(entries, "", every="1")), {})
        self.assertEqual(set(self.inputs), {"good", "a", "b", "c"})
        self.assertEqual(self.corpus_calls, 1)  # control-only operators have no corpus

    def test_unreadable_or_repeated_head_is_an_error(self):
        good = forbid("good")
        for raw in ("{", "[]", "{}", json.dumps({"entries": [good, good]}),
                    json.dumps({"entries": [good, other("good", "forbid_target_version")]}),
                    json.dumps({"entries": [good, {"project": "p"}]}),
                    json.dumps({"entries": [good, {"project": "p", "rule": {"id": "", "operator": "x"}}]}),
                    json.dumps({"entries": [good, {"rule": {"id": "x", "operator": "x"}}]})):
            for ids, every in (("good", "0"), ("", "1"), ("", "0")):
                with self.subTest(raw=raw[:80], every=every):
                    self.assert_error(self.run_oracle([good], ids, every=every, raw=raw), "rules-unreadable")

    def test_control_only_operators_are_reached_by_their_own_claim(self):
        for operator in ("require_intermediate_version", "require_component_version", "forbid_target_version"):
            with self.subTest(operator=operator):
                cases = self.run_oracle([other("bound", operator)], "bound")
                self.assertEqual(self.bad(cases), {})
                self.assertEqual(self.corpus_calls, 0)
                failed = self.run_oracle([other("bound", operator)], "bound", {"bound": 11})
                self.assert_error(failed, "not-reached:bound", "no-reachable-rule")

    def test_range_and_applicability_facts_shape_the_control(self):
        entry = other("bound", "require_intermediate_version")
        entry["rule"]["range"] = {"from": {"gte": "1.1.0", "lt": "1.2.0"}, "to": {"gte": "1.9.0", "lt": "2.0.0"}}
        entry["rule"]["appliesWhen"] = [dict(side="proposed", component=component("bound"), factId="component.sample.mode",
                                             enumValue="on")]
        self.run_oracle([entry], "bound")
        document = self.inputs["bound"]
        self.assertEqual(document["current"]["components"][0]["version"], "1.1.0")
        self.assertEqual(document["proposed"]["components"][0], dict(
            component=component("bound"), version="1.9.0",
            facts=[dict(id="component.sample.mode", state="declared", enumValue="on")]))

    def test_dependency_is_declared_below_its_bound(self):
        for bound, below in (("3.2.1", "3.2.0"), ("3.2.0", "3.1.0"), ("3.0.0", "2.0.0")):
            with self.subTest(bound=bound):
                self.run_oracle([other("bound", "require_component_version", bound=bound)], "bound")
                document = self.inputs["bound"]
                versions = {c["component"]: c["version"] for c in document["proposed"]["components"]}
                self.assertEqual(versions[component("bound-dependency")], below)
                self.assertEqual(versions[component("bound")], "2.0.0")
                self.assertEqual([c["component"] for c in document["current"]["components"]], [component("bound")])

    def test_dependency_without_a_builder_is_an_error(self):
        for entry in (other("bound", "require_component_version", comparison="lt"),
                      other("bound", "require_component_version", comparison="eq"),
                      other("bound", "require_component_version", comparison="lte"),
                      other("bound", "require_component_version", bound="0.0.0"),
                      other("bound", "require_component_version", bound="3.2"),
                      other("bound", "require_component_version", dependency=component("bound"))):
            with self.subTest(dependency=entry["rule"]["dependency"]):
                self.assert_error(self.run_oracle([forbid("good"), entry], "good,bound"), "trigger-build:bound")

    def test_withdrawn_rule_is_reached_by_its_withdrawn_claim_only(self):
        for operator_entry in (forbid("old"), other("old", "forbid_target_version")):
            with self.subTest(operator=operator_entry["rule"]["operator"]):
                entry = withdrawn(operator_entry)
                cases = self.run_oracle([entry], "old", {"old": 11}, claims={"old": [("old",) + WITHDRAWN]})
                self.assertEqual(self.bad(cases), {})
                self.assertEqual(self.corpus_calls, 0)
        for code, found, keys in (
                (11, [("old", "UNKNOWN", "RULE_EVIDENCE_STALE")], ["not-reached:old"]),
                (11, [("x",) + WITHDRAWN], ["not-reached:old"]),
                (2, [("old",) + WITHDRAWN], ["not-reached:old"]),
                (10, [("old", "BLOCKED", "R")], ["control-unclaimed:old"]),
                (0, [("old",) + WITHDRAWN], ["control-pass:old"])):
            with self.subTest(code=code, found=found):
                cases = self.run_oracle([forbid("good"), withdrawn(forbid("old"))], "good,old", {"old": code},
                                        claims={"old": found})
                self.assertEqual(sorted(self.bad(cases)), keys)

    def test_withdrawn_claim_does_not_reach_an_active_rule(self):
        cases = self.run_oracle([forbid("good"), forbid("old")], "good,old", {"old": 11},
                                claims={"old": [("old",) + WITHDRAWN]})
        self.assert_error(cases, "not-reached:old")

    def test_unknown_operator_is_an_error(self):
        self.assert_error(self.run_oracle([forbid("good"), other("bound", "unknown_op")], "good,bound"), "not-reached:bound")

    def test_project_filter_cannot_hide_a_changed_rule(self):
        entry = forbid("gone")
        entry["project"] = "elsewhere"
        cases = self.run_oracle([forbid("good"), entry], "good,gone", base="", projects="sample")
        self.assert_error(cases, "not-reached:gone")

    def test_allowed_control_pass_is_still_not_reached(self):
        allow = {"gone#control": {"ref": "tracked", "reason": "documented"}}
        cases = self.run_oracle([forbid("good"), forbid("gone")], "good,gone", {"gone": 0}, base="", allow=allow)
        self.assert_error(cases, "not-reached:gone")

    def test_reached_and_removed_ids_are_clean(self):
        cases = self.run_oracle([forbid("good"), forbid("also")], "good,also,removed.from.head")
        self.assertEqual(self.bad(cases), {})

    def test_failed_control_is_reported_once_with_its_own_verdict(self):
        for code, key, wrongpass in ((0, "control-pass:gone", True), (1, "control-crash:gone", False),
                                     ("hang", "control-crash:gone", False)):
            with self.subTest(code=code):
                bad = self.bad(self.run_oracle([forbid("good"), forbid("gone")], "good,gone", {"gone": code}))
                self.assertEqual(list(bad), [key])
                self.assertEqual(bad[key]["wrongpass"], wrongpass)

    def test_full_run_keeps_unreachable_rules_informational(self):
        cases = self.run_oracle([forbid("good"), forbid("gone"), other("bound", "forbid_target_version")], "",
                                {"gone": 11}, base="")
        self.assertEqual(self.bad(cases), {})
        self.assertNotIn("bound", self.inputs)  # control-only operators run in the pull-request gate only

    def test_withdrawn_rule_does_not_hide_that_no_active_rule_blocks(self):
        cases = self.run_oracle([withdrawn(forbid("old")), forbid("gone")], "", {"old": 11, "gone": 11}, base="",
                                claims={"old": [("old",) + WITHDRAWN]})
        self.assert_error(cases, "no-reachable-rule")
        self.assertEqual(self.corpus_calls, 0)


if __name__ == "__main__":
    unittest.main()
