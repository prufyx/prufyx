#!/usr/bin/env python3
"""Source floors: every acceptance path has a negative test; the last class runs the real rules oracle with a stub CLI."""
import copy, json, os, pathlib, subprocess, sys, tempfile, unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import qalib
import source_floors as sf

SEEDS = {("etcd", "3.5.17", "3.6.0"), ("etcd", "3.5.25", "3.6.0"), ("harbor", "2.10.3", "2.15.2"),
         ("harbor", "2.11.2", "2.15.2"), ("cilium", "1.18.6", "1.19.0")}


def real():
    return json.loads((HERE / "source_floors.json").read_text())


def rules(*extra):
    entries = [{"project": f["project"], "rule": {"id": f["id"], "operator": "forbid_predicate_value",
                "subject": {"component": f["component"], "from": f["probes"][0]["from"], "to": f["probes"][0]["to"]}}}
               for f in real()["floors"]]
    return entries + list(extra)


def claim(status="UNKNOWN", operator="forbid_predicate_value", reason="RULE_TRANSITION_NOT_REVIEWED"):
    return {"ruleId": "r", "status": status, "operator": operator, "reasonCode": reason}


def report(*claims, project="etcd", **extra):
    return json.dumps(dict({"project": project, "assessment": "UNKNOWN", "check": {"assessment": "UNKNOWN", "claims": list(claims)}}, **extra))


class Judge(unittest.TestCase):
    def rejected(self, code, out, wrong=False):
        got, why = sf.judge(code, out, "etcd")
        self.assertEqual(got, wrong, why)
        self.assertEqual(bool(why), not wrong)

    def accepted(self, code, out):
        self.assertEqual(sf.judge(code, out, "etcd"), (False, None))

    def test_exit_zero_is_a_wrong_pass_whatever_the_report_says(self):
        for out in ("", "junk", report(claim("PASS")), report()):
            self.rejected(0, out, wrong=True)

    def test_pass_verdict_with_a_non_zero_exit_is_a_wrong_pass(self):
        for verdict in ("PASS", "SCOPE_COMPLETE_PASS"):
            self.rejected(11, report(assessment=verdict), wrong=True)

    def test_other_exit_codes_prove_nothing(self):
        for code in (1, 2, 3, 12, 15, -9, -11, 139):
            self.rejected(code, report(claim()))

    def test_unreadable_or_foreign_report(self):
        for out in ("", "junk", "[]", "{}", report(project="harbor"), json.dumps({"project": "etcd"}),
                    json.dumps({"project": "etcd", "check": {"claims": "x"}}), report({"status": "UNKNOWN"})):
            self.rejected(11, out)

    def test_settled_unknown_reasons(self):
        for reason in sf.SETTLED_UNKNOWN:
            self.accepted(11, report(claim(reason=reason)))
        self.accepted(11, report())

    def test_other_unknown_reasons_are_errors(self):
        for reason in ("RULE_FACT_UNAVAILABLE", "RULE_APPLICABILITY_FACT_UNAVAILABLE", "RULE_APPLICABILITY_NOT_MATCHED",
                       "RULE_EVIDENCE_CLOCK_BEFORE_REVIEW", "RULE_DEPENDENCY_COMPONENT_MISSING", "SOMETHING_NEW"):
            self.rejected(11, report(claim(), claim(reason=reason)))

    def test_version_block(self):
        for op in sf.VERSION_OPERATORS:
            self.accepted(10, report(claim("BLOCKED", op), claim("PASS")))

    def test_fact_block_does_not_count(self):
        for op in ("forbid_predicate_value", "forbid_set_member", "require_component_version"):
            self.rejected(10, report(claim("BLOCKED", op)))
            self.rejected(10, report(claim("BLOCKED", "forbid_target_version"), claim("BLOCKED", op)))

    def test_blocked_exit_needs_a_version_block(self):
        self.rejected(10, report())
        self.rejected(10, report(claim()))

    def test_pass_claim_without_a_version_block(self):
        self.rejected(11, report(claim("PASS"), claim()))

    def test_other_statuses(self):
        for status in ("NO_KNOWN_ISSUE", "UNSUPPORTED", "NEW"):
            self.rejected(11, report(claim(status)))
        self.accepted(11, report(claim("NOTICE", "notice_one_way")))


class Cases(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.dir = pathlib.Path(d.name)
        patch = mock.patch.object(qalib, "NOW", "2026-11-29T00:00:00Z")
        patch.start()
        self.addCleanup(patch.stop)
        self.seen = []

    def run_cases(self, floors=None, entries=None, code=11, stdout=None, raw=None):
        path = self.dir / "floors.json"
        path.write_text(raw if raw is not None else json.dumps(floors or real()))
        rf = self.dir / sf.RULES
        rf.parent.mkdir(parents=True, exist_ok=True)
        rf.write_text(json.dumps({"entries": rules() if entries is None else entries}))

        def runner(project, doc, name):
            pair = (project, doc["current"]["components"][0]["version"], doc["proposed"]["components"][0]["version"])
            self.seen.append((pair, doc))
            return code, report(project=project) if stdout is None else stdout, ["prufyx", "check"]
        return sf.cases(str(self.dir), str(path), runner)

    def test_seeded_pairs_are_probed_with_safe_facts(self):
        out = self.run_cases()
        self.assertEqual({p for p, _ in self.seen}, SEEDS)
        for _, doc in self.seen:
            self.assertEqual([f["boolValue"] for f in doc["proposed"]["components"][0]["facts"]], [False])
        self.assertFalse(any(c["wrongpass"] or c["error"] or c["mismatch"] for c in out))

    def test_every_passing_seed_is_a_wrong_pass(self):
        out = self.run_cases(code=0)
        self.assertEqual(len(out), len(SEEDS))
        self.assertTrue(all(c["suite"] == "rules" and c["wrongpass"] and c["detail"]["citations"] for c in out))

    def test_inconclusive_probe_is_an_error(self):
        self.assertTrue(all(c["error"] for c in self.run_cases(code=2)))

    def test_runner_that_cannot_start_is_an_error(self):
        self.run_cases()

        def runner(*_):
            raise OSError("no binary")
        out = sf.cases(str(self.dir), str(self.dir / "floors.json"), runner)
        self.assertTrue(out and all(c["error"] for c in out))

    def assert_only_error(self, out, key):
        self.assertEqual([(c["key"], c["error"]) for c in out], [("floor|" + key, True)])
        self.assertEqual(self.seen, [])

    def test_bad_floor_files(self):
        def changed(fn):
            d = real()
            fn(d)
            return d
        first = lambda d: d["floors"][0]
        bad = [
            lambda d: d.update(schema="x"), lambda d: d.update(extra=1), lambda d: d.update(floors=[]),
            lambda d: d["floors"].append(copy.deepcopy(first(d))), lambda d: first(d).pop("citations"),
            lambda d: first(d).update(allow=True), lambda d: first(d).update(citations=[]),
            lambda d: first(d)["citations"][0].update(url="https://github.com/etcd-io/website/blob/main/x.md"),
            lambda d: first(d)["citations"][0].update(line=0), lambda d: first(d).update(probes=[]),
            lambda d: first(d)["probes"][0].update({"from": "3.5.26"}), lambda d: first(d)["probes"][0].update(to="3.7.0"),
            lambda d: first(d).update(safeFacts=[]), lambda d: first(d)["safeFacts"][0].update(boolValue="false"),
            lambda d: first(d).update(minimumSource="3.5"), lambda d: first(d).update(minimumSource="3.6.1"),
            lambda d: first(d).update(targetLine="3"), lambda d: first(d).update(component="etcd"),
        ]
        for i, fn in enumerate(bad):
            with self.subTest(i):
                self.assert_only_error(self.run_cases(changed(fn)), "list-unreadable")
        for raw in ("", "[]", "null", "{", '{"schema":"%s","schema":"%s","floors":[]}' % (sf.SCHEMA, sf.SCHEMA)):
            with self.subTest(raw):
                self.assert_only_error(self.run_cases(raw=raw), "list-unreadable")

    def test_missing_floor_file(self):
        self.assert_only_error(sf.cases(str(self.dir), str(self.dir / "absent.json")), "list-unreadable")

    def test_no_clock(self):
        with mock.patch.object(qalib, "NOW", ""):
            self.assert_only_error(self.run_cases(), "no-clock")

    def test_unreadable_rules(self):
        self.assert_only_error(self.run_cases(entries=[]), "rules-unreadable")

    def test_component_unknown_to_the_rules_is_an_error_and_pinned_pairs_still_run(self):
        out = self.run_cases(entries=rules()[1:])
        self.assertIn(("floor|etcd-3.6|rules", True), [(c["key"], c["error"]) for c in out])
        self.assertEqual({p for p, _ in self.seen}, SEEDS)

    def test_unreadable_rule_version_is_an_error(self):
        e = copy.deepcopy(rules()[0])
        e["rule"]["subject"]["from"] = "3.5"
        out = self.run_cases(entries=rules(e))
        self.assertIn(("floor|etcd-3.6|rules", True), [(c["key"], c["error"]) for c in out])

    def entry(self, source, target, rng=None):
        rule = {"id": "n", "operator": "forbid_predicate_value",
                "subject": {"component": "pkg:github/etcd-io/etcd", "from": source, "to": target}}
        if rng:
            rule["range"] = {"from": {"gte": rng[0], "lt": rng[1]}, "to": {"gte": rng[2], "lt": rng[3]}}
        return {"project": "etcd", "rule": rule}

    def test_a_new_rule_below_the_floor_is_probed(self):
        self.run_cases(entries=rules(self.entry("3.4.30", "3.6.4")))
        self.assertIn(("etcd", "3.4.30", "3.6.4"), {p for p, _ in self.seen})

    def test_a_ranged_rule_probes_its_lowest_source_and_floor_minus_one(self):
        self.run_cases(entries=rules(self.entry("3.5.30", "3.6.2", ("3.5.0", "3.6.0", "3.5.0", "3.7.0"))))
        got = {p for p, _ in self.seen}
        for pair in (("etcd", "3.5.0", "3.6.0"), ("etcd", "3.5.25", "3.6.0"), ("etcd", "3.5.0", "3.6.2")):
            self.assertIn(pair, got)
        self.assertNotIn(("etcd", "3.5.30", "3.6.2"), got)

    def test_rules_at_the_floor_or_on_another_line_add_nothing(self):
        self.run_cases(entries=rules(self.entry("3.5.26", "3.6.0"), self.entry("3.4.0", "3.7.0")))
        self.assertEqual({p for p, _ in self.seen}, SEEDS)


STUB = """#!%s
import json, sys
a = sys.argv
project = a[a.index("--project") + 1]
doc = json.load(open(a[a.index("--input") + 1]))
if any(f.get("boolValue") for c in doc["proposed"]["components"] for f in c["facts"]):
    sys.exit(10)
if STATUS == "PASS":
    sys.exit(0)
print(json.dumps({"project": project, "assessment": "UNKNOWN", "check": {"claims": []}}))
sys.exit(11)
"""


class OracleRun(unittest.TestCase):
    """The shipped rules_oracle.py: fails the suite on a passing floor probe, whatever the project and rule-id filters say."""

    def oracle(self, status, **env):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            stub = d / "prufyx"
            stub.write_text((STUB % sys.executable).replace("STATUS ==", "%r ==" % status))
            stub.chmod(0o700)
            entries = rules()
            for e in entries:
                e["rule"].update(appliesWhen=[], condition={"side": "proposed", "component": e["rule"]["subject"]["component"],
                                                            "factId": "f", "boolValue": True})
            rf = d / "src" / sf.RULES
            rf.parent.mkdir(parents=True)
            rf.write_text(json.dumps({"entries": entries}))
            full = dict(os.environ, QA_BIN=str(stub), QA_SRC=str(d / "src"), QA_TMP=str(d / "tmp"),
                        QA_NOW="2026-11-29T00:00:00Z", QA_STATE=str(d), QA_RUNBOX="", QA_BASE="", **env)
            subprocess.run([sys.executable, str(HERE / "rules_oracle.py"), "--out", str(d / "out.json")], env=full,
                           check=True, capture_output=True, timeout=300)
            return [c for c in json.loads((d / "out.json").read_text()) if c["key"].startswith("floor|")]

    def test_passing_floor_pairs_are_wrong_passes(self):
        out = self.oracle("PASS", QA_PROJECTS="nats", QA_RULES_IDS="none")
        self.assertEqual(len(out), len(SEEDS))
        self.assertTrue(all(c["wrongpass"] for c in out))

    def test_non_passing_floor_pairs_are_clean(self):
        out = self.oracle("UNKNOWN")
        self.assertEqual(len(out), len(SEEDS))
        self.assertFalse(any(c["wrongpass"] or c["error"] for c in out))


if __name__ == "__main__":
    unittest.main()
