#!/usr/bin/env python3
"""Source floors: every acceptance path has a negative test; the last class runs the real rules oracle with a stub CLI."""
import copy, json, os, pathlib, subprocess, sys, tempfile, unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import qalib
import source_floors as sf

CEPH_SEEDS = {("ceph", v, "20.2.4") for v in ("15.2.17", "16.2.15", "17.2.9")}
SEEDS = {("etcd", "3.5.17", "3.6.0"), ("etcd", "3.5.25", "3.6.0"), ("harbor", "2.10.3", "2.15.2"),
         ("harbor", "2.11.2", "2.15.2"), ("cilium", "1.18.6", "1.19.0"), ("cilium", "1.18.13", "1.19.7"),
         ("contour", "1.19.0", "1.20.0")} | CEPH_SEEDS
ORDER_SEEDS = {("ceph", "17.2.7", "18.2.0"), ("mariadb-operator", "0.38.1", "25.0.0"),
               ("mariadb-operator", "25.8.4", "25.10.4")}
SEEDS |= ORDER_SEEDS
FLOORS = {"etcd-3.6": "3.5.26", "harbor-2.15": "2.12.0", "cilium-1.19": "1.18.14", "contour-1.20": "1.19.1",
          "ceph-20.2": "18.2.0", "ceph-release-order": "release-order", "mariadb-operator-no-skip": "no-skip"}
MDB = "pkg:github/mariadb-operator/mariadb-operator"
CEPH = "pkg:github/ceph/ceph"
OTHER = {"project": "other", "rule": {"id": "o", "subject": {"component": "pkg:github/x/y", "from": "1.0.0", "to": "1.1.0"}}}
COMMUNITY_FLOORS = {"ceph-20.2", "ceph-release-order", "mariadb-operator-no-skip"}  # rules in the community pack


def real():
    return json.loads((HERE / "source_floors.json").read_text())


def sources():
    return real()["ruleSources"]


def withdrawn(community):
    """One withdrawn rule per floor of one pack: the static check stays clean and the component is named."""
    return [{"project": f["project"], "rule": {"id": f["id"], "operator": "forbid_predicate_value",
             "subject": {"component": f["component"], "from": f["probes"][0]["from"], "to": f["probes"][0]["to"]},
             "evidence": {"state": "withdrawn"}}} for f in real()["floors"] if (f["id"] in COMMUNITY_FLOORS) == community]


def put(root, rel, text):
    path = pathlib.Path(root) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def write_knowledge(root, entries, attested=None, project_entries=None):
    """The two public rules.json files of a synthetic checkout, each embedded by a Go file."""
    first = {"entries": entries} if attested is None else {"entries": entries, "lineAttestations": attested}
    second = {"entries": [OTHER] + withdrawn(True) if project_entries is None else project_entries}
    for rel, data in ((sf.RULES, first), (sf.PROJECT_RULES, second)):
        put(root, rel, json.dumps(data))
        put(root, str(pathlib.Path(rel).parent.parent / "pack.go"), "package p\n\n//go:embed data/rules.json\nvar f embed.FS\n")


def rules(*extra):
    """The withdrawn rules of the CNCF pack, then extra."""
    return withdrawn(False) + list(extra)


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
        self.routes = set()

    def run_cases(self, floors=None, entries=None, code=11, stdout=None, raw=None, project_entries=None):
        path = self.dir / "floors.json"
        path.write_text(raw if raw is not None else json.dumps(floors or real()))
        write_knowledge(self.dir, rules() if entries is None else entries, project_entries=project_entries)

        def runner(route, project, doc, name):
            pair = (project, doc["current"]["components"][0]["version"], doc["proposed"]["components"][0]["version"])
            self.seen.append((pair, doc))
            self.routes.add((route, project))
            if stdout is not None:
                out = stdout
            elif route == sf.CNCF:
                out = report(project=project)
            else:
                out = batch(report(project=project), project)
            return code, out, ["prufyx", "check"]
        return sf.cases(str(self.dir), str(path), runner)

    def test_seeded_pairs_are_probed_with_safe_facts(self):
        out = self.run_cases()
        self.assertEqual({p for p, _ in self.seen}, SEEDS)
        for pair, doc in self.seen:
            facts = {f["id"]: f["boolValue"] for side in ("current", "proposed") for f in doc[side]["components"][0]["facts"]}
            complete = facts.pop("component.mariadb_operator.resource_complete", None)
            self.assertEqual(complete, True if pair[0] == "mariadb-operator" else None, pair)
            self.assertEqual(set(facts.values()), {False}, pair)
            self.assertEqual(len(facts), 8 if pair == ("mariadb-operator", "25.8.4", "25.10.4") else 1, pair)
        self.assertFalse(any(c["wrongpass"] or c["error"] or c["mismatch"] for c in out))

    def test_each_floor_is_probed_on_the_route_of_its_pack(self):
        self.run_cases()
        self.assertEqual(self.routes, {("cncf", p) for p in ("etcd", "harbor", "cilium", "contour")}
                         | {("community_project", "ceph"), ("community_project", "mariadb-operator")})

    def test_a_component_in_both_packs_is_probed_on_both_routes(self):
        out = self.run_cases(project_entries=withdrawn(True) + withdrawn(False)[:1])
        self.assertEqual({r for r, p in self.routes if p == "etcd"}, set(sf.ROUTES))
        keys = [c["key"] for c in probes(out)]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertIn("floor|etcd-3.6|3.5.17->3.6.0|community_project", keys)

    def test_a_floor_no_pack_names_is_probed_on_every_route_and_is_an_error(self):
        out = self.run_cases(project_entries=[OTHER])
        self.assertIn(("floor|ceph-20.2|rules", True), [(c["key"], c["error"]) for c in out])
        self.assertEqual({r for r, p in self.routes if p == "ceph"}, set(sf.ROUTES))

    def test_a_new_community_rule_below_the_floor_is_probed(self):
        extra = {"project": "ceph", "rule": {"id": "n", "operator": "forbid_predicate_value",
                 "subject": {"component": "pkg:github/ceph/ceph", "from": "14.2.22", "to": "20.2.5"}}}
        out = self.run_cases(project_entries=withdrawn(True) + [extra])
        self.assertIn(("ceph", "14.2.22", "20.2.5"), {p for p, _ in self.seen})
        self.assertIn("floor|static|ceph-20.2|%s|n" % sf.PROJECT_RULES, [c["key"] for c in out if c["wrongpass"]])

    def test_every_passing_seed_is_a_wrong_pass(self):
        out = probes(self.run_cases(code=0))
        self.assertEqual(len(out), len(SEEDS))
        self.assertTrue(all(c["suite"] == "rules" and c["wrongpass"] and c["detail"]["citations"] for c in out))

    def test_inconclusive_probe_is_an_error(self):
        out = probes(self.run_cases(code=2))
        self.assertTrue(out and all(c["error"] for c in out))

    def test_runner_that_cannot_start_is_an_error(self):
        self.run_cases()

        self.routes.clear()

        def runner(*_):
            raise OSError("no binary")
        out = probes(sf.cases(str(self.dir), str(self.dir / "floors.json"), runner))
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
            lambda d: first(d).update(basis="guess"), lambda d: first(d).update(basis=[]), lambda d: first(d).pop("basis"),
            lambda d: first(d).update(note=" "), lambda d: first(d).update(minimumSource="3.5.x"),
            lambda d: first(d).update(minimumSource=None), lambda d: first(d)["probes"][0].update({"from": "v3.5.1"}),
        ]
        for i, fn in enumerate(bad):
            with self.subTest(i):
                self.assert_only_error(self.run_cases(changed(fn)), "list-unreadable")
        src = lambda d: d["ruleSources"]
        bad = [
            lambda d: d.pop("ruleSources"), lambda d: d.update(ruleSources=[]), lambda d: src(d).pop("support"),
            lambda d: src(d).update(allow=[]), lambda d: src(d).update(rules={}), lambda d: src(d).update(rules=[sf.RULES]),
            lambda d: src(d)["rules"].update({sf.RULES: "none"}), lambda d: src(d)["rules"].update({sf.RULES: []}),
            lambda d: src(d)["rules"].pop(sf.PROJECT_RULES), lambda d: src(d)["support"].append(sf.RULES),
            lambda d: src(d)["verdict"].append(src(d)["support"][0]), lambda d: src(d)["verdict"].append("a/*.json"),
            lambda d: src(d)["rules"].update({"a/*.json": "cncf"}), lambda d: src(d)["support"].append("a/*.json"),
            lambda d: src(d)["support"].append("a/*/b.json"), lambda d: src(d)["support"].append(""),
            lambda d: src(d).update(support={}),
        ]
        for i, fn in enumerate(bad):
            with self.subTest(sources=i):
                self.assert_only_error(self.run_cases(changed(fn)), "list-unreadable")
        for raw in ("", "[]", "null", "{", '{"schema":"%s","schema":"%s","floors":[]}' % (sf.SCHEMA, sf.SCHEMA)):
            with self.subTest(raw):
                self.assert_only_error(self.run_cases(raw=raw), "list-unreadable")

    def test_missing_floor_file(self):
        self.assert_only_error(sf.cases(str(self.dir), str(self.dir / "absent.json")), "list-unreadable")

    def test_no_clock(self):
        with mock.patch.object(qalib, "NOW", ""):
            out = self.run_cases()
        self.assertEqual([c["key"] for c in out if c["error"]], ["floor|no-clock"])
        self.assertEqual([c["key"] for c in probes(out)], ["floor|no-clock"])
        self.assertEqual(self.seen, [])

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
        self.assertIn(("floor|etcd-3.6|rules|cncf", True), [(c["key"], c["error"]) for c in out])
        self.assertEqual({p for p, _ in self.seen}, SEEDS)

    def test_shipped_floors(self):
        floors = sf.load(str(HERE / "source_floors.json"))
        self.assertEqual({f["id"]: f.get("minimumSource", f.get("kind")) for f in floors}, FLOORS)
        self.assertEqual({f["id"] for f in floors if f["basis"] == "derived"}, {"cilium-1.19"})

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


def probes(cases):
    return [c for c in cases if not c["key"].startswith("floor|static|")]


def rule(source="3.5.26", target="3.6.0", rng=None, component="pkg:github/etcd-io/etcd", operator="forbid_predicate_value",
         state="active", rid="n", **extra):
    body = dict({"id": rid, "operator": operator, "subject": {"component": component, "from": source, "to": target},
                 "evidence": {"state": state}}, **extra)
    if rng:
        body["range"] = {"from": {"gte": rng[0], "lt": rng[1]}, "to": {"gte": rng[2], "lt": rng[3]}, "bounds": []}
    return {"project": "etcd", "rule": body}


class Static(unittest.TestCase):
    """The scan of every rule entry: no binary, no probe."""

    def scan(self, entries=(), attested=None, project_entries=None):
        with tempfile.TemporaryDirectory() as d:
            write_knowledge(d, rules(*entries), attested, project_entries)
            return sf.static_cases(sf.load(str(HERE / "source_floors.json")), sf.read_knowledge(d, sources()))

    def flagged(self, *entries, **kw):
        out = self.scan(entries, **kw)
        self.assertEqual([c for c in out if c["error"]], [])
        return [c for c in out if c["wrongpass"]]

    def assert_error(self, out):
        self.assertTrue([c for c in out if c["error"]])
        self.assertNotIn("floor|static|etcd-3.6", [c["key"] for c in out])

    def test_clean_knowledge_reports_one_clean_case_per_floor(self):
        out = self.scan()
        self.assertEqual({c["key"] for c in out}, {"floor|static|" + i for i in FLOORS})
        self.assertFalse(any(c["wrongpass"] or c["error"] or c["mismatch"] for c in out))

    def test_anchor_below_and_at_each_floor(self):
        for f in (f for f in real()["floors"] if "kind" not in f):
            major, minor, patch = (int(x) for x in f["minimumSource"].split("."))
            below = "%d.%d.%d" % ((major, minor, patch - 1) if patch else (major, minor - 1, 99))
            target = f["targetLine"] + ".3"
            with self.subTest(f["id"]):
                hit = [c for c in self.flagged(rule(below, target, component=f["component"]))
                       if c["key"].split("|")[2] == f["id"]]
                self.assertEqual([c["key"] for c in hit], ["floor|static|%s|%s|n" % (f["id"], sf.RULES)])
                self.assertTrue(hit[0]["mismatch"] and hit[0]["detail"]["citations"])
                self.assertEqual(self.flagged(rule(f["minimumSource"], target, component=f["component"])), [])

    def test_gap_between_the_probed_pairs(self):
        """etcd 3.5.18-3.5.24: neither a pinned pair nor floor minus one patch, still flagged."""
        for source in ("3.5.18", "3.5.21", "3.5.24"):
            self.assertEqual(len(self.flagged(rule(source, "3.6.4"))), 1, source)
        gap = rule("3.5.30", "3.6.4", ("3.5.18", "3.5.25", "3.6.0", "3.7.0"))
        self.assertEqual([c["detail"]["covered"] for c in self.flagged(gap)],
                         [[{"match": "range", "lowestSource": "3.5.18"}]])

    def test_range_boundaries(self):
        for rng in (("3.5.25", "3.5.27", "3.6.0", "3.7.0"), ("3.4.0", "3.5.0", "3.6.9", "3.6.10"),
                    ("3.5.0", "3.6.0", "3.5.0", "3.6.1"), ("3.5.0", "3.6.0", "3.5.0", "3.8.0")):
            with self.subTest(rng):
                self.assertEqual(len(self.flagged(rule(rng=rng))), 1)
        for rng in (("3.5.26", "3.6.0", "3.6.0", "3.7.0"), ("3.5.0", "3.5.9", "3.5.0", "3.6.0"),
                    ("3.5.0", "3.5.9", "3.7.0", "3.8.0")):
            with self.subTest(rng):
                self.assertEqual(self.flagged(rule(rng=rng)), [])

    def test_crossing_that_reaches_the_line(self):
        crossing = {"change": {"version": "3.6.0"}, "horizon": {"lt": "3.8.0"}}
        self.assertEqual(len(self.flagged(rule(crossing=crossing))), 1)

    def test_other_lines_and_components_are_not_flagged(self):
        self.assertEqual(self.flagged(rule("3.4.0", "3.5.9"), rule("3.4.0", "3.7.0", rid="m"),
                                      rule("3.4.0", "3.6.0", component="pkg:github/x/y", rid="p")), [])

    def test_operators(self):
        for operator in sorted(sf.NEVER_PASS):
            self.assertEqual(self.flagged(rule("3.5.1", operator=operator)), [], operator)
        for operator in ("forbid_predicate_value", "forbid_set_member", "require_component_version", "require_set_member",
                         "something_new", None, []):
            self.assertEqual(len(self.flagged(rule("3.5.1", operator=operator))), 1, operator)

    def test_a_block_on_the_same_pair_does_not_excuse_a_passing_rule(self):
        hit = self.flagged(rule("3.5.1", operator="forbid_target_version", rid="m"), rule("3.5.1"))
        self.assertEqual([c["detail"]["rule"] for c in hit], ["n"])

    def test_only_withdrawn_evidence_is_skipped(self):
        self.assertEqual(self.flagged(rule("3.5.1", state="withdrawn")), [])
        for state in ("active", "stale", "Withdrawn", None):
            self.assertEqual(len(self.flagged(rule("3.5.1", state=state))), 1, state)

    def test_another_file_or_project_name_does_not_hide_a_rule(self):
        moved = dict(rule("3.5.1"), project="renamed")
        hit = self.flagged(project_entries=[moved])
        self.assertEqual([c["detail"]["file"] for c in hit], [sf.PROJECT_RULES])

    def test_unreadable_floored_rules_are_errors(self):
        chart = rule()
        chart["rule"]["subject"]["chart"] = {}
        bad = [rule("3.5"), rule(target="3.6"), rule("3.5.1-rc.1"), rule(rng=("3.5.x", "3.6.0", "3.6.0", "3.7.0")),
               rule(rng=("3.5.9", "3.5.9", "3.6.0", "3.7.0")), rule(range=None), rule(range={}), rule(crossing={}),
               rule(ranges=[]), rule(rid=""), rule(state="withdrawn", target="x"), chart]
        for i, entry in enumerate(bad):
            with self.subTest(i):
                self.assert_error(self.scan([entry]))

    def test_entry_without_a_component_leaves_no_floor_clean(self):
        for entry in ({}, {"rule": {}}, {"rule": {"subject": {}}}, {"rule": {"subject": {"component": 1}}}, [], None):
            with self.subTest(entry):
                out = self.scan([entry])
                self.assertEqual([c["error"] for c in out], [True])

    def attestation(self, line, *sources):
        return {"component": "pkg:github/etcd-io/etcd", "line": line,
                "releases": {"from": [{"version": v} for v in sources]}}

    def test_line_attestations(self):
        hit = self.flagged(attested=[self.attestation("3.6", "3.5.26", "3.5.19")])
        self.assertEqual([c["detail"]["sources"] for c in hit], [["3.5.19"]])
        self.assertEqual(self.flagged(attested=[self.attestation("3.6", "3.5.26"), self.attestation("3.5", "3.4.0")]), [])

    def test_unreadable_attestations_are_errors(self):
        for att in ({}, self.attestation("3.6"), self.attestation("3.6", "3.5"), self.attestation("3", "3.5.1"),
                    {"component": "pkg:github/etcd-io/etcd", "line": "3.6"}):
            with self.subTest(att):
                self.assert_error(self.scan(attested=[att]))

    def test_unreadable_knowledge_is_one_error(self):
        def run(damage):
            with tempfile.TemporaryDirectory() as d:
                write_knowledge(d, rules())
                damage(pathlib.Path(d))
                with mock.patch.object(qalib, "NOW", "2026-11-29T00:00:00Z"):
                    return sf.cases(d, str(HERE / "source_floors.json"), lambda *_: self.fail("probed"))

        damages = []
        for rel in (sf.RULES, sf.PROJECT_RULES):
            damages.append(lambda d, rel=rel: (d / rel).unlink())
            for raw in ("", "{", "[]", "{}", '{"entries":[]}', '{"entries":{}}', '{"entries":[1],"entries":[1]}',
                        '{"entries":[1],"lineAttestations":{}}'):
                damages.append(lambda d, rel=rel, raw=raw: (d / rel).write_text(raw))
        for i, damage in enumerate(damages):
            with self.subTest(i):
                out = [(c["key"], c["error"]) for c in run(damage)]
                self.assertEqual(out[-1], ("floor|rules-unreadable", True))
                self.assertTrue(all(error and key.startswith(("floor|source|", "floor|rules-")) for key, error in out))


def entry_of(fid):
    return next(f for f in sf.load(str(HERE / "source_floors.json")) if f["id"] == fid)


def parsed(text):
    return tuple(int(x) for x in text.split("."))


class OrderPairs(unittest.TestCase):
    """One exact pair against the two shipped release order entries."""

    def check(self, fid, bad, good):
        f = entry_of(fid)
        for source, target in bad:
            with self.subTest(bad=(source, target)):
                self.assertTrue(sf.order_violation(f, parsed(source), parsed(target)))
        for source, target in good:
            with self.subTest(good=(source, target)):
                self.assertIsNone(sf.order_violation(f, parsed(source), parsed(target)))

    def test_no_skip(self):
        self.check("mariadb-operator-no-skip", bad=[
            ("0.38.1", "25.0.0"), ("25.8.4", "25.10.4"), ("25.10.0", "25.10.4"), ("0.34.0", "0.35.1"),
            ("0.38.1", "25.8.1"), ("25.8.4", "26.3.0"), ("0.38.1", "26.6.0"), ("0.33.0", "0.34.0"),
            ("25.10.4", "25.10.5"), ("25.8.5", "26.3.0"), ("25.10.4", "25.10.4"), ("26.6.0", "26.3.0"),
            ("25.8.4", "25.8.3")], good=[
            ("0.38.1", "25.8.0"), ("25.8.4", "25.10.0"), ("25.10.3", "25.10.4"), ("25.10.4", "26.3.0"),
            ("26.3.0", "26.6.0"), ("26.3.0", "26.10.2"), ("0.34.0", "0.35.0")])

    def test_release_order(self):
        self.check("ceph-release-order", bad=[
            ("17.2.7", "18.2.0"), ("17.2.8", "18.2.2"), ("16.2.15", "17.2.6"), ("19.2.7", "20.2.4"),
            ("19.2.6", "20.2.3"), ("14.2.22", "15.2.0"), ("18.2.3", "19.2.0"), ("19.2.6", "20.2.6"),
            ("18.2.8", "18.2.8"), ("20.2.4", "19.2.7")], good=[
            ("17.2.6", "18.2.0"), ("18.2.8", "20.2.4"), ("19.2.6", "20.2.4"), ("17.2.7", "18.2.1"),
            ("19.2.7", "20.2.5")])


def mdb(source="25.8.4", target="25.10.4", **kw):
    return rule(source, target, component=MDB, **kw)


class OrderStatic(unittest.TestCase):
    """The static scan for release order entries."""

    scan, flagged = Static.scan, Static.flagged

    def ids(self, *entries, **kw):
        return [c["key"].split("|")[2] for c in self.flagged(*entries, **kw)]

    def test_anchor(self):
        self.assertEqual(self.ids(mdb()), ["mariadb-operator-no-skip"])
        self.assertEqual(self.ids(mdb("0.38.1", "25.0.0")), ["mariadb-operator-no-skip"])
        self.assertEqual(self.ids(rule("17.2.7", "18.2.0", component=CEPH)), ["ceph-release-order"])
        self.assertEqual(self.ids(mdb("25.8.4", "25.10.0"), mdb("26.3.0", "26.6.0", rid="m"),
                                  rule("18.2.8", "20.2.4", component=CEPH, rid="c")), [])
        hit = self.flagged(mdb())[0]
        self.assertTrue(hit["mismatch"] and hit["detail"]["citations"] and hit["detail"]["kind"] == "no-skip")

    def test_state_and_operator(self):
        self.assertEqual(self.ids(mdb(state="withdrawn")), [])
        for operator in sorted(sf.NEVER_PASS):
            self.assertEqual(self.ids(mdb(operator=operator)), [], operator)
        for state in ("active", "stale", "Withdrawn", None):
            self.assertEqual(len(self.ids(mdb(state=state))), 1, state)
        for operator in ("require_component_version", "something_new", None):
            self.assertEqual(len(self.ids(mdb(operator=operator))), 1, operator)

    def test_ranges_and_crossings_cannot_be_compared(self):
        wide = mdb("25.10.3", "25.10.4", rng=("25.10.3", "25.10.4", "25.10.4", "25.10.5"))
        self.assertEqual(self.ids(wide), ["mariadb-operator-no-skip"])
        later = mdb("26.3.0", "26.6.0", rng=("26.3.0", "26.4.0", "26.6.0", "26.7.0"))
        self.assertEqual(self.ids(later), [])
        crossing = {"change": {"version": "26.6.0"}, "horizon": {"lt": "26.7.0"}}
        self.assertEqual(self.ids(mdb("26.3.0", "26.6.0", crossing=crossing)), ["mariadb-operator-no-skip"])
        ceph = rule("19.2.6", "20.2.4", component=CEPH, rng=("19.2.6", "19.2.7", "20.2.4", "20.2.5"))
        self.assertEqual(self.ids(ceph), ["ceph-release-order"])

    def test_attestations(self):
        def att(component, *sources):
            return {"component": component, "line": "26.6", "releases": {"from": [{"version": v} for v in sources]}}
        hit = self.flagged(attested=[att(MDB, "26.3.0", "25.10.4")])
        self.assertEqual([c["detail"]["sources"] for c in hit], [["25.10.4"]])
        self.assertEqual(self.flagged(attested=[att(MDB, "26.3.0")]), [])
        self.assertEqual(self.ids(attested=[att(CEPH, "19.2.6")]), ["ceph-release-order"])
        for bad in (att(MDB), att(MDB, "25.10"), att(CEPH), {"component": CEPH, "line": "20.2"}):
            with self.subTest(bad):
                self.assertTrue([c for c in self.scan(attested=[bad]) if c["error"]])

    def test_unreadable_rule_is_an_error(self):
        for entry in (mdb("25.8"), mdb(ranges=[]), mdb(rid="")):
            out = self.scan([entry])
            self.assertTrue([c for c in out if c["error"]])
            self.assertNotIn("floor|static|mariadb-operator-no-skip", [c["key"] for c in out])


class OrderList(unittest.TestCase):
    def load(self, change):
        data = real()
        change({f["id"]: f for f in data["floors"]})
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "floors.json"
            path.write_text(json.dumps(data))
            return sf.load(str(path))

    def test_shipped_list_loads(self):
        self.assertEqual(len(self.load(lambda f: None)), len(FLOORS))

    def test_bad_entries(self):
        m = lambda f: f["mariadb-operator-no-skip"]
        c = lambda f: f["ceph-release-order"]
        good = {"from": "25.8.4", "to": "25.10.0", "safeFacts": [{"side": "proposed", "id": "x", "boolValue": False}]}
        bad = [
            lambda f: m(f).update(kind="skip"), lambda f: m(f).update(kind=None), lambda f: m(f).update(kind=[]),
            lambda f: m(f).pop("blockedBelow"), lambda f: m(f).update(minimumSource="1.0.0"),
            lambda f: c(f).update(blockedBelow="26.0.0"), lambda f: m(f).update(blockedBelow="26"),
            lambda f: m(f).update(blockedBelow="25.10.4"), lambda f: m(f).update(releases=[]),
            lambda f: m(f).update(releases=["25.8.4"]), lambda f: m(f)["releases"].reverse(),
            lambda f: m(f)["releases"].append("25.10.4"), lambda f: m(f)["releases"].append("25.10"),
            lambda f: m(f).update(releases={}), lambda f: c(f).update(releases=[]), lambda f: c(f).update(releases={}),
            lambda f: c(f)["releases"].update({"20.2": "2026-01-01"}),
            lambda f: c(f)["releases"].update({"18.2.0": "2023-8-7"}),
            lambda f: c(f)["releases"].update({"18.2.0": "2023-13-07"}),
            lambda f: c(f)["releases"].update({"18.2.0": None}), lambda f: m(f).update(probes=[]),
            lambda f: m(f)["probes"].append(good), lambda f: m(f)["probes"].append(copy.deepcopy(m(f)["probes"][0])),
            lambda f: m(f)["probes"][0].pop("safeFacts"), lambda f: m(f)["probes"][0].update(safeFacts=[]),
            lambda f: m(f)["probes"][0]["safeFacts"][0].update(boolValue=0), lambda f: m(f).update(citations=[]),
            lambda f: m(f).update(note=""), lambda f: m(f).update(basis="guess"), lambda f: m(f).update(id="etcd-3.6"),
            lambda f: m(f).update(component="mariadb-operator"), lambda f: m(f).pop("releases"),
        ]
        for i, change in enumerate(bad):
            with self.subTest(i):
                self.assertRaises((ValueError, KeyError, TypeError), self.load, change)


class OrderCases(unittest.TestCase):
    def run_cases(self, code):
        with tempfile.TemporaryDirectory() as d:
            write_knowledge(d, rules())

            def runner(route, project, doc, name):
                body = report(project=project)
                return code, body if route == sf.CNCF else batch(body, project), ["prufyx", "check"]
            with mock.patch.object(qalib, "NOW", "2026-11-29T00:00:00Z"):
                return sf.cases(d, str(HERE / "source_floors.json"), runner)

    def test_each_order_probe_that_passes_is_a_wrong_pass(self):
        keys = {c["key"] for c in self.run_cases(0) if c["wrongpass"]}
        for key in ("floor|ceph-release-order|17.2.7->18.2.0", "floor|mariadb-operator-no-skip|0.38.1->25.0.0",
                    "floor|mariadb-operator-no-skip|25.8.4->25.10.4"):
            self.assertIn(key, keys)

    def test_a_component_the_rules_do_not_name_is_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            write_knowledge(d, rules(), project_entries=[OTHER])
            with mock.patch.object(qalib, "NOW", "2026-11-29T00:00:00Z"):
                out = sf.cases(d, str(HERE / "source_floors.json"), lambda *_: (2, "", ["prufyx"]))
        errors = {c["key"] for c in out if c["error"]}
        self.assertTrue({"floor|ceph-release-order|rules", "floor|mariadb-operator-no-skip|rules"} <= errors)


class Sources(unittest.TestCase):
    """Every data file that can decide a PASS is classified; anything else leaves no floor clean."""

    def run_on(self, change):
        with tempfile.TemporaryDirectory() as d:
            write_knowledge(d, rules())
            change(pathlib.Path(d))
            with mock.patch.object(qalib, "NOW", "2026-11-29T00:00:00Z"):
                return sf.cases(d, str(HERE / "source_floors.json"), lambda *_: (2, "", ["prufyx"]))

    def source_errors(self, change):
        out = self.run_on(change)
        self.assertEqual([c for c in out if c["key"].startswith("floor|static|") and not c["wrongpass"]], [])
        got = [c for c in out if c["key"].startswith(("floor|source|", "floor|sources-"))]
        self.assertTrue(all(c["error"] for c in got))
        return [c["key"] for c in got]

    def embed(self, d, pattern, *files, text="{}", go="cli/internal/newcheck/new.go"):
        put(d, go, "package n\n\n//go:embed %s\nvar f embed.FS\n" % pattern)
        for rel in files:
            put(d, "cli/internal/newcheck/" + rel, text)

    def clean(self, change):
        out = self.run_on(change)
        self.assertEqual([c for c in out if c["key"].startswith(("floor|source|", "floor|sources-"))], [])
        self.assertEqual(len([c for c in out if c["key"].startswith("floor|static|")]), len(FLOORS))

    def test_untouched_checkout_is_clean(self):
        self.clean(lambda d: None)

    def test_a_new_rules_file_is_an_error_embedded_or_not(self):
        key = "floor|source|cli/internal/newcheck/data/rules.json"
        body = json.dumps({"entries": [rule("3.5.1")]})
        for rel in ("cli/internal/newcheck/data/rules.json", "other/rules.json"):
            with self.subTest(rel):
                self.assertEqual(self.source_errors(lambda d: put(d, rel, body)), ["floor|source|" + rel])
        self.assertEqual(self.source_errors(lambda d: self.embed(d, "data/rules.json", "data/rules.json")), [key])

    def test_a_new_embedded_data_file_is_an_error_whatever_its_name_and_pattern(self):
        for pattern, rel in (("data/pack.json", "data/pack.json"), ("data/*.yaml", "data/p.yaml"), ("data", "data/p.bin"),
                             ("all:data", "data/.p.json"), ('"data/a b.json"', "data/a b.json"), ("`data/p.json`", "data/p.json"),
                             ("*.go data/p.json", "data/p.json"), ("testdata/p.json", "testdata/p.json")):
            with self.subTest(pattern):
                self.assertEqual(self.source_errors(lambda d: self.embed(d, pattern, rel)),
                                 ["floor|source|cli/internal/newcheck/" + rel])

    def test_go_sources_test_files_and_testdata_are_not_rule_sources(self):
        self.clean(lambda d: self.embed(d, "*.go"))
        self.clean(lambda d: put(d, "cli/internal/newcheck/x_test.go", "//go:embed nothing.json\n"))
        self.clean(lambda d: put(d, "cli/internal/newcheck/testdata/rules.json", "{"))
        self.clean(lambda d: put(d, "cli/internal/newcheck/data/loose.json", "{"))
        self.clean(lambda d: put(d, "cli/internal/newcheck/x.go", "//     //go:embed nothing.json\n"))

    def test_an_embed_that_cannot_be_read_is_an_error(self):
        for line in ("absent.json", "data/*.json", "../x.json", '"unterminated', "", "/abs.json"):
            with self.subTest(line):
                self.assertEqual(self.source_errors(lambda d: self.embed(d, line)),
                                 ["floor|source|cli/internal/newcheck/new.go"])

        def binary(d):
            (d / "cli/internal/projectcheck/bad.go").write_bytes(b"\xff\xfe")
        self.assertEqual(self.source_errors(binary), ["floor|source|cli/internal/projectcheck/bad.go"])

    def test_a_listed_rules_file_that_nothing_embeds_is_an_error(self):
        self.assertEqual(self.source_errors(lambda d: (d / "cli/internal/projectcheck/pack.go").unlink()),
                         ["floor|source|" + sf.PROJECT_RULES])

    def listed(self, kind, rel, text):
        def change(d):
            put(d, rel, text)
            directory, name = rel.rsplit("/", 1)
            put(d, directory + "/embed.go", "package n\n\n//go:embed %s\nvar f embed.FS\n" % name)
        self.assertIn(rel, sources()[kind])
        return change

    def test_verdict_files(self):
        rel = "cli/internal/prometheusmode/source-contract-v1.json"
        self.clean(self.listed("verdict", rel, '{"project":"prometheus","url":"https://github.com/prometheus/prometheus"}'))
        for text in ("", "{", '{"a":1,"a":2}', '{"project":"ceph"}', '["pkg:github/Ceph/ceph"]', '{"ceph":1}',
                     '{"a":[{"url":"https://github.com/etcd-io/etcd/blob/x"}]}'):
            with self.subTest(text):
                self.assertEqual(self.source_errors(self.listed("verdict", rel, text)), ["floor|source|" + rel])

    def test_support_files(self):
        rel = "cli/internal/customresources/table.json"
        self.clean(self.listed("support", rel, '{"project":"cilium","operator":{"type":"string"},"subject":1}'))
        for text in ("", "{", json.dumps({"entries": [rule()]}), '[{"a":{"operator":"x","subject":{}}}]'):
            with self.subTest(text):
                self.assertEqual(self.source_errors(self.listed("support", rel, text)), ["floor|source|" + rel])

    def test_a_support_wildcard_stays_in_its_directory(self):
        target = "cli/internal/extract/crdversions/"

        def change(rel):
            def apply(d):
                put(d, target + rel, "{}")
                put(d, target + "e.go", "//go:embed %s\n" % rel)
            return apply
        self.clean(change("target-new.json"))
        for rel in ("targets-new.json", "target-new/x.json"):
            with self.subTest(rel):
                self.assertEqual(self.source_errors(change(rel)), ["floor|source|" + target + rel])

    def test_a_wrong_pass_is_still_reported_beside_an_unknown_source(self):
        def change(d):
            write_knowledge(d, rules(rule("3.5.1")))
            put(d, "other/rules.json", "{}")
        out = self.run_on(change)
        self.assertEqual([c["detail"]["rule"] for c in out if c["key"].startswith("floor|static|")], ["n"])

    def test_every_listed_source_of_this_checkout(self):
        """On a full checkout: nothing unclassified, nothing listed that is gone."""
        root = HERE.parent.parent
        if not (root / sf.RULES).exists():
            self.skipTest("not a full checkout")
        floors, listed = sf.parse(str(HERE / "source_floors.json"))
        self.assertEqual(sf.inventory(str(root), floors, listed), [])
        for rel in list(listed["rules"]) + listed["verdict"] + [p for p in listed["support"] if "*" not in p]:
            self.assertTrue((root / rel).is_file(), rel)


def batch(child, project="ceph", category="UNKNOWN_CLAIM", kind="community_project", **extra):
    item = {"kind": kind, "project": project, "outcome": "UNKNOWN", "category": category, "report": json.loads(child)}
    return json.dumps(dict({"schema": sf.BATCH_SCHEMA, "decision": "UNKNOWN", "aggregateCategory": category,
                            "items": [item]}, **extra))


class JudgeBatch(unittest.TestCase):
    def child(self, *claims):
        return report(*claims, project="ceph")

    def rejected(self, code, out, wrong=False):
        got, why = sf.judge_batch(code, out, "ceph")
        self.assertEqual(got, wrong, why)
        self.assertEqual(bool(why), not wrong)

    def test_accepted(self):
        for child in (self.child(), self.child(claim()), self.child(claim(reason="RULE_EVIDENCE_WITHDRAWN"))):
            self.assertEqual(sf.judge_batch(11, batch(child), "ceph"), (False, None))
        blocked = batch(self.child(claim("BLOCKED", "forbid_target_version")), category="BLOCKED")
        self.assertEqual(sf.judge_batch(10, blocked, "ceph"), (False, None))

    def test_exit_zero_and_pass_verdicts_are_wrong_passes(self):
        self.rejected(0, "junk", wrong=True)
        good = batch(self.child())
        for out in (batch(self.child(), category="PASS"), batch(self.child(), decision="PASS"),
                    good.replace('"outcome": "UNKNOWN"', '"outcome": "PASS"'),
                    batch(report(project="ceph", assessment="PASS"))):
            self.rejected(11, out, wrong=True)

    def test_unusable_reports_are_errors(self):
        for out in ("", "junk", "[]", "{}", self.child(), batch(self.child(), schema="x"), batch(self.child(), items=[]),
                    batch(self.child(), items=[1]), batch(self.child(), items={}), batch(self.child(), "rook"),
                    batch(self.child(), kind="cncf"), batch("[]"), batch("{}"), batch(report(project="rook")),
                    batch(self.child(claim("PASS"))), batch(self.child(claim(reason="RULE_FACT_UNAVAILABLE"))),
                    batch(self.child(claim(reason="RULE_DEPENDENCY_COMPONENT_MISSING")))):
            with self.subTest(out[:200]):
                self.rejected(11, out)
        two = json.loads(batch(self.child()))
        two["items"] *= 2
        self.rejected(11, json.dumps(two))
        for code in (1, 2, 3, 12, 13, -9):
            self.rejected(code, batch(self.child()))


class RunProbe(unittest.TestCase):
    def run_probe(self, route):
        done = subprocess.CompletedProcess([], 11, "out", "")
        with tempfile.TemporaryDirectory() as d, mock.patch.object(qalib, "TMP", d), mock.patch.object(
                qalib, "NOW", "2026-11-29T00:00:00Z"), mock.patch.object(subprocess, "run", return_value=done):
            floor = next(f for f in real()["floors"] if f["id"] == "ceph-20.2")
            code, out, cmd = sf.run_probe(route, "ceph", sf.document(floor, "15.2.17", "20.2.4"), "n-0")
            self.assertEqual((code, out), (11, "out"))
            plan = json.loads(pathlib.Path(cmd[cmd.index("--plan") + 1]).read_text()) if "--plan" in cmd else None
            self.assertEqual(cmd[-4:], ["--now", "2026-11-29T00:00:00Z", "--format", "json"])
            return cmd, plan

    def test_routes(self):
        cmd, plan = self.run_probe(sf.CNCF)
        self.assertEqual((cmd[1:3], plan), (["check", "cncf"], None))
        cmd, plan = self.run_probe(sf.COMMUNITY)
        self.assertEqual(cmd[1:3], ["check", "batch"])
        self.assertEqual(plan["items"], [{"id": "floor", "kind": "community_project", "project": "ceph",
                                          "from": "15.2.17", "to": "20.2.4", "inputPath": "input.json"}])


STUB = """#!%s
import json, sys
a = sys.argv
batch = a[2] == "batch"
if batch:
    item = json.load(open(a[a.index("--plan") + 1]))["items"][0]
    project, path = item["project"], a[a.index("--root") + 1] + "/" + item["inputPath"]
else:
    project, path = a[a.index("--project") + 1], a[a.index("--input") + 1]
doc = json.load(open(path))
if any(f["id"] == "f" and f.get("boolValue") for c in doc["proposed"]["components"] for f in c["facts"]):
    sys.exit(10)
if STATUS == "PASS":
    sys.exit(0)
child = {"project": project, "assessment": "UNKNOWN", "check": {"claims": []}}
if batch:
    child = {"schema": "prufyx.io/batch-check-report/v1alpha1", "decision": "UNKNOWN", "aggregateCategory": "UNKNOWN_CLAIM",
             "items": [{"kind": "community_project", "project": project, "outcome": "UNKNOWN",
                        "category": "UNKNOWN_CLAIM", "report": child}]}
print(json.dumps(child))
sys.exit(11)
"""


class OracleRun(unittest.TestCase):
    """The shipped rules_oracle.py: fails the suite on a passing floor probe, whatever the project and rule-id filters say."""

    def oracle(self, status, extra=(), static=False, **env):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            stub = d / "prufyx"
            stub.write_text((STUB % sys.executable).replace("STATUS ==", "%r ==" % status))
            stub.chmod(0o700)
            entries = rules(*extra)
            for e in entries:
                e["rule"].update(appliesWhen=[], condition={"side": "proposed", "component": e["rule"]["subject"]["component"],
                                                            "factId": "f", "boolValue": True})
            write_knowledge(d / "src", entries)
            full = dict(os.environ, QA_BIN=str(stub), QA_SRC=str(d / "src"), QA_TMP=str(d / "tmp"),
                        QA_NOW="2026-11-29T00:00:00Z", QA_STATE=str(d), QA_RUNBOX="", QA_BASE="", **env)
            subprocess.run([sys.executable, str(HERE / "rules_oracle.py"), "--out", str(d / "out.json")], env=full,
                           check=True, capture_output=True, timeout=300)
            out = [c for c in json.loads((d / "out.json").read_text()) if c["key"].startswith("floor|")]
            return [c for c in out if c["key"].startswith("floor|static|")] if static else probes(out)

    def test_passing_floor_pairs_are_wrong_passes(self):
        out = self.oracle("PASS", QA_PROJECTS="nats", QA_RULES_IDS="none")
        self.assertEqual(len(out), len(SEEDS))
        self.assertTrue(all(c["wrongpass"] for c in out))

    def test_non_passing_floor_pairs_are_clean(self):
        out = self.oracle("UNKNOWN")
        self.assertEqual(len(out), len(SEEDS))
        self.assertFalse(any(c["wrongpass"] or c["error"] for c in out))

    def test_a_gap_rule_fails_the_oracle_although_every_probe_is_clean(self):
        gap = rule("3.5.20", "3.6.4")
        gap["project"] = "other"  # no probe is derived from it
        run = dict(extra=[gap], QA_PROJECTS="nats", QA_RULES_IDS="none")
        self.assertFalse(any(c["wrongpass"] or c["error"] for c in self.oracle("UNKNOWN", **run)))
        out = self.oracle("UNKNOWN", static=True, **run)
        self.assertEqual([c["detail"]["rule"] for c in out if c["wrongpass"]], ["n"])


if __name__ == "__main__":
    unittest.main()
