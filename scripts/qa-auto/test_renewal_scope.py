"""Rule-renewal PR scope: approvals map to their project, community rules/attestation use the same diff attribution."""
import json, sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from select_projects import selection, RULES_COMMUNITY, ATTEST_COMMUNITY

SLUGS = ["alpha", "beta"]
CAT = {"alpha", "beta", "delta"}  # delta: catalogue project without a QA target
AP = "cli/knowledge/approvals/%s/%s.some-rule.1-2-to-1-3.json"


def crules(entries):
    return {"schema": "s", "revision": "r", "policyDigest": "d", "policyId": "p", "entries": entries}


def ent(rid, project, desc="d"):
    return {"project": project, "description": desc, "rule": {"id": rid},
            "requiredFacts": [{"component": "pkg:github/o/" + project}]}


def cattest(*comps, **kw):
    d = {"schema": "s", "attestation": "A", "revision": "r", "packDigest": "p", "ruleSetDigest": "q",
         "ruleCount": 1, "components": list(comps), "limitations": ["l"]}
    d.update(kw)
    return d


def run(changed, files=None, catalogue=CAT):
    def raw(v):
        return v if isinstance(v, (bytes, type(None))) else json.dumps(v).encode()
    reader = (lambda p: tuple(raw(x) for x in files[p])) if files is not None else None
    trusted = {"pkg:github/o/alpha": "alpha", "pkg:github/o/beta": "beta"}
    return selection(changed, SLUGS, reader, trusted, catalogue)


class RenewalScope(unittest.TestCase):
    def test_approvals_map_to_project(self):
        for path, want, mode in [(AP % ("cncf", "alpha"), ["alpha"], "incremental"),
                                 (AP % ("community", "beta"), ["beta"], "incremental"),
                                 (AP % ("community", "delta"), [], "none")]:
            with self.subTest(path=path):
                r = run([path])
                self.assertEqual((r["mode"], r["projects"]), (mode, want))

    def test_approvals_many_files_union(self):
        r = run([AP % ("cncf", "alpha"), AP % ("cncf", "beta"), AP % ("cncf", "alpha") + "x"])
        self.assertEqual((r["mode"], r["projects"]), ("incremental", ["alpha", "beta"]))

    def test_approvals_fail_closed(self):
        for path, cat in [(AP % ("cncf", "mystery"), CAT), (AP % ("cncf", "delta"), set()),
                          ("cli/knowledge/approvals/cncf/.hidden.json", CAT),
                          ("cli/knowledge/approvals/a/b/alpha.x.json", CAT)]:
            with self.subTest(path=path):
                self.assertEqual(run([path], catalogue=cat)["mode"], "full")

    def test_community_rules_entry_change(self):
        old = crules([ent("a.1", "alpha"), ent("b.1", "beta")])
        new = crules([ent("a.1", "alpha", "changed"), ent("b.1", "beta")])
        r = run([RULES_COMMUNITY], {RULES_COMMUNITY: (old, new)})
        self.assertEqual((r["mode"], r["projects"]), ("incremental", ["alpha"]))

    def test_community_rules_unparseable_full(self):
        old = crules([ent("a.1", "alpha")])
        self.assertEqual(run([RULES_COMMUNITY], {RULES_COMMUNITY: (old, b"{")})["mode"], "full")

    def test_community_rules_bad_project_full(self):
        old = crules([ent("a.1", "alpha")])
        new = crules([ent("a.1", "alpha"), {"description": "x", "rule": {"id": "z"}}])
        self.assertEqual(run([RULES_COMMUNITY], {RULES_COMMUNITY: (old, new)})["mode"], "full")

    def test_attestation_alone_unattributable_full(self):
        old, new = crules([ent("a.1", "alpha")]), crules([ent("a.1", "alpha")])
        files = {RULES_COMMUNITY: (old, new),
                 ATTEST_COMMUNITY: (cattest("pkg:github/o/alpha"), cattest("pkg:github/o/alpha", "pkg:github/o/zzz/mystery"))}
        self.assertEqual(run([ATTEST_COMMUNITY], files)["mode"], "full")

    def test_attestation_with_rules_selects_rules_projects(self):
        old = crules([ent("a.1", "alpha")])
        new = crules([ent("a.1", "alpha"), ent("a.2", "alpha")])
        files = {RULES_COMMUNITY: (old, new),
                 ATTEST_COMMUNITY: (cattest("pkg:github/o/alpha"), cattest("pkg:github/o/alpha", ruleCount=2, packDigest="z"))}
        r = run([RULES_COMMUNITY, ATTEST_COMMUNITY], files)
        self.assertEqual((r["mode"], r["projects"]), ("incremental", ["alpha"]))

    def test_derived_docs_with_rules_do_not_force_full(self):
        old, new = crules([ent("a.1", "alpha")]), crules([ent("a.1", "alpha", "c")])
        r = run([RULES_COMMUNITY, "README.md", "cli/docs/generated/coverage-counts.json",
                 "cli/docs/generated/community-support-inventory.json", "CHANGELOG.md"], {RULES_COMMUNITY: (old, new)})
        self.assertEqual((r["mode"], r["projects"]), ("incremental", ["alpha"]))


class Escalations(unittest.TestCase):
    def full(self, changed, files=None, **kw):
        r = run(changed, files, **kw)
        self.assertEqual(r["mode"], "full", r["reasons"])

    def test_unknown_file_under_knowledge(self):
        self.full(["cli/knowledge/other/unrelated.json"])

    def test_unknown_approvals_shape(self):
        self.full(["cli/knowledge/approvals/cncf/README"])
        self.full(["cli/knowledge/approvals/batches/x/alpha.json"])

    def test_other_schema_field_changed(self):
        old = crules([ent("a.1", "alpha")]); new = crules([ent("a.1", "alpha")]); new["policyId"] = "other"
        self.full([RULES_COMMUNITY], {RULES_COMMUNITY: (old, new)})
        new = crules([ent("a.1", "alpha")]); new["extra"] = 1
        self.full([RULES_COMMUNITY], {RULES_COMMUNITY: (old, new)})

    def test_entry_project_missing_or_unknown(self):
        old = crules([ent("a.1", "alpha")])
        self.full([RULES_COMMUNITY], {RULES_COMMUNITY: (old, crules([ent("a.1", "alpha"), ent("n.1", "newproj")]))})
        bad = ent("n.1", "alpha"); del bad["project"]
        self.full([RULES_COMMUNITY], {RULES_COMMUNITY: (old, crules([ent("a.1", "alpha"), bad]))})

    def test_removed_entry_of_unknown_project(self):
        old = crules([ent("a.1", "alpha"), ent("z.1", "gone")])
        self.full([RULES_COMMUNITY], {RULES_COMMUNITY: (old, crules([ent("a.1", "alpha")]))}, catalogue=set())

    def test_removed_target_project(self):
        t = "cli/internal/extract/crdversions/target-beta.json"
        self.full([t], {t: (b"{}", None)})

    def test_generated_without_rules(self):
        for g in ("cli/docs/generated/coverage-counts.json", "cli/docs/generated/community-support-inventory.md"):
            self.full([g])
            self.full([AP % ("cncf", "alpha"), g])

    def test_parse_error_attestation(self):
        files = {RULES_COMMUNITY: (crules([ent("a.1", "alpha")]), crules([ent("a.1", "alpha")])),
                 ATTEST_COMMUNITY: (cattest("pkg:github/o/alpha"), b"not json")}
        self.full([ATTEST_COMMUNITY], files)


class RuleIdResolution(unittest.TestCase):
    PATH = "cli/knowledge/approvals/community/spec.shape-removed.1-to-2.json"

    def files(self, rule_id="spec.shape-removed.1-to-2", project="alpha"):
        old = crules([ent("a.1", "alpha")])
        return {self.PATH: (None, {"record": {"ruleId": rule_id}}),
                RULES_COMMUNITY: (old, crules([ent("a.1", "alpha"), ent("spec.shape-removed.1-to-2", project)]))}

    def test_prefix_resolved_through_rule_entry(self):
        r = run([self.PATH], self.files())
        self.assertEqual((r["mode"], r["projects"]), ("incremental", ["alpha"]))

    def test_resolution_fails_closed(self):
        for files in (self.files(rule_id="other.rule.1"), self.files(project="mystery"), self.files(rule_id=None)):
            self.assertEqual(run([self.PATH], files)["mode"], "full")
        self.assertEqual(run([self.PATH])["mode"], "full")
        f = self.files(); f[self.PATH] = (None, b"not json")
        self.assertEqual(run([self.PATH], f)["mode"], "full")


if __name__ == "__main__":
    unittest.main()
