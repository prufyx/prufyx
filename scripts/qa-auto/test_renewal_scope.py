"""Rule-renewal PR scope: approvals map to their project, community rules/attestation use the same diff attribution."""
import json, sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from select_projects import selection, RULES, RULES_COMMUNITY, ATTEST_COMMUNITY

SLUGS = ["alpha", "beta"]
CAT = {"alpha", "beta", "delta"}  # delta: catalogue project without a QA target
AP = "cli/knowledge/approvals/%s/%s.some-rule.1-2-to-1-3.json"


def crules(entries):
    return {"schema": "s", "revision": "r", "policyDigest": "d", "policyId": "p", "entries": entries}


def ent(rid, project, desc="d", comps=None):
    return {"project": project, "description": desc, "rule": {"id": rid},
            "requiredFacts": [{"component": c} for c in (comps or ["pkg:github/o/" + project])]}


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
    def afiles(self, *pairs, group="cncf", entries=None, paths=None):
        """pairs: (approval file path, rule id); the rules.json of the group holds `entries` in base and head."""
        rules_path = RULES_COMMUNITY if group == "community" else RULES
        es = entries if entries is not None else [ent("alpha.r", "alpha"), ent("beta.r", "beta"), ent("delta.r", "delta"),
                                                  ent("spec.r", "alpha")]
        files = {rules_path: (crules(es), crules(es))}
        for path, rid in pairs:
            files[path] = (None, {"record": {"ruleId": rid}})
        return files

    def test_approvals_map_to_project(self):
        for group, rid, want, mode in [("cncf", "alpha.r", ["alpha"], "incremental"),
                                       ("community", "beta.r", ["beta"], "incremental"),
                                       ("community", "delta.r", [], "full")]:  # catalogue project without a QA target
            with self.subTest(rid=rid):
                p = AP % (group, rid.split(".")[0])
                r = run([p], self.afiles((p, rid), group=group))
                self.assertEqual((r["mode"], r["projects"]), (mode, want if mode != "full" else []))

    def test_approvals_many_files_union(self):
        p1, p2 = AP % ("cncf", "alpha"), AP % ("cncf", "beta")
        r = run([p1, p2, p1 + "x"], self.afiles((p1, "alpha.r"), (p2, "beta.r"), (p1 + "x", "alpha.r")))
        self.assertEqual((r["mode"], r["projects"]), ("incremental", ["alpha", "beta"]))

    def test_approval_prefix_is_never_trusted(self):
        # file prefix says beta, the rule id's real entry project is alpha (cf. cni-spec / container-network-interface-cni)
        p = AP % ("cncf", "beta")
        r = run([p], self.afiles((p, "spec.r")))
        self.assertEqual((r["mode"], r["projects"]), ("incremental", ["alpha"]))
        p = AP % ("cncf", "spec")  # prefix is no slug at all
        r = run([p], self.afiles((p, "spec.r")))
        self.assertEqual((r["mode"], r["projects"]), ("incremental", ["alpha"]))

    def test_approval_rule_id_not_found_is_full(self):
        p = AP % ("cncf", "alpha")
        self.assertEqual(run([p], self.afiles((p, "alpha.missing")))["mode"], "full")
        self.assertEqual(run([p], self.afiles((p, "alpha.r"), group="community"))["mode"], "full")  # id in the other pack only
        f = self.afiles((p, "alpha.r")); f[p] = (None, b"not json")
        self.assertEqual(run([p], f)["mode"], "full")
        self.assertEqual(run([p])["mode"], "full")  # no reader

    def test_approval_id_only_in_head_is_full(self):
        p = AP % ("cncf", "alpha")
        f = self.afiles((p, "new.r")); f[RULES] = (crules([ent("alpha.r", "alpha")]), crules([ent("alpha.r", "alpha"), ent("new.r", "alpha")]))
        self.assertEqual(run([p], f)["mode"], "full")

    def test_approval_closure_includes_required_components(self):
        es = [ent("bp.r", "alpha", comps=["pkg:github/o/alpha", "pkg:oci/o/lifecycle"]), ent("lf.r", "beta", comps=["pkg:oci/o/lifecycle"])]
        p = AP % ("cncf", "alpha")
        r = run([p], self.afiles((p, "bp.r"), entries=es))
        self.assertEqual((r["mode"], r["projects"]), ("incremental", ["alpha", "beta"]))

    def test_approvals_fail_closed(self):
        for path, cat in [(AP % ("cncf", "mystery"), CAT), (AP % ("cncf", "delta"), set()),
                          ("cli/knowledge/approvals/cncf/.hidden.json", CAT),
                          ("cli/knowledge/approvals/a/b/alpha.x.json", CAT)]:
            with self.subTest(path=path):
                self.assertEqual(run([path], catalogue=cat)["mode"], "full")

    def test_requiredfacts_closure_forward_and_dependants(self):
        # buildpacks (alpha) requires lifecycle's component; lifecycle (beta) entries are exercised under it
        es = [ent("bp.1", "alpha", comps=["pkg:github/o/alpha", "pkg:oci/o/lifecycle"]), ent("lf.1", "beta", comps=["pkg:oci/o/lifecycle"])]
        changed = [ent("bp.1", "alpha", "x", comps=["pkg:github/o/alpha", "pkg:oci/o/lifecycle"]), es[1]]
        r = run([RULES_COMMUNITY], {RULES_COMMUNITY: (crules(es), crules(changed))})
        self.assertEqual((r["mode"], r["projects"]), ("incremental", ["alpha", "beta"]))  # forward: lifecycle project
        changed = [es[0], ent("lf.1", "beta", "x", comps=["pkg:oci/o/lifecycle"])]
        r = run([RULES_COMMUNITY], {RULES_COMMUNITY: (crules(es), crules(changed))})
        self.assertEqual((r["mode"], r["projects"]), ("incremental", ["alpha", "beta"]))  # dependant: buildpacks

    def test_requiredfacts_closure_is_transitive(self):
        es = [ent("a.1", "alpha", comps=["pkg:x/1", "pkg:x/2"]), ent("b.1", "beta", comps=["pkg:x/2", "pkg:x/3"]),
              ent("c.1", "alpha", comps=["pkg:x/3"]), ent("d.1", "beta", comps=["pkg:x/9"])]
        new = [dict(es[0], description="x")] + es[1:]
        r = run([RULES_COMMUNITY], {RULES_COMMUNITY: (crules(es), crules(new))})
        self.assertEqual(r["projects"], ["alpha", "beta"])
        es = [ent("a.1", "alpha", comps=["pkg:x/1"]), ent("g.1", "gamma", comps=["pkg:x/1"])]  # gamma: no QA target
        new = [dict(es[0], description="x"), es[1]]
        self.assertEqual(run([RULES_COMMUNITY], {RULES_COMMUNITY: (crules(es), crules(new))}, catalogue=CAT | {"gamma"})["mode"], "full")

    def test_requiredfacts_closure_failure_is_full(self):
        es = [ent("a.1", "alpha"), ent("b.1", "beta")]
        bad = dict(ent("b.1", "beta"), requiredFacts="nope")
        new = [dict(es[0], description="x"), bad]
        self.assertEqual(run([RULES_COMMUNITY], {RULES_COMMUNITY: (crules(es), crules(new))})["mode"], "full")

    def test_nontarget_project_entry_forces_full(self):
        # kubernetes-level entry: no QA target, applies to every project
        es = [ent("a.1", "alpha"), ent("k.1", "kubernetes", comps=["pkg:github/kubernetes/kubernetes"])]
        new = [es[0], dict(es[1], description="x")]
        r = run([RULES_COMMUNITY], {RULES_COMMUNITY: (crules(es), crules(new))}, catalogue=CAT | {"kubernetes"})
        self.assertEqual(r["mode"], "full", r["reasons"])
        r = run([RULES_COMMUNITY], {RULES_COMMUNITY: (crules(es), crules(new + [ent("x.1", "alpha")]))}, catalogue=CAT | {"kubernetes"})
        self.assertEqual(r["mode"], "full", r["reasons"])

    def test_pack_digest_change_forces_full(self):
        old = crules([ent("a.1", "alpha")])
        for k in ("policyDigest", "registryDigest", "landscapeFileDigest", "revision", "policyId"):
            new = crules([ent("a.1", "alpha", "x")]); new[k] = "other"
            self.assertEqual(run([RULES_COMMUNITY], {RULES_COMMUNITY: (old, new)})["mode"], "full", k)

    def test_keyed_sections_use_own_component(self):
        old = crules([ent("a.1", "alpha")]); old["servedAPIs"] = [{"component": "pkg:github/o/alpha", "line": "1"}]
        new = crules([ent("a.1", "alpha")]); new["servedAPIs"] = [{"component": "pkg:github/o/alpha", "line": "1", "x": 1}]
        r = run([RULES_COMMUNITY], {RULES_COMMUNITY: (old, new)})
        self.assertEqual((r["mode"], r["projects"]), ("incremental", ["alpha"]))
        new["servedAPIs"][0]["component"] = "pkg:github/kubernetes/kubernetes"  # no binding => unknown => full
        self.assertEqual(run([RULES_COMMUNITY], {RULES_COMMUNITY: (old, new)})["mode"], "full")

    def test_attestation_without_its_rules_is_full(self):
        files = {RULES_COMMUNITY: (crules([ent("a.1", "alpha")]),) * 2,
                 ATTEST_COMMUNITY: (cattest("pkg:github/o/alpha"), cattest("pkg:github/o/alpha", "pkg:github/o/beta"))}
        self.assertEqual(run([ATTEST_COMMUNITY], files)["mode"], "full")

    def test_readme_without_rules_is_full(self):
        self.assertEqual(run(["README.md"])["mode"], "full")

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
        self.assertEqual(run([RULES_COMMUNITY, ATTEST_COMMUNITY], files)["mode"], "full")

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
        self.full([RULES_COMMUNITY, ATTEST_COMMUNITY], files)


class RuleIdResolution(unittest.TestCase):
    PATH = "cli/knowledge/approvals/community/spec.shape-removed.1-to-2.json"

    def files(self, rule_id="spec.shape-removed.1-to-2", project="alpha"):
        es = crules([ent("a.1", "alpha"), ent("spec.shape-removed.1-to-2", project)])
        return {self.PATH: (None, {"record": {"ruleId": rule_id}}), RULES_COMMUNITY: (es, es)}

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
