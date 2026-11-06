import json, sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from select_projects import selection, RULES, ATTEST

SLUGS = ["alpha", "beta", "gamma"]


def entry(rid, project, comp=None):
    return {"project": project, "description": "d", "rule": {"id": rid},
            "requiredFacts": [{"component": comp or "pkg:github/o/" + project}]}


def rules(entries=None, **kw):
    doc = {"schema": "s", "revision": "r1", "policyDigest": "a", "landscapeFileDigest": "b", "registryDigest": "c",
           "entries": entries if entries is not None else [entry("a.1", "alpha"), entry("b.1", "beta"), entry("g.1", "gamma"),
                                                         entry("k.1", "kube", "pkg:github/o/kube")],
           "lineAttestations": [{"component": "pkg:github/o/alpha", "line": "1", "factFamily": "f", "x": 1}],
           "pathPolicies": [], "servedAPIs": []}
    doc.update(kw)
    return doc


def attest(components=("pkg:github/o/alpha", "pkg:github/o/beta"), **kw):
    doc = {"schema": "s", "attestation": "A", "revision": "r", "packDigest": "p", "ruleSetDigest": "q",
           "ruleCount": 4, "components": list(components), "limitations": ["l"]}
    doc.update(kw)
    return doc


def run(changed, files):
    """files: path -> (old, new); values are objects (dumped) or raw bytes."""
    def raw(v):
        return v if isinstance(v, (bytes, type(None))) else json.dumps(v).encode()
    def reader(path):
        old, new = files[path]
        return raw(old), raw(new)
    return selection(changed, SLUGS, reader)


class AggregateScope(unittest.TestCase):
    def test_rules_two_projects_selected_exactly(self):
        old = rules()
        new = rules([entry("a.1", "alpha"), entry("b.1", "beta"), entry("g.2", "gamma"), entry("k.1", "kube", "pkg:github/o/kube")])
        new["entries"][0]["description"] = "changed"
        r = run([RULES], {RULES: (old, new)})
        self.assertEqual((r["mode"], r["projects"]), ("incremental", ["alpha", "gamma"]))

    def test_metadata_only_is_none_not_full(self):
        new = rules(); new["revision"] = "r2"
        r = run([RULES], {RULES: (rules(), new)})
        self.assertEqual((r["mode"], r["projects"]), ("none", []))

    def test_nontarget_project_attributed_without_crd_slug(self):
        new = rules(); new["entries"][3]["description"] = "x"
        r = run([RULES], {RULES: (rules(), new)})
        self.assertEqual((r["mode"], r["projects"]), ("none", []))

    def test_line_attestation_attributed_by_component(self):
        new = rules(); new["lineAttestations"][0]["x"] = 2
        r = run([RULES], {RULES: (rules(), new)})
        self.assertEqual(r["projects"], ["alpha"])

    def test_attestation_component_added(self):
        new = attest(("pkg:github/o/alpha", "pkg:github/o/beta", "pkg:github/o/gamma"), ruleCount=5, packDigest="z")
        r = run([ATTEST], {ATTEST: (attest(), new), RULES: (rules(), rules())})
        self.assertEqual(r["projects"], ["gamma"])

    def test_both_files_union(self):
        nr = rules(); nr["entries"][0]["description"] = "x"
        na = attest(("pkg:github/o/alpha", "pkg:github/o/beta", "pkg:github/o/gamma"))
        r = run([RULES, ATTEST], {RULES: (rules(), nr), ATTEST: (attest(), na)})
        self.assertEqual(r["projects"], ["alpha", "gamma"])

    # fail closed
    def full(self, changed, files, reader=True):
        r = run(changed, files) if reader else selection(changed, SLUGS)
        self.assertEqual(r["mode"], "full", r["reasons"])

    def test_no_reader_full(self):
        self.full([RULES], {}, reader=False)

    def test_unattributable_component_full(self):
        new = rules(); new["lineAttestations"][0]["component"] = "pkg:github/o/mystery"
        self.full([RULES], {RULES: (rules(), new)})

    def test_unattributable_attestation_component_full(self):
        self.full([ATTEST], {ATTEST: (attest(), attest(("pkg:github/o/alpha", "pkg:github/o/mystery"))), RULES: (rules(), rules())})

    def test_malformed_json_full(self):
        self.full([RULES], {RULES: (rules(), b"{not json")})
        self.full([RULES], {RULES: (b"[", rules())})

    def test_missing_base_full(self):
        self.full([RULES], {RULES: (None, rules())})

    def test_duplicate_member_full(self):
        self.full([RULES], {RULES: (rules(), b'{"schema":"s","schema":"s"}')})

    def test_unknown_section_change_full(self):
        new = rules(); new["newSection"] = []
        self.full([RULES], {RULES: (rules(), new)})
        new = rules(); new["schema"] = "other"
        self.full([RULES], {RULES: (rules(), new)})

    def test_duplicate_rule_id_full(self):
        new = rules([entry("a.1", "alpha"), entry("a.1", "beta")])
        self.full([RULES], {RULES: (rules(), new)})

    def test_bad_entry_shape_full(self):
        new = rules(); new["entries"][0]["project"] = "Bad Name"
        self.full([RULES], {RULES: (rules(), new)})
        new = rules(); new["entries"][0]["rule"] = "x"
        self.full([RULES], {RULES: (rules(), new)})

    def test_attestation_limitations_change_full(self):
        self.full([ATTEST], {ATTEST: (attest(), attest(limitations=["other"])), RULES: (rules(), rules())})

    def test_attestation_needs_rules(self):
        self.full([ATTEST], {ATTEST: (attest(), attest(("pkg:github/o/alpha",))), RULES: (rules(), b"x")})

    def test_reader_exception_full(self):
        def boom(path):
            raise OSError("x")
        self.assertEqual(selection([RULES], SLUGS, boom)["mode"], "full")

    def test_code_path_beside_aggregate_stays_full(self):
        new = rules(); new["entries"][0]["description"] = "x"
        for extra in ("cli/internal/cncfcheck/eval.go", "scripts/qa-auto/run.sh"):
            r = run([RULES, extra], {RULES: (rules(), new)})
            self.assertEqual(r["mode"], "full")


if __name__ == "__main__":
    unittest.main()
