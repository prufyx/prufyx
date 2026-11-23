import copy, json, sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from select_projects import selection, PRULES, PATTEST

RENEWED = ["argo-workflows", "ceph", "fluent-bit", "grafana", "kibana", "loki", "mariadb", "mariadb-operator"]
SLUGS = sorted(RENEWED + ["airflow", "other"])
APPR = "cli/knowledge/approvals/community/"
D1, D2 = "sha256:" + "a" * 64, "sha256:" + "b" * 64
D3, D4 = "sha256:" + "c" * 64, "sha256:" + "d" * 64
NEWER = "2026-11-18T09:58:00Z"


def rid(project):
    return project + ".rule.1-to-2"


def entry(project, reviewed="2026-09-11T00:00:00Z"):
    return {"project": project, "rule": {"id": rid(project)},
            "evidence": {"reviewedAt": reviewed, "validUntil": "2026-12-10T00:00:00Z", "state": "active"}}


def rules(projects=SLUGS, reviewed=None, **kw):
    doc = {"schema": "s", "revision": "r1", "policyId": "p", "policyDigest": "sha256:" + "0" * 64,
           "entries": [entry(p, (reviewed or {}).get(p, "2026-09-11T00:00:00Z")) for p in projects]}
    doc.update(kw)
    return doc


def attest(pack=D1, rs=D2, **kw):
    doc = {"schema": "a", "attestation": "X", "revision": "r1", "packDigest": pack, "ruleSetDigest": rs,
           "ruleCount": 10, "components": ["pkg:github/o/x"]}
    doc.update(kw)
    return doc


def approval(project, **over):
    rec = {"baseDigest": "absent", "candidateDigest": D1, "decision": "approve", "identity": "airstand",
           "pack": "community", "ruleId": rid(project)}
    rec.update(over)
    return {"schema": "prufyx.io/knowledge-approval/v2", "record": rec, "keyId": "k", "signature": "s"}


def raw(v):
    return v if isinstance(v, (bytes, type(None))) else json.dumps(v).encode()


def run(changed, files):
    def reader(path):
        old, new = files[path]
        return raw(old), raw(new)
    return selection(changed, SLUGS, reader, {})


def pr691():
    files = {PRULES: (rules(), rules(reviewed={p: NEWER for p in RENEWED})),
             PATTEST: (attest(), attest(D3, D4))}
    for p in RENEWED:
        files[APPR + rid(p) + ".json"] = (None, approval(p))
    return files


class ProjectCheckScope(unittest.TestCase):
    def full(self, files, extra=()):
        r = run(list(files) + list(extra), files)
        self.assertEqual(r["mode"], "full", r["reasons"])

    def test_pr691_shape_selects_exactly_the_renewed_projects(self):
        files = pr691()
        r = run(list(files) + ["README.md", "cli/docs/generated/community-support-inventory.json"], files)
        self.assertEqual((r["mode"], r["projects"]), ("incremental", RENEWED), r["reasons"])

    def test_approval_for_unknown_project_full(self):
        files = pr691()
        files[APPR + "ghost.rule.1-to-2.json"] = (None, approval("ghost"))
        self.full(files)

    def test_approval_rule_known_but_project_has_no_target_selects_nothing_extra(self):
        files = pr691()
        base = rules(SLUGS + ["notarget"])
        files[PRULES] = (base, rules(SLUGS + ["notarget"], reviewed={"ceph": NEWER}))
        files[APPR + rid("notarget") + ".json"] = (None, approval("notarget"))
        r = run(list(files), files)
        self.assertEqual((r["mode"], r["projects"]), ("incremental", RENEWED), r["reasons"])

    def test_unparseable_approval_full(self):
        for bad in (b"{not json", b"", b'{"a":1,"a":2}', b"[]", json.dumps({"schema": "x"}).encode()):
            files = pr691()
            files[APPR + rid("ceph") + ".json"] = (None, bad)
            self.full(files)

    def test_approval_wrong_pack_name_or_rule_full(self):
        for rec in (approval("ceph", pack="cncf"), approval("ceph", ruleId=rid("loki")),
                    approval("ceph", ruleId=""), approval("ceph", ruleId=5)):
            files = pr691()
            files[APPR + rid("ceph") + ".json"] = (None, rec)
            self.full(files)

    def test_approval_deleted_at_head_full(self):
        files = pr691()
        files[APPR + rid("ceph") + ".json"] = (approval("ceph"), None)
        self.full(files)

    def test_approval_without_reader_full(self):
        r = selection([APPR + rid("ceph") + ".json"], SLUGS, None, {})
        self.assertEqual(r["mode"], "full")

    def test_approval_nested_or_non_json_is_not_attributed(self):
        for p in (APPR + "sub/x.json", APPR + "x.txt"):
            files = pr691()
            files[p] = (None, approval("ceph"))
            r = run(list(files), files)
            self.assertEqual(r["mode"], "full", p)

    def test_attestation_non_digest_field_full(self):
        for mod in ({"ruleCount": 11}, {"revision": "r2"}, {"components": ["pkg:github/o/x", "pkg:github/o/y"]},
                    {"attestation": "Y"}, {"extra": 1}):
            files = pr691()
            files[PATTEST] = (attest(), attest(D3, D4, **mod))
            self.full(files)

    def test_attestation_bad_digest_or_unchanged_full(self):
        for new in (attest("sha256:xyz", D4), attest(D3, 5), attest(), b"null"):
            files = pr691()
            files[PATTEST] = (attest(), new)
            self.full(files)

    def test_attestation_digest_without_rule_change_full(self):
        self.full({PRULES: (rules(), rules()), PATTEST: (attest(), attest(D3, D4))})

    def test_rules_pack_identity_change_full(self):
        for mod in ({"revision": "r2"}, {"policyDigest": "sha256:" + "9" * 64}, {"policyId": "q"}, {"extra": 1}):
            files = pr691()
            files[PRULES] = (rules(), rules(reviewed={p: NEWER for p in RENEWED}, **mod))
            self.full(files)

    def test_rules_duplicate_rule_id_full(self):
        files = pr691()
        bad = rules(reviewed={"ceph": NEWER})
        bad["entries"].append(copy.deepcopy(bad["entries"][0]))
        files[PRULES] = (rules(), bad)
        self.full(files)

    def test_code_change_beside_renewal_full(self):
        for code in ("cli/internal/projectcheck/check.go", "cli/cmd/x.go", "scripts/qa-auto/select_projects.py"):
            files = pr691()
            r = run(list(files) + [code], files)
            self.assertEqual(r["mode"], "full", code)

    def test_mixed_attributable_and_unattributable_full(self):
        files = pr691()
        files["cli/knowledge/misc-file.json"] = (None, b"{}")
        self.full(files)

    def test_other_projectcheck_data_file_full(self):
        r = selection(["cli/internal/projectcheck/data/projects.json"], SLUGS, lambda p: (b"{}", b"{}"), {})
        self.assertEqual(r["mode"], "full")


if __name__ == "__main__":
    unittest.main()
