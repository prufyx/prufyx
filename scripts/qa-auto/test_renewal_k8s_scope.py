import json, os, subprocess, sys, unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent))
import k8s_oracle as oracle

PC_RULES = oracle.PC_RULES
PC_ATTEST = oracle.PC_ATTEST
APPR = "cli/knowledge/approvals/community/"
ALPHA = "k8s-single|1.20->1.21 sample.example/v1alpha1/Widget"
STABLE = "k8s-single|1.20->1.21 sample.example/v1/Widget"
SINGLES = {ALPHA: ("sample.example", "v1alpha1", "Widget"), STABLE: ("sample.example", "v1", "Widget")}
EVERY = set(SINGLES)


def entry(rid, project, reviewed="a"):
    return {"project": project, "rule": {"id": rid, "evidence": {"reviewedAt": reviewed}}}


def rules(reviewed=None, projects=(("ceph.r", "ceph"), ("loki.r", "loki"), ("kube.r", "kubernetes")), **kw):
    doc = {"schema": "s", "revision": "r", "policyDigest": "d",
           "entries": [entry(i, p, (reviewed or {}).get(i, "a")) for i, p in projects]}
    doc.update(kw)
    return doc


def approval(rid):
    return {"schema": "prufyx.io/knowledge-approval/v2", "record": {"ruleId": rid, "pack": "community"}}


def attest(components):
    return {"schema": "a", "revision": "r", "packDigest": "x", "ruleSetDigest": "y", "components": components}


def run(changed, files):
    """files: (rev, path) -> object | str | None (unreadable)."""
    def fake(*args, **kw):
        if args[:2] == ("git", "-C") and "diff" in args:
            return subprocess.CompletedProcess([], 0, "\n".join(changed) + "\n", "")
        rev, _, path = args[-1].partition(":")
        value = files.get((rev, path))
        if value is None:
            return subprocess.CompletedProcess([], 128, "", "missing")
        return subprocess.CompletedProcess([], 0, value if isinstance(value, str) else json.dumps(value), "")
    with patch.dict(os.environ, QA_BASE="base", QA_SHA="head", QA_REQUIRED_TARGETS=""), patch.object(oracle, "sh", side_effect=fake):
        return oracle.required_single_targets(SINGLES)


def pr691(over=None):
    f = {("base", PC_RULES): rules(), ("head", PC_RULES): rules({"ceph.r": "b", "loki.r": "b"}),
         ("base", PC_ATTEST): attest(["pkg:github/o/ceph"]), ("head", PC_ATTEST): attest(["pkg:github/o/ceph"]),
         ("head", APPR + "ceph.r.json"): approval("ceph.r"), ("head", APPR + "loki.r.json"): approval("loki.r")}
    f.update(over or {})
    return f


CHANGED = [PC_ATTEST, PC_RULES, APPR + "ceph.r.json", APPR + "loki.r.json", "README.md"]


class RenewalK8sScope(unittest.TestCase):
    def test_renewal_requires_no_kubernetes_single(self):
        self.assertEqual(run(CHANGED, pr691()), set())

    def test_changed_kubernetes_rule_requires_all(self):
        files = pr691({("head", PC_RULES): rules({"kube.r": "b"})})
        self.assertEqual(run(CHANGED, files), EVERY)

    def test_kubernetes_component_in_required_facts_requires_all(self):
        kube = [{"component": "pkg:github/kubernetes/kubernetes"}]
        def with_facts(doc, facts):
            doc["entries"][0]["requiredFacts"] = facts
            return doc
        # head only: the changed rule now requires a Kubernetes component
        head = with_facts(rules({"ceph.r": "b"}), kube)
        self.assertEqual(run(CHANGED, pr691({("head", PC_RULES): head})), EVERY)
        # base only: the changed rule used to require one
        base = with_facts(rules(), kube)
        self.assertEqual(run(CHANGED, pr691({("base", PC_RULES): base})), EVERY)

    def test_odd_required_facts_require_all(self):
        for facts in ("x", [1], [{"component": 5}]):
            doc = rules({"ceph.r": "b"})
            doc["entries"][0]["requiredFacts"] = facts
            self.assertEqual(run(CHANGED, pr691({("head", PC_RULES): doc})), EVERY, facts)

    def test_non_kubernetes_required_facts_stay_narrowed(self):
        base, head = rules(), rules({"ceph.r": "b"})
        for doc in (base, head):
            doc["entries"][0]["requiredFacts"] = [{"component": "pkg:github/ceph/ceph"}]
        self.assertEqual(run(CHANGED, pr691({("base", PC_RULES): base, ("head", PC_RULES): head})), set())

    def test_pack_metadata_change_requires_all(self):
        files = pr691({("head", PC_RULES): rules({"ceph.r": "b"}, revision="r2")})
        self.assertEqual(run(CHANGED, files), EVERY)

    def test_rule_removed_or_added_for_kubernetes_requires_all(self):
        files = pr691({("head", PC_RULES): rules(projects=(("ceph.r", "ceph"), ("loki.r", "loki")))})
        self.assertEqual(run(CHANGED, files), EVERY)

    def test_kubernetes_component_in_attestation_requires_all(self):
        files = pr691({("head", PC_ATTEST): attest(["pkg:github/kubernetes/kubernetes"])})
        self.assertEqual(run(CHANGED, files), EVERY)
        files = pr691({("base", PC_ATTEST): attest(["pkg:github/kubernetes/kubernetes"])})
        self.assertEqual(run(CHANGED, files), EVERY)

    def test_approval_of_kubernetes_or_unknown_rule_requires_all(self):
        for rid in ("kube.r", "nobody.r"):
            files = pr691({("head", APPR + "x.json"): approval(rid)})
            self.assertEqual(run(CHANGED + [APPR + "x.json"], files), EVERY, rid)

    def test_unparseable_or_unreadable_inputs_require_all(self):
        for key, value in ((("head", APPR + "ceph.r.json"), "{not json"), (("head", APPR + "ceph.r.json"), "[]"),
                           (("head", PC_RULES), "{not json"), (("head", PC_ATTEST), "[]"),
                           (("head", PC_RULES), None), (("base", PC_RULES), None)):
            files = pr691()
            if value is None:
                del files[key]
            else:
                files[key] = value
            self.assertEqual(run(CHANGED, files), EVERY, key)

    def test_nested_or_other_pack_approval_still_requires_all(self):
        for path in (APPR + "sub/x.json", "cli/knowledge/approvals/cncf/x.json"):
            self.assertEqual(run(CHANGED + [path], pr691()), EVERY, path)

    def test_code_change_beside_renewal_requires_all(self):
        self.assertEqual(run(CHANGED + ["cli/internal/projectcheck/projectcheck.go"], pr691()), EVERY)


if __name__ == "__main__":
    unittest.main()
