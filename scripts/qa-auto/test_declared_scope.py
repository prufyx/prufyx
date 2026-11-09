"""Declared scope controls use synthetic APIs, without a cluster or network."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import k8s_oracle as oracle
import qa_scope


ALPHA = "k8s-single|1.20->1.21 sample.example/v1alpha1/Widget"
RANGE = "k8s-range|1.20->1.21"


class ScopeContractTests(unittest.TestCase):
    def scope(self, required=()):
        value = qa_scope.declare("head", "base", "run", [RANGE, ALPHA], required,
                                 [dict(target=ALPHA, reason="unsupported alpha", next_test="reproduce single-alpha removal")])
        value.update(executed=[RANGE], state="COMPLETE")
        return value

    def test_exclusion_is_not_execution_and_required_exclusion_blocks(self):
        self.assertEqual(qa_scope.errors(self.scope(), "head", "base", "run"), [])
        self.assertIn("required target excluded", qa_scope.errors(self.scope([ALPHA]), "head", "base", "run"))
        missing = self.scope(["missing"])
        self.assertIn("required target absent from declared scope", qa_scope.errors(missing, "head", "base", "run"))

    def test_unprocessed_input_has_explicit_target_inventory(self):
        scope = self.scope()
        oracle.record_input(scope, RANGE, {"summary": {"documentsRead": 2, "documentsOmitted": 1}, "omitted": [{"reason": "TEMPLATED"}]}, 2)
        self.assertEqual(scope["omitted"][0]["target"], RANGE)
        self.assertEqual(scope["omitted"][0]["intake_omitted"], 1)
        self.assertTrue(qa_scope.errors(scope, "head", "base", "run"))

    def test_missing_execution_and_changed_binding_fail(self):
        for change in ({"executed": []}, {"head": "other"}, {"base": "other"}, {"run_id": "other"},
                       {"state": "DECLARED"}, {"requested": [ALPHA]}):
            with self.subTest(change=change):
                scope = self.scope()
                scope.update(change)
                self.assertTrue(qa_scope.errors(scope, "head", "base", "run"))

    def test_stable_cannot_be_excluded_under_alpha_profile(self):
        stable = "k8s-single|1.20->1.21 sample.example/v1/Widget"
        scope = qa_scope.declare("head", "base", "run", [RANGE, stable], [],
                                 [dict(target=stable, reason="unsupported", next_test="reproduce")])
        scope.update(executed=[RANGE], state="COMPLETE")
        self.assertTrue(qa_scope.errors(scope, "head", "base", "run"))

    def test_requirements_ambiguity_is_all_not_empty(self):
        singles = {ALPHA: ("sample.example", "v1alpha1", "Widget")}
        failed = subprocess.CompletedProcess([], 128, "", "unreadable")
        with patch.dict(os.environ, QA_BASE="base", QA_SHA="head"), patch.object(oracle, "sh", return_value=failed):
            self.assertEqual(oracle.required_single_targets(singles), {ALPHA})

    def test_exact_changed_fact_and_operator_requirements_are_additive(self):
        stable = "k8s-single|1.20->1.21 sample.example/v1/Widget"
        singles = {ALPHA: ("sample.example", "v1alpha1", "Widget"), stable: ("sample.example", "v1", "Widget")}
        entry = {"project": "kubernetes", "rule": {"id": "removal", "condition": {"factId": "fact"}}}
        before, after = {"entries": []}, {"entries": [entry]}
        results = [subprocess.CompletedProcess([], 0, "cli/internal/cncfcheck/data/rules.json\n", ""),
                   subprocess.CompletedProcess([], 0, json.dumps(before), ""),
                   subprocess.CompletedProcess([], 0, json.dumps(after), "")]
        with tempfile.TemporaryDirectory() as td:
            required_file = Path(td) / "required.json"
            required_file.write_text(json.dumps([ALPHA]))
            with patch.dict(os.environ, QA_BASE="base", QA_SHA="head", QA_REQUIRED_TARGETS=str(required_file)), patch.object(
                    oracle, "sh", side_effect=results), patch.object(oracle, "kubernetes_removal_facts", return_value={"fact": ["sample.example/v1/Widget"]}):
                self.assertEqual(oracle.required_single_targets(singles), {ALPHA, stable})

    ATTEST = "cli/internal/cncfcheck/data/corpus-attestation.json"

    def attest_run(self, components_before, components_after, trusted=None, rules=None, extra_paths=(), inputs=None):
        stable = "k8s-single|1.20->1.21 sample.example/v1/Widget"
        singles = {ALPHA: ("sample.example", "v1alpha1", "Widget"), stable: ("sample.example", "v1", "Widget")}
        att = lambda comps: json.dumps({"schema": "s", "revision": "r", "packDigest": "d", "ruleSetDigest": "d", "ruleCount": 1, "components": comps})
        rule = lambda proj, comp: {"project": proj, "rule": {"id": proj}, "requiredFacts": [{"component": comp}]}
        rules_doc = json.dumps(rules or {"schema": "s", "entries": [rule("alpha", "pkg:github/o/alpha"), rule("kubernetes", "pkg:github/kubernetes/kubernetes")]})
        if inputs is None:
            inputs = (att(components_before), att(components_after), rules_doc, rules_doc,
                      trusted if trusted is not None else {}, {"alpha"})
        listing = subprocess.CompletedProcess([], 0, "\n".join([self.ATTEST, *extra_paths]) + "\n", "")
        with patch.dict(os.environ, QA_BASE="base", QA_SHA="head"), patch.object(
                oracle, "sh", return_value=listing), patch.object(oracle, "attestation_inputs", return_value=inputs):
            return oracle.required_single_targets(singles), set(singles)

    def test_attestation_non_kubernetes_change_stays_narrow(self):
        got, _ = self.attest_run(["pkg:github/o/alpha"], ["pkg:github/o/alpha", "pkg:github/other/alpha"],
                                 extra_paths=["README.md", "cli/docs/generated/community-support-inventory.json"])
        self.assertEqual(got, set())
        got, _ = self.attest_run(["pkg:github/o/alpha"], [])
        self.assertEqual(got, set())

    def test_attestation_kubernetes_component_requires_all(self):
        for before, after in (([], ["pkg:github/kubernetes/kubernetes"]), (["pkg:github/o/kube-proxy"], []),
                              ([], ["pkg:generic/k8s-thing"])):
            got, every = self.attest_run(before, after)
            self.assertEqual(got, every)

    def test_attestation_kubernetes_attributed_via_trusted_binding_requires_all(self):
        got, every = self.attest_run([], ["pkg:github/o/renamed"], trusted={"pkg:github/o/renamed": "kubernetes"})
        self.assertEqual(got, every)

    def test_attestation_unattributable_or_unparseable_requires_all(self):
        got, every = self.attest_run([], ["pkg:github/o/unknown-thing"])
        self.assertEqual(got, every)
        got, every = self.attest_run(None, None, inputs=("{not json", "{}", "{}", "{}", {}, set()))
        self.assertEqual(got, every)
        def boom():
            raise ValueError("unreadable")
        with patch.object(oracle, "attestation_inputs", side_effect=boom), patch.dict(os.environ, QA_BASE="base", QA_SHA="head"), patch.object(
                oracle, "sh", return_value=subprocess.CompletedProcess([], 0, self.ATTEST + "\n", "")):
            self.assertEqual(oracle.required_single_targets({ALPHA: ("a", "b", "c")}), {ALPHA})

    def test_attestation_with_kubernetes_rules_change_requires_that_fact(self):
        stable = "k8s-single|1.20->1.21 sample.example/v1/Widget"
        singles = {ALPHA: ("sample.example", "v1alpha1", "Widget"), stable: ("sample.example", "v1", "Widget")}
        entry = {"project": "kubernetes", "rule": {"id": "removal", "condition": {"factId": "fact"}}}
        results = [subprocess.CompletedProcess([], 0, f"{self.ATTEST}\ncli/internal/cncfcheck/data/rules.json\n", ""),
                   subprocess.CompletedProcess([], 0, json.dumps({"entries": []}), ""),
                   subprocess.CompletedProcess([], 0, json.dumps({"entries": [entry]}), "")]
        att = json.dumps({"schema": "s", "revision": "r", "packDigest": "d", "ruleSetDigest": "d", "ruleCount": 1, "components": []})
        att2 = json.dumps({"schema": "s", "revision": "r", "packDigest": "d", "ruleSetDigest": "d", "ruleCount": 1, "components": ["pkg:github/o/alpha"]})
        rules = json.dumps({"schema": "s", "entries": [{"project": "alpha", "rule": {"id": "a"}, "requiredFacts": [{"component": "pkg:github/o/alpha"}]}]})
        with patch.dict(os.environ, QA_BASE="base", QA_SHA="head"), patch.object(oracle, "sh", side_effect=results), patch.object(
                oracle, "attestation_inputs", return_value=(att, att2, rules, rules, {}, {"alpha"})), patch.object(
                oracle, "kubernetes_removal_facts", return_value={"fact": ["sample.example/v1/Widget"]}):
            self.assertEqual(oracle.required_single_targets(singles), {stable})

    RULES = "cli/internal/cncfcheck/data/rules.json"

    def meta_run(self, before, after, trusted=None, inputs_fail=False, slugs=None, extra_entries=()):
        stable = "k8s-single|1.20->1.21 sample.example/v1/Widget"
        singles = {ALPHA: ("sample.example", "v1alpha1", "Widget"), stable: ("sample.example", "v1", "Widget")}
        base = {"schema": "s", "revision": "r1", "policyDigest": "p", "landscapeFileDigest": "l", "registryDigest": "g",
                "entries": [{"project": "alpha", "rule": {"id": "a"}, "requiredFacts": [{"component": "pkg:github/o/alpha"}]},
                            {"project": "kubernetes", "rule": {"id": "k", "condition": {"factId": "fact"}},
                             "requiredFacts": [{"component": "pkg:github/kubernetes/kubernetes"}]}],
                "lineAttestations": [], "servedAPIs": [], "pathPolicies": []}
        base["entries"].extend(json.loads(json.dumps(list(extra_entries))))
        def make(change):
            doc = json.loads(json.dumps(base))
            if callable(change):
                change(doc)
            elif change is not None:
                doc.update(change)
            return doc
        results = [subprocess.CompletedProcess([], 0, self.RULES + "\n", ""),
                   subprocess.CompletedProcess([], 0, json.dumps(make(before)) if not isinstance(before, str) else before, ""),
                   subprocess.CompletedProcess([], 0, json.dumps(make(after)) if not isinstance(after, str) else after, "")]
        inputs = ("{}", "{}", "{}", "{}", trusted or {}, set(slugs or {"alpha"}))
        with patch.dict(os.environ, QA_BASE="base", QA_SHA="head"), patch.object(oracle, "sh", side_effect=results), patch.object(
                oracle, "attestation_inputs", return_value=inputs), patch.object(
                oracle, "kubernetes_removal_facts", return_value={"fact": ["sample.example/v1/Widget"]}):
            return oracle.required_single_targets(singles), set(singles), stable

    @staticmethod
    def line(component, line="1.0"):
        return {"component": component, "line": line, "factFamily": "f", "ruleIds": []}

    def test_rules_line_attestation_non_kubernetes_with_metadata_stays_narrow(self):
        got, _, _ = self.meta_run(None, {"lineAttestations": [self.line("pkg:github/o/alpha")]})
        self.assertEqual(got, set())
        got, _, _ = self.meta_run(None, {"lineAttestations": [dict(self.line("pkg:github/o/alpha"), ruleIds=["a"])]})
        self.assertEqual(got, set())
        # unknown component bound by the trusted base binding to a non-kubernetes slug
        got, _, _ = self.meta_run(None, {"lineAttestations": [self.line("pkg:github/o/renamed")]},
                                  trusted={"pkg:github/o/renamed": "alpha"})
        self.assertEqual(got, set())

    def test_rules_non_kubernetes_entry_and_attestation_together_stay_narrow(self):
        def change(doc):
            doc["entries"][0]["rule"]["extra"] = 1
            doc["servedAPIs"] = [{"component": "pkg:github/o/alpha", "line": "1"}]
        got, _, _ = self.meta_run(None, change)
        self.assertEqual(got, set())

    def test_rules_kubernetes_attestation_requires_all(self):
        for comp in ("pkg:github/kubernetes/kubernetes", "pkg:github/o/kube-proxy", "pkg:generic/k8s-thing"):
            got, every, _ = self.meta_run(None, {"lineAttestations": [self.line("pkg:github/o/alpha"), self.line(comp)]})
            self.assertEqual(got, every, comp)
        got, every, _ = self.meta_run(None, {"pathPolicies": [{"component": "pkg:github/o/renamed", "policy": "p"}]},
                                      trusted={"pkg:github/o/renamed": "kubernetes"})
        self.assertEqual(got, every)

    def test_rules_ruleids_and_digest_changes_require_all(self):
        for ids in (["k"], ["missing"], ["a", "k"], "a", [1]):
            got, every, _ = self.meta_run(None, {"lineAttestations": [dict(self.line("pkg:github/o/alpha"), ruleIds=ids)]})
            self.assertEqual(got, every, ids)
        for key in ("revision", "registryDigest", "landscapeFileDigest", "policyDigest"):
            got, every, _ = self.meta_run(None, {key: "changed", "lineAttestations": [self.line("pkg:github/o/alpha")]})
            self.assertEqual(got, every, key)

    def test_rules_unknown_or_unattributable_metadata_requires_all(self):
        for after in ({"revision": "r2", "newSection": []},
                      {"revision": "r2"},
                      {"lineAttestations": [self.line("pkg:github/o/unknown-thing")]},
                      {"revision": 2, "lineAttestations": [self.line("pkg:github/o/alpha")]},
                      {"schema": "t", "lineAttestations": [self.line("pkg:github/o/alpha")]},
                      {"lineAttestations": [self.line("pkg:github/o/alpha"), self.line("pkg:github/o/alpha")]}):
            got, every, _ = self.meta_run(None, after)
            self.assertEqual(got, every, after)
        got, every, _ = self.meta_run(None, lambda d: d.update(extraKey=1))
        self.assertEqual(got, every)
        got, every, _ = self.meta_run(None, "{not json")
        self.assertEqual(got, every)

    def test_rules_kubernetes_entry_change_requires_that_fact(self):
        def change(doc):
            doc["entries"][1]["rule"]["extra"] = 1
        got, _, stable = self.meta_run(None, change)
        self.assertEqual(got, {stable})
        def both(doc):
            change(doc)
            doc["lineAttestations"] = [self.line("pkg:github/o/alpha")]
        got, _, stable = self.meta_run(None, both)
        self.assertEqual(got, {stable})

    THIRD_PARTY = ("k8s-cleaner", "kubemod", "kubevela", "kubemox", "kube-state-metrics")

    def third_party_run(self, after, entries=True):
        slugs = set(self.THIRD_PARTY) | {"alpha"}
        extra = [{"project": n, "rule": {"id": "r-" + n}, "requiredFacts": [{"component": "pkg:github/o/" + n}]}
                 for n in self.THIRD_PARTY] if entries else ()
        return self.meta_run(None, after, slugs=slugs, extra_entries=extra)

    def test_third_party_line_attestations_with_kube_like_names_stay_narrow(self):
        comps = ["pkg:github/gianlucam76/k8s-cleaner", "pkg:github/kubemod/kubemod", "pkg:github/kubevela/kubevela",
                 "pkg:github/o/kubemox", "pkg:github/kubernetes/kube-state-metrics"]
        got, _, _ = self.third_party_run({"lineAttestations": [self.line(c) for c in comps]}, entries=False)
        self.assertEqual(got, set())
        got, _, _ = self.third_party_run({"lineAttestations": [dict(self.line(c), ruleIds=["r-" + n])
                                                               for c, n in zip(comps, self.THIRD_PARTY)]})
        self.assertEqual(got, set())

    def test_kubernetes_component_line_attestation_still_requires_all(self):
        for comp in ("pkg:github/kubernetes/kubernetes", "pkg:golang/k8s.io/kubernetes", "pkg:generic/kubernetes@1.30"):
            got, every, _ = self.third_party_run({"lineAttestations": [self.line("pkg:github/o/kubemod"), self.line(comp)]})
            self.assertEqual(got, every, comp)

    def test_kube_like_name_without_trusted_binding_requires_all(self):
        got, every, _ = self.meta_run(None, {"lineAttestations": [self.line("pkg:github/o/kubemod")]})
        self.assertEqual(got, every)

    def test_kubernetes_like_is_exact(self):
        for name in ("kubernetes", "Kubernetes", "pkg:github/kubernetes/kubernetes", "pkg:golang/k8s.io/kubernetes@v1.30.0"):
            self.assertTrue(oracle._kubernetes_like(name), name)
        for name in self.THIRD_PARTY + ("pkg:github/gianlucam76/k8s-cleaner", "kubernetes-ingress", "pkg:github/o/kube-proxy", ""):
            self.assertFalse(oracle._kubernetes_like(name), name)

    def test_changed_third_party_entry_is_not_kubernetes(self):
        def change(doc):
            for e in doc["entries"]:
                if e["project"] == "kubemod":
                    e["rule"]["extra"] = 1
        got, _, _ = self.third_party_run(change)
        self.assertEqual(got, set())
        def kube(doc):
            change(doc)
            doc["entries"][1]["rule"]["extra"] = 1
        got, _, stable = self.third_party_run(kube)
        self.assertEqual(got, {stable})

    def test_summary_rejects_missing_bound_scope_and_required_exclusions(self):
        script_dir = Path(__file__).resolve().parent
        for mode, expected in (("valid", 0), ("missing", 3), ("required-excluded", 3), ("wrong-run", 3)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as td:
                output, state = Path(td, "results"), Path(td, "state")
                output.mkdir()
                state.mkdir()
                cases = [dict(suite=suite, key="synthetic", wrongpass=False, mismatch=False, error=False, detail={})
                         for suite in ("crd", "k8s-range", "bp325", "review", "rules")]
                Path(output, "synthetic.cases.json").write_text(json.dumps(cases))
                scope = self.scope([ALPHA] if mode == "required-excluded" else [])
                if mode == "wrong-run":
                    scope["run_id"] = "old-run"
                if mode != "missing":
                    Path(output, "k8s.scope.json").write_text(json.dumps(scope))
                crd = qa_scope.declare("head", "base", "run", ["crd-project|synthetic"], [], [], qa_scope.CRD_PROFILE)
                crd.update(executed=["crd-project|synthetic"], state="COMPLETE")
                Path(output, "crd.scope.json").write_text(json.dumps(crd))
                env = dict(os.environ, QA_BASE="base", QA_RUN_ID="run")
                result = subprocess.run(["python3", str(script_dir / "summarize.py"), "--dir", str(output),
                                         "--state", str(state), "--sha", "head", "--mode", "incremental", "--adhoc"],
                                        env=env, text=True, capture_output=True)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                summary = json.loads(Path(output, "summary.json").read_text())
                self.assertEqual(bool(summary["errors"]), expected != 0)
                if mode == "valid":
                    self.assertEqual(summary["scopes"]["k8s"]["excluded"][0]["target"], ALPHA)

    def test_declared_before_candidate_and_range_still_executes(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "k8s.cases.json"
            declarations = []
            def swagger(minor):
                return {("sample.example", "v1alpha1", "Widget")} if minor == 20 else {("sample.example", "v1", "Widget")}
            def scan(*args):
                declared = json.loads(Path(td, "k8s.scope.json.declared").read_text())
                self.assertEqual(declared["state"], "DECLARED")
                declarations.append(declared)
                return 11, {"verdict": "UNKNOWN", "paths": [], "findings": [],
                            "summary": {"documentsRead": 1, "documentsOmitted": 0}, "omitted": []}, ""
            with patch.object(oracle, "swagger", side_effect=swagger), patch.object(oracle, "prufyx", side_effect=scan), patch.object(
                    oracle, "inp", return_value="synthetic"), patch.object(oracle, "required_single_targets", return_value=set()), patch(
                    "sys.argv", ["k8s_oracle.py", "--out", str(output), "--lo", "20", "--hi", "21"]), contextlib.redirect_stdout(io.StringIO()):
                oracle.main()
            self.assertEqual(len(declarations), 1)
            final = json.loads(Path(td, "k8s.scope.json").read_text())
            self.assertEqual(set(final["executed"]), {RANGE, "k8s-version|1.20.0", "k8s-version|1.21.0", "k8s-single-set|1.20->1.21"})
            self.assertEqual(final["excluded"][0]["target"], ALPHA)
            self.assertFalse(any(case["error"] for case in json.loads(output.read_text())))


if __name__ == "__main__":
    unittest.main()
