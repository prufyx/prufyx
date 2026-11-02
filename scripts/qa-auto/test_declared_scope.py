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
