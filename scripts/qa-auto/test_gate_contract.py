"""Synthetic regressions for complete oracle reads and scoped verdicts."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import crd_oracle as crd
import qalib as q
import k8s_oracle as k8s


class ScopedVerdictTests(unittest.TestCase):
    def setUp(self):
        registry = {"sample.removal": {"project": "sample", "rule": {
            "operator": "forbid_set_member", "setCondition": {
                "factId": "component.sample.custom_resource_versions_set",
                "members": ["sample.example/v1/Widget"]}}}}
        self.registry = patch.object(q, "claim_registry", return_value=registry)
        self.registry.start()
        self.addCleanup(self.registry.stop)

    def report(self, verdict="UNKNOWN", status=None, locations=None):
        return {"verdict": verdict, "paths": [{"component": "sample", "hops": [
            {"families": [{"family": "crd.custom_resource_versions", "status": status}]}]}],
            "findings": [{"component": "sample", "ruleId": "sample.removal", "locations": locations or []}]}

    def check(self, report):
        return q.scoped_result(11, report, [("sample.example", "v1", "Widget")],
                               "sample", "crd.custom_resource_versions")

    def test_family_pass_masked_by_aggregate(self):
        for aggregate in ("UNKNOWN", "BLOCKED"):
            with self.subTest(aggregate=aggregate):
                self.assertTrue(self.check(self.report(aggregate, "PASS"))[0])

    def test_unrelated_or_missing_object_finding_does_not_match(self):
        for location in ({"kind": "Other", "name": "anything"},
                         {"kind": "Widget", "name": q.object_name("other.example", "v1", "Widget")},
                         {"kind": "Widget", "name": q.object_name("sample.example", "v2", "Widget")}):
            self.assertTrue(self.check(self.report(locations=[location]))[1])

    def test_exact_object_blocker_matches(self):
        report = self.report(locations=[{"kind": "Widget", "name": q.object_name("sample.example", "v1", "Widget")}])
        self.assertEqual(self.check(report)[:3], (False, False, []))
        report["findings"][0]["ruleId"] = "unrelated.rule"
        self.assertTrue(self.check(report)[1])
        report["findings"][0]["component"] = "unrelated"
        self.assertTrue(self.check(report)[1])

    def test_unreadable_git_cannot_become_empty_truth(self):
        with patch.object(crd, "sh", return_value=subprocess.CompletedProcess([], 128, "", "missing")):
            with self.assertRaises(ValueError):
                crd.crd_text({"paths": [{"path": "missing.yaml"}]}, "/unused", "v1")

    def test_empty_directory_is_not_evidence_of_removal(self):
        with patch.object(crd, "sh", return_value=subprocess.CompletedProcess([], 0, "", "")):
            with self.assertRaises(ValueError):
                crd.crd_text({"paths": [{"path": "crds", "directory": True, "match": ".*"}]}, "/unused", "v1")

    def test_timeout_bad_json_and_failure_exit_are_errors(self):
        for result in (subprocess.TimeoutExpired([], 1),
                       subprocess.CompletedProcess([], 0, "broken", ""),
                       subprocess.CompletedProcess([], 503, '{"verdict":"UNKNOWN"}', ""),
                       subprocess.CompletedProcess([], 0, '[]', "")):
            kwargs = {"side_effect": result} if isinstance(result, Exception) else {"return_value": result}
            with patch.object(q.subprocess, "run", **kwargs):
                self.assertIsNone(q.prufyx("scan", "unused", "a=1", "a=2")[1])

    def test_removal_rule_must_name_exact_gvk(self):
        registry = {"kubernetes.removal": {"project": "kubernetes", "rule": {
            "operator": "forbid_predicate_value", "condition": {
                "factId": "component.kubernetes.example_removed_gvk_present"}}}}
        facts = {"component.kubernetes.example_removed_gvk_present": ["example/v1/Widget"]}
        with patch.object(q, "claim_registry", return_value=registry), patch.object(q, "kubernetes_removal_facts", return_value=facts):
            self.assertTrue(q.removal_claim("kubernetes.removal", "kubernetes", "kubernetes.removed_served_gvk", "example/v1/Widget"))
            self.assertFalse(q.removal_claim("kubernetes.removal", "kubernetes", "kubernetes.removed_served_gvk", "other/v1/Widget"))

    def test_missing_input_document_is_error(self):
        self.assertTrue(q.complete_scan_scope({"summary": {"documentsRead": 2, "documentsOmitted": 0}, "omitted": []}, 2))
        for report in ({}, {"summary": {"documentsRead": 1}}, {"summary": {"documentsRead": True}}):
            self.assertFalse(q.complete_scan_scope(report, 2))

    def test_actual_intake_omissions_fail_complete_scope(self):
        fixture = Path(__file__).resolve().parents[2] / "cli/internal/scanrun/testdata/blocked-templated.json"
        report = json.loads(fixture.read_text())
        requested = report["summary"]["documentsRead"]
        self.assertEqual({item["reason"] for item in report["omitted"]}, {"UNPARSEABLE", "TEMPLATED"})
        self.assertFalse(q.complete_scan_scope(report, requested))
        for omitted_count, omitted in ((0, report["omitted"]), (2, []), (0, None), (False, [])):
            with self.subTest(omitted_count=omitted_count, omitted=omitted):
                altered = dict(report, summary=dict(report["summary"], documentsOmitted=omitted_count), omitted=omitted)
                self.assertFalse(q.complete_scan_scope(altered, requested))

    def test_missing_requested_release_line_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "target-sample.json"
            target.write_text(json.dumps({"target": {"repo": "example/sample", "tagPrefixes": ["v"],
                "paths": [{"path": "crds.yaml"}]}}))
            with patch.object(crd, "TD", td), patch.object(crd, "GITROOT", td), patch.object(
                    crd, "sh", return_value=subprocess.CompletedProcess([], 0, "v1.0.0\n", "")):
                result = crd.run("sample", [{"project": "sample", "pairs": [{"from": "1.0", "to": "2.0"}]}])
                self.assertTrue(result[0]["error"])

    def test_swagger_absence_and_503_are_not_silent_omissions(self):
        with tempfile.TemporaryDirectory() as td, patch.object(k8s, "CACHE", td):
            with patch.object(k8s.urllib.request, "urlopen", side_effect=OSError("503")):
                with self.assertRaises(OSError):
                    k8s.swagger(987)
            Path(td, "k8s-987.json").write_text('{"definitions":{}}')
            with self.assertRaises(ValueError):
                k8s.swagger(987)


class GateRunnerTests(unittest.TestCase):
    def test_summary_cannot_hide_runner_failure_or_wrong_binding(self):
        here = Path(__file__).resolve().parent
        for rc, binding, mismatch, expected in ((0, True, 0, 0), (124, True, 0, 3),
                                                (1, True, 0, 3), (0, False, 0, 3), (0, True, 1, 3)):
            with self.subTest(rc=rc, binding=binding, mismatch=mismatch), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                runner = root / "runner"
                runner.write_text('''#!/usr/bin/env python3
import json, os
from pathlib import Path
p = Path(os.environ['QA_STATE']) / 'results' / ('test-' + os.environ['QA_SHA'][:8])
p.mkdir(parents=True)
s = dict(sha=os.environ['QA_SHA'], base=os.environ['QA_BASE'], run_id=os.environ['QA_RUN_ID'],
         wrongpass=0, mismatch=0, errors=0, cases=1, skipped=[], mode='full', wrongpass_cases=[], error_cases=[])
''' + ("s['run_id'] = 'different'\n" if not binding else "") +
                    f"s['mismatch'] = {mismatch}\ns['new_mismatch'] = 0\n" +
                    "json.dump([], open(Path(os.environ['QA_STATE']) / 'known-mismatch.json', 'w'))\n" +
                    f"json.dump(s, open(p / 'summary.json', 'w'))\nraise SystemExit({rc})\n")
                runner.chmod(0o700)
                git = root / "git"
                git.write_text('#!/bin/sh\nexit 0\n')
                git.chmod(0o700)
                env = dict(os.environ, QA_STATE=str(root / "state"), QA_GATE_RUN=str(runner),
                           QA_GATE_TRIES="1", PATH=str(root) + ":" + os.environ["PATH"])
                result = subprocess.run([str(here / "batch_gate.sh"), "--trust-operator", "a" * 40, "b" * 40],
                                        env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                self.assertIn("ERR=" + ("0" if expected == 0 or mismatch else "1"), result.stdout)
                self.assertIn("MISMATCH=" + str(mismatch), result.stdout)


class YAMLReadTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("QA_TEST_CRDGVK"), "set QA_TEST_CRDGVK to the built helper")
    def test_multidocument_is_atomic(self):
        valid = """apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
spec:
  group: sample.example
  names:
    kind: Widget
  versions:
  - name: v1
    served: true
    storage: true
"""
        helper = os.environ["QA_TEST_CRDGVK"]
        fact_run = subprocess.run([helper, "-removal-facts"], text=True, capture_output=True)
        self.assertEqual(fact_run.returncode, 0)
        facts = json.loads(fact_run.stdout)
        self.assertIn("networking.k8s.io/v1beta1/Ingress", facts["component.kubernetes.ingress_networking_v1beta1_removed_gvk_present"])
        self.assertIn("flowcontrol.apiserver.k8s.io/v1beta3/FlowSchema", facts["component.kubernetes.flowcontrol_v1beta3_removed_gvk_present"])
        good = subprocess.run([helper], input=valid + "---\n" + valid, text=True, capture_output=True)
        self.assertEqual(good.returncode, 0)
        self.assertEqual(len(json.loads(good.stdout)), 2)
        for middle in ("invalid: [", "kind: CustomResourceDefinition\nspec: {}"):
            bad = subprocess.run([helper], input=valid + "---\n" + middle + "\n---\n" + valid,
                                 text=True, capture_output=True)
            self.assertNotEqual(bad.returncode, 0)
            self.assertEqual(bad.stdout, "")


if __name__ == "__main__":
    unittest.main()
