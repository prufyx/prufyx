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
    def report(self, verdict="UNKNOWN", status=None, locations=None):
        return {"verdict": verdict, "paths": [{"component": "sample", "hops": [
            {"families": [{"family": "crd.custom_resource_versions", "status": status}]}]}],
            "findings": [{"component": "sample", "locations": locations or []}]}

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

    def test_missing_input_document_is_error(self):
        self.assertTrue(q.complete_scan_scope({"summary": {"documentsRead": 2}}, 2))
        for report in ({}, {"summary": {"documentsRead": 1}}, {"summary": {"documentsRead": True}}):
            self.assertFalse(q.complete_scan_scope(report, 2))

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
        for rc, binding, expected in ((0, True, 0), (124, True, 3), (1, True, 3), (0, False, 3)):
            with self.subTest(rc=rc, binding=binding), tempfile.TemporaryDirectory() as td:
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
                self.assertIn("ERR=" + ("0" if expected == 0 else "1"), result.stdout)


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
