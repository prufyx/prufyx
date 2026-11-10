"""Entrypoint proofs with synthetic upstream bytes; no product binary or cluster."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from seeded_support import write_seeded
from test_batch_envelope_scope import gate_source
import urllib.error
from unittest.mock import patch

import crd_oracle as crd
import k8s_oracle as k8s
import qa_scope


HERE = Path(__file__).resolve().parent


def oracle_runner():
    """Use real oracle, summary and gate code; fake only upstream and scan I/O."""
    mode = os.environ["CONTROL"]
    out = Path(os.environ["QA_STATE"], "results", "control-" + os.environ["QA_SHA"][:8])
    out.mkdir(parents=True)
    count = []
    def fetch(url, **kwargs):
        if "/v1.21.0/" in url:
            if mode in ("404", "unproved-404", "required-404"):
                raise urllib.error.HTTPError(url, 404, "absent", {}, None)
            if mode == "503":
                raise urllib.error.HTTPError(url, 503, "unavailable", {}, None)
            if mode == "timeout":
                raise TimeoutError("timeout")
            if mode == "bad-json":
                return io.BytesIO(b"{broken")
        return io.BytesIO(json.dumps({"definitions": {"Widget": {"x-kubernetes-group-version-kind": [
            {"group": "sample.example", "version": "v1", "kind": "Widget"}]}}}).encode())
    def scan(*args):
        count.append(args)
        return 11, {"verdict": "UNKNOWN", "paths": [], "findings": [],
                    "summary": {"documentsRead": 1, "documentsOmitted": 0}, "omitted": []}, ""
    refs = "" if mode == "unproved-404" else "a" * 40 + "\trefs/tags/v1.20.0\n"
    k8s._sw.clear()
    with patch.object(k8s, "CACHE", str(out / "cache")), patch.object(k8s, "TMP", str(out / "tmp")), patch.object(
            k8s.urllib.request, "urlopen", side_effect=fetch), patch.object(k8s, "prufyx", side_effect=scan), patch.object(
            k8s, "required_single_targets", side_effect=lambda singles: set(singles) if mode == "required-404" else set()), patch.object(
            k8s.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, refs, "")), patch(
            "sys.argv", ["k8s_oracle.py", "--out", str(out / "k8s.cases.json"), "--lo", "20", "--hi", "21"]):
        k8s.main()
    with patch.object(crd, "COV", ""), patch("sys.argv", ["crd_oracle.py", "--no-changed-projects", "--out", str(out / "crd.cases.json")]):
        crd.main()
    (out / "scan-count").write_text(str(len(count)))
    (out / "other.cases.json").write_text(json.dumps([
        dict(suite=suite, key="synthetic", wrongpass=False, mismatch=False, error=False, detail={})
        for suite in ("bp325", "review", "rules")]))
    write_seeded(out)
    result = subprocess.run([sys.executable, str(HERE / "summarize.py"), "--dir", str(out),
        "--state", os.environ["QA_STATE"], "--sha", os.environ["QA_SHA"], "--mode", "incremental", "--adhoc"])
    path = out / "summary.json"
    summary = json.loads(path.read_text())
    if mode == "wrong-head":
        summary["sha"] = "c" * 40
    if mode == "wrong-base":
        summary["base"] = "c" * 40
    if mode == "zero":
        summary["cases"] = 0
    if mode == "missing-crd":
        del summary["scopes"]["crd"]
    path.write_text(json.dumps(summary))
    if mode == "stale":
        os.utime(path, (1, 1))
    return result.returncode


class OracleToGateTests(unittest.TestCase):
    def test_actual_oracle_summary_and_gate_controls(self):
        for mode, expected in (("clean", 0), ("404", 0), ("unproved-404", 3), ("required-404", 3),
                               ("timeout", 3), ("503", 3), ("bad-json", 3), ("wrong-head", 3),
                               ("wrong-base", 3), ("stale", 3), ("zero", 3), ("missing-crd", 3)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                runner = root / "runner"
                runner.write_text("#!/usr/bin/env python3\nimport sys\nsys.path.insert(0, " + repr(str(HERE)) +
                                  ")\nfrom test_task4_scope import oracle_runner\nraise SystemExit(oracle_runner())\n")
                runner.chmod(0o700)
                remote, head, base = gate_source(root)
                env = dict(os.environ, CONTROL=mode, QA_STATE=str(root / "state"), QA_GATE_RUN=str(runner),
                           QA_GATE_TRIES="1", QA_SCOPE_HEAD=head, QA_REPO_URL=remote)
                result = subprocess.run([str(HERE / "batch_gate.sh"), "--trust-operator", head, base],
                                        env=env, text=True, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                output = root / ("state/results/control-" + head[:8])
                scope = json.loads((output / "k8s.scope.json").read_text())
                self.assertIn("k8s-version|1.21.0", scope["requested"])
                if mode in ("unproved-404", "required-404", "timeout", "503", "bad-json", "404"):
                    self.assertEqual((output / "scan-count").read_text(), "0")
                if mode == "404":
                    self.assertTrue(scope["excluded"])
                    self.assertEqual(scope["excluded"][0]["evidence"]["previous_ref_sha"], "a" * 40)
                if expected == 0:
                    self.assertIn("ERR=0", result.stdout)


class CRDInventoryTests(unittest.TestCase):
    def test_first_blob_failure_retains_later_exact_pair_requests(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "sample.git").mkdir()
            (root / "target-sample.json").write_text(json.dumps({"target": {
                "repo": "example/sample", "tagPrefixes": ["v"], "paths": [{"path": "crd.yaml"}]}}))
            cov = [{"project": "sample", "pairs": [{"from": "1.0", "to": "1.1"}, {"from": "1.1", "to": "1.2"}]}]
            def source(*args, **kwargs):
                return subprocess.CompletedProcess(args, 0, "v1.0.0\nv1.1.0\nv1.2.0\n" if "tag" in args else "", "")
            plan = crd.new_plan()
            with patch.object(crd, "TD", td), patch.object(crd, "GITROOT", td), patch.object(crd, "sh", side_effect=source), patch.object(
                    crd, "served_set", side_effect=ValueError("first blob unreadable")):
                with self.assertRaises(ValueError):
                    crd.prepare("sample", cov, plan)
            self.assertIn("crd|sample|v1.1.0|v1.2.0", plan["requested"])

    def test_operator_requirements_only_add_to_selected_crd_scope(self):
        inferred = {"crd-project|sample", "crd-line|sample|1.0|1.1"}
        for extra in ([], ["crd|unrequested|v1.0.0|v1.1.0"]):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                required_file = root / "required.json"
                required_file.write_text(json.dumps(extra))
                def prepare(project, cov, plan):
                    plan.update(proj=project, pref="v")
                    plan["requested"].update(inferred)
                    plan["metadata"].update(inferred)
                with patch.dict(os.environ, QA_REQUIRED_CRD_TARGETS=str(required_file)), patch.object(
                        crd, "COV", ""), patch.object(crd, "GATE", True), patch.object(crd, "prepare", side_effect=prepare), patch(
                        "sys.argv", ["crd_oracle.py", "--projects", "sample", "--out", str(root / "crd.cases.json")]):
                    crd.main()
                scope = json.loads((root / "crd.scope.json").read_text())
                self.assertEqual(set(scope["required"]), inferred | set(extra))
                reasons = qa_scope.errors(scope, scope["head"], scope["base"], scope["run_id"], qa_scope.CRD_PROFILE)
                self.assertEqual(bool(reasons), bool(extra))

    def test_source_failure_and_empty_scope_do_not_shrink_requests(self):
        for mode in ("clean", "read-failed", "empty"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                (root / "sample.git").mkdir()
                (root / "target-sample.json").write_text(json.dumps({"target": {
                    "repo": "example/sample", "tagPrefixes": ["v"], "paths": [{"path": "crd.yaml"}]}}))
                cov = root / "cov.json"
                cov.write_text(json.dumps({"projects": [{"project": "sample", "pairs": [{"from": "1.0", "to": "1.1"}]}]}))
                calls = []
                def source(*args, **kwargs):
                    if "tag" in args:
                        return subprocess.CompletedProcess(args, 0, "v1.0.0\nv1.1.0\n", "")
                    if "show" in args:
                        return subprocess.CompletedProcess(args, 128 if mode == "read-failed" else 0,
                                                           "kind: CustomResourceDefinition\n", "")
                    if args[0] == crd.CRDGVK:
                        return subprocess.CompletedProcess(args, 0, json.dumps([
                            dict(G="sample.example", V="v1", K="Widget", Served=mode != "empty", Store=True)]), "")
                    return subprocess.CompletedProcess(args, 0, "", "")
                def scan(*args):
                    declared = json.loads((root / "crd.scope.json.declared").read_text())
                    self.assertIn("crd|sample|v1.0.0|v1.1.0", declared["requested"])
                    calls.append(args)
                    return 11, {"verdict": "UNKNOWN", "paths": [], "findings": [],
                                "summary": {"documentsRead": 1, "documentsOmitted": 0}, "omitted": []}, ""
                with patch.object(crd, "TD", td), patch.object(crd, "GITROOT", td), patch.object(crd, "TMP", td), patch.object(
                        crd, "COV", str(cov)), patch.object(crd, "GATE", True), patch.object(crd, "sh", side_effect=source), patch.object(
                        crd, "prufyx", side_effect=scan), patch("sys.argv", ["crd_oracle.py", "--projects", "sample", "--out", str(root / "crd.cases.json")]):
                    crd.main()
                scope = json.loads((root / "crd.scope.json").read_text())
                self.assertEqual(len(scope["requested"]), 3)
                self.assertEqual(len(calls), 1 if mode == "clean" else 0)
                reasons = qa_scope.errors(scope, scope["head"], scope["base"], scope["run_id"], qa_scope.CRD_PROFILE)
                self.assertEqual(bool(reasons), mode != "clean")
                if mode == "read-failed":
                    self.assertEqual({entry["target"] for entry in scope["omitted"]}, set(scope["requested"]))
                if mode == "empty":
                    self.assertEqual(len(scope["excluded"]), 1)
                    self.assertTrue(scope["excluded"][0]["next_test"])


if __name__ == "__main__":
    unittest.main()
