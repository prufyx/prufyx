"""Paired publication controls: real oracle/review/summary/gate, synthetic I/O."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import crd_oracle as crd
import k8s_oracle as k8s
import qalib as q
import corpus


HERE = Path(__file__).resolve().parent
REMOVED = ("sample.example", "v1beta1", "Widget")
RETAINED = ("sample.example", "v1", "Widget")
RULE = "kubernetes.synthetic-removal"
FACT = "component.kubernetes.synthetic_removed_gvk_present"
PLAN = "k8s-plan|1.28->1.29"


def publication_runner():
    mode = os.environ["CONTROL"]
    no_removals = mode.startswith("retained-")
    out = Path(os.environ["QA_STATE"], "results", "control-" + os.environ["QA_SHA"][:8])
    out.mkdir(parents=True)
    source = out / "source"
    harness = source / "cli/internal/communityapp/qa_review_synthetic_test.go"
    harness.parent.mkdir(parents=True)
    harness.touch()
    rules = source / "cli/internal/cncfcheck/data/rules.json"
    rules.parent.mkdir(parents=True)
    rules.write_text(json.dumps({"entries": [{"rule": {"id": name + ".relnotes.control"}}
                                           for name in ("falco", "cortex")]}))
    allow = out / "review-allow.json"
    allow.write_text(json.dumps({"R1.store-explicit": {"ref": "tracked-finding", "reason": "diagnostic only"}}))

    def review_command(*args, **kwargs):
        if "-w" in args:
            observations = {cid: dict(exit=10, text="synthetic blocker") for cid in (
                "R1.embedded", "R1.store-explicit", "R1.auto-store", "R1.batch",
                "R1.same-id-shadow", "R1.same-id-shadow-batch")}
            observations.update({"R1x.control" + str(i): dict(exit=10, text="synthetic blocker") for i in range(14)})
            if mode == "review-pass":
                observations["R1.store-explicit"]["exit"] = 0
            (source / "cli/qa-review-out.json").write_text(json.dumps(observations))
            code = 0
        else:
            code = 0 if any("R4.ctl." in str(arg) for arg in args) else 10
        return subprocess.CompletedProcess(args, code, "", "")

    with patch.object(q, "SRC", str(source)), patch.object(q, "TMP", str(out / "tmp")), patch.object(
            q, "sh", side_effect=review_command), patch("sys.argv", ["review_cases.py", "--out",
            str(out / "review.cases.json"), "--allow", str(allow)]):
        runpy.run_path(str(HERE / "review_cases.py"), run_name="__main__")

    calls = []
    def candidate(command, path, frm, to):
        calls.append((command, path, frm, to))
        body = Path(path).read_bytes()
        provenance = {"inputDigest": "sha256:" + hashlib.sha256(body).hexdigest()}
        finding = dict(component="kubernetes", ruleId=RULE,
                       hop=dict(index=1, **{"from": "1.28.0", "to": "1.29.0"}),
                       locations=[dict(kind="Widget", name=q.object_name(*REMOVED))])
        if command == "plan":
            stage = dict(index=1, component="kubernetes", **{"from": "1.28.0", "to": "1.29.0"},
                         verdict="BLOCKED", findings=[dict(ruleId=RULE)])
            if mode == "plan-unknown":
                stage["verdict"] = "UNKNOWN"
            if mode == "plan-no-finding":
                stage["findings"] = []
            if mode == "plan-wrong-rule":
                stage["findings"] = [dict(ruleId="unrelated.rule")]
            if mode == "plan-foreign-input":
                provenance["inputDigest"] = "different-input"
            if no_removals:
                stage.update(verdict="SCOPE_COMPLETE_PASS", findings=[])
            if mode == "retained-unknown":
                stage["verdict"] = "UNKNOWN"
            if mode == "plan-gap":
                stage["gaps"] = [dict(reason="missing evidence")]
            if mode == "plan-line-endpoint":
                stage["to"] = "1.29"
            if mode == "plan-empty-stages":
                return 10, dict(verdict="BLOCKED", stages=[], provenance=provenance), ""
            if no_removals:
                return 0, dict(verdict="SCOPE_COMPLETE_PASS", stages=[stage], provenance=provenance), ""
            return 10, dict(verdict="BLOCKED", stages=[stage], provenance=provenance), ""
        requested = body.count(b"apiVersion:")
        report = dict(verdict="BLOCKED", paths=[], findings=[finding],
                      summary=dict(documentsRead=requested, documentsOmitted=0), omitted=[], provenance=provenance)
        if no_removals:
            report.update(verdict="SCOPE_COMPLETE_PASS", findings=[])
        # Mutate only the companion scan: earlier range/single controls stay clean.
        if Path(path).stem == "plan":
            if mode == "plan-omitted":
                report["summary"]["documentsOmitted"] = 1
            if mode == "plan-wrong-object":
                finding["locations"][0]["name"] = q.object_name(*RETAINED)
            if mode == "retained-empty-input":
                report["summary"]["documentsRead"] = 0
            if mode == "plan-line-endpoint":
                finding["hop"]["to"] = "1.29"
        return (0 if no_removals else 10), report, ""

    registry = {RULE: dict(project="kubernetes", rule=dict(operator="forbid_predicate_value", condition=dict(factId=FACT)))}
    with patch.object(k8s, "swagger", side_effect=lambda m: {REMOVED, RETAINED} if m == 28 and not no_removals else {RETAINED}), patch.object(
            k8s, "TMP", str(out / "tmp")), patch.object(k8s, "prufyx", side_effect=candidate), patch.object(
            k8s, "required_single_targets", return_value={PLAN + " overall"}), patch.object(q, "claim_registry", return_value=registry), patch.object(
            q, "kubernetes_removal_facts", return_value={FACT: ["/".join(REMOVED)]}), patch("sys.argv", [
            "k8s_oracle.py", "--out", str(out / "k8s.cases.json"), "--lo", "28", "--hi", "29"]):
        k8s.main()
    (out / "candidate-calls.json").write_text(json.dumps(calls))
    # Keep the independent CRD inventory nonempty and required in every paired run.
    def prepare(project, cov, plan):
        plan.update(proj=project, pref="v")
        target = "crd|synthetic|v1.0.0|v1.1.0"
        plan["requested"].update(["crd-project|synthetic", target])
        plan["metadata"].add("crd-project|synthetic")
        plan["jobs"].append((target, "v1.0.0", "v1.1.0", {RETAINED}, []))
    with patch.object(crd, "COV", ""), patch.object(crd, "GATE", True), patch.object(
            crd, "prepare", side_effect=prepare), patch.object(crd, "TMP", str(out / "tmp")), patch.object(
            crd, "prufyx", return_value=(11, dict(verdict="UNKNOWN", paths=[], findings=[],
            summary=dict(documentsRead=1, documentsOmitted=0), omitted=[]), "")), patch("sys.argv", ["crd_oracle.py", "--projects", "synthetic",
            "--out", str(out / "crd.cases.json")]):
        crd.main()
    rules.write_text(json.dumps({"entries": [dict(project="sample", rule=dict(id="sample.control",
        operator="forbid_predicate_value", subject=dict(component="sample", **{"from": "1.0.0", "to": "2.0.0"}),
        condition=dict(side="current", component="sample", factId="component.sample.removed", value=True)))]}))
    rules_allow = out / "rules-allow.json"
    rules_allow.write_text(json.dumps({"sample.control#enc.control": {"ref": "tracked-variant", "reason": "diagnostic only"}}))
    def rule_command(args, **kwargs):
        path = Path(args[args.index("--input") + 1])
        code = 0 if mode == "rules-pass" and path.stem == "v0" else 10
        return subprocess.CompletedProcess(args, code, "", "")
    with patch.object(q, "SRC", str(source)), patch.object(q, "TMP", str(out / "tmp")), patch.object(
            corpus, "variants", return_value=[dict(id="enc.control", data=b"{}", project=None)]), patch.object(
            subprocess, "run", side_effect=rule_command), patch("sys.argv", ["rules_oracle.py", "--out",
            str(out / "rules.cases.json"), "--allow", str(rules_allow)]):
        runpy.run_path(str(HERE / "rules_oracle.py"), run_name="__main__")
    (out / "other.cases.json").write_text(json.dumps([q.case("bp325", "synthetic-control")]))
    return subprocess.run([sys.executable, str(HERE / "summarize.py"), "--dir", str(out), "--state",
        os.environ["QA_STATE"], "--sha", os.environ["QA_SHA"], "--mode", "incremental", "--adhoc"]).returncode


class PublicationCorrectionTests(unittest.TestCase):
    def test_clean_baseline_and_one_variable_negatives_reach_gate(self):
        for mode, expected in (("clean", 0), ("review-pass", 2), ("rules-pass", 2), ("plan-unknown", 3),
                               ("plan-no-finding", 3), ("plan-wrong-rule", 3), ("plan-wrong-object", 3),
                               ("plan-omitted", 3), ("plan-foreign-input", 3), ("plan-gap", 3),
                               ("plan-empty-stages", 3), ("plan-line-endpoint", 0),
                               ("retained-clean", 0), ("retained-unknown", 3), ("retained-empty-input", 3)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                runner = root / "runner"
                runner.write_text("#!/usr/bin/env python3\nimport sys\nsys.path.insert(0, " + repr(str(HERE)) +
                                  ")\nfrom test_publication_corrections import publication_runner\nraise SystemExit(publication_runner())\n")
                runner.chmod(0o700)
                git = root / "git"
                git.write_text("#!/bin/sh\nexit 0\n")
                git.chmod(0o700)
                env = dict(os.environ, CONTROL=mode, QA_STATE=str(root / "state"), QA_GATE_RUN=str(runner),
                           QA_GATE_TRIES="1", QA_SCOPE_HEAD="a" * 40, QA_PROJECTS="diagnostic-other",
                           PATH=str(root) + ":" + os.environ["PATH"])
                result = subprocess.run([str(HERE / "batch_gate.sh"), "--trust-operator", "a" * 40, "b" * 40],
                                        env=env, text=True, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                out = root / "state/results/control-aaaaaaaa"
                summary = json.loads((out / "summary.json").read_text())
                self.assertEqual(summary["skipped"], [])
                self.assertTrue(summary["scopes"]["crd"]["required"])
                scope = summary["scopes"]["k8s"]
                self.assertIn(PLAN + " overall", scope["requested"])
                self.assertIn(PLAN + " overall", scope["required"])
                calls = json.loads((out / "candidate-calls.json").read_text())
                self.assertEqual(calls[-2][0], "scan")
                self.assertEqual(calls[-1][0], "plan")
                self.assertEqual(calls[-2][1:], calls[-1][1:])
                if mode in ("clean", "review-pass", "rules-pass", "retained-clean", "plan-line-endpoint"):
                    self.assertIn(PLAN + " overall", scope["executed"])
                    self.assertEqual(scope["omitted"], [])
                else:
                    self.assertNotIn(PLAN + " overall", scope["executed"])
                    self.assertTrue(any(item["target"].startswith(PLAN) for item in scope["omitted"]))
                if mode == "review-pass":
                    self.assertEqual(summary["wrongpass"], 1)
                    self.assertEqual(summary["wrongpass_cases"][0]["key"], "R1.store-explicit")
                if mode == "rules-pass":
                    self.assertEqual(summary["wrongpass"], 1)
                    self.assertEqual(summary["wrongpass_cases"][0]["key"], "sample.control#enc.control")
                if expected == 0:
                    self.assertEqual((summary["wrongpass"], summary["mismatch"], summary["errors"]), (0, 0, 0))


if __name__ == "__main__":
    unittest.main()
