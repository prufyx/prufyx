"""Scope admission controls over real Git objects, without upstream or a cluster.

Synthetic envelopes exercise scope projection only. Signature verification remains
the knowledge gate's responsibility; these fixtures are not signed approvals.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import crd_oracle as crd
import qa_batch_scope as batch
import qa_scope


HERE = Path(__file__).resolve().parent
TARGET = "cli/internal/extract/crdversions/target-sample.json"
BATCH = "cli/knowledge/onboarding/ob-20261104-1.json"
BASE_REF = "refs/qa-batch/base"
HEAD_REF = "refs/qa-batch/head"
RUN_ID = "0123456789abcdef0123456789abcdef"


def gate_source(root):
    """A real local remote for gate tests; only candidate/oracle I/O is stubbed."""
    repo = root / "remote"
    repo.mkdir()
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], text=True, stderr=subprocess.PIPE).strip()
    git("init", "-q", "-b", "main")
    git("config", "user.name", "Spas Atanasov")
    git("config", "user.email", "11156623+airstand@users.noreply.github.com")
    target = repo / "cli/internal/extract/crdversions/target-diagnostic-other.json"
    target.parent.mkdir(parents=True)
    target.write_text('{"target":{"repo":"example/diagnostic-other"}}')
    git("add", ".")
    git("commit", "-qm", "Add source fixture")
    base = git("rev-parse", "HEAD")
    (repo / "README.md").write_text("Fixture change\n")
    git("add", ".")
    git("commit", "-qm", "Update source fixture")
    return str(repo), git("rev-parse", "HEAD"), base


def envelope_runner():
    """Real summary and final gate, with only suite execution synthesized."""
    contract = batch.environment_contract()
    mode = os.environ["CONTROL"]
    output = Path(os.environ["QA_STATE"], "results", "control-" + contract["head"][:8])
    output.mkdir(parents=True)
    pairs = batch.required_pairs(contract)
    targets = ["crd-project|" + p for p in contract["projects"]]
    targets += [batch.proof_target(project, pair) for project, pair in pairs]
    scopes = {
        "crd": qa_scope.declare(contract["head"], contract["base"], contract["run_id"], targets, targets, [], qa_scope.CRD_PROFILE),
        "k8s": qa_scope.declare(contract["head"], contract["base"], contract["run_id"], ["k8s-range|synthetic"], [], [])}
    for suite, scope in scopes.items():
        (output / (suite + ".scope.json.declared")).write_text(json.dumps(scope))
        scope.update(executed=list(scope["requested"]), state="COMPLETE")
    cases = [dict(suite=s, key="synthetic", wrongpass=False, mismatch=False, error=False, detail={})
             for s in ("k8s", "bp325", "review", "rules")]
    cases += [dict(suite="crd", key=batch.proof_target(project, pair), wrongpass=False, mismatch=False, error=False,
                   detail=dict(proof_pair=pair, requested=1, executed=1)) for project, pair in pairs]
    scope = scopes["crd"]
    if mode in ("dropped-project", "dropped-pair"):
        target = targets[0 if mode == "dropped-project" else -1]
        for key in ("requested", "required", "executed"):
            scope[key].remove(target)
        scope["declaration_digest"] = qa_scope.digest(scope)
    if mode == "missing-case":
        cases = [c for c in cases if c["suite"] != "crd"]
    if mode == "missing-suite":
        cases = [c for c in cases if c["suite"] != "review"]
    if mode in ("wrongpass", "hidden-wrongpass"):
        cases[-1]["wrongpass"] = True
    if mode == "empty-served":
        cases[-1]["detail"].update(requested=0, executed=0)
    for suite, scope in scopes.items():
        (output / (suite + ".scope.json")).write_text(json.dumps(scope))
    (output / "synthetic.cases.json").write_text(json.dumps(cases))
    if mode == "skipped-suite":
        (output / "skipped.json").write_text('["review"]')
    result = subprocess.run([sys.executable, str(HERE / "summarize.py"), "--dir", str(output),
        "--state", os.environ["QA_STATE"], "--sha", contract["head"], "--mode", "full", "--adhoc"])
    if mode == "changed-contract":
        contract["projects"] = []
        contract["declaration_digest"] = batch.digest(contract)
        Path(os.environ["QA_BATCH_SCOPE_FILE"]).write_text(json.dumps(contract))
    if mode == "hidden-wrongpass":
        path = output / "summary.json"
        summary = json.loads(path.read_text())
        summary.update(wrongpass=0, wrongpass_cases=[])
        path.write_text(json.dumps(summary))
        return 0
    return result.returncode


class BatchScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Spas Atanasov")
        self.git("config", "user.email", "11156623+airstand@users.noreply.github.com")
        self.target = {"schema": "prufyx.io/crd-version-target/v1", "target": {
            "project": "sample", "repo": "example/sample", "tagPrefixes": ["v"],
            "paths": [{"path": "deploy/crds.yaml"}]}}
        raw = self.write(TARGET, self.target)
        self.base = self.commit("Add target fixture")
        self.git("update-ref", BASE_REF, self.base)
        self.project = {"slug": "sample", "kind": "new", "catalog": "community",
            "artifacts": [{"path": TARGET, "digest": "sha256:" + hashlib.sha256(raw).hexdigest()}],
            "facts": ["component.sample.custom_resource_versions_set"], "groups": ["sample.example"],
            "proof": {"pair": {"fromTag": "v1.0.0", "toTag": "v1.1.0",
                "fromCommit": hashlib.sha1(b"upstream source fixture").hexdigest(),
                "toCommit": hashlib.sha1(b"upstream destination fixture").hexdigest()},
                "claims": {"confirmed": 0, "refuted": 0, "undetermined": 0}, "scan": []}}
        self.envelope = {"schema": "prufyx.io/knowledge-onboarding-batch/v2", "record": {
            "batchId": "ob-20261104-1", "projects": [self.project],
            "admissionBinding": {"profile": {"baseCommit": self.base,
                "baseTree": self.git("rev-parse", self.base + "^{tree}").strip()},
                "unsignedCommit": self.base,
                "unsignedTree": self.git("rev-parse", self.base + "^{tree}").strip()}}}

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], text=True,
                                       stderr=subprocess.PIPE)

    def write(self, path, value):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = (json.dumps(value, sort_keys=True) + "\n").encode()
        target.write_bytes(raw)
        return raw

    def commit(self, message):
        self.git("add", ".")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD").strip()

    def candidate(self, envelope=None):
        self.write(BATCH, self.envelope if envelope is None else envelope)
        self.head = self.commit("Add envelope fixture")
        self.git("update-ref", HEAD_REF, self.head)
        self.changed = self.root / "changed"
        self.changed.write_text(self.git("diff", "--name-only", self.base, self.head))

    def select(self, **overrides):
        env = dict(os.environ, QA_BASE=self.base, QA_SHA=self.head, QA_RUN_ID=RUN_ID,
                   QA_SCOPE_BASE_REF=BASE_REF, QA_SCOPE_HEAD_REF=HEAD_REF)
        env.update(overrides)
        result = subprocess.run([sys.executable, "-I", str(HERE / "select_projects.py"),
            "--changed", str(self.changed), "--src", str(self.repo)], env=env,
            capture_output=True, text=True, timeout=10)
        return result, json.loads(result.stdout) if result.returncode == 0 else None

    def test_v2_record_projects_and_exact_pair_enter_frozen_scope(self):
        self.candidate()
        result, selected = self.select()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sample", selected["projects"], "v2 record.projects disappeared")
        contract = selected["batch_scope"]
        self.assertEqual((contract["head"], contract["base"], contract["run_id"]),
                         (self.head, self.base, RUN_ID))
        self.assertEqual(contract["envelopes"][0]["projects"][0]["proof"]["pair"],
                         self.project["proof"]["pair"])
        self.assertEqual(contract["envelopes"][0]["blob"], self.git("rev-parse", self.head + ":" + BATCH).strip())

    def test_uncommitted_envelope_cannot_replace_fetched_scope(self):
        self.candidate()
        forged = copy.deepcopy(self.envelope)
        forged["record"]["projects"][0]["slug"] = "unrelated"
        self.write(BATCH, forged)
        result, selected = self.select()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sample", selected["projects"])
        self.assertNotIn("unrelated", selected["projects"])

    def test_missing_or_unknown_fixed_ref_provenance_blocks(self):
        self.candidate()
        for change in ({"QA_SCOPE_HEAD_REF": ""}, {"QA_SCOPE_BASE_REF": "refs/absent"},
                       {"QA_SHA": self.base}, {"QA_BASE": self.head}, {"QA_RUN_ID": ""}):
            with self.subTest(change=change):
                result, _ = self.select(**change)
                self.assertEqual(result.returncode, 3, result.stdout + result.stderr)

    def test_caller_changed_list_cannot_hide_signed_envelope(self):
        self.candidate()
        self.changed.write_text("")
        result, _ = self.select()
        self.assertEqual(result.returncode, 3, "caller diff disagrees with fixed Git refs: " + result.stdout)

    def test_unsupported_or_malformed_envelope_is_typed_block(self):
        for mode in ("schema", "empty", "duplicate", "kind", "artifact", "digest", "pair"):
            with self.subTest(mode=mode):
                envelope = copy.deepcopy(self.envelope)
                project = envelope["record"]["projects"][0]
                if mode == "schema":
                    envelope["schema"] = "prufyx.io/knowledge-onboarding-batch/v999"
                elif mode == "empty":
                    envelope["record"]["projects"] = []
                elif mode == "duplicate":
                    envelope["record"]["projects"].append(copy.deepcopy(project))
                elif mode == "kind":
                    project["kind"] = "unsupported"
                elif mode == "artifact":
                    project["artifacts"][0]["path"] = TARGET.replace("sample", "other")
                elif mode == "digest":
                    project["artifacts"][0]["digest"] = "sha256:" + hashlib.sha256(b"other").hexdigest()
                else:
                    del project["proof"]["pair"]["fromCommit"]
                self.candidate(envelope)
                result, _ = self.select()
                self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
                self.assertIn("SCOPE", result.stderr)

    def test_missing_required_target_is_not_excluded(self):
        self.git("rm", TARGET)
        self.candidate()
        result, _ = self.select()
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("UNSUPPORTED_SCOPE", result.stderr)

    def test_target_mode_and_nonobject_envelope_block(self):
        (self.repo / TARGET).chmod(0o755)
        self.candidate()
        result, _ = self.select()
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("nonregular artifact", result.stderr)
        (self.repo / TARGET).chmod(0o644)
        self.candidate([])
        result, _ = self.select()
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)

    def test_new_v1_scope_fails_closed(self):
        envelope = copy.deepcopy(self.envelope)
        envelope["schema"] = "prufyx.io/knowledge-onboarding-batch/v1"
        del envelope["record"]["admissionBinding"]
        envelope["record"]["projects"][0]["kind"] = "attest"
        self.candidate(envelope)
        result, selected = self.select()
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)

    def test_non_onboarding_diff_keeps_existing_target_selection(self):
        self.target["target"]["paths"] = [{"path": "deploy/other.yaml"}]
        self.write(TARGET, self.target)
        self.head = self.commit("Change target fixture")
        self.git("update-ref", HEAD_REF, self.head)
        self.changed = self.root / "changed"
        self.changed.write_text(self.git("diff", "--name-only", self.base, self.head))
        result, selected = self.select()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(selected["projects"], ["sample"])

    def test_duplicate_json_members_and_v2_attest_block(self):
        self.envelope["record"]["projects"][0]["kind"] = "attest"
        self.candidate()
        result, _ = self.select()
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.envelope["record"]["projects"][0]["kind"] = "new"
        raw = json.dumps(self.envelope).replace('"projects":', '"projects": [], "projects":', 1)
        (self.repo / BATCH).write_text(raw)
        self.head = self.commit("Duplicate member fixture")
        self.git("update-ref", HEAD_REF, self.head)
        result, _ = self.select()
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("duplicate JSON", result.stderr)

    def test_full_scope_and_diagnostic_additions_preserve_required_projects(self):
        path = TARGET.replace("sample", "extra")
        target = copy.deepcopy(self.target)
        target["target"]["project"] = "extra"
        self.write(path, target)
        self.candidate()
        result, selected = self.select(QA_PROJECTS="extra")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(selected["projects"], ["extra", "sample"])
        self.assertEqual(selected["batch_scope"]["kind"], "not_executed")
        self.assertEqual(selected["batch_scope"]["db"], "not_executed")

    def test_final_validation_rejects_project_pair_case_and_declaration_loss(self):
        self.candidate()
        contract = batch.freeze(self.repo, self.head, self.base, RUN_ID)
        pair = self.project["proof"]["pair"]
        exact = batch.proof_target("sample", pair)
        targets = ["crd-project|sample", exact]
        crd_scope = qa_scope.declare(self.head, self.base, RUN_ID, targets, targets, [], qa_scope.CRD_PROFILE)
        crd_scope.update(executed=targets, state="COMPLETE")
        k8s_scope = qa_scope.declare(self.head, self.base, RUN_ID, ["k8s-range|synthetic"], [], [])
        k8s_scope.update(executed=["k8s-range|synthetic"], state="COMPLETE")
        original = dict(crd=crd_scope, k8s=k8s_scope)
        cases = [dict(suite=s, key="synthetic", wrongpass=False, mismatch=False, error=False, detail={})
                 for s in ("k8s", "bp325", "review", "rules")]
        cases.append(dict(suite="crd", key=exact, wrongpass=False, mismatch=False, error=False,
                          detail=dict(proof_pair=pair, requested=1, executed=1)))
        self.assertEqual(batch.validate(contract, original, cases, original), [])
        for mode in ("project", "pair", "case", "duplicate-case", "omitted", "wrong-pair",
                     "empty", "excluded", "suite", "self-hash", "head", "base", "run"):
            with self.subTest(mode=mode):
                scopes, altered = copy.deepcopy(original), copy.deepcopy(cases)
                scope = scopes["crd"]
                if mode in ("project", "pair"):
                    target = targets[0 if mode == "project" else 1]
                    for key in ("requested", "required", "executed"):
                        scope[key].remove(target)
                    scope["declaration_digest"] = qa_scope.digest(scope)
                elif mode == "case":
                    altered.pop()
                elif mode == "duplicate-case":
                    altered.append(copy.deepcopy(altered[-1]))
                elif mode == "omitted":
                    scope["omitted"] = [{"target": exact, "reason": "failed"}]
                elif mode == "wrong-pair":
                    altered[-1]["detail"]["proof_pair"]["toCommit"] = self.base
                elif mode == "empty":
                    altered[-1]["detail"].update(requested=0, executed=0)
                elif mode == "excluded":
                    scope["executed"].remove(exact)
                    scope["excluded"] = [dict(target=exact, reason="empty", next_test="read source", evidence="complete served-set read: empty")]
                    scope["declaration_digest"] = qa_scope.digest(scope)
                elif mode == "suite":
                    altered = [c for c in altered if c["suite"] != "review"]
                elif mode == "self-hash":
                    scope["requested"].append("crd-project|unrelated")
                    scope["executed"].append("crd-project|unrelated")
                    scope["declaration_digest"] = qa_scope.digest(scope)
                else:
                    scope[{"head": "head", "base": "base", "run": "run_id"}[mode]] = "different"
                    scope["declaration_digest"] = qa_scope.digest(scope)
                self.assertTrue(batch.validate(contract, scopes, altered, original))

    def test_parent_digest_rejects_changed_contract_with_recomputed_self_hash(self):
        self.candidate()
        contract = batch.freeze(self.repo, self.head, self.base, RUN_ID)
        path = self.root / "frozen.json"
        expected = batch.digest(contract)
        contract["projects"] = []
        contract["declaration_digest"] = batch.digest(contract)
        path.write_text(json.dumps(contract))
        with patch.dict(os.environ, QA_BATCH_SCOPE_FILE=str(path), QA_BATCH_SCOPE_DIGEST=expected):
            with self.assertRaisesRegex(ValueError, "trusted parent"):
                batch.environment_contract()

    def test_interior_proof_pair_uses_pinned_commits_and_moved_tag_blocks(self):
        upstream = self.root / "git" / "sample.git"
        upstream.mkdir(parents=True)
        def git(*args):
            return subprocess.check_output(["git", "-C", str(upstream), *args], text=True, stderr=subprocess.PIPE).strip()
        git("init", "-q")
        git("config", "user.name", "Spas Atanasov")
        git("config", "user.email", "11156623+airstand@users.noreply.github.com")
        pins = {}
        for minor in (0, 1):
            for patch_number in (0, 1, 2):
                tag = f"v1.{minor}.{patch_number}"
                (upstream / "deploy").mkdir(exist_ok=True)
                (upstream / "deploy/crds.yaml").write_text(tag + "\n")
                git("add", ".")
                git("commit", "-qm", "Source fixture " + tag)
                pins[tag] = git("rev-parse", "HEAD")
                git("tag", "-a", tag, "-m", tag)
        pair = dict(fromTag="v1.0.1", fromCommit=pins["v1.0.1"], toTag="v1.1.1", toCommit=pins["v1.1.1"])
        self.project["proof"]["pair"] = pair
        self.candidate()
        contract = batch.freeze(self.repo, self.head, self.base, RUN_ID)
        binding = contract["envelopes"][0]["projects"][0]
        exact = batch.proof_target("sample", pair)
        reads = []
        def served(target, repo, ref):
            reads.append(ref)
            text = crd.crd_text(target, repo, ref)
            self.assertIn("v1.", text)
            return {("sample.example", "v1", "Widget")}
        original_sh = crd.sh
        def source(*args, **kwargs):
            if "fetch" in args:
                return subprocess.CompletedProcess(args, 0, "", "")
            return original_sh(*args, **kwargs)
        def plan():
            value = crd.new_plan()
            value.update(binding=binding, proof_pairs={exact: pair})
            value["requested"].add(exact)
            return value
        with patch.object(crd, "GITROOT", str(upstream.parent)), patch.object(crd, "sh", side_effect=source), patch.object(
                crd, "served_set", side_effect=served):
            value = plan()
            crd.prepare("sample", [], value)
            self.assertIn(exact, [job[0] for job in value["jobs"]])
            self.assertIn(pair["fromCommit"], reads)
            self.assertIn(pair["toCommit"], reads)
            self.assertNotIn(pair["fromTag"], reads)
            self.assertNotIn(pair["toTag"], reads)
            report = dict(verdict="UNKNOWN", paths=[], findings=[], summary=dict(documentsRead=1, documentsOmitted=0), omitted=[])
            with patch.object(crd, "TMP", str(self.root / "tmp")), patch.object(crd, "prufyx", return_value=(11, report, "")):
                cases, completed, omitted = crd.execute(value)
            self.assertIn(exact, completed)
            self.assertEqual([c["detail"]["proof_pair"] for c in cases if c["key"] == exact], [pair])
            self.assertEqual(omitted, [])
            with patch.object(crd, "served_set", side_effect=lambda target, repo, ref: set() if ref == pair["fromCommit"] else {("sample.example", "v1", "Widget")}):
                with self.assertRaisesRegex(ValueError, "served set empty"):
                    crd.prepare("sample", [], plan())
            git("tag", "-f", pair["fromTag"], pins["v1.0.2"])
            with self.assertRaisesRegex(ValueError, "tag moved"):
                crd.prepare("sample", [], plan())

    def test_v2_contract_reaches_actual_summary_and_final_gate(self):
        self.candidate()
        self.git("update-ref", "refs/heads/main", self.base)
        runner = self.root / "runner"
        runner.write_text("#!/usr/bin/env python3\nimport sys\nsys.path.insert(0, " + repr(str(HERE)) +
                          ")\nfrom test_batch_envelope_scope import envelope_runner\nraise SystemExit(envelope_runner())\n")
        runner.chmod(0o700)
        for mode, expected in (("clean", 0), ("dropped-project", 3), ("dropped-pair", 3),
                               ("missing-case", 3), ("missing-suite", 3), ("empty-served", 3),
                               ("skipped-suite", 3), ("changed-contract", 3),
                               ("wrongpass", 2), ("hidden-wrongpass", 2)):
            with self.subTest(mode=mode):
                state = self.root / (mode + "-state")
                env = dict(os.environ, CONTROL=mode, QA_REPO_URL=str(self.repo), QA_STATE=str(state),
                           QA_GATE_RUN=str(runner), QA_GATE_TRIES="1")
                result = subprocess.run([str(HERE / "batch_gate.sh"), "--trust-operator", self.head, self.base],
                                        env=env, text=True, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                if expected == 0:
                    receipt = json.loads((state / "gate" / (self.head + ".json")).read_text())
                    self.assertEqual(receipt["kind"], "not_executed")
                    self.assertEqual(receipt["db"], "not_executed")


if __name__ == "__main__":
    unittest.main()
