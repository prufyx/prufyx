"""Regression tests for the RFC-0007 corpus boundary."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
sys.path.insert(0, str(ROOT))
import validate  # noqa: E402


class CorpusValidationTests(unittest.TestCase):
    def test_validator_accepts_from_repo_and_corpus_directories(self):
        command = [sys.executable, "-B", str(ROOT / "validate.py")]
        for cwd in (REPO, ROOT):
            result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("scenarios=18", result.stdout)
            self.assertIn("refs=RFC-0007-DSL", result.stdout)

    def test_duplicate_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_bytes(b'{"id":"one","id":"two"}\n')
            with self.assertRaises(validate.ValidationError):
                validate.read_json(path)

    def test_all_scenarios_and_oracles_are_canonical(self):
        index, facts_doc, sources_doc, freshness, revision, registry = validate.load_inputs()
        facts, registered = validate.predicate_maps(facts_doc, registry)
        self.assertEqual(len(index["scenarioRefs"]), 18)
        for ref in index["scenarioRefs"]:
            scenario = validate.read_json(ROOT / ref["scenarioPath"])
            oracle = validate.read_json(ROOT / ref["oraclePath"])
            validate.check_scenario(scenario, facts, registered)
            validate.check_oracle(oracle, scenario, ref, "sha256:" + __import__("hashlib").sha256((ROOT / ref["scenarioPath"]).read_bytes()).hexdigest())
            self.assertEqual(scenario["schema"], "prufyx.io/synthetic-snapshot-factory/scenario/v4")
            self.assertEqual(oracle["schema"], "prufyx.io/synthetic-snapshot-factory/expected-oracle/v4")

    def test_every_committed_json_document_is_canonical(self):
        for path in ROOT.rglob("*.json"):
            self.assertEqual(path.read_bytes(), validate.canonical(validate.read_json(path)), path)

    def test_replay_bridge_gate_pins_v3_and_marks_external_authority(self):
        index, *_ = validate.load_inputs()
        validate.check_replay_bridge_gate(index, [ref["scenarioId"] for ref in index["scenarioRefs"]])
        gate = validate.read_json(ROOT / "replay-bridge-gate.json")
        self.assertEqual(gate["generation"]["status"], "CORPUS_VALIDATED_FACTORY_INTEGRATION_PENDING")
        self.assertEqual(gate["import"]["status"], "EXTERNAL_IMPLEMENTATION_REQUIRED")
        self.assertEqual(gate["projection"]["status"], "EXTERNAL_IMPLEMENTATION_REQUIRED")
        self.assertEqual(gate["testOnlyEvaluator"]["packageUnknown"], "NOT_ASSESSED")

    def test_schema_predicate_enums_are_exact_and_reject_unreviewed_ids(self):
        expected = set(validate.REVIEWED_PREDICATE_IDS)
        scenario_schema = validate.read_json(ROOT / "schema/scenario.schema.json")
        oracle_schema = validate.read_json(ROOT / "schema/expected-oracle.schema.json")
        index_schema = validate.read_json(ROOT / "schema/corpus-index.schema.json")
        self.assertEqual(set(scenario_schema["$defs"]["predicateId"]["enum"]), expected)
        self.assertEqual(set(oracle_schema["$defs"]["predicateId"]["enum"]), expected)
        self.assertEqual(set(index_schema["$defs"]["predicate"]["enum"]), expected)
        profiles = set(scenario_schema["properties"]["contractPins"]["properties"]["evaluatorProfile"]["enum"])
        self.assertEqual(profiles, {"NONE", "DECISION_BRANCH_COVERAGE_ONLY"})
        self.assertNotIn("component.argo_cd.unreviewed_predicate", expected)

    def test_v3_schema_ids_are_unique_and_all_object_contracts_are_closed(self):
        schema_files = sorted((ROOT / "schema").glob("*.schema.json"))
        ids = [validate.read_json(path)["$id"] for path in schema_files]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(identifier.endswith("/v3") for identifier in ids))

        def walk(value):
            if isinstance(value, dict):
                if value.get("type") == "object" and "properties" in value and "additionalProperties" in value:
                    self.assertFalse(value["additionalProperties"], value)
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        for path in schema_files:
            walk(validate.read_json(path))

    def test_well_formed_but_unreviewed_predicate_id_is_rejected(self):
        index, facts_doc, sources_doc, _, _, registry = validate.load_inputs()
        facts, registered = validate.predicate_maps(facts_doc, registry)
        scenario = validate.read_json(ROOT / "scenarios/syn-v4-no-op-latest-all-components.json")
        mutated = copy.deepcopy(scenario)
        predicate = next(p for c in mutated["snapshot"]["components"] for p in c["predicates"] if p["predicateId"] == "component.argo_cd.insecure_server_enabled")
        predicate["predicateId"] = "component.argo_cd.unreviewed_predicate"
        with self.assertRaises(validate.ValidationError):
            validate.check_scenario(mutated, facts, registered)

    def test_predicate_source_binding_mutation_is_rejected(self):
        index, facts_doc, sources_doc, _, _, registry = validate.load_inputs()
        mutated = copy.deepcopy(index)
        binding = next(x for x in mutated["predicateBindings"] if x["predicateId"] == "component.argo_cd.repo_server_configured")
        binding["sourceReceiptIds"] = ["argo-cd-v3.5.2-repo-server-reference"]
        with self.assertRaises(validate.ValidationError):
            validate.check_predicate_bindings(mutated, facts_doc, registry, sources_doc)

    def test_version_receipt_component_mutation_is_rejected(self):
        index, facts_doc, sources_doc, freshness, _, registry = validate.load_inputs()
        facts, registered = validate.predicate_maps(facts_doc, registry)
        ref = next(x for x in index["scenarioRefs"] if x["scenarioId"] == "syn-v4-argo-cd-minor-to-latest")
        scenario = validate.read_json(ROOT / ref["scenarioPath"])
        oracle = validate.read_json(ROOT / ref["oraclePath"])
        mutated = copy.deepcopy(ref)
        row = next(x for x in mutated["versionMatrix"] if x["componentId"] == "pkg:oci/argoproj/argo-cd")
        row["sourceIds"] = ["prometheus-v3.14.0-release-api"]
        with self.assertRaises(validate.ValidationError):
            validate.check_ref(mutated, scenario, oracle, facts, registered, sources_doc, freshness, index)

    def test_version_receipt_wrong_or_missing_release_is_rejected(self):
        index, facts_doc, sources_doc, freshness, _, registry = validate.load_inputs()
        facts, registered = validate.predicate_maps(facts_doc, registry)
        ref = next(x for x in index["scenarioRefs"] if x["scenarioId"] == "syn-v4-argo-cd-minor-to-latest")
        scenario = validate.read_json(ROOT / ref["scenarioPath"])
        oracle = validate.read_json(ROOT / ref["oraclePath"])
        mutated = copy.deepcopy(ref)
        row = next(x for x in mutated["versionMatrix"] if x["componentId"] == "pkg:oci/argoproj/argo-cd")
        row["sourceIds"] = ["argo-cd-v3.5.2-release-api"]
        with self.assertRaises(validate.ValidationError):
            validate.check_ref(mutated, scenario, oracle, facts, registered, sources_doc, freshness, index)

    def test_snapshot_exact_version_must_match_matrix(self):
        index, facts_doc, sources_doc, freshness, _, registry = validate.load_inputs()
        facts, registered = validate.predicate_maps(facts_doc, registry)
        ref = next(x for x in index["scenarioRefs"] if x["scenarioId"] == "syn-v4-argo-cd-minor-to-latest")
        scenario = validate.read_json(ROOT / ref["scenarioPath"])
        oracle = validate.read_json(ROOT / ref["oraclePath"])
        mutated = copy.deepcopy(scenario)
        component = next(c for c in mutated["snapshot"]["components"] if c["componentId"] == "pkg:oci/argoproj/argo-cd")
        component["version"] = "9.9.9"
        with self.assertRaises(validate.ValidationError):
            validate.check_ref(ref, mutated, oracle, facts, registered, sources_doc, freshness, index)

    def test_snapshot_unknown_version_state_must_match_matrix(self):
        index, facts_doc, sources_doc, freshness, _, registry = validate.load_inputs()
        facts, registered = validate.predicate_maps(facts_doc, registry)
        ref = next(x for x in index["scenarioRefs"] if x["scenarioId"] == "syn-v4-argo-cd-minor-to-latest")
        scenario = validate.read_json(ROOT / ref["scenarioPath"])
        oracle = validate.read_json(ROOT / ref["oraclePath"])
        mutated = copy.deepcopy(scenario)
        component = next(c for c in mutated["snapshot"]["components"] if c["componentId"] == "pkg:oci/argoproj/argo-cd")
        component.pop("version")
        component["versionState"] = "unknown"
        with self.assertRaises(validate.ValidationError):
            validate.check_ref(ref, mutated, oracle, facts, registered, sources_doc, freshness, index)

    def test_snapshot_conflict_values_must_match_matrix(self):
        index, facts_doc, sources_doc, freshness, _, registry = validate.load_inputs()
        facts, registered = validate.predicate_maps(facts_doc, registry)
        ref = next(x for x in index["scenarioRefs"] if x["scenarioId"] == "syn-v4-conflicting-argo-cd-versions")
        scenario = validate.read_json(ROOT / ref["scenarioPath"])
        oracle = validate.read_json(ROOT / ref["oraclePath"])
        mutated = copy.deepcopy(scenario)
        component = next(c for c in mutated["snapshot"]["components"] if c["componentId"] == "pkg:oci/argoproj/argo-cd")
        component["conflictingVersions"] = ["3.5.1", "3.4.8"]
        with self.assertRaises(validate.ValidationError):
            validate.check_ref(ref, mutated, oracle, facts, registered, sources_doc, freshness, index)
        mutated = copy.deepcopy(ref)
        row = next(x for x in mutated["versionMatrix"] if x["componentId"] == "pkg:oci/argoproj/argo-cd")
        row["sourceIds"] = row["sourceIds"] + [row["sourceIds"][0]]
        with self.assertRaises(validate.ValidationError):
            validate.check_ref(mutated, scenario, oracle, facts, registered, sources_doc, freshness, index)

    def test_predicate_role_scope_mutation_is_rejected(self):
        index, facts_doc, sources_doc, _, _, registry = validate.load_inputs()
        facts, registered = validate.predicate_maps(facts_doc, registry)
        scenario = validate.read_json(ROOT / "scenarios/syn-v4-exact-context-match-non-authoritative.json")
        mutated = copy.deepcopy(scenario)
        predicate = next(p for c in mutated["snapshot"]["components"] for p in c["predicates"] if p["predicateId"] == "component.argo_cd.insecure_server_enabled")
        predicate["sourceRole"] = "repo-server"
        with self.assertRaises(validate.ValidationError):
            validate.check_scenario(mutated, facts, registered)

    def test_pinned_fact_role_scope_mutation_is_rejected(self):
        index, facts_doc, sources_doc, _, _, registry = validate.load_inputs()
        for predicate_id, replacement in {
            "component.argo_cd.insecure_server_enabled": ["repo-server"],
            "component.argo_workflows.managed_namespace_configured": ["argo-server"],
            "component.cert_manager.owner_ref_enabled": ["webhook"],
            "component.prometheus.log_level": ["server"],
        }.items():
            mutated = copy.deepcopy(facts_doc)
            fact = next(x for x in mutated["facts"] if x.get("predicate", {}).get("predicateId") == predicate_id)
            fact["predicate"]["roleScope"] = replacement
            with self.assertRaises(validate.ValidationError):
                validate.check_predicate_bindings(index, mutated, registry, sources_doc)

    def test_normalized_index_role_binding_mutation_is_rejected(self):
        index, facts_doc, sources_doc, _, _, registry = validate.load_inputs()
        mutated = copy.deepcopy(index)
        binding = next(x for x in mutated["predicateBindings"] if x["predicateId"] == "component.prometheus.log_level")
        binding["sourceRole"] = "controller"
        with self.assertRaises(validate.ValidationError):
            validate.check_predicate_bindings(mutated, facts_doc, registry, sources_doc)

    def test_source_revision_mutation_is_rejected(self):
        index, facts_doc, sources_doc, freshness, _, registry = validate.load_inputs()
        facts, registered = validate.predicate_maps(facts_doc, registry)
        ref = index["scenarioRefs"][0]
        scenario = validate.read_json(ROOT / ref["scenarioPath"])
        oracle = validate.read_json(ROOT / ref["oraclePath"])
        mutated = copy.deepcopy(scenario)
        mutated["contractPins"]["sourceRevision"] = "2026-09-01-community-v3"
        with self.assertRaises(validate.ValidationError):
            validate.check_scenario(mutated, facts, registered)
        mutated_oracle = copy.deepcopy(oracle)
        mutated_oracle["sourceRevision"] = "2026-09-01-community-v3"
        with self.assertRaises(validate.ValidationError):
            validate.check_oracle(mutated_oracle, scenario, ref, ref["scenarioDigest"])
        mutated_index = copy.deepcopy(index)
        mutated_index["sourceRevision"] = "2026-09-01-community-v3"
        with self.assertRaises(validate.ValidationError):
            validate.check_source_revision(mutated_index["sourceRevision"], "corpus-index")

    def test_oracle_reason_action_mutation_is_rejected(self):
        index, facts_doc, sources_doc, freshness, _, registry = validate.load_inputs()
        facts, registered = validate.predicate_maps(facts_doc, registry)
        ref = next(x for x in index["scenarioRefs"] if x["scenarioId"] == "syn-v4-exact-context-match-non-authoritative")
        scenario = validate.read_json(ROOT / ref["scenarioPath"])
        oracle = validate.read_json(ROOT / ref["oraclePath"])
        mutated = copy.deepcopy(ref)
        mutated["bridge"]["predicateOutcomes"][0]["nextAction"] = "claim compatibility"
        with self.assertRaises(validate.ValidationError):
            validate.check_ref(mutated, scenario, oracle, facts, registered, sources_doc, freshness, index)

    def test_manifest_source_revision_binding_is_rejected_on_drift(self):
        index, facts_doc, sources_doc, freshness, _, registry = validate.load_inputs()
        facts, registered = validate.predicate_maps(facts_doc, registry)
        ref = next(x for x in index["scenarioRefs"] if x["scenarioId"] == "syn-v4-no-op-latest-all-components")
        scenario = validate.read_json(ROOT / ref["scenarioPath"])
        oracle = validate.read_json(ROOT / ref["oraclePath"])
        mutated = copy.deepcopy(ref)
        mutated["bridge"]["manifestExpectation"]["compilerSourceRevision"] = "synthetic-local"
        with self.assertRaises(validate.ValidationError):
            validate.check_ref(mutated, scenario, oracle, facts, registered, sources_doc, freshness, index)

    def test_independent_oracle_carries_reason_and_next_action(self):
        index, *_ = validate.load_inputs()
        ref = next(x for x in index["scenarioRefs"] if x["scenarioId"] == "syn-v4-config-mismatch-attention")
        oracle = validate.read_json(ROOT / ref["oraclePath"])
        rows = oracle["evaluator"]["predicateOutcomes"]
        self.assertTrue(all(row["reason"] and row["nextAction"] for row in rows))
        self.assertIn(oracle["rejectionClass"], {"NONE", "FRESHNESS", "CONFLICT", "INTEGRITY"})

    def test_every_evaluator_oracle_authors_package_reason_class(self):
        index, *_ = validate.load_inputs()
        evaluated = 0
        preflight = 0
        for ref in index["scenarioRefs"]:
            oracle = validate.read_json(ROOT / ref["oraclePath"])
            if oracle["evaluator"] is None:
                preflight += 1
                self.assertIsNone(oracle["packageUnknown"])
            else:
                evaluated += 1
                self.assertEqual(oracle["packageUnknown"]["reasonClass"], "PACKAGE_TAKEDOWN_NOT_ASSESSED")
        self.assertEqual((evaluated, preflight), (16, 2))

    def test_package_reason_class_missing_changed_or_extra_fails_closed(self):
        index, *_ = validate.load_inputs()
        ref = next(x for x in index["scenarioRefs"] if x["scenarioId"] == "syn-v4-argo-cd-minor-to-latest")
        package = validate.read_json(ROOT / ref["oraclePath"])["packageUnknown"]
        for mutation in ("missing", "changed", "extra"):
            candidate = copy.deepcopy(package)
            if mutation == "missing":
                del candidate["reasonClass"]
            elif mutation == "changed":
                candidate["reasonClass"] = "MISSING_OR_UNSUPPORTED_CONTEXT"
            else:
                candidate["reasonClass"] = "PACKAGE_TAKEDOWN_NOT_ASSESSED"
                candidate["unreviewedField"] = True
            with self.assertRaises(validate.ValidationError, msg=mutation):
                validate.check_package_unknown(candidate, f"packageUnknown.{mutation}")

    def test_mutation_recipe_is_outside_valid_scenario_loading(self):
        index, *_ = validate.load_inputs()
        self.assertEqual(len(index["mutationRecipes"]), 1)
        recipe = validate.read_json(ROOT / index["mutationRecipes"][0]["path"])
        self.assertEqual(recipe["targetRole"], "ROOT_MANIFEST")
        self.assertEqual(recipe["expectedImport"], {"outcome": "REJECT", "reasonClass": "INTEGRITY"})

    def test_tampered_baseline_current_expectation_matches_declared_snapshot(self):
        scenario = validate.read_json(ROOT / "scenarios/syn-v4-tampered-source-binding-baseline.json")
        current = scenario["expectations"]["currentBundle"]
        self.assertEqual(current["authority"], "LOCAL_MANIFEST_INTEGRITY_ONLY")
        self.assertFalse(current["evaluationEligible"])
        self.assertEqual(current["requiredOmissionCodes"], [])
        self.assertEqual(
            [(row["componentId"], row["versionState"], row["version"]) for row in current["componentStates"]],
            [(component["componentId"], "exact", component["version"]) for component in scenario["snapshot"]["components"]],
        )

    def test_valid_scenario_with_null_current_expectation_is_rejected(self):
        index, facts_doc, _, _, _, registry = validate.load_inputs()
        facts, registered = validate.predicate_maps(facts_doc, registry)
        scenario = validate.read_json(ROOT / "scenarios/syn-v4-tampered-source-binding-baseline.json")
        mutated = copy.deepcopy(scenario)
        mutated["expectations"]["currentBundle"] = None
        with self.assertRaises(validate.ValidationError):
            validate.check_scenario(mutated, facts, registered)

    def test_tampered_baseline_oracle_current_null_or_value_is_rejected(self):
        index, facts_doc, _, _, _, registry = validate.load_inputs()
        facts, registered = validate.predicate_maps(facts_doc, registry)
        ref = next(x for x in index["scenarioRefs"] if x["scenarioId"] == "syn-v4-tampered-source-binding-baseline")
        scenario = validate.read_json(ROOT / ref["scenarioPath"])
        oracle = validate.read_json(ROOT / ref["oraclePath"])
        for current in (None, {**oracle["currentBundle"], "componentStates": [{**oracle["currentBundle"]["componentStates"][0], "version": "9.9.9"}] + oracle["currentBundle"]["componentStates"][1:]}):
            mutated = copy.deepcopy(oracle)
            mutated["currentBundle"] = current
            body = dict(mutated)
            body.pop("oracleDigest")
            mutated["oracleDigest"] = "sha256:" + __import__("hashlib").sha256(validate.canonical(body)).hexdigest()
            with self.assertRaises(validate.ValidationError):
                validate.check_oracle(mutated, scenario, ref, ref["scenarioDigest"])

    def test_freshness_expiry_is_half_open_and_stale_case_is_rejected(self):
        index, facts_doc, sources_doc, freshness, _, registry = validate.load_inputs()
        ref = next(x for x in index["scenarioRefs"] if x["scenarioId"] == "syn-v4-no-op-latest-all-components")
        at_expiry = copy.deepcopy(ref["bridge"])
        at_expiry["freshness"]["now"] = freshness["expiresAfter"]
        with self.assertRaises(validate.ValidationError):
            validate.check_freshness(freshness, at_expiry)
        stale = next(x for x in index["scenarioRefs"] if x["scenarioId"] == "syn-v4-stale-observation-negative")
        self.assertEqual(stale["bridge"]["expectedRejectionClass"], "FRESHNESS")
        validate.check_freshness(freshness, stale["bridge"])

    def test_fleet_digest_comes_from_semantic_projection(self):
        index, *_ = validate.load_inputs()
        docs = {ref["scenarioId"]: validate.read_json(ROOT / ref["scenarioPath"]) for ref in index["scenarioRefs"]}
        refs = {ref["scenarioId"]: ref for ref in index["scenarioRefs"]}
        a, b, c = (refs[key] for key in ("syn-v4-fleet-equivalence-member-a", "syn-v4-fleet-equivalence-member-b", "syn-v4-fleet-non-equivalent-config"))
        self.assertEqual(validate.fleet_digest(docs[a["scenarioId"]], a), validate.fleet_digest(docs[b["scenarioId"]], b))
        self.assertNotEqual(validate.fleet_digest(docs[a["scenarioId"]], a), validate.fleet_digest(docs[c["scenarioId"]], c))
        self.assertEqual(a["bridge"]["fleet"]["reuseExpectation"], "REUSE_EXACT_MATCH")
        self.assertEqual(c["bridge"]["fleet"]["reuseExpectation"], "DO_NOT_REUSE_DIFFERENT_PROFILE")


if __name__ == "__main__":
    unittest.main()
