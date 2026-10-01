#!/usr/bin/env python3
"""Offline validator for the RFC-0007 public-synthetic scenario corpus."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[2]
REVISION = REPO / "knowledge" / "revisions" / "2026-09-01-community-v3"
REGISTRY = REPO / "cli" / "scripts" / "component-configuration-adapters.json"
SOURCE_REVISION = "synthetic-snapshot-factory-v4"
V1_ROOT = REPO / "testdata" / "synthetic-cluster-scenarios" / "v1"
V2_ROOT = REPO / "testdata" / "synthetic-cluster-scenarios" / "v2"
V2_TREE_DIGEST = "sha256:cc7ec9ff7b5b24f0059e06c2b1af51c14fa64eff1cd22009bfa7282b2e9aff81"
V1_TREE_DIGEST = "sha256:e476288b5865e4ba52c4c35d7649d1059ce48f1d7861e61fd77653c7a03f3e0a"
COMPONENTS = {
    "pkg:oci/argoproj/argo-cd",
    "pkg:oci/argoproj/argo-workflows",
    "pkg:oci/cert-manager/cert-manager",
    "pkg:oci/prometheus/prometheus",
}
REVIEWED_PREDICATE_IDS = {
    "component.argo_cd.insecure_server_enabled",
    "component.argo_cd.repo_server_configured",
    "component.argo_workflows.namespaced_mode",
    "component.argo_workflows.managed_namespace_configured",
    "component.cert_manager.dns01_recursive_nameservers_configured",
    "component.cert_manager.feature_gate_acme_use_ari",
    "component.cert_manager.feature_gate_ca_injector_merging",
    "component.cert_manager.feature_gate_certificate_request_controllers",
    "component.cert_manager.feature_gate_experimental_gateway_api_support",
    "component.cert_manager.feature_gate_listener_sets",
    "component.cert_manager.feature_gate_other_names",
    "component.cert_manager.feature_gate_server_side_apply",
    "component.cert_manager.owner_ref_enabled",
    "component.prometheus.log_level",
    "component.prometheus.web_admin_api_enabled",
    "component.prometheus.web_lifecycle_enabled",
}
PREDICATE_ROLE = {
    "component.argo_cd.insecure_server_enabled": "server",
    "component.argo_cd.repo_server_configured": "repo-server",
    "component.argo_workflows.managed_namespace_configured": "workflow-controller",
    "component.argo_workflows.namespaced_mode": "workflow-controller",
    "component.cert_manager.dns01_recursive_nameservers_configured": "controller",
    "component.cert_manager.feature_gate_acme_use_ari": "controller",
    "component.cert_manager.feature_gate_ca_injector_merging": "controller",
    "component.cert_manager.feature_gate_certificate_request_controllers": "controller",
    "component.cert_manager.feature_gate_experimental_gateway_api_support": "controller",
    "component.cert_manager.feature_gate_listener_sets": "controller",
    "component.cert_manager.feature_gate_other_names": "controller",
    "component.cert_manager.feature_gate_server_side_apply": "controller",
    "component.cert_manager.owner_ref_enabled": "controller",
    "component.prometheus.log_level": "server",
    "component.prometheus.web_admin_api_enabled": "server",
    "component.prometheus.web_lifecycle_enabled": "server",
}
# Explicit normalization from the pinned fact roleScope values to the closed
# sourceRole vocabulary used by the RFC Scenario DSL.
PREDICATE_FACT_ROLE_SCOPE = {
    "component.argo_cd.insecure_server_enabled": {"argocd-server"},
    "component.argo_cd.repo_server_configured": {"argocd-server"},
    "component.argo_workflows.namespaced_mode": {"workflow-controller", "argo-server"},
    "component.argo_workflows.managed_namespace_configured": {"workflow-controller"},
    "component.cert_manager.owner_ref_enabled": {"cert-manager-controller"},
    "component.cert_manager.dns01_recursive_nameservers_configured": {"cert-manager-controller"},
    "component.cert_manager.feature_gate_acme_use_ari": {"cert-manager-controller"},
    "component.cert_manager.feature_gate_experimental_gateway_api_support": {"cert-manager-controller"},
    "component.cert_manager.feature_gate_listener_sets": {"cert-manager-controller"},
    "component.cert_manager.feature_gate_server_side_apply": {"cert-manager-controller"},
    "component.cert_manager.feature_gate_other_names": {"cert-manager-controller"},
    "component.cert_manager.feature_gate_certificate_request_controllers": {"cert-manager-controller"},
    "component.cert_manager.feature_gate_ca_injector_merging": {"cert-manager-controller"},
    "component.prometheus.web_admin_api_enabled": {"prometheus-server"},
    "component.prometheus.web_lifecycle_enabled": {"prometheus-server"},
    "component.prometheus.log_level": {"prometheus-server"},
}
TARGETS = {
    "pkg:oci/argoproj/argo-cd": ("3.5.2", "argo-cd-v3.5.2-release-api"),
    "pkg:oci/argoproj/argo-workflows": ("4.1.2", "argo-workflows-v4.1.2-release-api"),
    "pkg:oci/cert-manager/cert-manager": ("1.21.1", "cert-manager-v1.21.1-release-api"),
    "pkg:oci/prometheus/prometheus": ("3.14.0", "prometheus-v3.14.0-release-api"),
}
VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
ID = re.compile(r"^syn-[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
FORBIDDEN = re.compile(r"(?:Bearer\s+[A-Za-z0-9._-]{12,}|-----BEGIN|/(?:Users|home)/|file://|https?://|[A-Za-z]:\\)", re.I)
NO_AUTHORITY = {"S" + "AFE", "B" + "LOCKED"}

class ValidationError(ValueError):
    pass

def fail(message: str) -> None:
    raise ValidationError(message)

def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()

def read_json(path: Path, require_canonical: bool = True) -> Any:
    raw = path.read_bytes()
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                fail(f"{path}: duplicate key {key}")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda x: fail(f"{path}: nonfinite {x}"))
    except ValidationError:
        raise
    except Exception as exc:
        fail(f"{path}: invalid JSON ({exc})")
    if require_canonical and raw != canonical(value):
        fail(f"{path}: non-canonical JSON")
    return value

def shape(value: Any, required: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != required:
        fail(f"{label}: closed shape mismatch")

def shape_at_least(value: Any, required: set[str], label: str) -> None:
    if not isinstance(value, dict) or not required <= set(value):
        fail(f"{label}: required fields missing")

def stamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not STAMP.fullmatch(value):
        fail(f"{label}: UTC timestamp required")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        fail(f"{label}: invalid timestamp ({exc})")

def version(value: Any, label: str) -> None:
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        fail(f"{label}: semver required")

def digest(value: Any, label: str) -> None:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        fail(f"{label}: sha256 digest required")

def enum(value: Any, choices: set[str], label: str) -> None:
    if value not in choices:
        fail(f"{label}: invalid value {value!r}")

def load_inputs() -> tuple[dict, dict, dict, dict, dict, dict]:
    index = read_json(ROOT / "corpus-index.json")
    facts_doc = read_json(REVISION / "facts.json", False)
    sources_doc = read_json(REVISION / "sources.json", False)
    fresh = read_json(REVISION / "freshness.json", False)
    revision = read_json(REVISION / "revision.json", False)
    registry = read_json(REGISTRY, False)
    return index, facts_doc, sources_doc, fresh, revision, registry

def predicate_maps(facts_doc: dict, registry: dict):
    facts = {}
    for fact in facts_doc.get("facts", []):
        predicate = fact.get("predicate")
        if not predicate:
            continue
        pid = predicate.get("predicateId")
        if pid in facts:
            fail(f"duplicate revision predicate {pid}")
        facts[pid] = fact
    registered = {}
    for adapter in registry.get("adapters", []):
        if adapter.get("componentId") not in COMPONENTS:
            continue
        for p in adapter.get("predicates", []):
            pid = p.get("id")
            if pid in registered:
                fail(f"duplicate registry predicate {pid}")
            registered[pid] = (adapter["componentId"], p["valueKind"])
    return facts, registered

def check_predicate_bindings(index: dict, facts_doc: dict, registry: dict, sources_doc: dict) -> None:
    facts, registered = predicate_maps(facts_doc, registry)
    receipts = {s["sourceId"]: s for s in sources_doc.get("sources", [])}
    bindings = index["predicateBindings"]
    ids = [b["predicateId"] for b in bindings]
    if len(ids) != len(set(ids)) or set(ids) != REVIEWED_PREDICATE_IDS or set(facts) != REVIEWED_PREDICATE_IDS or set(registered) != REVIEWED_PREDICATE_IDS:
        fail("predicate binding IDs do not exactly cover revision and registry")
    for b in bindings:
        pid = b["predicateId"]
        fact = facts[pid]
        pred = fact["predicate"]
        if b["componentId"] != fact["componentId"] or b["factId"] != fact["factId"]:
            fail(f"{pid}: fact/component binding drift")
        if b["valueKind"] != pred["valueKind"] or b["sourceReceiptIds"] != pred["sourceReceiptIds"]:
            fail(f"{pid}: value kind or sourceReceiptIds drift")
        expected_span_ids = list(fact.get("sourceSpanIds") or [])
        expected_span_digests = []
        for source_id in b["sourceReceiptIds"]:
            source = receipts[source_id]
            spans = {span["spanId"]: span["textDigest"] for span in source.get("spans", [])}
            for span_id in expected_span_ids:
                if span_id not in spans:
                    fail(f"{pid}: source span is not present in bound receipt")
                expected_span_digests.append(spans[span_id])
        if b["sourceSpanIds"] != expected_span_ids or b["sourceSpanDigests"] != expected_span_digests:
            fail(f"{pid}: source span identity/digest drift")
        if b["sourceRole"] != PREDICATE_ROLE[pid] or b["factRoleScope"] != sorted(PREDICATE_FACT_ROLE_SCOPE[pid]):
            fail(f"{pid}: normalized/fact role binding drift")
        if set(pred.get("roleScope") or ()) != PREDICATE_FACT_ROLE_SCOPE[pid]:
            fail(f"{pid}: pinned fact roleScope is not the approved role binding")
        for sid in b["sourceReceiptIds"]:
            if sid not in receipts:
                fail(f"{pid}: unknown source receipt {sid}")
            if receipts[sid]["componentId"] != b["componentId"]:
                fail(f"{pid}: source/component ownership drift")
    for pid, (component, value_kind) in registered.items():
        if facts[pid]["predicate"]["valueKind"] != value_kind or facts[pid]["componentId"] != component:
            fail(f"{pid}: registry/fact mismatch")

def check_targets(index: dict, sources_doc: dict) -> None:
    receipts = {s["sourceId"]: s for s in sources_doc["sources"]}
    got = {t["componentId"]: (t["version"], t["sourceReceiptId"]) for t in index["targetCatalog"]}
    if got != TARGETS:
        fail(f"target catalog drift: {got!r}")
    for component, (ver, sid) in TARGETS.items():
        if sid not in receipts or receipts[sid]["componentId"] != component:
            fail(f"target source binding invalid for {component}")
        version(ver, f"target {component}")

def check_lifecycle(index: dict, scenario_ids: set[str]) -> None:
    rows = index["lifecycleCatalog"]
    ids = [x.get("scenarioId") for x in rows]
    if len(ids) != len(set(ids)) or set(ids) != scenario_ids:
        fail("lifecycle catalog must cover scenarios exactly once")
    for row in rows:
        shape(row, {"scenarioId","owner","reviewedAt","lifecycle","replacementRule"}, "lifecycle")
        if row["lifecycle"] not in {"ACTIVE","QUARANTINED","RETIRED"} or not isinstance(row["owner"], str) or not row["owner"] or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", row["reviewedAt"]) or not row["replacementRule"]:
            fail(f"{row.get('scenarioId')}: invalid lifecycle metadata")

def check_mutation_recipes(index: dict, scenario_ids: set[str]) -> list[Path]:
    paths = []
    seen = set()
    for row in index["mutationRecipes"]:
        shape(row, {"recipeId","path","baselineScenarioId","expectedRejectionClass"}, "mutation index row")
        if row["recipeId"] in seen or row["baselineScenarioId"] not in scenario_ids or row["expectedRejectionClass"] != "INTEGRITY":
            fail("mutation recipe index binding invalid")
        seen.add(row["recipeId"])
        path = ROOT / row["path"]
        if not path.is_file():
            fail(f"{row['recipeId']}: missing mutation recipe")
        recipe = read_json(path)
        shape(recipe, {"schema","kind","recipeId","baselineScenarioId","mutationClass","targetRole","expectedImport","downstreamCalls","cleanup","marker"}, "mutation recipe")
        if recipe["schema"] != "prufyx.io/synthetic-snapshot-factory/mutation-recipe/v4" or recipe["kind"] != "SyntheticSnapshotMutationRecipe" or recipe["recipeId"] != row["recipeId"] or recipe["baselineScenarioId"] != row["baselineScenarioId"] or recipe["mutationClass"] != "MANIFEST_DIGEST_MISMATCH" or recipe["targetRole"] != "ROOT_MANIFEST":
            fail(f"{row['recipeId']}: mutation contract drift")
        if recipe["expectedImport"] != {"outcome":"REJECT","reasonClass":"INTEGRITY"} or recipe["downstreamCalls"] != {"currentBundle":False,"evaluator":False} or recipe["cleanup"] != {"expectedResidue":False,"required":True}:
            fail(f"{row['recipeId']}: mutation isolation contract drift")
        if recipe["marker"] != {"classification":"PUBLIC_SYNTHETIC","fixtureAuthority":"SYNTHETIC_NON_AUTHORITATIVE_TEST_INPUT","execution":"TEST_HELPER_ONLY"}:
            fail(f"{row['recipeId']}: mutation marker drift")
        paths.append(path)
    return paths

def check_source_revision(value: Any, label: str) -> None:
    if value != SOURCE_REVISION:
        fail(f"{label}: sourceRevision drift")

def receipt_version(receipt: dict) -> str | None:
    tag = receipt.get("tag") or receipt.get("stableIdentity", {}).get("tag")
    return tag[1:] if isinstance(tag, str) and tag.startswith("v") else None

def check_scenario(s: dict, facts: dict, registered: dict) -> None:
    shape(s, {"schema","kind","scenarioId","description","classification","fixtureAuthority","generation","contractPins","snapshot","expectations"}, "scenario")
    if s["schema"] != "prufyx.io/synthetic-snapshot-factory/scenario/v4" or s["kind"] != "SyntheticSnapshotScenario":
        fail(f"{s.get('scenarioId')}: not RFC-0007 scenario DSL")
    if not ID.fullmatch(s["scenarioId"]) or not isinstance(s["description"], str) or not s["description"].isascii():
        fail(f"{s['scenarioId']}: invalid identity")
    if s["classification"] != "PUBLIC_SYNTHETIC" or s["fixtureAuthority"] != "SYNTHETIC_NON_AUTHORITATIVE_TEST_INPUT":
        fail(f"{s['scenarioId']}: synthetic marker drift")
    g = s["generation"]
    shape_at_least(g, {"mode","generatedAt","seed","scaleFactor"}, f"{s['scenarioId']}.generation")
    stamp(g["generatedAt"], f"{s['scenarioId']}.generation.generatedAt")
    enum(g["mode"], {"VALID","NEGATIVE"}, "generation.mode")
    if not isinstance(g["seed"], int) or not 0 <= g["seed"] <= 2**32 - 1 or g["scaleFactor"] not in {1,20,50,1000}:
        fail(f"{s['scenarioId']}: invalid generation controls")
    if g["mode"] == "NEGATIVE":
        muts = g.get("negativeMutations", [])
        if g["scaleFactor"] != 1 or len(muts) != 1:
            fail(f"{s['scenarioId']}: negative must have one mutation at scale 1")
        shape(muts[0], {"mutationId","class","targetRole","expectedReasonClass"}, f"{s['scenarioId']}.mutation")
    elif "negativeMutations" in g:
        fail(f"{s['scenarioId']}: valid scenario has mutation")
    cp = s["contractPins"]
    shape(cp, {"observationSchema","observationIndexSchema","sourceRevision","rendererContractDigest","predicateRegistryDigest","predicateRegistryVersion","evaluatorContractDigest","evaluatorProfile"}, f"{s['scenarioId']}.contractPins")
    for k in ("rendererContractDigest","predicateRegistryDigest","evaluatorContractDigest"):
        digest(cp[k], f"{s['scenarioId']}.{k}")
    if cp["predicateRegistryVersion"] != "v1" or cp["evaluatorProfile"] != "DECISION_BRANCH_COVERAGE_ONLY":
        fail(f"{s['scenarioId']}: contract pin drift")
    check_source_revision(cp["sourceRevision"], f"{s['scenarioId']}.contractPins")
    snap = s["snapshot"]
    shape(snap, {"collectionStatus","kubernetesVersion","environmentProfile","components","omissions"}, f"{s['scenarioId']}.snapshot")
    enum(snap["collectionStatus"], {"complete_for_declared_surface","partial_for_declared_surface"}, "collectionStatus")
    if not isinstance(snap["kubernetesVersion"], str) or not snap["kubernetesVersion"].startswith("v"):
        fail(f"{s['scenarioId']}: Kubernetes version")
    version(snap["kubernetesVersion"][1:], f"{s['scenarioId']}.kubernetesVersion")
    enum(snap["environmentProfile"], {"SYNTHETIC_MINIMAL_AMD64","SYNTHETIC_MINIMAL_ARM64","SYNTHETIC_EMPTY_NODE_SURFACE"}, "environmentProfile")
    if len(snap["components"]) != 4:
        fail(f"{s['scenarioId']}: component surface must contain four components")
    seen_components = set()
    for c in snap["components"]:
        shape_at_least(c, {"componentId","roles","predicates","versionState"}, "component")
        if c["componentId"] in seen_components or c["componentId"] not in COMPONENTS:
            fail(f"{s['scenarioId']}: duplicate/unknown component")
        seen_components.add(c["componentId"])
        enum(c["versionState"], {"exact","unknown","conflict"}, "component.versionState")
        if c["versionState"] == "exact":
            shape(c, {"componentId","roles","predicates","version","versionState"}, "exact component")
            version(c.get("version"), f"{c['componentId']}.version")
        elif c["versionState"] == "conflict":
            shape(c, {"componentId","roles","predicates","conflictingVersions","versionState"}, "conflict component")
            if not isinstance(c["conflictingVersions"], list) or len(c["conflictingVersions"]) < 2 or len(set(c["conflictingVersions"])) != len(c["conflictingVersions"]):
                fail(f"{c['componentId']}: invalid conflicting versions")
            for item in c["conflictingVersions"]:
                version(item, f"{c['componentId']}.conflictingVersion")
        else:
            shape(c, {"componentId","roles","predicates","versionState"}, "unknown component")
        if not isinstance(c["roles"], list) or not c["roles"] or len(set(c["roles"])) != len(c["roles"]):
            fail(f"{c['componentId']}: invalid roles")
        if not isinstance(c["predicates"], list):
            fail(f"{c['componentId']}: predicates must be list")
        seen = set()
        for p in c["predicates"]:
            shape_at_least(p, {"predicateId","sourceRole","state"}, "predicate")
            pid = p["predicateId"]
            if pid in seen or pid not in REVIEWED_PREDICATE_IDS or pid not in facts or registered[pid][0] != c["componentId"]:
                fail(f"{s['scenarioId']}: predicate component/reference mismatch")
            seen.add(pid)
            enum(p["state"], {"observed","missing","ambiguous","stale","conflicting","unsupported"}, f"{pid}.state")
            enum(p["sourceRole"], {"server","controller","application-controller","repo-server","workflow-controller","webhook","cainjector"}, f"{pid}.sourceRole")
            if PREDICATE_ROLE.get(pid) != p["sourceRole"]:
                fail(f"{pid}: sourceRole is not the reviewed role scope")
            if set(facts[pid]["predicate"].get("roleScope") or ()) != PREDICATE_FACT_ROLE_SCOPE[pid]:
                fail(f"{pid}: pinned fact roleScope is not the approved role binding")
            if p["state"] == "observed" and "value" not in p:
                fail(f"{pid}: observed predicate missing value")
            if p["state"] != "observed" and "value" in p:
                fail(f"{pid}: non-observed predicate has value")
            if p["state"] == "observed":
                expected_kind = facts[pid]["predicate"]["valueKind"]
                if expected_kind in {"boolean", "presence", "featureGate"} and not isinstance(p["value"], bool):
                    fail(f"{pid}: boolean-like value kind requires boolean")
                if expected_kind == "enum" and (not isinstance(p["value"], str) or not p["value"]):
                    fail(f"{pid}: enum value kind requires string")
    if seen_components != COMPONENTS:
        fail(f"{s['scenarioId']}: component surface mismatch")
    for o in snap["omissions"]:
        shape(o, {"code","requiredForEvaluation"}, "omission")
        if not isinstance(o["code"], str) or not isinstance(o["requiredForEvaluation"], bool):
            fail(f"{s['scenarioId']}: invalid omission")
    e = s["expectations"]
    shape(e, {"observationImport","currentBundle","evaluator","compatibilityEvidenceEligible","releaseEvidenceEligible"}, f"{s['scenarioId']}.expectations")
    shape(e["observationImport"], {"outcome","reasonClass"}, "observationImport")
    enum(e["observationImport"]["outcome"], {"ACCEPT","REJECT"}, "observationImport.outcome")
    if e["compatibilityEvidenceEligible"] is not False or e["releaseEvidenceEligible"] is not False:
        fail(f"{s['scenarioId']}: eligibility must remain false")
    if g["mode"] == "NEGATIVE":
        if e["observationImport"] != {"outcome":"REJECT","reasonClass":"INTEGRITY"} or e["currentBundle"] is not None or e["evaluator"] is not None:
            fail(f"{s['scenarioId']}: negative expectation is not an integrity rejection")
    else:
        if e["observationImport"] != {"outcome":"ACCEPT","reasonClass":"NONE"}:
            fail(f"{s['scenarioId']}: valid import expectation drift")
        if e["currentBundle"] is None:
            fail(f"{s['scenarioId']}: valid scenario requires persisted currentBundle expectation")
    if e["evaluator"] is not None:
        ev = e["evaluator"]
        if ev.get("aggregate") != "UNKNOWN" or ev.get("executionAllowed") is not False or not isinstance(ev.get("predicateOutcomes"), list):
            fail(f"{s['scenarioId']}: evaluator aggregate/outcomes")
        pids = [x.get("predicateId") for x in ev["predicateOutcomes"]]
        expected_pids = REVIEWED_PREDICATE_IDS
        if len(pids) != len(set(pids)) or set(pids) != expected_pids:
            fail(f"{s['scenarioId']}: evaluator must cover every predicate exactly once")

def check_freshness(freshness: dict, bridge: dict) -> None:
    observed = stamp(freshness["observedAt"], "revision freshness.observedAt")
    expires = stamp(freshness["expiresAfter"], "revision freshness.expiresAfter")
    now = stamp(bridge["freshness"]["now"], "bridge freshness.now")
    inside = observed <= now < expires
    if bridge["expectedRejectionClass"] == "FRESHNESS":
        if inside:
            fail("freshness rejection case unexpectedly lies inside revision interval")
        return
    if not inside:
        fail(f"freshness interval violation: {observed} <= {now} < {expires} required")
    generated = stamp(bridge["freshness"]["generatedAt"], "bridge freshness.generatedAt")
    max_age = bridge["freshness"]["maxAgeSeconds"]
    if not isinstance(max_age, int) or max_age < 1 or now < generated or (now - generated).total_seconds() > max_age:
        fail("bridge freshness age violation")

def derive_semantic_projection(s: dict, ref: dict, revision_id: str = "2026-09-01-community-v3") -> dict:
    observations = []
    for component in s["snapshot"]["components"]:
        for p in component["predicates"]:
            observations.append([component["componentId"], p["predicateId"], p["sourceRole"], p["state"], p.get("value")])
    observations.sort(key=lambda x: (x[0], x[1], x[2]))
    versions = []
    for row in ref["versionMatrix"]:
        versions.append([row["componentId"], row["currentState"], row["currentVersion"], sorted(row["currentValues"]), row["proposedVersion"]])
    versions.sort()
    snapshot_versions = []
    for component in s["snapshot"]["components"]:
        snapshot_versions.append([
            component["componentId"],
            component["versionState"],
            component.get("version"),
            sorted(component.get("conflictingVersions", [])),
        ])
    snapshot_versions.sort()
    return {
        "knowledgeRevision": revision_id,
        "contractPins": s["contractPins"],
        "environment": {
            "kubernetesVersion": s["snapshot"]["kubernetesVersion"],
            "environmentProfile": s["snapshot"]["environmentProfile"],
            "collectionStatus": s["snapshot"]["collectionStatus"],
            "omissions": sorted(o["code"] for o in s["snapshot"]["omissions"]),
        },
        "versions": versions,
        "snapshotVersions": snapshot_versions,
        "observations": observations,
        "sourceIds": sorted(ref["sourceIds"]),
        "freshness": ref["bridge"]["freshness"],
    }

def fleet_digest(s: dict, ref: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(derive_semantic_projection(s, ref))).hexdigest()

def check_package_unknown(value: Any, label: str) -> None:
    expected = {
        "authority": "BRANCH_COVERAGE_ONLY_NO_COMPATIBILITY_CLAIM",
        "reasonClass": "PACKAGE_TAKEDOWN_NOT_ASSESSED",
        "revisionId": "2026-09-01-community-v3",
        "registerPath": "yank-takedown.json",
        "registerDigest": "sha256:c4b988734d913c2d6e11dd355b86b45037cc6f1d41fa5d68e40adda1eb1885d7",
        "predicateId": "package.takedown_status",
        "outcome": "UNKNOWN",
        "reason": "knowledge revision takedown status is NOT_ASSESSED; target tags require an official yank/takedown check",
        "nextAction": "Check official yank/takedown status for: v3.5.2, v4.1.2, v1.21.1, v3.14.0",
        "targetTags": ["v3.5.2", "v4.1.2", "v1.21.1", "v3.14.0"],
        "sourceReceiptIds": [],
        "sourceSpanIds": [],
        "sourceSpanDigests": [],
    }
    if value != expected:
        fail(f"{label}: package NOT_ASSESSED UNKNOWN provenance drift")

def check_oracle(oracle: dict, scenario: dict, ref: dict, expected_digest: str) -> None:
    shape(oracle, {"schema","kind","scenarioId","scenarioDigest","sourceRevision","evaluatorContractDigest","observationImport","currentBundle","evaluator","packageUnknown","compatibilityEvidenceEligible","releaseEvidenceEligible","authority","rejectionClass","rejectionReason","rejectionNextAction","oracleDigest"}, "oracle")
    if oracle["schema"] != "prufyx.io/synthetic-snapshot-factory/expected-oracle/v4" or oracle["kind"] != "SyntheticSnapshotExpectedOracle":
        fail(f"{oracle.get('scenarioId')}: oracle schema drift")
    if oracle["authority"] != "BRANCH_COVERAGE_ONLY_NO_COMPATIBILITY_CLAIM" or oracle["evaluatorContractDigest"] != scenario["contractPins"]["evaluatorContractDigest"]:
        fail(f"{oracle['scenarioId']}: oracle authority/contract binding drift")
    check_source_revision(oracle["sourceRevision"], f"{oracle['scenarioId']}.sourceRevision")
    if oracle["scenarioId"] != scenario["scenarioId"] or oracle["scenarioDigest"] != expected_digest:
        fail(f"{oracle['scenarioId']}: scenario digest binding drift")
    digest(oracle["oracleDigest"], "oracleDigest")
    body = dict(oracle); claimed = body.pop("oracleDigest")
    if "sha256:" + hashlib.sha256(canonical(body)).hexdigest() != claimed:
        fail(f"{oracle['scenarioId']}: oracle digest mismatch")
    if oracle["compatibilityEvidenceEligible"] is not False or oracle["releaseEvidenceEligible"] is not False:
        fail(f"{oracle['scenarioId']}: oracle eligibility drift")
    if oracle["evaluator"] is None:
        if oracle["packageUnknown"] is not None:
            fail(f"{oracle['scenarioId']}: rejected/non-evaluated oracle must not emit package UNKNOWN")
    else:
        check_package_unknown(oracle["packageUnknown"], f"{oracle['scenarioId']}.packageUnknown")
    expectations = scenario["expectations"]
    for field in ("observationImport", "currentBundle", "evaluator", "compatibilityEvidenceEligible", "releaseEvidenceEligible"):
        actual = oracle[field]
        expected_value = expectations[field]
        if field == "evaluator" and actual is not None and expected_value is not None:
            actual = dict(actual)
            actual["predicateOutcomes"] = [{k: v for k, v in row.items() if k not in {"reason", "nextAction"}} for row in actual["predicateOutcomes"]]
        if actual != expected_value:
            fail(f"{oracle['scenarioId']}: oracle expectation drift in {field}")
    if oracle["evaluator"] is not None:
        ev = oracle["evaluator"]
        if ev.get("aggregate") != "UNKNOWN" or len(ev.get("predicateOutcomes", [])) != len(REVIEWED_PREDICATE_IDS):
            fail(f"{oracle['scenarioId']}: oracle aggregate/rows drift")

def check_ref(ref: dict, scenario: dict, oracle: dict, facts: dict, registered: dict, sources_doc: dict, freshness: dict, index: dict) -> None:
    if ref["scenarioId"] != scenario["scenarioId"] or ref["scenarioId"] != oracle["scenarioId"]:
        fail("scenario/oracle/index ID mismatch")
    manifest = ref["bridge"]["manifestExpectation"]
    shape(manifest, {"compilerSourceRevision"}, f"{ref['scenarioId']}.manifestExpectation")
    check_source_revision(manifest["compilerSourceRevision"], f"{ref['scenarioId']}.manifestExpectation.compilerSourceRevision")
    snapshot_components = {c["componentId"]: c for c in scenario["snapshot"]["components"]}
    matrix_components = {m["componentId"]: m for m in ref["versionMatrix"]}
    if set(snapshot_components) != set(matrix_components):
        fail(f"{ref['scenarioId']}: snapshot and version matrix component sets differ")
    for component_id, component in snapshot_components.items():
        matrix = matrix_components[component_id]
        if component["versionState"] != matrix["currentState"]:
            fail(f"{ref['scenarioId']}: snapshot/matrix version state drift for {component_id}")
        if component["versionState"] == "exact":
            if component.get("version") != matrix["currentVersion"] or matrix["currentValues"]:
                fail(f"{ref['scenarioId']}: exact snapshot/matrix version drift for {component_id}")
        elif component["versionState"] == "unknown":
            if "version" in component or component.get("conflictingVersions") or matrix["currentVersion"] is not None or matrix["currentValues"]:
                fail(f"{ref['scenarioId']}: unknown snapshot/matrix version drift for {component_id}")
        elif component["versionState"] == "conflict":
            if "version" in component or sorted(component.get("conflictingVersions", [])) != sorted(matrix["currentValues"]) or matrix["currentVersion"] is not None:
                fail(f"{ref['scenarioId']}: conflict snapshot/matrix version drift for {component_id}")
    receipts = {x["sourceId"]: x for x in sources_doc["sources"]}
    for matrix in ref["versionMatrix"]:
        if len(matrix["sourceIds"]) != len(set(matrix["sourceIds"])):
            fail(f"{ref['scenarioId']}: duplicate version row source IDs")
        row_receipts = [receipts[sid] for sid in matrix["sourceIds"] if sid in receipts]
        if len(row_receipts) != len(matrix["sourceIds"]) or any(r["componentId"] != matrix["componentId"] for r in row_receipts):
            fail(f"{ref['scenarioId']}: version row receipt component ownership drift")
        row_versions = {receipt_version(r) for r in row_receipts}
        required_versions = {matrix["proposedVersion"]}
        if matrix["currentState"] == "exact" and matrix["currentVersion"] is not None:
            required_versions.add(matrix["currentVersion"])
        if matrix["currentState"] == "conflict":
            required_versions.update(matrix["currentValues"])
        if not required_versions <= row_versions:
            fail(f"{ref['scenarioId']}: version row is missing exact release receipt")
    if ref["bridge"]["expectedAggregate"] != "UNKNOWN":
        fail(f"{ref['scenarioId']}: aggregate must be UNKNOWN")
    mode = ref["bridge"]["evaluationMode"]
    expected_class = ref["bridge"]["expectedRejectionClass"]
    expected = {"EVALUATE":"NONE","REVISION_FRESHNESS_REJECTED":"FRESHNESS","VERSION_CONFLICT_REJECTED":"CONFLICT","IMPORT_REJECTED":"INTEGRITY"}
    if expected.get(mode) != expected_class:
        fail(f"{ref['scenarioId']}: bridge rejection mode/class mismatch")
    if oracle["rejectionClass"] != expected_class or oracle["rejectionReason"] != ref["bridge"]["rejectionReason"] or oracle["rejectionNextAction"] != ref["bridge"]["rejectionNextAction"]:
        fail(f"{ref['scenarioId']}: independent rejection oracle drift")
    if expected_class == "NONE":
        if ref["bridge"]["rejectionReason"] is not None or ref["bridge"]["rejectionNextAction"] is not None:
            fail(f"{ref['scenarioId']}: evaluable case has preflight rejection text")
    else:
        if not isinstance(ref["bridge"]["rejectionReason"], str) or not isinstance(ref["bridge"]["rejectionNextAction"], str):
            fail(f"{ref['scenarioId']}: rejected case needs reason and next action")
    check_freshness(freshness, ref["bridge"])
    if mode == "EVALUATE" and scenario["expectations"]["evaluator"] is None:
        fail(f"{ref['scenarioId']}: evaluation mode without evaluator")
    if mode != "EVALUATE" and scenario["expectations"]["evaluator"] is not None:
        fail(f"{ref['scenarioId']}: preflight mode has evaluator")
    bindings = {b["predicateId"]: b for b in index["predicateBindings"]}
    rows = ref["bridge"]["predicateOutcomes"]
    if mode == "EVALUATE":
        expected_pids = REVIEWED_PREDICATE_IDS
        if len(rows) != len(expected_pids) or {r["predicateId"] for r in rows} != expected_pids:
            fail(f"{ref['scenarioId']}: bridge rows do not cover all predicates")
    elif rows:
        fail(f"{ref['scenarioId']}: preflight bridge must not contain evaluator rows")
    for row in rows:
        if row["componentId"] != bindings[row["predicateId"]]["componentId"]:
            fail(f"{row['predicateId']}: row component drift")
        if row["predicateId"] == "component.cert_manager.feature_gate_ca_injector_merging":
            if row["outcome"] != "UNKNOWN" or row["reasonClass"] != "UNSUPPORTED_PREDICATE" or row["reason"] != "predicate is explicitly unsupported by the reviewed revision" or row["nextAction"] != "Obtain a separately reviewed source-backed predicate definition":
                fail("unsupported predicate must use explicit unsupported reason")
        elif row["outcome"] == "MATCH":
            if row["reasonClass"] != "CONTEXT_MATCH_NON_AUTHORITATIVE" or row["reason"] != "exact source- and role-bound context observation matches; this is not compatibility evidence" or row["nextAction"] != "No compatibility conclusion is available from this context match":
                fail(f"{row['predicateId']}: MATCH oracle reason drift")
        elif row["outcome"] == "MISMATCH":
            if row["reasonClass"] != "CONTEXT_MISMATCH_ATTENTION" or row["reason"] != "observed role-bound value differs from the reviewed context predicate" or row["nextAction"] != "Review the customer-owned role configuration against the cited source boundary":
                fail(f"{row['predicateId']}: MISMATCH reason class drift")
        elif row["outcome"] == "UNKNOWN" and row["reasonClass"] not in {"MISSING_OR_UNSUPPORTED_CONTEXT","UNSUPPORTED_PREDICATE"}:
            fail(f"{row['predicateId']}: UNKNOWN reason class drift")
        elif row["outcome"] == "UNKNOWN" and row["reasonClass"] == "MISSING_OR_UNSUPPORTED_CONTEXT":
            expected_pid = row["predicateId"]
            if row["reason"] != f"missing exact observed value for predicate {expected_pid} in role-bound configuration" or row["nextAction"] != f"Inspect the current role configuration for predicate {expected_pid}":
                fail(f"{expected_pid}: UNKNOWN oracle reason drift")
    if mode == "EVALUATE":
        oracle_rows = {r["predicateId"]: r for r in oracle["evaluator"]["predicateOutcomes"]}
        for row in rows:
            got = oracle_rows.get(row["predicateId"])
            if not got or got["componentId"] != row["componentId"] or got["outcome"] != row["outcome"] or got["reasonClass"] != row["reasonClass"] or got["reason"] != row["reason"] or got["nextAction"] != row["nextAction"]:
                fail(f"{ref['scenarioId']}: oracle row drift for {row['predicateId']}")
    if "fleet" not in ref["bridge"]:
        fail(f"{ref['scenarioId']}: missing derived fleet equivalence proof")
    actual = fleet_digest(scenario, ref)
    if ref["bridge"]["fleet"]["semanticProjectionDigest"] != actual or ref["bridge"]["fleet"]["equivalenceKey"] != "derived-" + actual[7:23]:
        fail(f"{ref['scenarioId']}: fleet digest is not derived from semantic projection")

def check_replay_bridge_gate(index: dict, scenario_ids: list[str]) -> None:
    gate = read_json(ROOT / "replay-bridge-gate.json")
    expected = {
        "apiVersion": "prufyx.io/synthetic-snapshot-factory/replay-bridge-gate/v4",
        "authority": {"clusterUsed": False, "modelUsed": False, "mutationAuthority": "CUSTOMER_ONLY", "networkUsed": False},
        "corpusId": "community-v4-context-corpus-v4",
        "generation": {"contract": "RFC-0007 Scenario DSL through the live synthetic-snapshot factory", "status": "CORPUS_VALIDATED_FACTORY_INTEGRATION_PENDING"},
        "import": {"contract": "production observation importer compatibility", "status": "EXTERNAL_IMPLEMENTATION_REQUIRED"},
        "kind": "SyntheticSnapshotReplayBridgeGate",
        "knowledgeRevision": index["knowledgeRevision"],
        "projection": {"authority": "NONE", "clusterUsed": False, "contract": "RFC-0010 test-only evaluation projection", "modelUsed": False, "networkUsed": False, "status": "EXTERNAL_IMPLEMENTATION_REQUIRED"},
        "scenarioCount": 18,
        "scenarioIds": sorted(scenario_ids),
        "sourceRevision": SOURCE_REVISION,
        "testOnlyEvaluator": {"authority": "NONE", "contract": "v3 evaluator input bridge", "packageUnknown": "NOT_ASSESSED", "status": "EXTERNAL_IMPLEMENTATION_REQUIRED"},
    }
    if gate != expected:
        fail("replay bridge gate drift: exact v3 pins, scenario coverage, or external status changed")

def scan_privacy(paths: list[Path]) -> None:
    for path in paths:
        text = path.read_text()
        if FORBIDDEN.search(text):
            fail(f"{path.name}: private endpoint/path/secret-like content")
        for token in NO_AUTHORITY:
            if re.search(rf"\b{token}\b", text):
                fail(f"{path.name}: unauthorized aggregate token {token}")

def tree_digest(root: Path) -> tuple[int, str, list[tuple[str, str]]]:
    rows = []
    for path in sorted(x for x in root.rglob("*") if x.is_file() and "__pycache__" not in x.parts):
        relative = path.relative_to(root).as_posix()
        rows.append((relative, "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()))
    payload = "".join(f"{relative}\0{file_digest}\n" for relative, file_digest in rows).encode()
    return len(rows), "sha256:" + hashlib.sha256(payload).hexdigest(), rows

def check_migration_provenance(index: dict, refs: list[dict]) -> Path:
    path = ROOT / "migration-provenance.json"
    migration = read_json(path)
    shape(migration, {"schema", "kind", "from", "to", "sourceTree", "fileMappings", "addedFiles", "semanticPreservation", "chain"}, "migration provenance")
    if migration["schema"] != "prufyx.io/synthetic-snapshot-factory/migration-provenance/v4" or migration["kind"] != "SyntheticSnapshotCorpusMigrationProvenance":
        fail("migration provenance identity drift")
    if migration["from"] != {"corpusId":"community-v3-context-corpus-v2", "sourceRevision":"synthetic-snapshot-factory-v2"} or migration["to"] != {"corpusId":"community-v4-context-corpus-v4", "sourceRevision":SOURCE_REVISION}:
        fail("migration provenance corpus transition drift")
    count, actual_tree, rows = tree_digest(V2_ROOT)
    source_tree = migration["sourceTree"]
    shape(source_tree, {"algorithm", "fileCount", "preDigest", "postDigest"}, "migration sourceTree")
    if source_tree["algorithm"] != "sha256(concat(relativePath + NUL + fileSha256 + LF), sorted paths; excludes __pycache__ and migration-provenance.json)" or source_tree["fileCount"] != count - 1 or source_tree["preDigest"] != V2_TREE_DIGEST:
        fail("v2 predecessor tree changed or migration witness drift")
    predecessor_rows = [(p, d) for p, d in rows if p != "migration-provenance.json"]
    payload = "".join(f"{relative}\0{file_digest}\n" for relative, file_digest in predecessor_rows).encode()
    if "sha256:" + hashlib.sha256(payload).hexdigest() != V2_TREE_DIGEST:
        fail("v2 predecessor tree digest recomputation drift")
    successor_rows = [(p, d) for p, d in tree_digest(ROOT)[2] if p != "migration-provenance.json"]
    successor_payload = "".join(f"{relative}\0{file_digest}\n" for relative, file_digest in successor_rows).encode()
    if "sha256:" + hashlib.sha256(successor_payload).hexdigest() != source_tree["postDigest"]:
        fail("v3 successor tree digest recomputation drift")
    mappings = migration["fileMappings"]
    if len(mappings) != len(predecessor_rows):
        fail("migration file mapping count drift")
    expected = []
    for relative, v2_digest in predecessor_rows:
        successor = relative
        if relative == "mutations/syn-tampered-source-binding.json":
            successor = "mutations/syn-v4-tampered-source-binding.json"
        elif "/syn-" in relative and relative.endswith(".json"):
            successor = relative.replace("/syn-", "/syn-v4-", 1)
        v3_path = ROOT / successor
        if not v3_path.is_file():
            fail(f"migration missing v3 counterpart: {relative}")
        expected.append({"path":relative, "v2Digest":v2_digest, "v3Path":successor, "v3Digest":"sha256:" + hashlib.sha256(v3_path.read_bytes()).hexdigest()})
    if mappings != expected:
        fail("migration v2-to-v3 file digest mapping drift")
    added = migration["addedFiles"]
    mapped_paths = {row["v3Path"] for row in mappings}
    expected_added = [{"path": p, "v3Digest": "sha256:" + hashlib.sha256((ROOT / p).read_bytes()).hexdigest()} for p in sorted(x.relative_to(ROOT).as_posix() for x in ROOT.rglob("*") if x.is_file() and "__pycache__" not in x.parts and x.name != "migration-provenance.json" and x.relative_to(ROOT).as_posix() not in mapped_paths)]
    if added != expected_added:
        fail("migration v3 added-file binding drift")
    chain = migration["chain"]
    if chain != {"previous":"testdata/synthetic-cluster-scenarios/v2/migration-provenance.json", "previousDigest":"sha256:" + hashlib.sha256((V2_ROOT / "migration-provenance.json").read_bytes()).hexdigest(), "fromCorpus":"community-v3-context-corpus", "toCorpus":"community-v3-context-corpus-v2", "status":"IMMUTABLE_PREDECESSOR_BOUND"}:
        fail("v1-to-v2 predecessor chain binding drift")
    semantics = migration["semanticPreservation"]
    shape(semantics, {"scenarioCount", "evaluatorCount", "preflightCount", "packageReasonClassAdded", "authority"}, "migration semanticPreservation")
    if semantics != {"scenarioCount":18, "evaluatorCount":16, "preflightCount":2, "packageReasonClassAdded":"PACKAGE_TAKEDOWN_NOT_ASSESSED", "authority":"CANDIDATE_ONLY_NO_RELEASE_AUTHORITY"}:
        fail("migration semantic preservation drift")
    return path

def validate_all() -> str:
    index, facts_doc, sources_doc, freshness, revision, registry = load_inputs()
    shape(index, {"apiVersion","kind","schemaVersion","corpusId","sourceRevision","knowledgeRevision","marker","predicateBindings","targetCatalog","scenarioRefs","generationDescriptors","mutationRecipes","lifecycleCatalog"}, "corpus-index")
    check_source_revision(index["sourceRevision"], "corpus-index")
    if index["apiVersion"] != "prufyx.io/synthetic-snapshot-factory/corpus-index/v4" or index["kind"] != "SyntheticSnapshotScenarioCorpusIndex" or index["schemaVersion"] != "3.0.0":
        fail("index contract identity drift")
    manifest_doc = json.loads((REVISION / "manifest.json").read_text())
    expected_knowledge_pins = {
        "id": "2026-09-01-community-v3",
        "digest": revision["revisionDigest"],
        "manifestDigest": manifest_doc["manifestDigest"],
        "signingRequestDigest": "sha256:05033c110a61536d285d482e7a3117e9e6a1c000f9a3388dfd32fd3756c05bc7",
        "policyDigest": "sha256:24fa693c7f5051e00e22c6ef76f903b0fb8a3054552a0d5d2d57e58dbffc68ab",
        "predicateRegistryDigest": "sha256:684399f89ebcd9de625418a59de63bacacdc5dc3117925cc409cd09df0c7d63b",
        "evaluatorContractDigest": "sha256:64e01db17daf4b57aeced2217b7f652242f99f460876e9e085a0ded413ad9d4b",
        "rendererContractDigest": "sha256:7a15df13be5c832398da310dd5b12815f253657d6acf17f843f742fa1337d414",
    }
    if index["knowledgeRevision"] != expected_knowledge_pins:
        fail("knowledge revision digest binding drift")
    marker = index["marker"]
    if marker != {"authority":"CANDIDATE_ONLY_NO_RELEASE_AUTHORITY","classification":"PUBLIC_SYNTHETIC","clusterUsed":False,"evaluationEligible":False,"fixtureAuthority":"SYNTHETIC_NON_AUTHORITATIVE_TEST_INPUT","modelUsed":False,"mutationAuthority":"CUSTOMER_ONLY","networkUsed":False}:
        fail("index synthetic marker drift")
    check_predicate_bindings(index, facts_doc, registry, sources_doc)
    check_targets(index, sources_doc)
    facts, registered = predicate_maps(facts_doc, registry)
    refs = index["scenarioRefs"]
    ids = [r["scenarioId"] for r in refs]
    if len(ids) != 18 or len(ids) != len(set(ids)):
        fail("corpus must contain 18 unique scenario IDs")
    check_replay_bridge_gate(index, ids)
    migration_path = check_migration_provenance(index, refs)
    mutation_paths = check_mutation_recipes(index, set(ids))
    check_lifecycle(index, set(ids))
    source_ids = {x["sourceId"] for x in sources_doc["sources"]}
    scenario_docs = {}
    oracle_docs = {}
    for ref in refs:
        if ref["scenarioId"] in scenario_docs:
            fail("duplicate scenario reference")
        sp = ROOT / ref["scenarioPath"]; op = ROOT / ref["oraclePath"]
        if not sp.is_file() or not op.is_file():
            fail(f"{ref['scenarioId']}: missing canonical scenario/oracle")
        scenario = read_json(sp); oracle = read_json(op)
        scenario_docs[ref["scenarioId"]] = scenario
        oracle_docs[ref["scenarioId"]] = oracle
        check_scenario(scenario, facts, registered)
        if scenario["scenarioId"] != ref["scenarioId"]:
            fail(f"{ref['scenarioId']}: scenario ID drift")
        scenario_hash = "sha256:" + hashlib.sha256(sp.read_bytes()).hexdigest()
        oracle_hash = "sha256:" + hashlib.sha256(op.read_bytes()).hexdigest()
        if ref["scenarioDigest"] != scenario_hash or ref["oracleDigest"] != oracle_hash:
            fail(f"{ref['scenarioId']}: index file digest drift")
        check_oracle(oracle, scenario, ref, scenario_hash)
        if not set(ref["sourceIds"]) <= source_ids or not set(ref["sourceIds"]):
            fail(f"{ref['scenarioId']}: unknown/empty source IDs")
        if len(ref["sourceIds"]) != len(set(ref["sourceIds"])):
            fail(f"{ref['scenarioId']}: duplicate scenario source IDs")
        matrix_components = {m["componentId"] for m in ref["versionMatrix"]}
        if matrix_components != COMPONENTS:
            fail(f"{ref['scenarioId']}: version matrix component mismatch")
        for m in ref["versionMatrix"]:
            if m["proposedVersion"] != TARGETS[m["componentId"]][0]:
                fail(f"{ref['scenarioId']}: proposed target drift")
            if not set(m["sourceIds"]) <= source_ids or not set(m["sourceIds"]):
                fail(f"{ref['scenarioId']}: version row source binding")
            if len(m["sourceIds"]) != len(set(m["sourceIds"])):
                fail(f"{ref['scenarioId']}: duplicate version row source IDs")
            receipts = {x["sourceId"]: x for x in sources_doc["sources"]}
            row_receipts = [receipts[sid] for sid in m["sourceIds"]]
            if any(r["componentId"] != m["componentId"] for r in row_receipts):
                fail(f"{ref['scenarioId']}: version row receipt component ownership drift")
            row_versions = {receipt_version(r) for r in row_receipts}
            required_versions = {m["proposedVersion"]}
            if m["currentState"] == "exact" and m["currentVersion"] is not None:
                required_versions.add(m["currentVersion"])
            if m["currentState"] == "conflict":
                required_versions.update(m["currentValues"])
            if not required_versions <= row_versions:
                fail(f"{ref['scenarioId']}: version row is missing exact release receipt")
        check_ref(ref, scenario, oracle, facts, registered, sources_doc, freshness, index)
    for d in index["generationDescriptors"]:
        if d["id"] not in {"synthetic-20x","synthetic-50x","synthetic-1000x"} or d["outputMode"] != "DESCRIPTOR_ONLY_NO_COMMITTED_OUTPUT" or d["isCapacityEvidence"] is not False:
            fail("generation descriptor is not a descriptor-only entry")
        expected = {"synthetic-20x": (20,20), "synthetic-50x": (50,50), "synthetic-1000x": (1000,250)}[d["id"]]
        if d["multiplier"] != expected[0] or d["rootCount"] != expected[0] or d["partitionSize"] != expected[1]:
            fail("generation descriptor cardinality drift")
    scan_privacy([ROOT / "corpus-index.json", ROOT / "replay-bridge-gate.json", migration_path, *[ROOT / r["scenarioPath"] for r in refs], *[ROOT / r["oraclePath"] for r in refs], *mutation_paths])
    # Equivalence proof is semantic: member labels and scenario IDs are excluded.
    a = next(r for r in refs if r["scenarioId"] == "syn-v4-fleet-equivalence-member-a")
    b = next(r for r in refs if r["scenarioId"] == "syn-v4-fleet-equivalence-member-b")
    c = next(r for r in refs if r["scenarioId"] == "syn-v4-fleet-non-equivalent-config")
    da, db, dc = (fleet_digest(scenario_docs[r["scenarioId"]], r) for r in (a,b,c))
    if da != db or dc == da or a["bridge"]["fleet"]["reuseExpectation"] != "REUSE_EXACT_MATCH" or b["bridge"]["fleet"]["reuseExpectation"] != "REUSE_EXACT_MATCH" or c["bridge"]["fleet"]["reuseExpectation"] != "DO_NOT_REUSE_DIFFERENT_PROFILE":
        fail("fleet equivalence/non-equivalence proof failed")
    return f"canonical corpus scenarios={len(refs)} predicates={len(index['predicateBindings'])} targets={len(index['targetCatalog'])} refs=RFC-0007-DSL oracles=exact-rows"

def main() -> int:
    try:
        print(validate_all())
    except ValidationError as exc:
        print("validation failed:", exc, file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
