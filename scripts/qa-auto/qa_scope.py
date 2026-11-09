"""Versioned requested/executed inventories for the removal oracles."""
import hashlib
import json
import re

SCHEMA = "prufyx.io/qa-scope/v2"
PROFILE = "kubernetes-api-removals-v2"
CRD_PROFILE = "crd-removals-v1"
# A stage that ran to completion but, by construction of the oracle input, cannot decide one rule family.
# Recorded at execution time (not declared in advance), so it is not part of the declaration digest.
SCOPE_LIMIT_REASONS = ("kubelet-version-declaration-not-supplied",)
DECLARED_FIELDS = ("schema", "profile", "head", "base", "run_id", "requested", "required", "excluded")


def digest(scope):
    declared = {key: scope[key] for key in DECLARED_FIELDS}
    return hashlib.sha256(json.dumps(declared, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def declare(head, base, run_id, requested, required, excluded, profile=PROFILE):
    scope = dict(schema=SCHEMA, profile=profile, head=head, base=base, run_id=run_id,
                 requested=sorted(requested), required=sorted(required), excluded=excluded,
                 executed=[], omitted=[], state="DECLARED")
    scope["declaration_digest"] = digest(scope)
    return scope


def errors(scope, head, base, run_id, profile=PROFILE):
    """Exclusions describe missing evidence; required exclusions block the gate."""
    try:
        if (scope["schema"], scope["profile"], scope["head"], scope["base"], scope["run_id"]) != (SCHEMA, profile, head, base, run_id):
            return ["scope identity mismatch"]
        if scope["declaration_digest"] != digest(scope):
            return ["scope declaration changed after execution"]
        requested, required, executed = (scope[key] for key in ("requested", "required", "executed"))
        excluded = [entry["target"] for entry in scope["excluded"]]
        for values in (requested, required, executed, excluded):
            if not isinstance(values, list) or not all(isinstance(x, str) and x for x in values) or len(values) != len(set(values)):
                return ["scope inventory invalid"]
        if not isinstance(scope["omitted"], list):
            return ["omission inventory invalid"]
        omitted = [entry["target"] for entry in scope["omitted"]]
        if not all(isinstance(target, str) and target in requested for target in omitted):
            return ["omission target outside requested scope"]
        if not requested or scope["state"] != "COMPLETE":
            return ["scope inventory incomplete"]
        if set(executed) & set(excluded) or set(requested) != set(executed) | set(excluded) | set(omitted):
            return ["requested/executed/excluded inventory mismatch"]
        if not set(required) <= set(requested):
            return ["required target absent from declared scope"]
        if set(required) & set(excluded):
            return ["required target excluded"]
        if any(not valid_exclusion(entry, profile) for entry in scope["excluded"]):
            return ["exclusion lacks bounded next test"]
        if omitted:
            return ["input targets omitted or incompletely processed"]
        if not valid_scope_limits(scope.get("scope_limits", []), executed):
            return ["scope limit lacks reason or bounded next test"]
        return []
    except (KeyError, TypeError, ValueError, IndexError):
        return ["scope inventory malformed"]


def valid_scope_limits(limits, executed):
    """Each limit names an executed Kubernetes plan stage, a known reason and a bounded next test."""
    if not isinstance(limits, list):
        return False
    targets = []
    for entry in limits:
        if not isinstance(entry, dict) or set(entry) != {"target", "reason", "next_test"}:
            return False
        target = entry["target"]
        if (not isinstance(target, str) or not target.startswith("k8s-plan|") or " stage " not in target
                or target not in executed or entry["reason"] not in SCOPE_LIMIT_REASONS
                or not isinstance(entry["next_test"], str) or not entry["next_test"].strip()):
            return False
        targets.append(target)
    return len(targets) == len(set(targets))


def valid_exclusion(entry, profile):
    if not entry.get("reason") or not entry.get("next_test"):
        return False
    target = entry["target"]
    if profile == CRD_PROFILE:
        return target.startswith("crd|") and entry.get("evidence") == "complete served-set read: empty"
    if target.startswith("k8s-single|") and "alpha" in target.rsplit("/", 2)[-2]:
        return True
    proof = entry.get("evidence", {})
    missing = re.fullmatch(r"refs/tags/v1\.([0-9]+)\.0", proof.get("missing_ref", ""))
    return (entry.get("kind") == "unavailable-version" and target.startswith("k8s-") and
            proof.get("source") == "https://github.com/kubernetes/kubernetes.git" and
            missing is not None and int(missing[1]) > 0 and
            proof.get("previous_ref") == f"refs/tags/v1.{int(missing[1])-1}.0" and
            re.fullmatch(r"[0-9a-f]{40}", proof.get("previous_ref_sha", "")) is not None)


def remaining_omitted(scope, executed, reason):
    covered = set(executed) | {entry["target"] for entry in scope["excluded"]} | {entry["target"] for entry in scope["omitted"]}
    scope["omitted"].extend(dict(target=target, reason=reason) for target in sorted(set(scope["requested"]) - covered))


def bundle_errors(scopes, head, base, run_id):
    if not isinstance(scopes, dict) or set(scopes) != {"k8s", "crd"}:
        return ["both Kubernetes and CRD inventories are required"]
    return (errors(scopes["k8s"], head, base, run_id) +
            errors(scopes["crd"], head, base, run_id, CRD_PROFILE))
