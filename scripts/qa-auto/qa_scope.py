"""Versioned requested/executed inventory for Kubernetes oracle targets."""
import hashlib
import json

SCHEMA = "prufyx.io/qa-scope/v1"
PROFILE = "kubernetes-api-removals-v1"
DECLARED_FIELDS = ("schema", "profile", "head", "base", "run_id", "requested", "required", "excluded")


def digest(scope):
    declared = {key: scope[key] for key in DECLARED_FIELDS}
    return hashlib.sha256(json.dumps(declared, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def declare(head, base, run_id, requested, required, excluded):
    scope = dict(schema=SCHEMA, profile=PROFILE, head=head, base=base, run_id=run_id,
                 requested=sorted(requested), required=sorted(required), excluded=excluded,
                 executed=[], omitted=[], state="DECLARED")
    scope["declaration_digest"] = digest(scope)
    return scope


def errors(scope, head, base, run_id):
    """Exclusions describe missing evidence; required exclusions block the gate."""
    try:
        if (scope["schema"], scope["profile"], scope["head"], scope["base"], scope["run_id"]) != (SCHEMA, PROFILE, head, base, run_id):
            return ["scope identity mismatch"]
        if scope["declaration_digest"] != digest(scope):
            return ["scope declaration changed after execution"]
        requested, required, executed = (scope[key] for key in ("requested", "required", "executed"))
        excluded = [entry["target"] for entry in scope["excluded"]]
        for values in (requested, required, executed, excluded):
            if not isinstance(values, list) or not all(isinstance(x, str) and x for x in values) or len(values) != len(set(values)):
                return ["scope inventory invalid"]
        if not isinstance(scope["omitted"], list) or scope["omitted"]:
            return ["input targets omitted or incompletely processed"]
        if not requested or scope["state"] != "COMPLETE":
            return ["scope inventory incomplete"]
        if set(executed) & set(excluded) or set(requested) != set(executed) | set(excluded):
            return ["requested/executed/excluded inventory mismatch"]
        if not set(required) <= set(requested):
            return ["required target absent from declared scope"]
        if set(required) & set(excluded):
            return ["required target excluded"]
        if any(not entry.get("reason") or not entry.get("next_test") or not entry["target"].startswith("k8s-single|") or "alpha" not in entry["target"].rsplit("/", 2)[-2] for entry in scope["excluded"]):
            return ["exclusion lacks bounded next test"]
        return []
    except (KeyError, TypeError, ValueError, IndexError):
        return ["scope inventory malformed"]
