#!/usr/bin/env python3
"""Seeded wrong-PASS cases: the oracle must catch known wrong PASSes before its verdict on the real corpus counts.

A seed is a pair with a REAL expected removal (frozen literals below: removed Kubernetes APIs and the whole-CRD / version-level /
mixed shapes of the CRD oracle) for which the scanner is made to answer PASS: a fabricated scanner result (exit 0 or a PASS-like
verdict, no findings) is handed to the oracle's own classifier. The scanner itself is never changed and never run. The classifier
must answer WRONGPASS; a seed it does not flag is an UNCAUGHT seed and the run is a hard failure (WRONGPASS class).

Trust: this file, the frozen pairs and the registries below are part of the oracle (digested by qalib.oracle_digest). They are
loaded from the installed qa-auto directory (base), never from the checked-out candidate: the runner refuses to run when this
file lies inside the candidate source tree or the per-run scratch, and when QA_SEEDS_DIGEST (a pinned digest) is set and differs.
Classifier code is the installed crd_oracle / k8s_oracle / qalib; the rule registry and the Kubernetes removal facts the
classifier consults are replaced by the frozen ones below, so a candidate rules.json cannot change what a seed means.

usage: seeds.py --out seeded.json [--src CANDIDATE_SRC]
writes {"digest","total","caught","uncaught":[ids],"ids":[ids],"error":null|text}; exit 0 all caught, 2 a seed uncaught, 3 refused/crashed.
"""
import argparse, hashlib, json, os, sys
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# ---- frozen classifier inputs (never read from the candidate) -----------------------------------------------------------
K8S = "kubernetes"
K8S_FAMILY = "kubernetes.removed_served_gvk"
CRD_FAMILY = "crd.custom_resource_versions"
CRD_PROJECT = "seedproj"
FROZEN_REGISTRY = {
    "seed.crd.version": {"project": CRD_PROJECT, "rule": {
        "id": "seed.crd.version", "operator": "forbid_set_member",
        "setCondition": {"factId": "component.seedproj.custom_resource_versions_set",
                         "members": ["versioned.example/v1beta1/Old"]}}},
    "seed.k8s.removed": {"project": K8S, "rule": {
        "id": "seed.k8s.removed", "operator": "forbid_predicate_value",
        "condition": {"factId": "component.kubernetes.removed_gvk_present"}}},
}
FROZEN_REMOVAL_FACTS = {"component.kubernetes.removed_gvk_present": [
    "extensions/v1beta1/Ingress", "policy/v1beta1/PodSecurityPolicy", "batch/v1beta1/CronJob"]}

# real removals: the Ingress and PodSecurityPolicy/CronJob beta APIs are gone from 1.22 / 1.25
INGRESS = ["extensions", "v1beta1", "Ingress"]
PSP = ["policy", "v1beta1", "PodSecurityPolicy"]
CRONJOB = ["batch", "v1beta1", "CronJob"]
WHOLE = ["gone.example", "v1", "Gone"]
WHOLE2 = ["gone.example", "v1", "AlsoGone"]
VERSION = ["versioned.example", "v1beta1", "Old"]

PASS0 = {"verdict": "PASS", "findings": [], "gaps": [], "paths": []}
SCP = {"verdict": "SCOPE_COMPLETE_PASS", "findings": [], "gaps": [], "paths": []}


def family_pass(component, family):
    """UNKNOWN/BLOCKED aggregate verdict that hides a PASS family status for the component."""
    return {"verdict": "UNKNOWN", "findings": [], "gaps": [],
            "paths": [{"component": component, "hops": [{"index": 0, "families": [{"family": family, "status": "PASS"}]}]}]}


# ---- seeds: id, check kind, fabricated scanner result, expected-removal pair -------------------------------------------
SEEDS = [
    # CRD oracle, whole-CRD design class
    {"id": "crd-whole-exit0-pass", "kind": "crd_pair", "code": 0, "report": PASS0, "removed": [WHOLE], "whole": [WHOLE]},
    {"id": "crd-whole-two-scope-complete-pass", "kind": "crd_pair", "code": 0, "report": SCP, "removed": [WHOLE, WHOLE2],
     "whole": [WHOLE, WHOLE2]},
    {"id": "crd-whole-unknown-family-pass-masked", "kind": "crd_pair", "code": 11, "report": family_pass(CRD_PROJECT, CRD_FAMILY),
     "removed": [WHOLE], "whole": [WHOLE]},
    # CRD oracle, version level
    {"id": "crd-version-exit0-pass", "kind": "crd_pair", "code": 0, "report": PASS0, "removed": [VERSION], "whole": []},
    {"id": "crd-version-verdict-pass-exit11", "kind": "crd_pair", "code": 11, "report": SCP, "removed": [VERSION], "whole": []},
    # CRD oracle, mixed set
    {"id": "crd-mixed-exit0-pass", "kind": "crd_pair", "code": 0, "report": PASS0, "removed": [WHOLE, VERSION], "whole": [WHOLE]},
    {"id": "crd-mixed-blocked-family-pass", "kind": "crd_pair", "code": 10,
     "report": dict(family_pass(CRD_PROJECT, CRD_FAMILY), verdict="BLOCKED"), "removed": [WHOLE, VERSION], "whole": [WHOLE]},
    # Kubernetes removed-API scans (range / single)
    {"id": "k8s-single-exit0-pass", "kind": "k8s_scan", "code": 0, "report": PASS0, "removed": [INGRESS]},
    {"id": "k8s-range-family-pass-masked", "kind": "k8s_scan", "code": 11, "report": family_pass(K8S, K8S_FAMILY),
     "removed": [INGRESS, PSP, CRONJOB]},
    # Kubernetes plan stage checks
    {"id": "k8s-plan-stage-scan-pass", "kind": "k8s_stage", "code": 0, "report": PASS0, "stage_verdict": "BLOCKED",
     "removed": [PSP]},
    {"id": "k8s-plan-stage-verdict-pass", "kind": "k8s_stage", "code": 10, "report": {"verdict": "BLOCKED", "findings": [], "paths": []},
     "stage_verdict": "SCOPE_COMPLETE_PASS", "removed": [CRONJOB]},
    {"id": "k8s-plan-overall-pass", "kind": "k8s_overall", "code": 0, "report": PASS0, "removed": [PSP]},
    # rules oracle
    {"id": "rules-control-exit0-pass", "kind": "rules_control", "code": 0, "removed": []},
    {"id": "rules-variant-exit0-pass", "kind": "rules_variant", "code": 0, "variant": "enc.bom", "removed": []},
]


def seeds_file_digest(path=None):
    with open(path or os.path.abspath(__file__), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _stage(seed):
    removed = [tuple(x) for x in seed["removed"]]
    return {"from": "1.24", "to": "1.25", "index": 0, "verdict": seed["stage_verdict"], "component": K8S,
            "findings": [], "gaps": []}, removed


def evaluate(seed):
    """True when the oracle's classifier flags this seed as a WRONGPASS. Imports the installed classifier lazily."""
    import crd_oracle, k8s_oracle, qalib
    kind = seed["kind"]
    with mock.patch.object(qalib, "claim_registry", return_value=FROZEN_REGISTRY), \
            mock.patch.object(qalib, "kubernetes_removal_facts", return_value=FROZEN_REMOVAL_FACTS):
        removed = [tuple(x) for x in seed["removed"]]
        if kind == "crd_pair":
            whole = [tuple(x) for x in seed["whole"]]
            result = crd_oracle.classify_pair(seed["code"], seed["report"], removed, whole, CRD_PROJECT,
                                              later_groups=set())
            return result[0] is True
        if kind == "k8s_scan":
            wp, _mm, _missing, _statuses = qalib.scoped_result(seed["code"], seed["report"], removed, K8S, K8S_FAMILY)
            return wp is True
        if kind == "k8s_stage":
            stage, removed = _stage(seed)
            wp, _mm, _missing, _statuses, _complete = k8s_oracle.plan_stage_outcome(stage, seed["code"], seed["report"], removed, True)
            return wp is True
        if kind == "k8s_overall":
            return k8s_oracle.plan_overall_wrongpass(True, seed["code"], seed["report"]) is True
        if kind == "rules_control":
            return qalib.rules_control_wrongpass(seed["code"]) is True
        if kind == "rules_variant":
            import corpus
            if seed["variant"] in corpus.PASS_OK:
                raise ValueError("seed variant may legitimately PASS")
            return qalib.rules_variant_wrongpass(seed["code"], seed["variant"], corpus.PASS_OK) is True
    raise ValueError("unknown seed kind " + repr(kind))


def run_all(seeds=None):
    """(caught ids, uncaught ids); an exception while evaluating a seed counts as uncaught, never as caught."""
    caught, uncaught = [], []
    for seed in (SEEDS if seeds is None else seeds):
        try:
            ok = evaluate(seed)
        except Exception:
            ok = False
        (caught if ok else uncaught).append(seed["id"])
    return caught, uncaught


def check_unique_ids(seeds=None):
    ids = [s["id"] for s in (SEEDS if seeds is None else seeds)]
    return bool(ids) and len(ids) == len(set(ids)) and all(isinstance(i, str) and i for i in ids)


def refuse_candidate_source(candidate_dirs, own=None):
    """Raise when this file lies inside a candidate source tree or the per-run scratch (a seed set must come from the base)."""
    own = os.path.realpath(own or os.path.abspath(__file__))
    for d in candidate_dirs:
        if not d:
            continue
        root = os.path.realpath(d)
        if own == root or own.startswith(root.rstrip(os.sep) + os.sep):
            raise PermissionError("seed file lies inside the candidate tree " + d)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--src", default="")
    a = ap.parse_args(argv)
    digest = seeds_file_digest()
    out = {"digest": digest, "total": len(SEEDS), "caught": 0, "uncaught": [], "ids": [s["id"] for s in SEEDS], "error": None}
    code = 3
    try:
        refuse_candidate_source([a.src, os.environ.get("QA_SRC", ""), os.environ.get("QA_BOX_DIR", "")])
        pinned = os.environ.get("QA_SEEDS_DIGEST", "")
        if pinned and pinned != digest:
            raise PermissionError("seed file digest differs from the pinned QA_SEEDS_DIGEST")
        if not check_unique_ids():
            raise ValueError("seed ids empty, duplicated or malformed")
        caught, uncaught = run_all()
        out.update(caught=len(caught), uncaught=uncaught)
        code = 0 if not uncaught else 2
    except Exception as error:  # fail closed: nothing proven, caught stays 0
        out.update(caught=0, error=f"{type(error).__name__}: {error}"[:300])
    tmp = a.out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(out, f, indent=1)
    os.replace(tmp, a.out)
    print("SEEDED=%d/%d%s" % (out["caught"], out["total"], (" uncaught=" + ",".join(out["uncaught"])) if out["uncaught"] else "")
          + ((" error=" + out["error"]) if out["error"] else ""))
    return code


if __name__ == "__main__":
    sys.exit(main())
