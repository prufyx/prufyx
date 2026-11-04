"""Trusted Git-derived scope for a single onboarding batch or a data-only run."""
import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

BASE_REF = "refs/qa-batch/base"
HEAD_REF = "refs/qa-batch/head"
TARGET_DIR = "cli/internal/extract/crdversions/"
BATCH_DIR = "cli/knowledge/onboarding/"
SCHEMA = "prufyx.io/qa-batch-scope/v1"


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("SCOPE_INVALID: duplicate JSON member")
        value[key] = item
    return value


def parse(raw):
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("SCOPE_INVALID: JSON exceeds scope limit")
    try:
        return json.loads(raw, object_pairs_hook=unique_object)
    except RecursionError as error:
        raise ValueError("SCOPE_INVALID: JSON nesting exceeds scope limit") from error


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def git(src, *args):
    return subprocess.check_output(["git", "-C", str(src), *args], stderr=subprocess.PIPE).decode().strip()


def blob(src, ref, path):
    entry = git(src, "ls-tree", ref, "--", path).split()
    if len(entry) != 4 or entry[0:2] != ["100644", "blob"] or entry[3] != path:
        raise ValueError("UNSUPPORTED_SCOPE: missing or nonregular artifact " + path)
    raw = subprocess.check_output(["git", "-C", str(src), "cat-file", "blob", entry[2]], stderr=subprocess.PIPE)
    return entry[2], raw


def proof_target(project, pair):
    return "crd-proof|" + "|".join([project] + [pair[k] for k in ("fromTag", "fromCommit", "toTag", "toCommit")])


def freeze(src, head, base, run_id, extra_projects=()):
    from select_projects import selection
    if (not re.fullmatch(r"[0-9a-f]{40}", head) or not re.fullmatch(r"[0-9a-f]{40}", base)
            or not run_id or len(run_id) > 128):
        raise ValueError("SCOPE_PROVENANCE: exact head/base/run required")
    if git(src, "rev-parse", HEAD_REF + "^{commit}") != head or git(src, "rev-parse", BASE_REF + "^{commit}") != base:
        raise ValueError("SCOPE_PROVENANCE: fixed refs differ")
    if git(src, "rev-parse", "HEAD") != head:
        raise ValueError("SCOPE_PROVENANCE: checkout differs from fetched head")
    changed = git(src, "diff", "--name-only", "--no-renames", base, head).splitlines()
    paths = git(src, "ls-tree", "-r", "--name-only", head, "--", TARGET_DIR).splitlines()
    slugs = sorted(p[len(TARGET_DIR + "target-"):-5] for p in paths
                   if re.fullmatch(re.escape(TARGET_DIR) + r"target-[a-z0-9-]+\.json", p))
    selected = selection(changed, slugs)
    projects = set(slugs if selected["mode"] == "full" else selected["projects"]) | set(extra_projects)
    batch_paths = [p for p in changed if p.startswith(BATCH_DIR)]
    envelopes = []
    if batch_paths:
        if len(batch_paths) != 1 or not re.fullmatch(re.escape(BATCH_DIR) + r"ob-[0-9]{8}-[1-9][0-9]{0,2}\.json", batch_paths[0]):
            raise ValueError("UNSUPPORTED_SCOPE: exactly one added onboarding envelope required")
        path = batch_paths[0]
        if git(src, "ls-tree", base, "--", path):
            raise ValueError("UNSUPPORTED_SCOPE: onboarding envelope is not added")
        oid, raw = blob(src, HEAD_REF, path)
        envelope = parse(raw)
        if not isinstance(envelope, dict) or envelope.get("schema") != "prufyx.io/knowledge-onboarding-batch/v2":
            raise ValueError("UNSUPPORTED_SCOPE: onboarding schema requires v2")
        declared = envelope["record"]["projects"]
        if not isinstance(declared, list) or not 1 <= len(declared) <= 15:
            raise ValueError("SCOPE_INVALID: project list empty or over limit")
        seen, bindings = set(), []
        for project in declared:
            slug = project["slug"]
            if (not isinstance(slug, str) or not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", slug)
                    or len(slug) > 100 or slug in seen):
                raise ValueError("SCOPE_INVALID: invalid or duplicate project")
            seen.add(slug)
            if project["kind"] != "new" or project["catalog"] not in ("cncf", "community"):
                raise ValueError("UNSUPPORTED_SCOPE: project kind/catalog")
            target_path = TARGET_DIR + "target-" + slug + ".json"
            target_blob, target_raw = blob(src, HEAD_REF, target_path)
            expected_artifact = {"path": target_path, "digest": "sha256:" + hashlib.sha256(target_raw).hexdigest()}
            if project["artifacts"] != [expected_artifact]:
                raise ValueError("SCOPE_MISMATCH: target artifact differs")
            target = parse(target_raw)
            if (not isinstance(target, dict) or target.get("schema") != "prufyx.io/crd-version-target/v1"
                    or not isinstance(target.get("target"), dict) or target["target"].get("project") != slug):
                raise ValueError("UNSUPPORTED_SCOPE: target schema/project")
            pair = project["proof"]["pair"]
            if (set(pair) != {"fromTag", "fromCommit", "toTag", "toCommit"}
                    or any(not isinstance(pair[k], str) or not re.fullmatch(r"[0-9a-f]{40}", pair[k]) for k in ("fromCommit", "toCommit"))
                    or any(not isinstance(pair[k], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", pair[k]) for k in ("fromTag", "toTag"))):
                raise ValueError("SCOPE_INVALID: exact proof pair required")
            bindings.append({"slug": slug, "kind": project["kind"], "catalog": project["catalog"],
                             "target": {"path": target_path, "blob": target_blob, "mode": "100644", "spec": target["target"], **expected_artifact},
                             "proof": {"pair": pair}})
            projects.add(slug)
        envelopes.append({"path": path, "blob": oid, "mode": "100644", "digest": hashlib.sha256(raw).hexdigest(), "projects": bindings})
    if not projects <= set(slugs):
        raise ValueError("UNSUPPORTED_SCOPE: selected project target missing")
    return dict(schema=SCHEMA, head=head, base=base, run_id=run_id, mode=selected["mode"],
                source_tree=git(src, "rev-parse", head + "^{tree}"), projects=sorted(projects),
                envelopes=envelopes, extra_projects=sorted(set(extra_projects)),
                suites=["crd", "k8s", "bp325", "review", "rules"], kind="not_executed", db="not_executed")


def environment_contract():
    path = os.environ.get("QA_BATCH_SCOPE_FILE", "")
    if not path:
        return None
    value = parse(Path(path).read_bytes())
    if digest(value) != os.environ.get("QA_BATCH_SCOPE_DIGEST"):
        raise ValueError("SCOPE_MISMATCH: frozen contract differs from trusted parent")
    return value


def required_pairs(contract):
    return [(p["slug"], p["proof"]["pair"]) for e in contract["envelopes"] for p in e["projects"]]


def validate(contract, scopes, cases, declarations):
    """Never let markers or a rewritten self-digest stand in for execution."""
    import qa_scope
    errors = qa_scope.bundle_errors(scopes, contract["head"], contract["base"], contract["run_id"])
    for suite in contract["suites"]:
        if not any(c.get("suite", "").split("-")[0] == suite for c in cases):
            errors.append("SCOPE_INCOMPLETE: missing suite " + suite)
    if not contract["envelopes"]:
        return errors
    for suite in ("crd", "k8s"):
        scope, declared = scopes.get(suite, {}), declarations.get(suite, {})
        if any(scope.get(k) != declared.get(k) for k in qa_scope.DECLARED_FIELDS):
            errors.append("SCOPE_MISMATCH: original declaration differs " + suite)
    crd = scopes.get("crd", {})
    required = {"crd-project|" + p for p in contract["projects"]}
    required.update(proof_target(project, pair) for project, pair in required_pairs(contract))
    if not required <= set(crd.get("required", [])) or not required <= set(crd.get("executed", [])):
        errors.append("SCOPE_INCOMPLETE: frozen required project/pair missing")
    # Every requested exact scan needs its original case, including failed cases.
    for target in crd.get("required", []):
        if target.startswith("crd|"):
            key = target[len("crd|"):]
        elif target.startswith("crd-proof|"):
            key = target
        else:
            continue
        matching = [c for c in cases if c.get("suite") == "crd" and c.get("key") == key]
        if len(matching) != 1:
            errors.append("SCOPE_INCOMPLETE: exact scan case missing or duplicated " + target)
    for project, pair in required_pairs(contract):
        matching = [c for c in cases if c.get("suite") == "crd" and c.get("key") == proof_target(project, pair)]
        if len(matching) != 1:
            continue
        case = matching[0]
        detail = case.get("detail", {})
        if (detail.get("proof_pair") != pair or type(detail.get("requested")) is not int or detail["requested"] <= 0
                or detail.get("executed") != detail["requested"] or case.get("error") is not False):
            errors.append("SCOPE_INCOMPLETE: exact proof pair did not execute completely")
    return errors


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    try:
        value = freeze(args.src, args.head, args.base, args.run_id,
                       [p for p in os.environ.get("QA_PROJECTS", "").split(",") if p])
        Path(args.out).write_text(json.dumps(value, sort_keys=True) + "\n")
        print(digest(value))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        ap.exit(3, "SCOPE_INVALID: " + str(error) + "\n")
