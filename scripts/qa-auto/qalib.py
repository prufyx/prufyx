"""Shared helpers for the qa-auto oracle suites. Python 3 stdlib only.

Environment (set by run.sh): QA_BIN prufyx binary, QA_CRDGVK helper binary,
QA_SRC source checkout, QA_CACHE persistent cache (bare clones, swagger),
QA_NOW pinned scan time, QA_TMP per-run scratch.
A case is {"suite","key","wrongpass","mismatch","error","detail"}.
"""
import hashlib, json, os, re, shlex, subprocess, sys
from functools import lru_cache

ENV = os.environ.get
BIN = ENV("QA_BIN", "prufyx")
CRDGVK = ENV("QA_CRDGVK", "crdgvk")
SRC = ENV("QA_SRC", ".")
CACHE = ENV("QA_CACHE", "/tmp/qa-auto-cache")
TMP = ENV("QA_TMP", "/tmp/qa-auto-tmp")
NOW = ENV("QA_NOW", "")
SCAN_FLAGS = ["--format", "json", "--distribution", "official_upstream",
              "--resource-scope-complete", "--target-api-apply-required"]


RUNBOX = ENV("QA_RUNBOX", "")  # command prefix (word-split) that runs head-built binaries in a throwaway sandbox


def boxed(a):
    """argv with the QA_RUNBOX prefix when it runs a binary built from the PR head (QA_BIN / QA_CRDGVK)."""
    a = list(a)
    if RUNBOX and a and a[0] in (BIN, CRDGVK):
        return shlex.split(RUNBOX) + a
    return a


def sh(*a, inp=None, cwd=None):
    return subprocess.run(boxed(a), input=inp, capture_output=True, text=True, cwd=cwd)


def vkey(t):
    return tuple(int(x) for x in re.findall(r"\d+", t))


def object_name(g, v, k):
    return "qa-" + hashlib.sha256(json.dumps([g, v, k]).encode()).hexdigest()[:24]


def doc(g, v, k, name=None):
    av = f"{g}/{v}" if g else v
    name = name or object_name(g, v, k)
    return f"apiVersion: {av}\nkind: {k}\nmetadata:\n  name: {name}\n  namespace: default\n"


def write_private(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, 0o600)


def prufyx(cmd, path, frm, to, bin_=None):
    """Run `prufyx scan|plan`; returns (exit, parsed-json-or-None, stderr tail)."""
    args = [bin_ or BIN, cmd, path, "--from", frm, "--to", to] + SCAN_FLAGS
    if NOW:
        args += ["--now", NOW]
    try:
        r = subprocess.run(boxed(args), capture_output=True, text=True, timeout=float(ENV("QA_SCAN_TIMEOUT", "120")))
    except (OSError, subprocess.TimeoutExpired) as e:
        return 124, None, type(e).__name__
    try:
        j = json.loads(r.stdout)
        if not isinstance(j, dict) or r.returncode not in (0, 10, 11, 2, 3):
            j = None
    except Exception:
        j = None
    return r.returncode, j, (r.stdout[:200] + r.stderr[:200]).replace("\n", " ")


def is_pass(code, j):
    """exit 0 or any PASS-like verdict (PASS, SCOPE_COMPLETE_PASS, ...)"""
    return code == 0 or "PASS" in str((j or {}).get("verdict"))


def case(suite, key, wrongpass=False, mismatch=False, error=False, **detail):
    return {"suite": suite, "key": key, "wrongpass": bool(wrongpass),
            "mismatch": bool(mismatch), "error": bool(error), "detail": detail}


def dump(cases, path):
    with open(path, "w") as f:
        json.dump(cases, f)


def unowned_removals(cases):
    """Number of unowned removals (group/kind entries) in the clean UNOWNED_REMOVAL_UNKNOWN cases."""
    return sum(len(c["detail"].get("unownedRemoved") or []) for c in cases
               if c.get("detail", {}).get("status") == "UNOWNED_REMOVAL_UNKNOWN" and not c["error"])


def counts(cases):
    n = {k: sum(1 for c in cases if c[k]) for k in ("wrongpass", "mismatch", "error")}
    unsupported = sum(1 for c in cases if c.get("detail", {}).get("status") == "UNSUPPORTED_COMMUNITY")
    if unsupported:
        n["unsupported_community"] = unsupported
    design = sum(1 for c in cases if c.get("detail", {}).get("status") == "DESIGN_UNKNOWN_WHOLE_CRD_REMOVAL" and not c["error"])
    if design:
        n["design_unknown_whole_crd_removal"] = design
    unowned = unowned_removals(cases)
    if unowned:
        n["unowned_removal_unknown"] = unowned
    return n


@lru_cache(maxsize=1)
def claim_registry():
    with open(os.path.join(SRC, "cli/internal/cncfcheck/data/rules.json")) as rules_file:
        entries = json.load(rules_file)["entries"]
    registry = {entry["rule"]["id"]: entry for entry in entries}
    if len(registry) != len(entries):
        raise ValueError("duplicate rule identifiers")
    return registry


@lru_cache(maxsize=1)
def kubernetes_removal_facts():
    result = sh(CRDGVK, "-removal-facts")
    if result.returncode:
        raise ValueError("Kubernetes removal fact map unreadable")
    facts = json.loads(result.stdout)
    if not isinstance(facts, dict) or not facts:
        raise ValueError("Kubernetes removal fact map empty")
    return facts


def removal_claim(rule_id, component, family, member):
    entry = claim_registry().get(rule_id, {})
    rule = entry.get("rule", {})
    if entry.get("project") != component:
        return False
    if family == "crd.custom_resource_versions":
        condition = rule.get("setCondition", {})
        return (rule.get("operator") == "forbid_set_member" and
                condition.get("factId", "").endswith(".custom_resource_versions_set") and
                member in condition.get("members", []))
    condition = rule.get("condition", {})
    return (rule.get("operator") == "forbid_predicate_value" and
            re.fullmatch(r"component\.kubernetes\.[a-z0-9_]+_removed_gvk_present",
                         condition.get("factId", "")) is not None and
            member in kubernetes_removal_facts().get(condition["factId"], []))


def scoped_result(code, report, removed, component, family):
    """Compare exact synthetic GVK objects and their component's scoped claims."""
    paths = [p for p in report.get("paths", []) if p.get("component") == component]
    statuses = [f.get("status") for p in paths for h in p.get("hops", [])
                for f in h.get("families", []) if f.get("family") == family]
    missing = []
    for g, v, k in removed:
        if not any(f.get("component") == component and
                   removal_claim(f.get("ruleId"), component, family, "/".join((g, v, k))) and
                   any(loc.get("kind") == k and loc.get("name") == object_name(g, v, k)
                       for loc in f.get("locations", [])) for f in report.get("findings", [])):
            missing.append("/".join((g, v, k)))
    wp = bool(removed) and (is_pass(code, report) or "PASS" in statuses)
    mismatch = bool(missing) or (not removed and any(
        f.get("component") == component for f in report.get("findings", [])))
    return wp, mismatch and not wp, missing, statuses


def complete_scan_scope(report, requested):
    """Every supplied synthetic document must be read without an intake omission."""
    summary = report.get("summary", {})
    observed = summary.get("documentsRead")
    omitted_count = summary.get("documentsOmitted")
    omitted = report.get("omitted")
    return (type(observed) is int and observed == requested and
            type(omitted_count) is int and omitted_count == 0 and
            isinstance(omitted, list) and not omitted)


def oracle_digest():
    """sha256 over the oracle's own sources (crd_oracle.py, summarize.py, qalib.py, qa_scope.py, qa_batch_scope.py): a change resets the rise baselines."""
    here = os.path.dirname(os.path.abspath(__file__))
    digest = hashlib.sha256()
    for name in ("crd_oracle.py", "summarize.py", "qalib.py", "qa_scope.py", "qa_batch_scope.py"):
        with open(os.path.join(here, name), "rb") as src:
            digest.update(hashlib.sha256(src.read()).digest())
    return digest.hexdigest()


def case_sig(c):
    """Fingerprint of the nature of a mismatch: sha256 of the sorted missing list, status, verdict and scan exit code.
    A known-gap entry registered with this sig stops covering the case when any of them changes."""
    d = c.get("detail", {})
    blob = json.dumps([sorted(d.get("missing") or []), d.get("status"), d.get("verdict"), d.get("exit")], sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


if __name__ == "__main__":
    # usage: python3 qalib.py sig RESULTS_DIR "suite|key"   prints the sig to put into known-gaps.json
    import glob
    if len(sys.argv) != 4 or sys.argv[1] != "sig":
        raise SystemExit("usage: qalib.py sig RESULTS_DIR suite|key")
    found = [c for f in sorted(glob.glob(sys.argv[2] + "/*.cases.json")) for c in json.load(open(f))
             if f"{c['suite']}|{c['key']}" == sys.argv[3] and c.get("mismatch")]
    if len(found) != 1:
        raise SystemExit(f"expected exactly one mismatch case for {sys.argv[3]}, found {len(found)}")
    print(case_sig(found[0]))
