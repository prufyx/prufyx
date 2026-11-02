"""Shared helpers for the qa-auto oracle suites. Python 3 stdlib only.

Environment (set by run.sh): QA_BIN prufyx binary, QA_CRDGVK helper binary,
QA_SRC source checkout, QA_CACHE persistent cache (bare clones, swagger),
QA_NOW pinned scan time, QA_TMP per-run scratch.
A case is {"suite","key","wrongpass","mismatch","error","detail"}.
"""
import hashlib, json, os, re, shlex, subprocess, sys

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


def counts(cases):
    return {k: sum(1 for c in cases if c[k]) for k in ("wrongpass", "mismatch", "error")}


def scoped_result(code, report, removed, component, family):
    """Compare exact synthetic GVK objects and their component's scoped claims."""
    paths = [p for p in report.get("paths", []) if p.get("component") == component]
    statuses = [f.get("status") for p in paths for h in p.get("hops", [])
                for f in h.get("families", []) if f.get("family") == family]
    missing = []
    for g, v, k in removed:
        if not any(f.get("component") == component and
                   any(loc.get("kind") == k and loc.get("name") == object_name(g, v, k)
                       for loc in f.get("locations", [])) for f in report.get("findings", [])):
            missing.append("/".join((g, v, k)))
    wp = bool(removed) and (is_pass(code, report) or "PASS" in statuses)
    mismatch = bool(missing) or (not removed and any(
        f.get("component") == component for f in report.get("findings", [])))
    return wp, mismatch and not wp, missing, statuses


def complete_scan_scope(report, requested):
    """The scan must acknowledge every supplied synthetic document."""
    observed = report.get("summary", {}).get("documentsRead")
    return type(observed) is int and observed == requested
