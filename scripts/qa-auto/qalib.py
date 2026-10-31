"""Shared helpers for the qa-auto oracle suites. Python 3 stdlib only.

Environment (set by run.sh): QA_BIN prufyx binary, QA_CRDGVK helper binary,
QA_SRC source checkout, QA_CACHE persistent cache (bare clones, swagger),
QA_NOW pinned scan time, QA_TMP per-run scratch.
A case is {"suite","key","wrongpass","mismatch","error","detail"}.
"""
import json, os, re, subprocess, sys

ENV = os.environ.get
BIN = ENV("QA_BIN", "prufyx")
CRDGVK = ENV("QA_CRDGVK", "crdgvk")
SRC = ENV("QA_SRC", ".")
CACHE = ENV("QA_CACHE", "/tmp/qa-auto-cache")
TMP = ENV("QA_TMP", "/tmp/qa-auto-tmp")
NOW = ENV("QA_NOW", "")
SCAN_FLAGS = ["--format", "json", "--distribution", "official_upstream",
              "--resource-scope-complete", "--target-api-apply-required"]


def sh(*a, inp=None, cwd=None):
    return subprocess.run(a, input=inp, capture_output=True, text=True, cwd=cwd)


def vkey(t):
    return tuple(int(x) for x in re.findall(r"\d+", t))


def doc(g, v, k, name=None):
    av = f"{g}/{v}" if g else v
    name = name or f"qa-{k.lower()}-{v}-{(g or 'core').replace('.', '-')}"
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
    r = sh(*args)
    try:
        j = json.loads(r.stdout)
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
