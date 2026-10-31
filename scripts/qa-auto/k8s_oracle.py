#!/usr/bin/env python3
"""Kubernetes removed-API oracle from upstream swagger.json (GVK set per minor).

usage: k8s_oracle.py --out cases.json [--lo 20] [--hi 37]
Suites: k8s-range (all GVKs of minor m, scan m -> m+1), k8s-single (each removed
non-alpha GVK alone), k8s-plan (multi-hop `prufyx plan`, per-stage verdicts).
WRONGPASS: a removed GVK is in the input and scan/plan exits 0 / says PASS.
"""
import argparse, json, os, sys, urllib.request
from qalib import *

SKIP_KINDS = ("DeleteOptions", "WatchEvent", "Status", "CreateOptions", "UpdateOptions",
              "PatchOptions", "Scale", "Eviction", "Binding", "EphemeralContainers")
_sw = {}


def swagger(m):
    if m in _sw:
        return _sw[m]
    fn = f"{CACHE}/k8s-{m}.json"
    if not os.path.exists(fn):
        os.makedirs(CACHE, exist_ok=True)
        url = f"https://raw.githubusercontent.com/kubernetes/kubernetes/v1.{m}.0/api/openapi-spec/swagger.json"
        data = urllib.request.urlopen(url, timeout=120).read()
        open(fn + ".part", "wb").write(data)
        os.replace(fn + ".part", fn)
    s = set()
    for df in json.load(open(fn))["definitions"].values():
        for g in df.get("x-kubernetes-group-version-kind", []):
            k = g["kind"]
            if k.endswith("List") or k in SKIP_KINDS:
                continue
            s.add((g["group"], g["version"], k))
    _sw[m] = s
    return s


def inp(gvks, name):
    fn = f"{TMP}/k8s/{name}.yaml"
    write_private(fn, "---\n".join(doc(g, v, k) for (g, v, k) in sorted(gvks)))
    return fn


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--lo", type=int, default=int(ENV("QA_K8S_LO", "20")))
    ap.add_argument("--hi", type=int, default=int(ENV("QA_K8S_HI", "37")))
    a = ap.parse_args()
    hi = a.hi
    try:
        swagger(hi)
    except Exception:
        hi -= 1  # newest minor not published yet
    cases = []
    for m in range(a.lo, hi):
        sa, sb = swagger(m), swagger(m + 1)
        removed = sorted(sa - sb)
        fr, to = f"kubernetes=1.{m}.0", f"kubernetes=1.{m+1}.0"
        code, j, tail = prufyx("scan", inp(sa, "range"), fr, to)
        key = f"1.{m}->1.{m+1}"
        if j is None:
            cases.append(case("k8s-range", key, error=True, why=tail))
        else:
            txt = json.dumps(j.get("findings", []))
            miss = [x for x in removed if "alpha" not in x[1] and not (x[2] in txt and x[1] in txt)]
            cases.append(case("k8s-range", key, wrongpass=bool(removed) and is_pass(code, j),
                              mismatch=bool(miss) and not is_pass(code, j), exit=code,
                              verdict=j.get("verdict"), removed=len(removed), notMentioned=["/".join(x) for x in miss[:12]]))
        for x in removed:
            if "alpha" in x[1]:
                continue
            code, j, tail = prufyx("scan", inp({x}, "single"), fr, to)
            key = f"1.{m}->1.{m+1} {'/'.join(x)}"
            if j is None:
                cases.append(case("k8s-single", key, error=True, why=tail))
            else:
                cases.append(case("k8s-single", key, wrongpass=is_pass(code, j),
                                  mismatch=j.get("verdict") not in ("BLOCKED", "UNKNOWN") and not is_pass(code, j),
                                  exit=code, verdict=j.get("verdict")))
    for lo, h in [(20, 30), (24, 37), (30, 37), (28, 29), (36, 37)]:
        if lo < a.lo or h > hi:
            continue
        gv = {x for x in swagger(lo) if "alpha" not in x[1]}
        code, j, tail = prufyx("plan", inp(gv, "plan"), f"kubernetes=1.{lo}.0", f"kubernetes=1.{h}.0")
        if j is None:
            cases.append(case("k8s-plan", f"1.{lo}->1.{h}", error=True, why=tail))
            continue
        anyexp = False
        for s in j.get("stages", []):
            k = int(s["to"].split(".")[1])
            exp = sorted(x for x in (swagger(k - 1) - swagger(k)) if x in gv)
            anyexp |= bool(exp)
            got = s["verdict"]
            cases.append(case("k8s-plan", f"1.{lo}->1.{h} stage {s['from']}->{s['to']}",
                              wrongpass=bool(exp) and "PASS" in got,
                              mismatch=(got == "BLOCKED") != bool(exp) and "PASS" not in got and got != "UNKNOWN",
                              verdict=got, expectedBlocked=bool(exp)))
        cases.append(case("k8s-plan", f"1.{lo}->1.{h} overall", wrongpass=anyexp and is_pass(code, j),
                          exit=code, verdict=j.get("verdict")))
    dump(cases, a.out)
    print("k8s total", json.dumps(counts(cases)), "cases", len(cases))


if __name__ == "__main__":
    main()
