#!/usr/bin/env python3
"""CRD oracle: served CRD GVKs at real upstream tags vs `prufyx scan`.

usage: crd_oracle.py --out cases.json [--projects a,b | --all] [--jobs N]
Targets come from $QA_SRC/cli/internal/extract/crdversions/target-*.json,
pairs from $QA_COV (coverage report, every pair forced to A) or, when a project
is not in it, from consecutive minor lines found in the tags.
WRONGPASS: a served GVK is gone at TO and the scan exits 0 / says PASS.
MISMATCH: any other disagreement (missed finding, false finding, CRD family not PASS).
"""
import argparse, glob, json, os, re, shutil, sys
from concurrent.futures import ThreadPoolExecutor
from qalib import *

TD = os.path.join(SRC, "cli/internal/extract/crdversions")
COV = ENV("QA_COV", "")


def projects_all():
    return sorted(re.sub(r"^target-|\.json$", "", os.path.basename(p)) for p in glob.glob(TD + "/target-*.json"))


def crd_text(tj, gd, tag):
    """Concatenated CRD YAML of one project at one tag (from the bare clone gd)."""
    txt = ""
    for p in tj["paths"]:
        if p.get("directory"):
            fl = sh("git", "-C", gd, "ls-tree", "-r", "--name-only", tag, p["path"] + "/").stdout.split()
            fl = [f for f in fl if re.search(p["match"], f.split("/")[-1])]
        else:
            fl = [p["path"]]
        for f in fl:
            txt += "\n---\n" + sh("git", "-C", gd, "show", f"{tag}:{f}").stdout
    return txt


def run(proj, cov):
    S = "crd"
    try:
        tj = json.load(open(f"{TD}/target-{proj}.json"))["target"]
    except Exception as e:
        return [case(S, proj, error=True, why="target unreadable: %s" % e)]
    repo = tj["repo"].replace("github.com/", "")
    gd = f"{CACHE}/git/{proj}.git"
    os.makedirs(os.path.dirname(gd), exist_ok=True)
    if not os.path.isdir(gd):
        r = sh("git", "clone", "-q", "--bare", "--filter=blob:none", f"https://github.com/{repo}.git", gd)
        if r.returncode:
            shutil.rmtree(gd, ignore_errors=True)
            return [case(S, proj, error=True, why="clone: " + r.stderr[:200])]
    r = sh("git", "-C", gd, "fetch", "-q", "--tags", "--force")
    if r.returncode:
        return [case(S, proj, error=True, why="fetch tags: " + r.stderr[:200])]
    pref = tj["tagPrefixes"][0]
    tags = sh("git", "-C", gd, "tag", "-l").stdout.split()
    lines = {}
    for t in tags:
        if re.fullmatch(re.escape(pref) + r"\d+\.\d+\.\d+", t):
            lines.setdefault(vkey(t)[:2], []).append(t)
    for l in lines:
        lines[l].sort(key=vkey)
    cache = {}

    def served(tag):
        if tag not in cache:
            r = sh(CRDGVK, inp=crd_text(tj, gd, tag))
            cache[tag] = {(x["G"], x["V"], x["K"]) for x in json.loads(r.stdout) if x["Served"]}
        return cache[tag]

    comp = next((x for x in cov if x["project"] == proj), None)
    if comp is None:
        ls = sorted(lines)
        pairs = [{"from": ".".join(map(str, a)), "to": ".".join(map(str, b))} for a, b in zip(ls, ls[1:])]
    else:
        pairs = comp["pairs"]
    out = []
    n = 0
    for pr in pairs:
        l1 = tuple(int(x) for x in pr["from"].split("."))
        l2 = tuple(int(x) for x in pr["to"].split("."))
        if l1 not in lines or l2 not in lines:
            continue
        for f in sorted({lines[l1][0], lines[l1][-1]}, key=vkey):
            sf = served(f)
            docs = "---\n".join(doc(g, v, k) for (g, v, k) in sorted(sf))
            for t in sorted({lines[l2][0], lines[l2][-1]}, key=vkey):
                removed = sorted(sf - served(t))
                n += 1
                fn = f"{TMP}/crd/{proj}-{n}.yaml"
                write_private(fn, docs)
                code, j, tail = prufyx("scan", fn, f"{proj}={f[len(pref):]}", f"{proj}={t[len(pref):]}")
                os.remove(fn)
                key = f"{proj}|{f}|{t}"
                if j is None and "community catalog" in tail:
                    # community-catalog projects are not scanned yet (documented refusal), nothing to compare
                    return [case(S, proj, note="skipped: community catalog, scan does not check it", why=tail[:120])]
                if j is None:
                    out.append(case(S, key, error=True, why=tail))
                    continue
                fnd = j.get("findings", [])
                crd = [x["status"] for p in j.get("paths", []) for h in p.get("hops", [])
                       for x in h.get("families", []) if x.get("family") == "crd.custom_resource_versions"]
                exp = ["/".join(x) for x in removed]
                wp = bool(exp) and is_pass(code, j)
                mm = (not wp) and ((bool(exp) and not fnd) or (not exp and bool(fnd)) or
                                   (not exp and crd != [] and "PASS" not in crd))
                out.append(case(S, key, wrongpass=wp, mismatch=mm, exit=code, verdict=j.get("verdict"),
                                crd=crd, expectRemoved=exp[:200], nExpect=len(exp), nFindings=len(fnd),
                                gaps=sorted({g.get("reason", "") for g in j.get("gaps", [])})[:3]))
    if not out:
        out.append(case(S, proj, error=True, why="no usable pairs"))
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--projects", default="")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--jobs", type=int, default=int(ENV("QA_JOBS", "3")))
    a = ap.parse_args()
    cov = json.load(open(COV))["projects"] if COV and os.path.exists(COV) else []
    ps = projects_all() if a.all or not a.projects else a.projects.split(",")
    cases = []
    with ThreadPoolExecutor(a.jobs) as ex:
        for p, res in zip(ps, ex.map(lambda p: run(p, cov), ps)):
            cases += res
            c = counts(res)
            print(f"crd {p} cases={len(res)} wrongpass={c['wrongpass']} mismatch={c['mismatch']} error={c['error']}", flush=True)
    dump(cases, a.out)
    print("crd total", json.dumps(counts(cases)))
