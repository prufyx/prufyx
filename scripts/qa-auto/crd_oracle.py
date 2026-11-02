#!/usr/bin/env python3
"""CRD oracle: served CRD GVKs at real upstream tags vs `prufyx scan`.

usage: crd_oracle.py --out cases.json [--projects a,b | --all] [--jobs N]
Targets come from $QA_SRC/cli/internal/extract/crdversions/target-*.json,
pairs from $QA_COV (coverage report, every pair forced to A) or, when a project
is not in it, from consecutive minor lines found in the tags.
WRONGPASS: a served GVK is gone at TO and the scan exits 0 / says PASS.
MISMATCH: any other disagreement (missed finding, false finding, CRD family not PASS).
"""
import argparse, glob, json, os, re, shutil, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
from qalib import *

TD = os.path.join(SRC, "cli/internal/extract/crdversions")
COV = ENV("QA_COV", "")
# PR/gate mode (QA_BASE set): clones of head-named repos go to the per-run scratch, never into the persistent cache,
# so an attacker repo named by a head cannot become the CRD truth of later runs.
GATE = bool(ENV("QA_BASE", ""))
GITROOT = os.path.join(TMP, "git") if GATE else os.path.join(CACHE, "git")
NAME = re.compile(r"[A-Za-z0-9_][\w.-]*", re.A)


def _safe_path(x):
    return (isinstance(x, str) and 0 < len(x) <= 300 and re.fullmatch(r"[A-Za-z0-9_][\w./-]*", x, re.A) is not None
            and ".." not in x.split("/") and not x.startswith("/"))


def validate_target(tj):
    """Fail closed on any target value that could steer git or a regex engine; returns (repo, error)."""
    try:
        repo = str(tj["repo"])
        repo = repo[len("github.com/"):] if repo.startswith("github.com/") else repo
        o, _, n = repo.partition("/")
        if not (NAME.fullmatch(o) and NAME.fullmatch(n)):
            return "", f"repo {repo[:80]!r} is not owner/name"
        prefs = tj["tagPrefixes"]
        if not isinstance(prefs, list) or not prefs or not all(isinstance(x, str) and re.fullmatch(r"[\w./-]*", x, re.A) and not x.startswith("-") for x in prefs):
            return "", "tagPrefixes invalid"
        for p in tj["paths"]:
            if not _safe_path(p.get("path")):
                return "", f"path {str(p.get('path'))[:80]!r} invalid"
            if p.get("directory"):
                m = p["match"]
                if not isinstance(m, str) or len(m) > 200 or "(" in m or "\\" in m and re.search(r"\\[1-9]", m) or re.search(r"[+*}]\?*[+*{]", m) or len(re.findall(r"[*+]|\{\d*,\d*\}", m)) > 2:
                    return "", "match invalid (length, any group, backreference or stacked quantifier or more than 2 unbounded quantifiers)"
                re.compile(m)
        return repo, ""
    except Exception as e:
        return "", f"target invalid: {type(e).__name__}"


def projects_all():
    return sorted(re.sub(r"^target-|\.json$", "", os.path.basename(p)) for p in glob.glob(TD + "/target-*.json"))


class MatchTimeout(Exception):
    pass


_MATCH_CODE = ("import json,re,sys\nd=json.load(sys.stdin)\nr=re.compile(d['m'])\n"
               "print(json.dumps([f for f in d['f'] if len(f.split('/')[-1])<=255 and r.search(f.split('/')[-1])]))")
MATCH_TIMEOUT = float(ENV("QA_MATCH_TIMEOUT", "5"))


def match_names(pattern, files):
    """The target's `match` regex is head-supplied: apply it in a child process under a hard wall-clock bound."""
    try:
        r = subprocess.run([sys.executable, "-I", "-c", _MATCH_CODE], input=json.dumps({"m": pattern, "f": files}),
                           capture_output=True, text=True, timeout=MATCH_TIMEOUT)
        if r.returncode:
            raise ValueError("matcher child failed")
        return json.loads(r.stdout)
    except subprocess.TimeoutExpired:
        raise MatchTimeout(pattern[:80])
    except Exception as e:
        raise MatchTimeout(f"match failed: {type(e).__name__}")


def checked(*args):
    r = sh(*args)
    if r.returncode:
        raise ValueError("command failed: " + " ".join(args[:4]))
    return r.stdout


def crd_text(tj, gd, tag):
    """Concatenated CRD YAML of one project at one tag (from the bare clone gd)."""
    txt = ""
    for p in tj["paths"]:
        if p.get("directory"):
            fl = checked("git", "-C", gd, "ls-tree", "-r", "--name-only", "--end-of-options", tag, p["path"] + "/").splitlines()
            fl = match_names(p["match"], fl)
            if not fl:
                raise ValueError("no files matched requested directory")
        else:
            fl = [p["path"]]
        for f in fl:
            body = checked("git", "-C", gd, "show", "--end-of-options", f"{tag}:{f}")
            if not body.strip():
                raise ValueError("requested blob was empty")
            txt += "\n---\n" + body
    return txt


def served_set(tj, gd, tag):
    text = crd_text(tj, gd, tag)
    result = sh(CRDGVK, inp=text)
    if result.returncode:
        raise ValueError("CRD YAML helper failed")
    rows = json.loads(result.stdout)
    if not isinstance(rows, list):
        raise ValueError("helper output must be a list")
    for row in rows:
        if (not isinstance(row, dict) or
                any(not isinstance(row.get(key), str) or not row[key].strip() for key in ("G", "V", "K")) or
                any(type(row.get(key)) is not bool for key in ("Served", "Store"))):
            raise ValueError("helper output contains an invalid GVK row")
    if not rows and "CustomResourceDefinition" in text:
        raise ValueError("helper omitted every CRD version")
    return {(row["G"], row["V"], row["K"]) for row in rows if row["Served"]}


def run(proj, cov):
    try:
        return _run(proj, cov)
    except Exception as e:  # fail closed: an error case, never a skip
        return [case("crd", proj, error=True, why="oracle failed: %s" % e)]


def _run(proj, cov):
    S = "crd"
    try:
        with open(f"{TD}/target-{proj}.json") as target_file:
            tj = json.load(target_file)["target"]
    except Exception as e:
        return [case(S, proj, error=True, why="target unreadable: %s" % e)]
    repo, bad = validate_target(tj)
    if bad:
        return [case(S, proj, error=True, why="target rejected: " + bad)]
    if not re.fullmatch(r"[A-Za-z0-9_][\w.-]*", proj, re.A):
        return [case(S, proj, error=True, why="project name rejected")]
    gd = f"{GITROOT}/{proj}.git"
    os.makedirs(os.path.dirname(gd), exist_ok=True)
    if not os.path.isdir(gd):
        r = sh("git", "clone", "-q", "--bare", "--filter=blob:none", "--", f"https://github.com/{repo}.git", gd)
        if r.returncode:
            shutil.rmtree(gd, ignore_errors=True)
            return [case(S, proj, error=True, why="clone: " + r.stderr[:200])]
    r = sh("git", "-C", gd, "fetch", "-q", "--tags", "--force")
    if r.returncode:
        return [case(S, proj, error=True, why="fetch tags: " + r.stderr[:200])]
    pref = tj["tagPrefixes"][0]
    tags = checked("git", "-C", gd, "tag", "-l").splitlines()
    lines = {}
    for t in tags:
        if re.fullmatch(re.escape(pref) + r"\d+\.\d+\.\d+", t):
            lines.setdefault(vkey(t)[:2], []).append(t)
    for l in lines:
        lines[l].sort(key=vkey)
    cache = {}

    def served(tag):
        if tag not in cache:
            cache[tag] = served_set(tj, gd, tag)
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
            out.append(case(S, proj + "|" + pr["from"] + "|" + pr["to"], error=True, why="requested release line missing"))
            continue
        for f in sorted({lines[l1][0], lines[l1][-1]}, key=vkey):
            sf = served(f)
            if not sf:
                for t in sorted({lines[l2][0], lines[l2][-1]}, key=vkey):
                    out.append(case(S, proj + "|" + f + "|" + t, error=True,
                                    why="SKIP: verified empty served source scope", status="SKIP",
                                    requested=0, executed=0))
                continue
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
                    return [case(S, proj, error=True, note="SKIP: community catalog, scan does not check it", why=tail[:120])]
                if j is None:
                    out.append(case(S, key, error=True, why=tail))
                    continue
                fnd = j.get("findings", [])
                exp = ["/".join(x) for x in removed]
                wp, mm, missing, crd = scoped_result(code, j, removed, proj, "crd.custom_resource_versions")
                out.append(case(S, key, wrongpass=wp, mismatch=mm, error=not complete_scan_scope(j, len(sf)), exit=code, verdict=j.get("verdict"),
                                crd=crd, missing=missing, requested=len(sf), executed=j.get("summary", {}).get("documentsRead"), expectRemoved=exp[:200], nExpect=len(exp), nFindings=len(fnd),
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
    cov = json.load(open(COV))["projects"] if COV else []
    ps = projects_all() if a.all or not a.projects else a.projects.split(",")
    cases = []
    with ThreadPoolExecutor(a.jobs) as ex:
        for p, res in zip(ps, ex.map(lambda p: run(p, cov), ps)):
            cases += res
            c = counts(res)
            print(f"crd {p} cases={len(res)} wrongpass={c['wrongpass']} mismatch={c['mismatch']} error={c['error']}", flush=True)
    dump(cases, a.out)
    print("crd total", json.dumps(counts(cases)))
