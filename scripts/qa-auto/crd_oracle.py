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
        return json.loads(r.stdout)
    except subprocess.TimeoutExpired:
        raise MatchTimeout(pattern[:80])
    except Exception as e:
        raise MatchTimeout(f"match failed: {type(e).__name__}")


class ExpectedSetError(Exception):
    """The expected (served) GVK set of a tag could not be computed completely: never use a partial set."""


def _git(gd, *args):
    r = sh("git", "-C", gd, *args)
    if r.returncode:
        raise ExpectedSetError("git %s failed (exit %s): %s" % (args[0], r.returncode, (r.stderr or "")[:120].replace("\n", " ")))
    return r.stdout


def crd_text(tj, gd, tag):
    """Concatenated CRD YAML of one project at one tag (from the bare clone gd); raises ExpectedSetError on any read failure."""
    txt = ""
    for p in tj["paths"]:
        if p.get("directory"):
            listed = _git(gd, "ls-tree", "-r", "--name-only", "--end-of-options", tag, p["path"] + "/").split()
            fl = match_names(p["match"], listed)
        else:
            # a path the tree does not hold at this tag is a fact (ls-tree succeeded and printed nothing); a failing ls-tree is not
            fl = [p["path"]] if _git(gd, "ls-tree", "--name-only", "--end-of-options", tag, p["path"]).strip() else []
        for f in fl:
            body = _git(gd, "show", "--end-of-options", f"{tag}:{f}")
            if not body.strip():
                raise ExpectedSetError("%s: %s read as empty" % (tag, f))
            txt += "\n---\n" + body
    return txt


def served_set(tj, gd, tag):
    """Served (group, version, kind) set at a tag; ExpectedSetError on any subprocess, read or parse problem."""
    txt = crd_text(tj, gd, tag)
    r = sh(CRDGVK, inp=txt)
    if r.returncode:
        raise ExpectedSetError("crdgvk failed (exit %s): %s" % (r.returncode, (r.stderr or "")[:120].replace("\n", " ")))
    try:
        items = json.loads(r.stdout)
        if not isinstance(items, list):
            raise ValueError("not a list")
        got = {(x["G"], x["V"], x["K"]) for x in items if x["Served"]}
        if not all(isinstance(t, str) for g in got for t in g):
            raise ValueError("non-string GVK")
    except Exception as e:
        raise ExpectedSetError("crdgvk output unusable (%s: %s)" % (type(e).__name__, str(e)[:80]))
    if not items and "CustomResourceDefinition" in txt:
        raise ExpectedSetError("%s: CRD text read but crdgvk found no CRD versions" % tag)
    return got


def judge(code, j, removed):
    """Verdict of one scan against the expected removed GVKs (sorted (g, v, k) tuples) of the probe file.

    A removed GVK is covered only when a finding has a location naming its probe object (kind and name). The scan
    can still answer PASS for the crd family, so a family PASS (or an exit-0/PASS verdict) with any removed GVK that
    no finding covers is a wrong PASS, whatever the aggregate verdict says. Uncovered without a PASS claim is a mismatch.
    Returns (wrongpass, mismatch, detail)."""
    j = j if isinstance(j, dict) else {}

    def items(x):  # dict items of a list, [] for any other shape
        return [y for y in x if isinstance(y, dict)] if isinstance(x, list) else []
    fnd = items(j.get("findings"))
    named = {(l.get("kind"), l.get("name")) for f in fnd for l in items(f.get("locations"))}
    crd = [x.get("status") for p in items(j.get("paths")) for h in items(p.get("hops"))
           for x in items(h.get("families")) if x.get("family") == "crd.custom_resource_versions"]
    uncovered = ["/".join(x) for x in removed if (x[2], doc_name(*x)) not in named]
    fam_pass = any("PASS" in str(s) for s in crd)
    wp = bool(removed) and (is_pass(code, j) or (bool(uncovered) and fam_pass))
    mm = (not wp) and ((bool(removed) and bool(uncovered)) or (not removed and bool(fnd)) or
                       (not removed and crd != [] and "PASS" not in crd))
    return wp, mm, {"crd": crd, "nFindings": len(fnd), "uncovered": uncovered[:200]}


def run(proj, cov):
    try:
        return _run(proj, cov)
    except MatchTimeout as e:  # fail closed: an error case, never a skip
        return [case("crd", proj, error=True, why="target match regex exceeded %ss or failed: %s" % (MATCH_TIMEOUT, e))]


def _run(proj, cov):
    S = "crd"
    try:
        tj = json.load(open(f"{TD}/target-{proj}.json"))["target"]
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
    r = sh("git", "-C", gd, "tag", "-l")
    if r.returncode:
        return [case(S, proj, error=True, why="tag list: " + r.stderr[:200])]
    tags = r.stdout.split()
    lines = {}
    for t in tags:
        if re.fullmatch(re.escape(pref) + r"\d+\.\d+\.\d+", t):
            lines.setdefault(vkey(t)[:2], []).append(t)
    for l in lines:
        lines[l].sort(key=vkey)
    comp = next((x for x in cov if x["project"] == proj), None)
    if comp is None:
        ls = sorted(lines)
        pairs = [{"from": ".".join(map(str, a)), "to": ".".join(map(str, b))} for a, b in zip(ls, ls[1:])]
    else:
        pairs = comp["pairs"]
    return compare_pairs(proj, tj, gd, pref, lines, pairs)


def compare_pairs(proj, tj, gd, pref, lines, pairs):
    S = "crd"
    cache = {}

    def served(tag):
        if tag not in cache:
            try:
                cache[tag] = served_set(tj, gd, tag)
            except ExpectedSetError as e:
                cache[tag] = e
        if isinstance(cache[tag], ExpectedSetError):
            raise cache[tag]
        return cache[tag]

    out = []
    n = 0
    for pr in pairs:
        l1 = tuple(int(x) for x in pr["from"].split("."))
        l2 = tuple(int(x) for x in pr["to"].split("."))
        if l1 not in lines or l2 not in lines:
            continue
        for f in sorted({lines[l1][0], lines[l1][-1]}, key=vkey):
            for t in sorted({lines[l2][0], lines[l2][-1]}, key=vkey):
                n += 1
                key = f"{proj}|{f}|{t}"
                try:  # any unread/unparsed source is an error case for this pair, never a smaller expected set
                    sf = served(f)
                    removed = sorted(sf - served(t))
                except ExpectedSetError as e:
                    out.append(case(S, key, error=True, why="expected set: %s" % e))
                    continue
                docs = "---\n".join(doc(g, v, k) for (g, v, k) in sorted(sf))
                fn = f"{TMP}/crd/{proj}-{n}.yaml"
                write_private(fn, docs)
                code, j, tail = prufyx("scan", fn, f"{proj}={f[len(pref):]}", f"{proj}={t[len(pref):]}")
                os.remove(fn)
                if j is None and "community catalog" in tail:
                    # community-catalog projects are not scanned yet (documented refusal), nothing to compare
                    return [case(S, proj, note="skipped: community catalog, scan does not check it", why=tail[:120])]
                if j is None:
                    out.append(case(S, key, error=True, why=tail))
                    continue
                wp, mm, d = judge(code, j, removed)
                exp = ["/".join(x) for x in removed]
                out.append(case(S, key, wrongpass=wp, mismatch=mm, exit=code, verdict=j.get("verdict"),
                                crd=d["crd"], expectRemoved=exp[:200], nExpect=len(exp), nFindings=d["nFindings"],
                                uncovered=d["uncovered"],
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
