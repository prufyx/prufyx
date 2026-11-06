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
import qa_scope
import qa_batch_scope

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
            if type(p.get("optional", False)) is not bool:
                return "", "optional must be a boolean"
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


def path_absent(gd, tag, path):
    """True only when git answers successfully and the path is not in the tree (a git failure raises)."""
    return not checked("git", "-C", gd, "ls-tree", "--name-only", "--end-of-options", tag, path).strip()


def remote_applies(tj, tagname):
    """Mirror of the extractor's Remote.appliesTo: releases from `fromLine` on read their CRDs from another repository."""
    rm = tj.get("remote")
    if not rm:
        return False
    try:
        floor = tuple(int(x) for x in str(rm["fromLine"]).split("."))
        if len(floor) != 2:
            raise ValueError
    except Exception:
        raise ValueError("remote fromLine invalid")
    m = re.search(r"(\d+)\.(\d+)", tagname or "")
    if not m:  # cannot place the release on a line: never assume it is served locally
        raise ValueError("remote-served target: release line of %r unknown" % (tagname,))
    return (int(m.group(1)), int(m.group(2))) >= floor


def crd_text(tj, gd, tag, tagname=None):
    """Concatenated CRD YAML of one project at one tag (from the bare clone gd).
    Semantics mirror the extractor: an Optional path that is absent at the tag contributes nothing, a missing
    non-optional path is an error, a present directory without matching files is an error. A release that the
    target serves from a Remote repository is not readable from this mirror: explicit error, never empty."""
    if remote_applies(tj, tagname if tagname is not None else tag):
        raise ValueError("remote-served release (%s from %s): remote repository is not in the oracle mirror" % (
            tagname or tag, tj["remote"].get("repo", "?")))
    txt = ""
    for p in tj["paths"]:
        if p.get("optional") and path_absent(gd, tag, p["path"]):
            continue
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


def lines_from(lines, min_from):
    """Release lines at or above the target's minFrom ("0.36"); the target declares nothing older is served from its path."""
    if not min_from:
        return lines
    floor = tuple(int(x) for x in str(min_from).split("."))
    return [l for l in lines if l >= floor]


def adjacent_pairs(lines, min_from, project):
    retained = lines_from(lines, min_from)
    dropped = max(0, len(lines) - 1) - max(0, len(retained) - 1)
    if min_from:
        print(f"crd {project}: minFrom={min_from} dropped_pairs={dropped}", flush=True)
    return [{"from": ".".join(map(str, a)), "to": ".".join(map(str, b))}
            for a, b in zip(retained, retained[1:])]


def served_set(tj, gd, tag, tagname=None):
    text = crd_text(tj, gd, tag, tagname)
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


def prepare(proj, cov, plan):
    """Resolve the whole source inventory before any candidate scan is started."""
    plan["requested"].add("crd-project|" + proj)
    comp = next((x for x in cov if x["project"] == proj), None)
    if comp is not None:
        plan["requested"].update(f"crd-line|{proj}|{pair['from']}|{pair['to']}" for pair in comp["pairs"])
    if plan.get("binding"):
        tj = plan["binding"]["target"]["spec"]
    else:
        with open(f"{TD}/target-{proj}.json") as target_file:
            tj = json.load(target_file)["target"]
    repo, bad = validate_target(tj)
    if bad:
        raise ValueError("target rejected: " + bad)
    if not re.fullmatch(r"[A-Za-z0-9_][\w.-]*", proj, re.A):
        raise ValueError("project name rejected")
    gd = f"{GITROOT}/{proj}.git"
    os.makedirs(os.path.dirname(gd), exist_ok=True)
    if not os.path.isdir(gd):
        r = sh("git", "clone", "-q", "--bare", "--filter=blob:none", "--", f"https://github.com/{repo}.git", gd)
        if r.returncode:
            shutil.rmtree(gd, ignore_errors=True)
            raise ValueError("clone failed")
    r = sh("git", "-C", gd, "fetch", "-q", "--tags", "--force")
    if r.returncode:
        raise ValueError("fetch tags failed")
    pinned = {}
    for pair in plan.get("proof_pairs", {}).values():
        for side in ("from", "to"):
            tag, expected = pair[side + "Tag"], pair[side + "Commit"]
            if tag not in pinned:
                actual = checked("git", "-C", gd, "rev-parse", "--verify", "refs/tags/" + tag + "^{commit}").strip()
                if not re.fullmatch(r"[0-9a-f]{40}", actual):
                    raise ValueError("proof tag did not resolve to a commit")
                pinned[tag] = actual
            if pinned[tag] != expected:
                raise ValueError("proof tag moved or commit differs")
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
            ref = pinned.get(tag, tag)
            cache[tag] = served_set(tj, gd, ref, tag) if tj.get("remote") else served_set(tj, gd, ref)
        return cache[tag]

    if comp is None:
        pairs = adjacent_pairs(sorted(lines), tj.get("minFrom"), proj)
    else:
        pairs = comp["pairs"]
    if not pairs:
        raise ValueError("no usable pairs")
    plan.update(proj=proj, pref=pref, catalog=tj.get("catalog", ""))
    known_pairs = []
    missing_line = False
    for pr in pairs:
        line_target = f"crd-line|{proj}|{pr['from']}|{pr['to']}"
        plan["requested"].add(line_target)
        l1 = tuple(int(x) for x in pr["from"].split("."))
        l2 = tuple(int(x) for x in pr["to"].split("."))
        if l1 not in lines or l2 not in lines:
            missing_line = True
            continue
        exact = [(f, t) for f in sorted({lines[l1][0], lines[l1][-1]}, key=vkey)
                 for t in sorted({lines[l2][0], lines[l2][-1]}, key=vkey)]
        plan["requested"].update(f"crd|{proj}|{f}|{t}" for f, t in exact)
        known_pairs.extend((line_target, f, t) for f, t in exact)
    if missing_line:
        raise ValueError("requested release line missing")
    # The envelope's exact pair may be neither the first nor last patch of a
    # release line. Keep it as its own immutable, mandatory execution.
    for target, pair in plan.get("proof_pairs", {}).items():
        f, t = pair["fromTag"], pair["toTag"]
        if not f.startswith(pref) or not t.startswith(pref):
            raise ValueError("proof tags do not match target prefix")
        sf, st = served(f), served(t)
        if not sf:
            raise ValueError("required proof pair source served set empty")
        plan["jobs"].append((target, f, t, sf, sorted(sf - st)))
    for line_target, f, t in known_pairs:
        sf, st = served(f), served(t)
        target = f"crd|{proj}|{f}|{t}"
        if not sf:
            plan["excluded"].append(dict(target=target, evidence="complete served-set read: empty",
                reason="verified empty served source scope; no PASS claim",
                next_test="select a source release with served objects or review this empty-source boundary"))
        else:
            plan["jobs"].append((target, f, t, sf, sorted(sf - st)))
        plan["metadata"].add(line_target)
    plan["metadata"].add("crd-project|" + proj)


def community_refusal(catalog, tail):
    """True only for a community-catalog target whose scan refused it with the documented usage message."""
    return catalog == "community" and "is in the community catalog" in tail and "does not check community projects" in tail


def execute(plan):
    out, executed, omitted = [], set(plan["metadata"]), []
    proj, pref = plan["proj"], plan["pref"]
    for n, (target, f, t, sf, removed) in enumerate(plan["jobs"]):
        docs = "---\n".join(doc(g, v, k) for (g, v, k) in sorted(sf))
        fn = f"{TMP}/crd/{proj}-{n}.yaml"
        write_private(fn, docs)
        try:
            code, j, tail = prufyx("scan", fn, f"{proj}={f[len(pref):]}", f"{proj}={t[len(pref):]}")
        finally:
            os.remove(fn)
        executed.add(target)
        key = target if target.startswith("crd-proof|") else f"{proj}|{f}|{t}"
        if j is None and community_refusal(plan.get("catalog"), tail):
            # scan declares community-catalog projects unsupported: not a verdict, so nothing to compare.
            # Still executed every night, so the first release whose scan accepts them is checked automatically.
            out.append(case("crd", key, status="UNSUPPORTED_COMMUNITY", exit=code, why=tail))
            continue
        if j is None:
            omitted.append(dict(target=target, reason="candidate response unreadable; replay the full input"))
            out.append(case("crd", key, error=True, why=tail))
            continue
        wp, mm, missing, crd = scoped_result(code, j, removed, proj, "crd.custom_resource_versions")
        complete = complete_scan_scope(j, len(sf))
        if not complete:
            omitted.append(dict(target=target, reason="input omitted or incomplete; replay the full input"))
        out.append(case("crd", key, wrongpass=wp, mismatch=mm, error=not complete, exit=code,
                        verdict=j.get("verdict"), crd=crd, missing=missing, requested=len(sf),
                        executed=j.get("summary", {}).get("documentsRead"), expectRemoved=["/".join(x) for x in removed],
                        nExpect=len(removed), nFindings=len(j.get("findings", [])),
                        **({"proof_pair": plan["proof_pairs"][target]} if target in plan.get("proof_pairs", {}) else {})))
    for exclusion in plan["excluded"]:
        out.append(case("crd", exclusion["target"], status="EXCLUDED", **exclusion))
    return out, executed, omitted


def new_plan():
    return dict(requested=set(), metadata=set(), excluded=[], jobs=[])


def _run(proj, cov):
    plan = new_plan()
    prepare(proj, cov, plan)
    return execute(plan)[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--projects", default="")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--no-changed-projects", action="store_true")
    ap.add_argument("--jobs", type=int, default=int(ENV("QA_JOBS", "3")))
    a = ap.parse_args()
    cov = []
    if COV:
        with open(COV) as coverage_file:
            cov = json.load(coverage_file)["projects"]
    ps = [] if a.no_changed_projects else (projects_all() if a.all or not a.projects else a.projects.split(","))
    contract = qa_batch_scope.environment_contract()
    bindings = {}
    if contract is not None:
        if (contract["head"], contract["base"], contract["run_id"]) != (
                ENV("QA_SCOPE_HEAD", ENV("QA_SHA", "")), ENV("QA_BASE", ""), ENV("QA_RUN_ID", "")):
            raise ValueError("scope contract identity differs")
        ps = sorted(set(ps) | set(contract["projects"]))
        bindings = {p["slug"]: p for e in contract["envelopes"] for p in e["projects"]}
    if not ps and not a.no_changed_projects:
        raise ValueError("requested project inventory empty")
    plans = {}
    cases = []
    # All source plans, including failed requests, exist before any scan.
    for project in ps:
        plan = plans[project] = new_plan()
        if project in bindings:
            plan["binding"] = bindings[project]
            pair = bindings[project]["proof"]["pair"]
            target = qa_batch_scope.proof_target(project, pair)
            plan["proof_pairs"] = {target: pair}
            plan["requested"].update({"crd-project|" + project, target})
        try:
            prepare(project, cov, plan)
        except Exception as error:
            plan["error"] = str(error)
    requested = set().union(*(plan["requested"] for plan in plans.values()))
    excluded = [entry for plan in plans.values() if "error" not in plan for entry in plan["excluded"]]
    executed = set()
    if a.no_changed_projects:
        requested.add("crd-project|no-changed-projects")
    required = set(requested) if GATE and ps else set()
    if ENV("QA_REQUIRED_CRD_TARGETS", ""):
        with open(ENV("QA_REQUIRED_CRD_TARGETS")) as required_file:
            extra = json.load(required_file)
        if not isinstance(extra, list) or not all(isinstance(target, str) for target in extra):
            raise ValueError("additional required CRD targets invalid")
        required.update(extra)
    head, base, run_id = ENV("QA_SCOPE_HEAD", ENV("QA_SHA", "")), ENV("QA_BASE", ""), ENV("QA_RUN_ID", "")
    scope = qa_scope.declare(head, base, run_id, requested, required, excluded, qa_scope.CRD_PROFILE)
    scope_path = a.out.removesuffix(".cases.json") + ".scope.json"
    dump(scope, scope_path + ".declared")
    if a.no_changed_projects:
        executed.update(requested)
        cases.append(case("crd", "no-changed-projects", status="VERIFIED_ABSENCE",
                          next_test="reselect projects on the next changed target or rule diff"))
    for project, plan in plans.items():
        if "error" in plan:
            cases.append(case("crd", project, error=True, why=plan["error"]))
            continue
        try:
            result, completed, omitted = execute(plan)
            cases.extend(result)
            executed.update(completed)
            scope["omitted"].extend(omitted)
        except Exception as error:
            cases.append(case("crd", project, error=True, why="execution failed: " + str(error)))
    qa_scope.remaining_omitted(scope, executed, "source or execution failed; repair and replay this target")
    scope.update(executed=sorted(executed), state="COMPLETE")
    for reason in qa_scope.errors(scope, head, base, run_id, qa_scope.CRD_PROFILE):
        cases.append(case("crd", "declared-scope", error=True, why=reason))
    dump(scope, scope_path)
    dump(cases, a.out)
    print("crd total", json.dumps(counts(cases)))


if __name__ == "__main__":
    main()
