#!/usr/bin/env python3
"""Decide what a run must cover from the files changed since the last green sha.

usage: select_projects.py --changed FILE --src DIR     (FILE: git diff --name-only, one path per line)
prints {"db": bool (db-related path changed: run the db suite), "mode": "full|incremental|none", "projects": [...], "relevant": bool, "reasons": [...]}
  target-<p>.json            -> project p
  knowledge / data / lines   -> projects whose slug is in the path, else full
  any other cli/** or scripts/qa-auto/** -> full (the scanner or this harness changed)
  docs, tests, changelog ... -> ignored
"""
import argparse, glob, json, os, re

def selection(changed, slugs):
    projects, reasons, full, db = set(), [], False, False
    DBRE = re.compile(r"^cli/(internal/)?(knowledge|[a-z]*db[a-z]*)")
    for p in changed:
        if not p:
            continue
        if DBRE.search(p) and not re.search(r"_test\.go$|\.md$|/docs/", p):
            db = True
        m = re.fullmatch(r"cli/internal/extract/crdversions/target-(.+)\.json", p)
        if m:
            projects.add(m.group(1)); reasons.append("target " + m.group(1)); continue
        if re.search(r"coveragereport/testdata/lines-.*\.json$", p) or re.search(r"(^|/)(knowledge|data)/", p):
            hit = [s for s in slugs if s in p]
            if hit:
                projects.update(hit); reasons.append("data " + p)
            else:
                full = True; reasons.append("data (no project in path) " + p)
            continue
        if p.startswith("scripts/qa-auto/") and not p.endswith(".md"):
            full = True; reasons.append("tooling " + p); continue
        if re.search(r"(^|/)(testdata|docs|changelog\.d|\.github)/|\.md$|_test\.go$|^(LICENSES|NOTICE|THIRD-PARTY|SOURCE-PREVIEW)", p):
            continue
        if p.startswith("cli/") or p.startswith("scripts/qa-auto/"):
            full = True; reasons.append("code/tooling " + p)
    mode = "full" if full else ("incremental" if projects else "none")
    return {"mode": mode, "projects": sorted(projects), "relevant": mode != "none", "db": db, "reasons": reasons[:20]}


if __name__ == "__main__":
    import subprocess
    import sys
    ap = argparse.ArgumentParser()
    ap.add_argument("--changed", required=True)
    ap.add_argument("--src", required=True)
    a = ap.parse_args()
    changed = open(a.changed).read().splitlines()
    slugs = sorted(re.sub(r"^target-|\.json$", "", os.path.basename(p))
                   for p in glob.glob(a.src + "/cli/internal/extract/crdversions/target-*.json"))
    selected = selection(changed, slugs)
    if os.environ.get("QA_BASE"):
        # -I excludes the script directory; import only this trusted companion.
        sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
        import qa_batch_scope
        try:
            if (os.environ.get("QA_SCOPE_HEAD_REF") != qa_batch_scope.HEAD_REF or
                    os.environ.get("QA_SCOPE_BASE_REF") != qa_batch_scope.BASE_REF):
                raise ValueError("SCOPE_PROVENANCE: fixed refs required")
            head, base = os.environ.get("QA_SHA", ""), os.environ["QA_BASE"]
            actual = qa_batch_scope.git(a.src, "diff", "--name-only", "--no-renames", base, head).splitlines()
            if changed != actual:
                raise ValueError("SCOPE_PROVENANCE: caller diff differs from fixed objects")
            frozen = qa_batch_scope.environment_contract()
            extra = frozen["extra_projects"] if frozen else [p for p in os.environ.get("QA_PROJECTS", "").split(",") if p]
            contract = qa_batch_scope.freeze(a.src, head, base, os.environ.get("QA_RUN_ID", ""), extra)
            if frozen is not None and frozen != contract:
                raise ValueError("SCOPE_MISMATCH: fetched contract differs from trusted parent")
            selected.update(projects=contract["projects"], batch_scope=contract)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            ap.exit(3, "SCOPE_INVALID: " + str(error) + "\n")
    print(json.dumps(selected))
