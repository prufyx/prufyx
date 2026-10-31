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

ap = argparse.ArgumentParser()
ap.add_argument("--changed", required=True)
ap.add_argument("--src", required=True)
a = ap.parse_args()
slugs = sorted(re.sub(r"^target-|\.json$", "", os.path.basename(p))
               for p in glob.glob(a.src + "/cli/internal/extract/crdversions/target-*.json"))
projects, reasons, full, db = set(), [], False, False
DBRE = re.compile(r"^cli/(internal/)?(knowledge|[a-z]*db[a-z]*)")
for p in open(a.changed).read().split("\n"):
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
print(json.dumps({"mode": mode, "projects": sorted(projects), "relevant": mode != "none", "db": db, "reasons": reasons[:20]}))
