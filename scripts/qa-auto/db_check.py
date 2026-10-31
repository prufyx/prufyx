#!/usr/bin/env python3
"""Turn the db suite result (dbqa.json) into qa-auto cases. A FAIL is a mismatch unless its id is in the allow-list
(JSON object {"TN02": "QA-33 ..."}; the entry stays until a human removes it). Missing/unreadable result = error case.
usage: db_check.py --json DIR/dbqa.json --allow STATE/db-allow.json --out cases.json"""
import argparse, json, os
from qalib import case, dump, counts

ap = argparse.ArgumentParser()
ap.add_argument("--json", required=True)
ap.add_argument("--allow", required=True)
ap.add_argument("--out", required=True)
a = ap.parse_args()
allow = json.load(open(a.allow)) if os.path.exists(a.allow) else {}
try:
    d = json.load(open(a.json))
    cases = [case("db", c["id"], mismatch=c["status"] == "FAIL" and c["id"] not in allow,
                  status=c["status"], desc=c["desc"][:80], detail=c["detail"][:160],
                  allowed=allow.get(c["id"]) if c["status"] == "FAIL" else None) for c in d["cases"]]
    cases = [c for c in cases if c["detail"].get("status") != "PASS"]  # keep failures and skips only
    cases.append(case("db", "summary", pass_=d["pass_"], fail=d["fail"], skip=d["skip"], sha=d["sha"][:12]))
except Exception as e:
    cases = [case("db", "suite", error=True, why="no usable dbqa.json: %r" % e)]
dump(cases, a.out)
print("db", json.dumps(counts(cases)))
