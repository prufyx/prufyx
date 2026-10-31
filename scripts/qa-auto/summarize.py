#!/usr/bin/env python3
"""Merge suite case files into one summary, one verdict line, an alarm file and a status file.

usage: summarize.py --dir RUNDIR --state STATE --sha SHA --mode MODE [--seed-baseline]
exit 0 green, 2 alarm (WRONGPASS>0 or a mismatch not in the baseline), 3 inconclusive (errors only)
Baseline: STATE/known-mismatch.json (list of "suite|key"); seeded from a full run when missing.
"""
import argparse, glob, json, os, time

ap = argparse.ArgumentParser()
ap.add_argument("--dir", required=True)
ap.add_argument("--state", required=True)
ap.add_argument("--sha", required=True)
ap.add_argument("--mode", required=True)
ap.add_argument("--note", default="")
ap.add_argument("--adhoc", action="store_true")
a = ap.parse_args()
cases = []
for f in sorted(glob.glob(a.dir + "/*.cases.json")):
    cases += json.load(open(f))
skipped = json.load(open(a.dir + "/skipped.json")) if os.path.exists(a.dir + "/skipped.json") else []
if a.mode != "none":
    # empty coverage must never be green: every mandatory suite needs at least one case
    for suite in ("crd", "k8s", "bp325", "review"):
        if not any(c["suite"].split("-")[0] == suite for c in cases):  # k8s-range, k8s-single, k8s-plan count as k8s
            cases.append({"suite": suite, "key": "no-cases", "wrongpass": False, "mismatch": False, "error": True,
                          "detail": {"why": "suite produced no cases"}})
bp = a.state + "/known-mismatch.json"
seeded = False
if not os.path.exists(bp) and a.mode == "full" and not a.adhoc:
    json.dump(sorted({f"{c['suite']}|{c['key']}" for c in cases if c["mismatch"] and not c["wrongpass"]}), open(bp, "w"))
    seeded = True
base = set(json.load(open(bp))) if os.path.exists(bp) else set()
wp = [c for c in cases if c["wrongpass"]]
mm = [c for c in cases if c["mismatch"] and not c["wrongpass"]]
new = [c for c in mm if f"{c['suite']}|{c['key']}" not in base]
er = [c for c in cases if c["error"]]
alarm = bool(wp or new)
state = "ALARM" if alarm else ("INCONCLUSIVE" if er else ("GREEN-PARTIAL" if skipped else "GREEN"))
line = f"WRONGPASS={len(wp)} MISMATCH={len(mm)} NEWMISMATCH={len(new)} ERR={len(er)} sha={a.sha[:8]} mode={a.mode} {state}"
now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
summ = {"time": now, "sha": a.sha, "mode": a.mode, "state": state, "verdict": line, "wrongpass": len(wp),
        "mismatch": len(mm), "new_mismatch": len(new), "errors": len(er), "cases": len(cases),
        "baseline_seeded": seeded, "skipped": skipped, "adhoc": a.adhoc, "note": a.note,
        "wrongpass_cases": wp[:50], "new_mismatch_cases": new[:50], "error_cases": er[:20]}
json.dump(summ, open(a.dir + "/summary.json", "w"), indent=1)
status = {k: summ[k] for k in ("time", "sha", "mode", "state", "verdict", "wrongpass", "mismatch", "new_mismatch", "errors")}
status["alarm"] = alarm
if not a.adhoc:
    json.dump(status, open(a.state + "/status.json.tmp", "w"))
    os.replace(a.state + "/status.json.tmp", a.state + "/status.json")
if alarm:
    os.makedirs(a.state + "/alarms", exist_ok=True)
    json.dump({"kind": "qa-auto-wrongpass" if wp else "qa-auto-new-mismatch", "id": f"qa-auto/{a.sha[:8]}",
               "raised": now, "verdict": line, "wrongpass_cases": wp[:50], "new_mismatch_cases": new[:50],
               "summary": a.dir + "/summary.json"}, open(f"{a.state}/alarms/{a.sha[:8]}.alarm.json", "w"), indent=1)
print(line)
raise SystemExit(2 if alarm else (3 if er else (4 if skipped else 0)))
