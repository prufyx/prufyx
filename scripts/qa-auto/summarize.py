#!/usr/bin/env python3
"""Merge suite case files into one summary, one verdict line, an alarm file and a status file.

usage: summarize.py --dir RUNDIR --state STATE --sha SHA --mode MODE [--seed-baseline]
exit 0 green, 2 alarm (WRONGPASS>0 or a mismatch not in the baseline), 3 inconclusive (errors only)
Baseline: STATE/known-mismatch.json (list of "suite|key"); seeded from a full run when missing.
Explained gaps: STATE/known-gaps.json, a hand-edited list of {key, reason, owner, since, ref, sig} ("suite|key"); a plain mismatch
with a valid entry (non-empty reason, owner and string sig equal to its case_sig) is KNOWN_GAP, never auto-seeded, never covers a
WRONGPASS or a whole-CRD candidate. An entry without a sig covers nothing (get it with `qalib.py sig RESULTS_DIR suite|key`).
At most QA_GAPS_MAX_NEW (default 10, never above 25) entries may be new per full run, taken in sorted key order; the entries beyond
that cover nothing and their cases alarm, whatever the baseline says.
"""
import argparse, glob, hashlib, json, os, sys, time
import qalib
import qa_scope
import qa_batch_scope

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
    for suite in ("crd", "k8s", "bp325", "review", "rules"):
        if not any(c["suite"].split("-")[0] == suite for c in cases):  # k8s-range, k8s-single, k8s-plan count as k8s
            cases.append({"suite": suite, "key": "no-cases", "wrongpass": False, "mismatch": False, "error": True,
                          "detail": {"why": "suite produced no cases"}})
scopes = {}
if a.mode != "none":
    try:
        for suite in ("k8s", "crd"):
            with open(a.dir + "/" + suite + ".scope.json") as scope_file:
                scopes[suite] = json.load(scope_file)
        scope_errors = qa_scope.bundle_errors(scopes, a.sha, os.environ.get("QA_BASE", ""), os.environ.get("QA_RUN_ID", ""))
    except (OSError, ValueError):
        scope_errors = ["declared Kubernetes or CRD scope missing or unreadable"]
    try:
        contract = qa_batch_scope.environment_contract()
        if contract is not None:
            declarations = {}
            if contract["envelopes"]:
                for suite in ("crd", "k8s"):
                    with open(a.dir + "/" + suite + ".scope.json.declared") as declared_file:
                        declarations[suite] = json.load(declared_file)
            scope_errors.extend(qa_batch_scope.validate(contract, scopes, cases, declarations))
    except (OSError, ValueError, KeyError, TypeError):
        scope_errors.append("frozen batch scope missing, malformed or changed")
    for reason in scope_errors:
        cases.append({"suite": "k8s", "key": "scope", "wrongpass": False, "mismatch": False,
                      "error": True, "detail": {"why": reason}})
def candidate(c):
    """A whole-CRD candidate that ends as a mismatch is a regression of the documented-design class: no baseline excuses it."""
    return bool(c.get("detail", {}).get("wholeCrdCandidate"))


bp = a.state + "/known-mismatch.json"
seeded = False
if not os.path.exists(bp) and a.mode == "full" and not a.adhoc:
    json.dump(sorted({f"{c['suite']}|{c['key']}" for c in cases if c["mismatch"] and not c["wrongpass"] and not candidate(c)}), open(bp, "w"))
    seeded = True
base = set(json.load(open(bp))) if os.path.exists(bp) else set()
GAPS_MAX_NEW, GAPS_MAX_NEW_LIMIT = 10, 25
try:
    GAPS_MAX_NEW = min(GAPS_MAX_NEW_LIMIT, max(0, int(os.environ.get("QA_GAPS_MAX_NEW", GAPS_MAX_NEW))))
except ValueError:
    pass
registry = {}
gap_sigs = {}
try:
    with open(a.state + "/known-gaps.json") as gaps_file:
        raw_gaps = json.load(gaps_file)
    if not isinstance(raw_gaps, list):
        raise ValueError("registry is not a list")
    for e in raw_gaps:
        if (isinstance(e, dict) and isinstance(e.get("key"), str) and e["key"].strip()
                and isinstance(e.get("reason"), str) and e["reason"].strip()
                and isinstance(e.get("owner"), str) and e["owner"].strip()):
            registry[e["key"]] = e
            sig = e.get("sig")
            if sig not in (None, ""):
                gap_sigs[e["key"]] = sig if isinstance(sig, str) else None  # a non-string sig never matches
        else:
            print(f"known-gaps: entry ignored (needs key, reason and owner): {str(e)[:80]}", file=sys.stderr)
except FileNotFoundError:
    pass
except (OSError, ValueError) as err:
    print(f"known-gaps: registry unreadable, ignored: {err}", file=sys.stderr)
wp = [c for c in cases if c["wrongpass"]]
mm = [c for c in cases if c["mismatch"] and not c["wrongpass"]]
ckey = lambda c: f"{c['suite']}|{c['key']}"
try:
    with open(a.state + "/status.json") as sf:
        prev_gap_keys = json.load(sf).get("known_gap_keys")
    prev_gap_keys = set(prev_gap_keys) if isinstance(prev_gap_keys, list) else set()
except (OSError, ValueError, TypeError):
    prev_gap_keys = set()
new_entries = sorted(set(registry) - prev_gap_keys)
over_cap = set(new_entries[GAPS_MAX_NEW:])  # beyond the registration cap: cover nothing
gaps_breach = bool(over_cap)
if gaps_breach:
    print(f"known-gaps: registry grew by {len(new_entries)} entries in one run (max {GAPS_MAX_NEW}): INCONCLUSIVE, entries beyond the cap cover nothing, register in smaller steps", file=sys.stderr)
def covered(c):
    """A plain mismatch is explained by a valid entry (inside the cap) whose sig is that of this case; no sig, wrong sig: not covered."""
    k = ckey(c)
    if candidate(c) or k not in registry or k in over_cap:
        return False
    return gap_sigs.get(k) is not None and gap_sigs[k] == qalib.case_sig(c)
known_gap = [c for c in mm if covered(c)]
new = [c for c in mm if (ckey(c) not in base or candidate(c) or ckey(c) in over_cap) and not covered(c)]
nosig = sorted(k for k in registry if gap_sigs.get(k) is None)

# only a plain mismatch can be explained: a registered key whose case is wrongpass is reported, not resolved or honoured.
# A key is resolved only when its suite ran with at least one clean case and none of that key is an error: skipped, absent or errored suites prove nothing.
skipped_suites = {str(x).split("(")[0] for x in skipped}
resolved_gaps = sorted(k for k in registry if a.mode == "full" and not a.adhoc and k.split("|")[0] not in skipped_suites
                       and any(c["suite"] == k.split("|")[0] and not c["error"] for c in cases)
                       and not any(ckey(c) == k and (c["mismatch"] or c["wrongpass"] or c["error"]) for c in cases))
er = [c for c in cases if c["error"]]
oracle_digest = qalib.oracle_digest()
design = sum(1 for c in cases if c.get("detail", {}).get("status") == "DESIGN_UNKNOWN_WHOLE_CRD_REMOVAL" and not c["error"])
DESIGN_HARD_CAP = 80
try:
    with open(a.state + "/status.json") as prev_file:
        prev_status = json.load(prev_file)
    prev_design = prev_status.get("design_unknown_whole_crd_baseline")
    prev_design = prev_design if type(prev_design) is int and prev_design > 0 else None
    prev_digest = prev_status.get("oracle_digest")
except (OSError, ValueError, TypeError, AttributeError):
    prev_design, prev_digest = None, None
kept_design = prev_design
# a changed oracle (any of the five digested files) resets the count comparisons for this run, but a count that rises past the
# rise threshold over the kept baseline in the same run cannot be told from a regression: INCONCLUSIVE, baseline and digest are kept
oracle_changed = prev_digest != oracle_digest and os.path.exists(a.state + "/status.json")
if oracle_changed:
    prev_design = None
    print("oracle changed: rise baseline reset", file=sys.stderr)
oracle_rise = a.mode == "full" and oracle_changed and kept_design is not None and design > kept_design + max(5, -(-kept_design // 5))
# growth beyond +20% (at least +5) of the last accepted full-run count, or past the hard cap, is a scanner regression until proven otherwise
cap_breach = design > DESIGN_HARD_CAP or (a.mode == "full" and prev_design is not None and design > prev_design + max(5, -(-prev_design // 5)))
design_rise = a.mode == "full" and prev_design is not None and design > prev_design
design_drop = a.mode == "full" and prev_design is not None and prev_design >= 10 and design * 2 < prev_design
# an errored run (any error case: a source that could not be read produced no design cases, so its count is too low) or any other
# INCONCLUSIVE state never stores or lowers the baseline: only a clean complete full run may move it
baseline_stored = not (cap_breach or oracle_rise or er or gaps_breach or a.mode != "full" or a.adhoc)
design_baseline = (design or None) if baseline_stored else kept_design
alarm = bool(wp or new)
state = "ALARM" if alarm else ("INCONCLUSIVE" if (er or cap_breach or oracle_rise or gaps_breach) else ("GREEN-PARTIAL" if skipped else "GREEN"))
line = f"WRONGPASS={len(wp)} MISMATCH={len(mm)} NEWMISMATCH={len(new)} KNOWN_GAP={len(known_gap)} ERR={len(er)} DESIGN_UNKNOWN_WHOLE_CRD={design}{f" ORACLE_CHANGED design={kept_design or 0}->{design}" if oracle_changed else ""}{" ORACLE_RISE" if oracle_rise else ""}{" RISE" if design_rise else ""}{" CAP" if cap_breach else ""}{" DROP" if design_drop else ""} sha={a.sha[:8]} mode={a.mode} {state}"
fetch_retries = sum(c.get("detail", {}).get("fetch_retries", 0) for c in cases if type(c.get("detail", {}).get("fetch_retries")) is int)
now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
unsupported = sum(1 for c in cases if c.get("detail", {}).get("status") == "UNSUPPORTED_COMMUNITY")
unknown_floor = sum(1 for c in cases if c.get("detail", {}).get("status") == "UNKNOWN_EARLIEST_SERVED")
previous = {}
try:
    with open(a.state + "/status.json") as previous_file:
        previous = json.load(previous_file)
except (OSError, ValueError):
    pass
previous_count = previous.get("unsupported_community") if (previous.get("mode") == a.mode and not oracle_changed) else None
rise = (unsupported > previous_count if type(previous_count) is int and a.mode != "none" else None)
summ = {"scopes": scopes, "run_id": os.environ.get("QA_RUN_ID", ""), "base": os.environ.get("QA_BASE", ""), "time": now, "sha": a.sha, "mode": a.mode, "state": state, "verdict": line, "wrongpass": len(wp),
        "mismatch": len(mm), "new_mismatch": len(new), "known_gap": len(known_gap), "known_gap_cases": [ckey(c) for c in known_gap], "known_gap_nosig": nosig,
        "resolved_gaps": resolved_gaps, "known_gap_registration_breach": gaps_breach, "errors": len(er),
        "fetch_retries": fetch_retries, "unsupported_community": unsupported, "unsupported_community_rise": rise, "unknown_earliest_served": unknown_floor,
        "design_unknown_whole_crd_removal": design, "design_unknown_whole_crd_rise": design_rise, "design_unknown_whole_crd_cap_breach": cap_breach, "design_unknown_whole_crd_oracle_rise": oracle_rise, "design_unknown_whole_crd_drop": design_drop, "design_unknown_whole_crd_baseline": design_baseline, "cases": len(cases),
        "baseline_seeded": seeded, "skipped": skipped, "adhoc": a.adhoc, "note": a.note,
        "wrongpass_cases": wp[:50], "new_mismatch_cases": new[:50], "error_cases": er[:20]}
json.dump(summ, open(a.dir + "/summary.json", "w"), indent=1)
status = {k: summ[k] for k in ("time", "sha", "mode", "state", "verdict", "wrongpass", "mismatch", "new_mismatch", "errors", "design_unknown_whole_crd_removal", "design_unknown_whole_crd_rise", "design_unknown_whole_crd_cap_breach", "design_unknown_whole_crd_drop", "design_unknown_whole_crd_baseline")}
kept_digest = oracle_digest if (baseline_stored or not os.path.exists(a.state + "/status.json")) else prev_digest
status.update(known_gap_nosig=nosig, known_gap=len(known_gap), known_gap_cases=[ckey(c) for c in known_gap], resolved_gaps=resolved_gaps,
              known_gap_registration_breach=gaps_breach, oracle_changed=oracle_changed, oracle_digest=kept_digest,
              known_gap_keys=sorted(prev_gap_keys if (gaps_breach or a.mode != "full" or a.adhoc) else registry),
              unknown_earliest_served=unknown_floor, unsupported_community=unsupported, unsupported_community_rise=rise)
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
if fetch_retries:
    print(f"fetch_retries={fetch_retries}")
for k in nosig:
    print(f"known-gap entry {k} has no sig: it covers nothing")
if unknown_floor:
    print(f"UNKNOWN_EARLIEST_SERVED={unknown_floor}")
if resolved_gaps:
    print("RESOLVED_GAP=" + ",".join(resolved_gaps))
if rise:
    print(f"UNSUPPORTED_COMMUNITY_RISE={previous_count}->{unsupported}")
raise SystemExit(2 if alarm else (3 if (er or cap_breach or oracle_rise or gaps_breach) else (4 if skipped else 0)))
