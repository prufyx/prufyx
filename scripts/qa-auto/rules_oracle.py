#!/usr/bin/env python3
"""Wrong-PASS gate for the shipped rules (suite "rules"). Python 3 stdlib only.
usage: rules_oracle.py --out FILE.cases.json [--allow STATE/rules-allow.json]

Nothing here trusts the rule under test. For every entry of cli/internal/cncfcheck/data/rules.json whose operator is
forbid_predicate_value or forbid_set_member (step 1; the version-bound operators and release-note members follow) the
generator builds the one input the rule's own appliesWhen / condition / setCondition describes, and runs
`check cncf --project P --input F`:
  control   the trigger itself must BLOCK (exit 10). Exit 11 (UNKNOWN), 2/3 (refused/integrity) or 15 (newer pack) mean the
            black-box input cannot reach the rule: INFO "unreachable", counted in the summary. Exit 0 is a wrong-PASS
            candidate ("control-pass:<rule id>", wrongpass + mismatch; allow-list key '<rule id>#control'); a hang or any
            other exit code is "control-crash:<rule id>" (mismatch). The corpus of such a rule is skipped.
  corpus    for every reachable rule each variant of corpus.py (encoding, structure, value, wrapper, scoping) must be
            non-PASS. BLOCK, UNKNOWN (11), integrity (3), a refused input (2) and a newer-pack refusal (15) are fine.
WRONGPASS = exit 0 (verdict text is never matched loosely). Variants in corpus.PASS_OK may PASS. MISMATCH = a crash (any other exit code) or a run over 20 s.
Case key = "<rule id>#<variant id>".

Allow-list STATE/rules-allow.json = {"<rule id>#<variant id>" | "*#<variant id>": {"ref": "tracking reference", "reason": "..."}}
for documented, scoped PASS cases. An allowed key that still passes is reported and does not alarm; an allowed key whose
case is now non-PASS (or a "*" key that matched nothing although the variant ran, or a key whose rule id left rules.json
or whose in-scope rule did not run it) is a STALE entry and alarms (mismatch
+ error), so the list only shrinks. A malformed entry is an error. A missing or empty list is the release gate.
Environment: the qalib variables plus QA_PROJECTS (comma list, only these projects), QA_JOBS (parallel runs, default 3).
"""
import argparse, concurrent.futures as cf, base64, json, os, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from qalib import BIN, SRC, boxed, TMP, NOW, ENV, case, counts, dump, write_private
import corpus
PASS_OK = corpus.PASS_OK

RULES = "cli/internal/cncfcheck/data/rules.json"
OPS = ("forbid_predicate_value", "forbid_set_member")
BLOCKED = 10
NOT_PASS = {2, 3, 10, 11, 15}
TIMEOUT = 20
PASS_VERDICTS = {"PASS", "SCOPE_COMPLETE_PASS"}  # the CLI's verdict enum (cli/internal/**: VerdictPass); exact match only
UNREACHABLE = {2, 3, 11, 15}  # control refused / integrity / UNKNOWN / newer pack: the input cannot reach the rule
PROBE_NOW = NOW or "2026-11-20T00:00:00Z"
ap = argparse.ArgumentParser()
ap.add_argument("--out", required=True)
ap.add_argument("--allow", default=os.path.join(ENV("QA_STATE", "."), "rules-allow.json"))
a = ap.parse_args()
W = os.path.join(TMP, "rules")
os.makedirs(W, exist_ok=True)
INPUT_SCHEMA = "prufyx.io/operator-declared-constraint-input/v1alpha1"
AUTHORITY = "OPERATOR_DECLARED_MINIMIZED"


def fact_of(cond):
    f = {"id": cond["factId"], "state": "declared"}
    f.update({k: v for k, v in cond.items() if k not in ("component", "factId", "side")})
    return f


def trigger(entry):
    """(input doc, side of the condition, condition fact id, appliesWhen fact ids) or None."""
    rule = entry["rule"]
    sub = rule["subject"]
    rng = rule.get("range") or {}
    frm = (rng.get("from") or {}).get("gte") or sub["from"]
    to = (rng.get("to") or {}).get("gte") or sub["to"]
    if rule["operator"] == "forbid_set_member":
        sc = rule["setCondition"]
        conds = [dict(sc, setValue={"members": [sc["members"][0]], "complete": True})]
        conds[0].pop("members")
        main = conds[0]
        when = []
    else:
        main = rule["condition"]
        when = list(rule.get("appliesWhen") or [])
        conds = when + [main]
    sides = {"current": {}, "proposed": {}}
    for c in conds:
        sides[c["side"]].setdefault(c["component"], []).append(fact_of(c))
    for side, ver in (("current", frm), ("proposed", to)):  # the rule's component is on both sides at its versions
        sides[side].setdefault(sub["component"], [])
    doc = {"schema": INPUT_SCHEMA, "authority": AUTHORITY}
    for side, ver in (("current", frm), ("proposed", to)):
        doc[side] = {"components": [{"component": comp, "version": ver, "facts": facts} for comp, facts in sorted(sides[side].items())]}
    return doc, main["side"], main["factId"], [c["factId"] for c in when]


def run(project, data, tag):
    f = os.path.join(W, tag)
    write_private(f, "")
    with open(f, "wb") as fh:
        fh.write(data)
    cmd = [BIN, "check", "cncf", "--project", project, "--input", f, "--now", PROBE_NOW, "--format", "json"]
    try:
        r = subprocess.run(boxed(cmd), capture_output=True, text=True, timeout=TIMEOUT, errors="replace")
    except subprocess.TimeoutExpired:
        return -9, "timeout", cmd
    try:
        j = json.loads(r.stdout)
    except Exception:
        j = None
    note = (r.stdout[:200] + r.stderr[:200]).replace("\n", " ")
    verdict = j.get("verdict") if isinstance(j, dict) else None
    if r.returncode != 0 and verdict in PASS_VERDICTS:
        note = "exit %d with verdict %s; " % (r.returncode, verdict) + note
    return r.returncode, note, cmd


try:
    data = json.load(open(os.path.join(SRC, RULES)))
except Exception as e:
    dump([case("rules", "rules-unreadable", error=True, why=repr(e))], a.out)
    print("rules unreadable", e)
    raise SystemExit(0)
only = {p for p in ENV("QA_PROJECTS", "").split(",") if p}
only_ids = {i for i in ENV("QA_RULES_IDS", "").split(",") if i}  # PR gate: changed rule ids only (empty = all)
entries = [e for e in data["entries"] if e["rule"]["operator"] in OPS and (not only or e["project"] in only)
           and (not only_ids or e["rule"]["id"] in only_ids)]
ALL_IDS = {e["rule"]["id"] for e in data["entries"]}
RUN_IDS = {e["rule"]["id"] for e in entries}
JOBS = int(ENV("QA_JOBS", "3") or 3)

# controls ------------------------------------------------------------------------------------------------------
work = []  # (entry, doc, side, cond_id, when_ids, tag)
for i, e in enumerate(entries):
    try:
        work.append((e,) + trigger(e) + ("c%d" % i,))
    except Exception as ex:
        work.append((e, None, None, None, None, repr(ex)))
reach, unreach, nobuild, ctl_bad = [], [], [], []


def control(w):
    e, doc, side, cid, when, tag = w
    if doc is None:
        return w, None
    code, note, _ = run(e["project"], json.dumps(doc).encode(), tag + ".json")
    return w, (code, note)


with cf.ThreadPoolExecutor(JOBS) as ex:
    for w, res in ex.map(control, work):
        rid = w[0]["rule"]["id"]
        if res is None:
            nobuild.append(rid)
        elif res[0] == BLOCKED:
            reach.append(w)
        elif res[0] in UNREACHABLE:
            unreach.append((rid, res[0]))
        else:  # 0 = PASS on the rule's own trigger, -9 = hang, anything else = crash: never silently skipped
            ctl_bad.append((w, res))

# corpus --------------------------------------------------------------------------------------------------------
jobs = []  # (entry, doc, variant)
for w in reach:
    e, doc, side, cid, when, tag = w
    for v in corpus.variants(doc, side, cid, when, e["project"]):
        jobs.append((e, doc, v))
OBS = []  # (key, rid, variant id, project, code, note, data, cmd)


def probe(ij):
    n, (e, doc, v) = ij
    rid = e["rule"]["id"]
    code, note, cmd = run(v["project"] or e["project"], v["data"], "v%d.json" % n)
    return (rid + "#" + v["id"], rid, v["id"], e["project"], code, note, v["data"], cmd)


with cf.ThreadPoolExecutor(JOBS) as ex:
    OBS = list(ex.map(probe, enumerate(jobs)))

# verdict -------------------------------------------------------------------------------------------------------
allow, bad = {}, []
if os.path.exists(a.allow):
    try:
        allow = json.load(open(a.allow))
        assert isinstance(allow, dict)
    except Exception as e:
        allow, bad = {}, ["unreadable allow-list: %r" % e]
for k, v in allow.items():
    if "#" not in k:
        bad.append(f"{k}: key must be '<rule id>#<variant id>' or '*#<variant id>'")
    elif not (isinstance(v, dict) and str(v.get("ref", "")).strip() and str(v.get("reason", "")).strip()):
        bad.append(f"{k}: entry needs {{'ref': text, 'reason': text}}")


def repro(data, cmd):
    try:
        text = data.decode("utf-8")
        if "\x00" in text or text.startswith("﻿"):
            raise ValueError
        return {"input": text[:4000]}
    except Exception:
        return {"input_b64": base64.b64encode(data[:4000]).decode()}


cases, matched, ran_variants, ran_keys = [], set(), set(), set()
# The trigger is built from the rule's own appliesWhen/condition, so exit 0 on it is a wrong-PASS candidate (the generator
# has no "not reliably constructible" marker; a legitimate PASS is documented in the allow-list as '<rule id>#control').
for w, (code, note) in ctl_bad:
    e = w[0]
    rid = e["rule"]["id"]
    ckey = rid + "#control"
    ran_keys.add(ckey)
    if code == 0 and ckey in allow and not bad:
        matched.add(ckey)
        continue
    kind = "control-pass:" if code == 0 else "control-crash:"
    cases.append(case("rules", kind + rid, wrongpass=(code == 0), mismatch=True, project=e["project"], rule=rid, exit=code,
                      note=note, why="trigger built from the rule did not BLOCK (exit %s)" % code))
for key, rid, vid, project, code, note, data, cmd in OBS:
    ran_keys.add(key)
    ran_variants.add(vid)
    if code in NOT_PASS:
        if key in allow and not bad:
            cases.append(case("rules", "stale-allow:" + key, mismatch=True, error=True, exit=code, ref=allow[key].get("ref"),
                              why="FIXED - remove from allow-list"))
        continue
    passed = code == 0
    if passed and vid in PASS_OK:
        continue  # semantically different input (prerelease below bound, downgrade): PASS is correct; crash/hang still alarms
    entry = allow.get(key) or allow.get("*#" + vid)
    if entry and not bad and passed:
        matched.add(key if key in allow else "*#" + vid)
        continue
    cases.append(case("rules", key, wrongpass=passed, mismatch=not passed, project=project, rule=rid, variant=vid, exit=code,
                      note=note, command="prufyx " + " ".join(cmd[1:]), **repro(data, cmd)))
for k in allow:
    if "#" not in k or bad:
        continue
    if k.startswith("*#"):
        if k[2:] in ran_variants and k not in matched:
            cases.append(case("rules", "stale-allow:" + k, mismatch=True, error=True, ref=allow[k].get("ref"), why="matched no wrong PASS - remove"))
    elif k not in ran_keys:
        rid = k.split("#", 1)[0]
        if rid not in ALL_IDS:
            cases.append(case("rules", "stale-allow:" + k, mismatch=True, error=True, ref=allow[k].get("ref"),
                              why="rule id is no longer in rules.json - remove"))
        elif rid in RUN_IDS:
            cases.append(case("rules", "stale-allow:" + k, mismatch=True, error=True, ref=allow[k].get("ref"),
                              why="rule is in scope but the key did not run (no BLOCKing control, or variant gone) - remove"))
        else:
            cases.append(case("rules", "allowed-not-run:" + k, ref=allow[k].get("ref")))  # outside QA_PROJECTS scope: INFO
for msg in bad:
    cases.append(case("rules", "allow-list", error=True, why=msg))
for rid in nobuild:
    cases.append(case("rules", "trigger-build:" + rid, error=True, why="trigger generator failed for this entry"))
if not reach:
    cases.append(case("rules", "no-reachable-rule", error=True, why="no rule produced a BLOCKing control (generator or build broken)"))
cases.append(case("rules", "summary", entries=len(entries), controls_block=len(reach), unreachable=len(unreach),
                  unreachable_pass=sum(1 for _, c in unreach if c == 0), variants_run=len(OBS),
                  unreachable_ids=[f"{r}:{c}" for r, c in unreach], allowed=len([k for k in allow if "#" in k])))
dump(cases, a.out)
print("rules entries=%d controls_block=%d unreachable=%d variants=%d" % (len(entries), len(reach), len(unreach), len(OBS)),
      json.dumps(counts(cases)))
