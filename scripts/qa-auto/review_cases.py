#!/usr/bin/env python3
"""Permanent regression cases (suite "review", fast path, seconds to a minute).
usage: review_cases.py --out FILE.cases.json [--allow STATE/review-allow.json]

R1  removal-crossing rule: a synthetic crossing BLOCK that the embedded pack reports must not turn into exit 0 through
    `--knowledge-db`, the automatic store choice, `check batch`, or a same-id non-crossing rule in the store. Driven by
    a Go test under the tags prufyx_synthetic_knowledge prufyx_qa_review (the only way to load synthetic rules); the
    test records exit codes, this script judges them.
R2  opensearch removed experimental key must not be a bare PASS (flat and nested YAML).
R3  falco/cortex release-note set members: the removed member must BLOCK (falco -m is the alias), a differently cased
    member must not PASS. Live only when the build carries the release-note rules.
R4  kubernetes --native-resource: a resource at an API version the target no longer serves must not PASS (W3);
    controls at served versions must PASS.
GAP adjacent removals no rule covers yet: expected non-PASS, a PASS is a mismatch (known gap), never allow-listable.

WRONGPASS = exit 0 where the verdict must not pass. MISMATCH = any other deviation.
Allow-list STATE/review-allow.json = {"ID": {"ref": "tracking reference", "reason": "..."}}: only the ids in ALLOWABLE
(the open known findings) may be listed. An allowed id that returns the known wrong PASS (exit 0 on a gate case) is
reported and does not alarm; any other deviation (crash, exit -1, exit 2, ...) stays a mismatch. An allowed id that now
passes as expected is a STALE entry and alarms (mismatch + error), so the list only shrinks. An empty or missing list
is the release gate. Malformed entries are errors. Every skipped case raises an error case.
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from qalib import BIN, SRC, TMP, NOW, ENV, case, counts, dump, sh, write_private

ALLOWABLE = {"R1.store-explicit", "R1.auto-store", "R1.batch", "R1.same-id-shadow", "R1.same-id-shadow-batch",  # F1-F4
             "R2.flat", "R2.nested",                                                                             # A1
             "R3.falco.m",                                                                                       # falco -m
             "R4.ingress-ext-1.25-1.26"}                                                                         # W3
def allowable(cid):  # open review findings; the R1x adversarial variants are known findings too
    return cid in ALLOWABLE or (cid.startswith("R1x.") and not cid.startswith("R1x.other-project"))


BLOCKED, UNKNOWN, INTEGRITY = 10, 11, 3
NOT_PASS = {INTEGRITY, BLOCKED, UNKNOWN}
RULES = "cli/internal/cncfcheck/data/rules.json"
PROBE_NOW = NOW or "2026-11-20T00:00:00Z"
ap = argparse.ArgumentParser()
ap.add_argument("--out", required=True)
ap.add_argument("--allow", default=os.path.join(ENV("QA_STATE", "."), "review-allow.json"))
a = ap.parse_args()
W = os.path.join(TMP, "review")
os.makedirs(W, exist_ok=True)
SKIPPED = []
OBS = []  # (id, kind, exit, ok exit codes, note); kind gate (exit 0 = wrongpass) | gap (exit 0 = mismatch only)


def obs(cid, kind, code, ok, note=""):
    OBS.append((cid, kind, code, set(ok), note))


def run(*args):
    r = sh(BIN, *args)
    return r.returncode, (r.stdout + r.stderr)[:300].replace("\n", " ")


def has_rules(*needles):
    try:
        text = open(os.path.join(SRC, RULES)).read()
    except OSError:
        return False
    return all(n in text for n in needles)


# R1 ------------------------------------------------------------------------------------------------------------
go_out = os.path.join(SRC, "cli", "qa-review-out.json")
test_file = os.path.join(SRC, "cli/internal/communityapp/qa_review_synthetic_test.go")
r1 = {}
R1_HARNESS_FAIL = ""
if os.path.exists(test_file):
    if os.path.exists(go_out):
        os.remove(go_out)
    cmd = ('GOFLAGS=-mod=vendor QA_REVIEW_OUT="$PWD/qa-review-out.json" go test -count=1 '
           '-tags "prufyx_synthetic_knowledge prufyx_qa_review" -run TestQAReviewCrossing ./internal/communityapp/')
    g = sh(ENV("QA_DEVBOX", "devbox"), "-w", os.path.join(SRC, "cli"), "sh", "-c", cmd, inp="")
    try:
        r1 = json.load(open(go_out))
    except Exception:
        pass
    if len(r1) < 20:
        print((g.stdout + g.stderr)[-1500:])
        R1_HARNESS_FAIL = f"Go harness recorded {len(r1)} of at least 20 entries"
else:
    print("review: no Go harness in this source tree")
if r1:
    for cid in sorted(r1):
        o = r1[cid]
        want = o.get("want", "block")
        if want == "pass":  # a crossing rule of another project must not change this answer
            obs(cid, "ctl", o["exit"], {0}, o["text"][:150])
        elif want.startswith("equal:"):  # no crossing rule: same answer with and without a store
            ref = r1.get(want[6:], {}).get("exit", -1)
            obs(cid, "ctl", o["exit"], {ref} | ({2} if o["exit"] == 2 else set()), "embedded=%s %s" % (ref, o["text"][:120]))
        elif want == "info":
            continue
        else:
            obs(cid, "ctl" if cid == "R1.embedded" else "gate", o["exit"], {BLOCKED} if cid == "R1.embedded" else NOT_PASS, o["text"][:150])
if os.path.exists(test_file):
    for cid in ("R1.store-explicit", "R1.auto-store", "R1.batch", "R1.same-id-shadow", "R1.same-id-shadow-batch", "R1.embedded"):
        if cid not in r1:
            obs(cid, "ctl" if cid == "R1.embedded" else "gate", -1, {BLOCKED} if cid == "R1.embedded" else NOT_PASS, "not recorded")

# R2 ------------------------------------------------------------------------------------------------------------
for cid, text in (("R2.flat", "opensearch.experimental.feature.pluggable.caching.enabled: true\n"),
                  ("R2.nested", "opensearch:\n  experimental:\n    feature:\n      pluggable:\n        caching:\n          enabled: true\n")):
    f = os.path.join(W, cid + ".yml")
    write_private(f, text)
    code, note = run("check", "project", "--project", "opensearch", "--effective-config", f, "--from", "2.19.7", "--to", "3.0.0",
                     "--effective-config-complete", "--precedence-resolved", "--now", PROBE_NOW, "--format", "json")
    if code == 2 and "failed admission" in note:  # the build has no OpenSearch rules yet: nothing to check
        SKIPPED.append(cid)  # no pinned "rules absent" build exists: a skip is an error (raised below)
        continue
    obs(cid, "gate", code, NOT_PASS, note)

# R3 ------------------------------------------------------------------------------------------------------------
def declared(project, comp, frm, to, member):
    fact = {"id": f"component.{project}.cli_flags_set", "state": "declared", "setValue": {"members": [member], "complete": True}}
    side = lambda v, facts: {"components": [{"component": comp, "version": v, "facts": facts}]}
    return json.dumps({"schema": "prufyx.io/operator-declared-constraint-input/v1alpha1", "authority": "OPERATOR_DECLARED_MINIMIZED",
                       "current": side(frm, []), "proposed": side(to, [fact])})


def member(cid, kind, ok, project, comp, frm, to, m):
    f = os.path.join(W, cid + ".json")
    write_private(f, declared(project, comp, frm, to, m))
    code, note = run("check", "cncf", "--project", project, "--input", f, "--now", PROBE_NOW, "--format", "json")
    obs(cid, kind, code, ok, note)


FALCO, CORTEX = "pkg:github/falcosecurity/falco", "pkg:github/cortexproject/cortex"
if not has_rules('"falco.relnotes.'):
    SKIPPED.append("R3.falco")
else:
    member("R3.falco.m", "gate", {BLOCKED}, "falco", FALCO, "0.34.1", "0.35.0", "m")
    member("R3.falco.mesos-api", "gate", {BLOCKED}, "falco", FALCO, "0.34.1", "0.35.0", "mesos-api")  # control
    for m in ("pm", "pmesos"):  # `-p mesos` is not representable: known gap
        member("R3.falco." + m, "gap", NOT_PASS, "falco", FALCO, "0.34.1", "0.35.0", m)
    member("GAP.falco.userspace", "gap", NOT_PASS, "falco", FALCO, "0.36.2", "0.37.0", "userspace")
if not has_rules('"cortex.relnotes.'):
    SKIPPED.append("R3.cortex")
else:
    member("R3.cortex.lower", "gate", {BLOCKED}, "cortex", CORTEX, "1.8.1", "1.9.0", "store.max-look-back-period")  # control
    member("R3.cortex.upper", "gate", NOT_PASS, "cortex", CORTEX, "1.8.1", "1.9.0", "Store.max-look-back-period")
    member("GAP.cortex.per-user-override-config", "gap", NOT_PASS, "cortex", CORTEX, "1.8.1", "1.9.0", "limits.per-user-override-config")

# R4 ------------------------------------------------------------------------------------------------------------
RES = {
    "ingress-ext": "apiVersion: extensions/v1beta1\nkind: Ingress\nmetadata:\n  name: qa\n  namespace: default\nspec:\n  backend:\n    serviceName: s\n    servicePort: 80\n",
    "ingress-v1": "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: qa\n  namespace: default\nspec:\n  defaultBackend:\n    service:\n      name: s\n      port:\n        number: 80\n",
    "cronjob-beta": "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: qa\n  namespace: default\nspec:\n  schedule: '* * * * *'\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          restartPolicy: Never\n          containers:\n          - name: c\n            image: busybox\n",
}
for cid, res, frm, to, ok in (("R4.ingress-ext-1.21-1.22", "ingress-ext", "1.21.0", "1.22.0", NOT_PASS),
                              ("R4.ingress-ext-1.25-1.26", "ingress-ext", "1.25.0", "1.26.0", NOT_PASS),
                              ("R4.cronjob-beta-1.24-1.25", "cronjob-beta", "1.24.0", "1.25.0", NOT_PASS),
                              ("R4.ctl.ingress-v1-1.25-1.26", "ingress-v1", "1.25.0", "1.26.0", {0}),
                              ("R4.ctl.ingress-v1-1.21-1.22", "ingress-v1", "1.21.0", "1.22.0", {0})):
    f = os.path.join(W, cid + ".yaml")
    write_private(f, RES[res])
    code, note = run("check", "cncf", "--project", "kubernetes", "--native-resource", f, "--from", frm, "--to", to,
                     "--distribution", "official_upstream", "--target-api-apply-required", "--resource-scope-complete",
                     "--now", PROBE_NOW, "--format", "json")
    obs(cid, "gate", code, ok, note)

# verdict -------------------------------------------------------------------------------------------------------
allow, bad = {}, []
if os.path.exists(a.allow):
    try:
        allow = json.load(open(a.allow))
        assert isinstance(allow, dict)
    except Exception as e:
        allow, bad = {}, ["unreadable allow-list: %r" % e]
for k, v in allow.items():
    if not allowable(k):
        bad.append(f"{k}: not an allow-listable review finding")
    elif not (isinstance(v, dict) and str(v.get("ref", "")).strip() and str(v.get("reason", "")).strip()):
        bad.append(f"{k}: entry needs {{'ref': text, 'reason': text}}")
cases, seen = [], set()
for cid, kind, code, ok, note in OBS:
    seen.add(cid)
    good = code in ok
    entry = allow.get(cid) if allowable(cid) else None
    if entry and not bad and good:
        cases.append(case("review", "stale-allow:" + cid, mismatch=True, error=True, exit=code, ref=entry.get("ref"),
                          why="FIXED - remove from allow-list"))
    elif not good:
        passed = code == 0
        known = bool(entry) and passed and kind == "gate"  # only the known wrong PASS is suppressed
        cases.append(case("review", cid, wrongpass=passed and kind == "gate" and not known,
                          mismatch=not known and not (passed and kind == "gate"), exit=code, expect=sorted(ok), note=note,
                          allowed=entry if known else None, unexpected_for_allowed=bool(entry) and not known))
for cid in allow:
    if allowable(cid) and cid not in seen:
        cases.append(case("review", "allowed-not-run:" + cid, ref=allow[cid].get("ref") if isinstance(allow[cid], dict) else None))
for msg in bad:
    cases.append(case("review", "allow-list", error=True, why=msg))
if R1_HARNESS_FAIL:
    cases.append(case("review", "R1-harness", error=True, mismatch=True, why=R1_HARNESS_FAIL))
for sk in SKIPPED:
    cases.append(case("review", "skipped:" + sk, error=True, mismatch=True, why="case skipped; the build must carry these rules"))
if not OBS:
    cases.append(case("review", "no-cases", error=True, why="no review case ran (Go harness missing or failed)"))
cases.append(case("review", "summary", ran=len(OBS), skipped=SKIPPED, allowed=len([c for c in allow if allowable(c)])))
dump(cases, a.out)
print("review", json.dumps(counts(cases)))
