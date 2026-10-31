#!/usr/bin/env python3
"""Permanent regression cases from an independent review (suite "review", fast path, seconds to a minute).
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
Allow-list STATE/review-allow.json = {"ID": {"wi": "WI-1", "reason": "..."}}: only the ids in ALLOWABLE (the open
review findings) may be listed, each with a valid work item. An allowed id that fails is reported and does not alarm;
an allowed id that now passes is a STALE entry and alarms (mismatch + error), so the list only shrinks. An empty or
missing list is the release gate. Malformed entries are errors.
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from qalib import BIN, SRC, TMP, NOW, ENV, case, counts, dump, sh, write_private

WIS = {"WI-1", "WI-2", "WI-3", "WI-4"}
ALLOWABLE = {"R1.store-explicit", "R1.auto-store", "R1.batch", "R1.same-id-shadow", "R1.same-id-shadow-batch",  # F1-F4
             "R2.flat", "R2.nested",                                                                             # A1
             "R3.falco.m",                                                                                       # falco -m
             "R4.ingress-ext-1.25-1.26"}                                                                         # W3
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
if os.path.exists(test_file):
    if os.path.exists(go_out):
        os.remove(go_out)
    cmd = ('GOFLAGS=-mod=vendor QA_REVIEW_OUT="$PWD/qa-review-out.json" go test -count=1 '
           '-tags "prufyx_synthetic_knowledge prufyx_qa_review" -run TestQAReviewCrossing ./internal/communityapp/')
    g = sh(ENV("QA_DEVBOX", "devbox"), "-w", os.path.join(SRC, "cli"), "sh", "-c", cmd, inp="")
    try:
        r1 = json.load(open(go_out))
    except Exception:
        print((g.stdout + g.stderr)[-600:])
else:
    print("review: no Go harness in this source tree")
if r1:
    ctl = r1.get("R1.embedded", {})
    obs("R1.embedded", "ctl", ctl.get("exit", -1), {BLOCKED}, ctl.get("text", "")[:150])
    for cid in ("R1.store-explicit", "R1.auto-store", "R1.batch", "R1.same-id-shadow", "R1.same-id-shadow-batch"):
        o = r1.get(cid)
        obs(cid, "gate", o["exit"] if o else -1, NOT_PASS, o["text"][:150] if o else "not recorded")

# R2 ------------------------------------------------------------------------------------------------------------
for cid, text in (("R2.flat", "opensearch.experimental.feature.pluggable.caching.enabled: true\n"),
                  ("R2.nested", "opensearch:\n  experimental:\n    feature:\n      pluggable:\n        caching:\n          enabled: true\n")):
    f = os.path.join(W, cid + ".yml")
    write_private(f, text)
    code, note = run("check", "project", "--project", "opensearch", "--effective-config", f, "--from", "2.19.7", "--to", "3.0.0",
                     "--effective-config-complete", "--precedence-resolved", "--now", PROBE_NOW, "--format", "json")
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
if has_rules('"falco.relnotes.'):
    member("R3.falco.m", "gate", {BLOCKED}, "falco", FALCO, "0.34.1", "0.35.0", "m")
    member("R3.falco.mesos-api", "gate", {BLOCKED}, "falco", FALCO, "0.34.1", "0.35.0", "mesos-api")  # control
    for m in ("pm", "pmesos"):  # `-p mesos` is not representable: known gap
        member("R3.falco." + m, "gap", NOT_PASS, "falco", FALCO, "0.34.1", "0.35.0", m)
    member("GAP.falco.userspace", "gap", NOT_PASS, "falco", FALCO, "0.36.2", "0.37.0", "userspace")
if has_rules('"cortex.relnotes.'):
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
    if k not in ALLOWABLE:
        bad.append(f"{k}: not an allow-listable review finding")
    elif not (isinstance(v, dict) and v.get("wi") in WIS and str(v.get("reason", "")).strip()):
        bad.append(f"{k}: entry needs {{'wi': one of {sorted(WIS)}, 'reason': text}}")
cases, seen = [], set()
for cid, kind, code, ok, note in OBS:
    seen.add(cid)
    good = code in ok
    entry = allow.get(cid) if cid in ALLOWABLE else None
    if entry and not bad and good:
        cases.append(case("review", "stale-allow:" + cid, mismatch=True, error=True, exit=code, wi=entry.get("wi"),
                          why="FIXED - remove from allow-list"))
    elif not good:
        passed = code == 0
        cases.append(case("review", cid, wrongpass=passed and kind == "gate" and not entry,
                          mismatch=not entry and not (passed and kind == "gate"), exit=code, expect=sorted(ok), note=note,
                          allowed=entry))
for cid in allow:
    if cid in ALLOWABLE and cid not in seen:
        cases.append(case("review", "allowed-not-run:" + cid, wi=allow[cid].get("wi") if isinstance(allow[cid], dict) else None))
for msg in bad:
    cases.append(case("review", "allow-list", error=True, why=msg))
if not OBS:
    cases.append(case("review", "no-cases", error=True, why="no review case ran (Go harness missing or failed)"))
cases.append(case("review", "summary", ran=len(OBS), allowed=len([c for c in allow if c in ALLOWABLE])))
dump(cases, a.out)
print("review", json.dumps(counts(cases)))
