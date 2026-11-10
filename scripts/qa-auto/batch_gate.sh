#!/usr/bin/env bash
# qa-auto batch wrong-PASS gate: runs run.sh in PR mode (QA_SHA=head, QA_BASE=base; ad-hoc, never touches
# last_green/last_checked/status.json) on a bot/onboarding batch head and prints ONE line:
#   GATE <sha8> WRONGPASS=n MISMATCH=m ERR=e cases=c [rules=absent] [SKIPPED=..] base=<sha8> SEEDED=k/n
#   SEEDED=k/n is the trailing seeded-case field (seeds.py): n injected wrong PASSes were run BEFORE the real corpus and k were
#   caught. k<n is a wrong PASS (exit 2, WRONGPASS>=n-k, the corpus verdict is not trusted); SEEDED=none = no usable seeded result
#   (inconclusive, exit 3). The seeds come from the installed scripts (base), never from the head; QA_SEEDS_DIGEST (optional) pins
#   the seeds.py sha256. A line without SEEDED is the pre-seeding format.
#
#   batch_gate.sh [--trust-operator] <head-sha> [base-sha]   gate one head (base default: merge-base with main, else main tip)
#   batch_gate.sh --poll [--dry]          gate every open PR of QA_GATE_REPO whose head sha has no STATE/gate/<sha>.json
#                                         (head ref bot/* or onboard/*, or label "batch"); read-only against GitHub.
#                                         --dry lists what would be gated and gates nothing.
#
# SECURITY (the gate builds and runs PR-head code, so it is layered):
#  1. WHO: --poll and the explicit `<sha>` form only gate same-repo PRs by QA_GATE_AUTHORS (empty/unset = refuse);
#     `--trust-operator` skips this check for a sha the operator vouches for.
#  2. WHAT: an author allow-list does not bound content (bot batches are generated from untrusted upstream input), so
#     run.sh refuses (exit 3, "code change in bot batch") any head whose diff touches a path outside the DATA allow-list.
#  3. WHERE: head-built binaries run only through QA_RUNBOX (throwaway container: no network, read-only tree, no state,
#     no secrets); run.sh refuses to run without it. The remaining host steps (git, python oracles from the installed
#     scripts) only parse data.
#
# Exit: 0 green, 2 wrong PASS (case ids + repro on stderr), 3 inconclusive (errors, skipped suite, crash, timeout, new mismatch,
# code change in the batch), 75 busy. The GATE line ends with base=<sha8> (the base it was gated against); a green record is
# STALE once main moved and the head is no longer on the main tip: re-run after rebasing (a new head sha is a new gate).
# Skipped suites: only the known "rules(absent)" (rules_oracle.py not on this base yet) and "kind" (the gate always
# sets QA_NO_KIND=1) are informational; any other skipped suite makes the gate inconclusive (3), never green.
# MISMATCH counts every mismatch, including historical baselines; MISMATCH>0 is inconclusive (3).
# A merge needs a green line for the CURRENT head sha: a new head sha is a new gate.
#
# Parameters (environment, all optional):
#   QA_STATE          as run.sh (default QA_WORK_ROOT/qa-auto-state); results go to STATE/gate/<sha>.json
#   QA_REPO_URL       default https://github.com/prufyx/prufyx.git (fetch source)
#   QA_GATE_REPO      owner/name for the PR list, default prufyx/prufyx
#   QA_GATE_AUTHORS   comma list of GitHub logins whose PRs --poll may gate (required for --poll)
#   QA_GATE_CAP       seconds per gate (default 1200)
#   QA_GATE_TRIES     inconclusive attempts per head before it is recorded as INCONCLUSIVE (default 3)
#   QA_ALARM_HOOK     executable called with STATE/gate/<sha>.alarm.json on WRONGPASS
#   QA_GATE_RUN       run.sh to use (default: next to this script)
#   QA_RUNBOX         REQUIRED: command prefix that runs a head-built binary in a throwaway sandbox (see run.sh)
# Everything else (QA_DEVBOX, QA_WORK_ROOT, QA_MAXLOAD, QA_PRE_BUILD for seeded-failure proofs, ...) is passed to run.sh.
# The gate runs the crd/k8s/bp325/review suites (+ rules when present); kind probes and the db suite are not part of it.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${QA_REPO_URL:=https://github.com/prufyx/prufyx.git}"
: "${QA_GATE_REPO:=prufyx/prufyx}"
: "${QA_WORK_ROOT:=${TMPDIR:-/tmp}/qa-auto}"
: "${QA_STATE:=$QA_WORK_ROOT/qa-auto-state}"
: "${QA_GATE_CAP:=1200}"
: "${QA_GATE_TRIES:=3}"
: "${QA_GATE_RUN:=$HERE/run.sh}"
export QA_STATE QA_WORK_ROOT QA_REPO_URL
G=$QA_STATE/gate
mkdir -p "$G"

main_tip() { git ls-remote "$QA_REPO_URL" refs/heads/main | cut -f1; }

merge_base() { # HEAD -> merge-base with main (GitHub compare, read only), falls back to main tip
  local mb=""
  if command -v gh >/dev/null 2>&1; then
    mb=$(gh api "repos/$QA_GATE_REPO/compare/main...$1" --jq .merge_base_commit.sha 2>/dev/null || true)
  fi
  if ! [[ "$mb" =~ ^[0-9a-f]{40}$ ]]; then
    mb=$(python3 -I - "$QA_GATE_REPO" "$1" <<'PY' 2>/dev/null
import json, sys, urllib.request
r = urllib.request.urlopen(f"https://api.github.com/repos/{sys.argv[1]}/compare/main...{sys.argv[2]}", timeout=20)
print(json.load(r)["merge_base_commit"]["sha"])
PY
) || mb=""
  fi
  [[ "$mb" =~ ^[0-9a-f]{40}$ ]] || { [ "${QA_MB_STRICT:-0}" = 1 ] && mb="" || mb=$(main_tip); }
  echo "$mb"
}

# gate_one HEAD BASE -> prints the GATE line, writes STATE/gate/<head>.json when conclusive; returns the exit code
gate_one() (
  local head=$1 base=$2 s8=${1:0:8} rc out line
  [[ "$head" =~ ^[0-9a-f]{40}$ ]] || { echo "GATE ${s8} bad head sha (need 40 hex)" >&2; return 3; }
  [ -n "$base" ] || { echo "GATE $s8 cannot resolve base" >&2; return 3; }
  local run_id; run_id=$(python3 -I -c 'import uuid; print(uuid.uuid4().hex)')
  # Keep authenticated source objects and the expected contract outside every
  # candidate build/run mount. The final verdict re-derives from these objects.
  local scope_root scope_digest scope_file
  scope_root=$(mktemp -d "$QA_STATE/scope-parent.XXXXXX") || return 3
  trap 'rm -rf -- "$scope_root"' EXIT
  scope_file=$G/$head.$run_id.scope.json
  mkdir -p "$scope_root/src"
  git init -q "$scope_root/src" &&
    git -C "$scope_root/src" fetch -q --depth 64 "$QA_REPO_URL" \
      "$head:refs/qa-batch/head" "$base:refs/qa-batch/base" &&
    git -C "$scope_root/src" checkout -q --detach refs/qa-batch/head &&
    git -C "$scope_root/src" merge-base --is-ancestor "$base" "$head" || {
      echo "gate: SCOPE_PROVENANCE exact fetched head/base ancestry unavailable" >&2; return 3;
    }
  scope_digest=$(python3 -I "$HERE/qa_batch_scope.py" --src "$scope_root/src" --head "$head" \
    --base "$base" --run-id "$run_id" --out "$scope_file") || return 3
  local t0; t0=$(date +%s)
  local log; log=$(mktemp "${TMPDIR:-/tmp}/qa-gate-log.XXXXXX")
  # the gate raises its own alarm below: keep run.sh's hook, the kind probes and the db suite out of it
  # own session = own process group: on timeout/TERM/INT the whole group (oracles, binaries) is killed, never orphaned
  QA_BATCH_SCOPE_FILE=$scope_file QA_BATCH_SCOPE_DIGEST=$scope_digest \
    QA_RUN_ID=$run_id QA_SHA=$head QA_BASE=$base QA_NO_KIND=1 QA_DB_SUITE= QA_DB=0 QA_POLL=0 QA_ALARM_HOOK= \
    setsid timeout -k 30 "$QA_GATE_CAP" "$QA_GATE_RUN" >"$log" 2>&1 </dev/null &
  GPID=$!
  trap 'kill -TERM -- -"$GPID" 2>/dev/null; sleep 2; kill -KILL -- -"$GPID" 2>/dev/null; exit 143' TERM INT
  wait "$GPID"; rc=$?
  trap - TERM INT
  kill -KILL -- -"$GPID" 2>/dev/null || true   # stragglers that outlived run.sh
  out=$(ls -1dt "$QA_STATE"/results/*-"$s8" 2>/dev/null | head -1)
  if [ "$rc" = 75 ]; then
    echo "GATE $s8 busy" ; rm -f "$log"; return 75
  fi
  if [ "$rc" = 3 ] && grep -q 'code change in bot batch' "$log"; then
    # definitive, not retried: a human reviews a batch that touches code
    local why; why=$(grep -m1 'code change in bot batch' "$log" | sed 's/^qa-auto: //')
    line="GATE $s8 INCONCLUSIVE code change in bot batch base=${base:0:8}"
    echo "$line"; echo "  $why" >&2; rm -f "$log"
    python3 -I - "$G/$head.json" "$head" "$base" "$line" "$why" <<'PY'
import json, sys, time
f, head, base, line, why = sys.argv[1:]
json.dump({"sha": head, "base": base, "line": line, "exit": 3, "state": "INCONCLUSIVE", "reason": why,
           "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, open(f, "w"), indent=1)
PY
    return 3
  fi
  if [ -z "$out" ] || [ ! -s "$out/summary.json" ] || [ "$(date -r "$out/summary.json" +%s)" -lt "$t0" ]; then
    echo "GATE $s8 WRONGPASS=0 MISMATCH=0 ERR=1 cases=0 base=${base:0:8} SEEDED=none"
    { echo "gate: no summary (run.sh exit $rc, cap ${QA_GATE_CAP}s); tail:"; tail -5 "$log"; } >&2
    rm -f "$log"
    n=$(( $(cat "$G/$head.try" 2>/dev/null || echo 0) + 1 )); echo "$n" >"$G/$head.try"
    if [ "$n" -ge "$QA_GATE_TRIES" ]; then
      printf '{"sha":"%s","base":"%s","line":"GATE %s WRONGPASS=0 MISMATCH=0 ERR=1 cases=0 base=%s SEEDED=none","exit":3,"state":"INCONCLUSIVE"}\n' "$head" "$base" "$s8" "${base:0:8}" >"$G/$head.json"
      rm -f "$G/$head.try"
    fi
    return 3
  fi
  rm -f "$log"
  python3 -I - "$out/summary.json" "$head" "$base" "$G" "$rc" "$(main_tip)" "$run_id" "$HERE" "$scope_root" "$scope_file" "$scope_digest" <<'PY'
import json, os, sys, time
from pathlib import Path
summ, head, base, gdir, rc, tip, run_id, script_dir, scope_root, scope_file, expected_digest = sys.argv[1:]
sys.path.insert(0, script_dir)
import qa_scope
import qa_batch_scope
import qalib
s = json.load(open(summ))
run_error = (int(rc) != 0 or
             s.get("run_id") != run_id or s.get("base") != base or
             type(s.get("cases")) is not int or s["cases"] <= 0)
scope_errors = qa_scope.bundle_errors(s.get("scopes", {}), head, base, run_id)
contract = {}
try:
    contract = qa_batch_scope.parse(Path(scope_file).read_bytes())
    recomputed = qa_batch_scope.freeze(Path(scope_root, "src"), head, base, run_id, contract["extra_projects"])
    if qa_batch_scope.digest(contract) != expected_digest or contract != recomputed:
        raise ValueError("SCOPE_MISMATCH: original frozen contract differs")
    cases = []
    for path in sorted(Path(summ).parent.glob("*.cases.json")):
        cases.extend(json.loads(path.read_bytes(), object_pairs_hook=qa_batch_scope.unique_object))
    declarations = {}
    if contract["envelopes"]:
        for suite in ("crd", "k8s"):
            declarations[suite] = qa_batch_scope.parse(Path(summ).with_name(suite + ".scope.json.declared").read_bytes())
    scope_errors.extend(qa_batch_scope.validate(contract, s.get("scopes", {}), cases, declarations))
    # A summary cannot erase a failed case still present in the original suite.
    for name, flag in (("wrongpass", "wrongpass"), ("mismatch", "mismatch"), ("errors", "error")):
        actual = sum(c.get(flag) is True for c in cases)
        if actual > s.get(name, 0):
            scope_errors.append("SCOPE_MISMATCH: failed case removed from summary")
            s[name] = actual
except (OSError, ValueError, KeyError, TypeError) as error:
    scope_errors.append("SCOPE_INVALID: " + str(error))
# Seeded wrong-PASS result (seeds.py, run before the real corpus): fail closed on anything that is not a complete, installed-digest
# bound result; an uncaught seed is a wrong PASS whatever else the summary says.
seed = s.get("seeded")
seed_text = "none"
try:
    if not (isinstance(seed, dict) and type(seed.get("caught")) is int and type(seed.get("total")) is int
            and 0 < seed["total"] and 0 <= seed["caught"] <= seed["total"] and isinstance(seed.get("digest"), str)
            and isinstance(seed.get("uncaught"), list)):
        raise ValueError("SEEDED result missing or malformed")
    seed_text = f"{seed['caught']}/{seed['total']}"
    if seed["digest"] != qalib.seeds_digest():
        raise ValueError("SEEDED digest differs from the installed seeds.py")
    pinned = os.environ.get("QA_SEEDS_DIGEST", "")
    if pinned and seed["digest"] != pinned:
        raise ValueError("SEEDED digest differs from the pinned QA_SEEDS_DIGEST")
    if seed.get("error"):
        raise ValueError("SEEDED run error: " + str(seed["error"])[:200])
    if seed["caught"] != seed["total"] - len(seed["uncaught"]):
        raise ValueError("SEEDED caught/uncaught disagree")
    if seed["caught"] < seed["total"]:
        s["wrongpass"] = max(s.get("wrongpass", 0), seed["total"] - seed["caught"])
        scope_errors.append("SEEDED_UNCAUGHT: " + ",".join(seed["uncaught"][:10]))
except ValueError as error:
    scope_errors.append(str(error))
    if isinstance(seed, dict) and isinstance(seed.get("uncaught"), list) and seed["uncaught"]:
        s["wrongpass"] = max(s.get("wrongpass", 0), len(seed["uncaught"]))
s["errors"] = s.get("errors", 0) + int(run_error) + int(bool(scope_errors))
if scope_errors:
    print("gate: " + "; ".join(scope_errors), file=sys.stderr)
if run_error:
    print(f"gate: runner exit/binding invalid (exit {rc})", file=sys.stderr)
if s.get("sha") != head:  # results dir is found by 8-char prefix: the full sha must match
    print(f"gate: summary sha {s.get('sha')!r} != head {head}", file=sys.stderr)
    sys.exit(3)
# Publication requires every mismatch to be resolved; a historical baseline cannot waive it.
m = s["mismatch"]
# skipped suites: "rules(absent)" is known and informational until rules_oracle.py lands on main (it would otherwise
# keep every gate inconclusive); "kind" is skipped by the gate itself (QA_NO_KIND=1). ANY other skip => inconclusive.
skipped = list(s.get("skipped", []))
info = [k for k in skipped if k in ("rules(absent)", "kind")]
bad = [k for k in skipped if k not in ("rules(absent)", "kind")]
line = f"GATE {head[:8]} WRONGPASS={s['wrongpass']} MISMATCH={m} ERR={s['errors']} cases={s['cases']}"
if "rules(absent)" in info:
    line += " rules=absent"
if bad:
    line += " SKIPPED=" + ",".join(bad)
line += f" base={base[:8]} SEEDED={seed_text}"
# Any mismatch is inconclusive, including one recorded in a historical baseline.
code = 2 if s["wrongpass"] else (3 if s["errors"] or bad or m else 0)
json.dump({"sha": head, "base": base, "line": line, "exit": code, "state": {0: "GREEN", 2: "WRONGPASS", 3: "INCONCLUSIVE"}[code],
           "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "mode": s["mode"], "skipped": skipped,
           "main": tip, "wrongpass": s["wrongpass"], "mismatch": m, "errors": s["errors"], "cases": s["cases"],
           "wrongpass_cases": s["wrongpass_cases"], "error_cases": s["error_cases"], "summary": summ, "scopes": s.get("scopes"),
           "seeded": seed, "batch_scope_digest": expected_digest, "batch_scope": contract,
           "kind": "not_executed", "db": "not_executed"},
          open(f"{gdir}/{head}.json.tmp", "w"), indent=1)
print(line)
if code == 2:
    for c in s["wrongpass_cases"][:20]:
        print(f"  WRONGPASS {c['suite']}|{c['key']} {json.dumps(c['detail'])[:300]}", file=sys.stderr)
    print(f"  repro: QA_SHA={head} QA_BASE={base} QA_NO_KIND=1 scripts/qa-auto/run.sh  (case detail: {summ})", file=sys.stderr)
if code == 3:
    if bad:
        print(f"  SKIPPED suites (inconclusive): {', '.join(bad)}", file=sys.stderr)
    if m:
        print(f"  MISMATCH={m} (total, including historical baselines): triage before merge", file=sys.stderr)
    for c in s["error_cases"][:5]:
        print(f"  ERR {c['suite']}|{c['key']} {json.dumps(c['detail'])[:200]}", file=sys.stderr)
sys.exit(code)
PY
  rc=$?
  case $rc in 0|2|3|75) ;; *) rc=3 ;; esac   # python crash or any unexpected code is inconclusive, never green
  line=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["line"])' "$G/$head.json.tmp" 2>/dev/null || true)
  # inconclusive heads are retried (poll) up to QA_GATE_TRIES times, then recorded as INCONCLUSIVE
  if [ "$rc" = 3 ]; then
    n=$(( $(cat "$G/$head.try" 2>/dev/null || echo 0) + 1 )); echo "$n" >"$G/$head.try"
    if [ "$n" -lt "$QA_GATE_TRIES" ]; then rm -f "$G/$head.json.tmp"; return 3; fi
    if [ ! -f "$G/$head.json.tmp" ]; then   # sha mismatch / python crash, tries used up: record it, never re-gate forever
      line="GATE $s8 INCONCLUSIVE gate verdict crashed base=${base:0:8}"; echo "$line"
      printf '{"sha":"%s","base":"%s","line":"%s","exit":3,"state":"INCONCLUSIVE"}\n' "$head" "$base" "$line" >"$G/$head.json.tmp"
    fi
  fi
  [ -f "$G/$head.json.tmp" ] && mv "$G/$head.json.tmp" "$G/$head.json"
  rm -f "$G/$head.try"
  if [ "$rc" = 2 ] && [ -n "${QA_ALARM_HOOK:-}" ] && [ -x "$QA_ALARM_HOOK" ]; then
    python3 -I - "$G/$head.json" "$G/$head.alarm.json" <<'PY'
import json, sys
g = json.load(open(sys.argv[1]))
json.dump({"kind": "qa-auto-batch-wrongpass", "id": f"qa-auto-gate/{g['sha'][:8]}", "raised": g["time"], "verdict": g["line"],
           "wrongpass_cases": g["wrongpass_cases"], "new_mismatch_cases": [], "summary": g["summary"]}, open(sys.argv[2], "w"), indent=1)
PY
    "$QA_ALARM_HOOK" "$G/$head.alarm.json" || echo "gate: alarm hook failed with exit $?" >&2
  fi
  return $rc
)

# stale_check HEAD MAIN_TIP: a recorded GREEN was gated against an older main. It stays valid only while the head sits on
# the current main tip; otherwise the record is rewritten as STALE (exit 3) until the head is rebased (new sha = new gate).
stale_check() {
  local head=$1 tip=$2 rec mb
  rec=$(python3 -I -c 'import json,sys;g=json.load(open(sys.argv[1]));print(g.get("exit",3),g.get("main",""))' "$G/$head.json" 2>/dev/null) || return 0
  [ "${rec%% *}" = 0 ] || return 0
  [ "${rec#* }" = "$tip" ] && return 0
  mb=$(QA_MB_STRICT=1 merge_base "$head")   # lookup failure = "" = stale (fail closed)
  if [ -n "$mb" ] && [ "$mb" = "$tip" ]; then   # head is on the current tip: the result still describes what would be merged
    python3 -I - "$G/$head.json" "$tip" <<'PY'
import json, sys
g = json.load(open(sys.argv[1])); g["main"] = sys.argv[2]
json.dump(g, open(sys.argv[1] + ".tmp", "w"), indent=1)
PY
    mv "$G/$head.json.tmp" "$G/$head.json"
  else
    python3 -I - "$G/$head.json" "$tip" "$mb" <<'PY'
import json, sys
g = json.load(open(sys.argv[1]))
g.update({"exit": 3, "state": "STALE", "line": g["line"] + f" STALE main={sys.argv[2][:8]} (gated against base {g['base'][:8]}; rebase and re-gate)"})
json.dump(g, open(sys.argv[1] + ".tmp", "w"), indent=1)
PY
    mv "$G/$head.json.tmp" "$G/$head.json"
    echo "gate: ${head:0:8} STALE: main moved to ${tip:0:8} and the head is not on it" >&2
  fi
}

poll() {
  local dry=${1:-0} list tip rcall=0 head num ref base rc prev
  QA_GATE_AUTHORS=${QA_GATE_AUTHORS:-}
  if [ -z "${QA_GATE_AUTHORS//[, ]/}" ]; then
    echo "gate: QA_GATE_AUTHORS is empty or unset: refusing to gate anything (the gate executes PR head code; set a comma list of trusted GitHub logins)" >&2
    return 1
  fi
  # SECURITY: only same-repo PRs by QA_GATE_AUTHORS; fork PRs would run attacker code on this host
  list=$(QA_GATE_AUTHORS=$QA_GATE_AUTHORS python3 -I - "$QA_GATE_REPO" <<'PY'
import json, os, re, subprocess, sys, urllib.request
repo = sys.argv[1]
owner = repo.split("/")[0]
authors = {a.strip().lower() for a in os.environ.get("QA_GATE_AUTHORS", "").split(",") if a.strip()}
try:
    prs = json.loads(subprocess.run(["gh", "pr", "list", "--repo", repo, "--state", "open", "--limit", "100",
                                    "--json", "number,headRefOid,headRefName,labels,isCrossRepository,headRepositoryOwner,author"],
                                    capture_output=True, text=True, check=True).stdout)
    for p in prs:
        p["cross"] = bool(p.get("isCrossRepository")) or (p.get("headRepositoryOwner") or {}).get("login", "").lower() != owner.lower()
        p["login"] = (p.get("author") or {}).get("login", "")
except Exception:
    raw = json.load(urllib.request.urlopen(f"https://api.github.com/repos/{repo}/pulls?state=open&per_page=100", timeout=30))
    prs = []
    for p in raw:
        hr = p["head"].get("repo") or {}
        prs.append({"number": p["number"], "headRefOid": p["head"]["sha"], "headRefName": p["head"]["ref"], "labels": p["labels"],
                    "cross": hr.get("full_name") != repo, "login": (p.get("user") or {}).get("login", "")})
for p in prs:
    trig = re.match(r"(bot|onboard)/", p["headRefName"]) or any(l["name"] == "batch" for l in p["labels"])
    if not trig:
        continue
    if p["cross"]:
        print(f"gate: skip PR #{p['number']} {p['headRefName']}: fork (cross-repository) PR", file=sys.stderr)
    elif p["login"].lower() not in authors:
        print(f"gate: skip PR #{p['number']} {p['headRefName']}: author {p['login']!r} not in QA_GATE_AUTHORS", file=sys.stderr)
    else:
        print(p["headRefOid"], p["number"], p["headRefName"])
PY
  ) || { echo "gate: PR list failed" >&2; return 3; }
  [ -n "$list" ] || { echo "gate: no batch PRs"; return 0; }
  tip=$(main_tip)
  while read -r head num ref; do
    [ -n "$head" ] || continue
    if [ -f "$G/$head.json" ]; then
      [ "$dry" = 1 ] || stale_check "$head" "$tip"
      # already recorded: fold its verdict so a bad head keeps the poll non-zero
      prev=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1])).get("exit",3))' "$G/$head.json" 2>/dev/null || echo 3)
      [ "$dry" = 1 ] && echo "gate: PR #$num $ref ${head:0:8} recorded (exit $prev)"
      case $prev in 0) ;; 2) rcall=2 ;; *) [ "$rcall" = 0 ] && rcall=3 ;; esac
      continue
    fi
    if [ "$dry" = 1 ]; then echo "gate: PR #$num $ref ${head:0:8} would be gated"; continue; fi
    # strict: a failed compare lookup must never fall back to the main tip (a head behind main would then show main's
    # changes as its own and get a permanent INCONCLUSIVE record); write nothing and retry next tick
    base=$(QA_MB_STRICT=1 merge_base "$head")
    if [ -z "$base" ]; then
      echo "gate: PR #$num $ref ${head:0:8} cannot resolve base, retry next tick" >&2
      [ "$rcall" = 0 ] && rcall=3
      continue
    fi
    echo "gate: PR #$num $ref"
    gate_one "$head" "$base"; rc=$?
    case $rc in
      0) ;;
      75) return 75 ;;
      2) rcall=2 ;;
      *) [ "$rcall" = 0 ] && rcall=3 ;;
    esac
  done <<<"$list"
  return $rcall
}

hex40() { [[ "${1:-}" =~ ^[0-9a-f]{40}$ ]]; }

# trusted_head SHA: the explicit form needs the same filter as --poll: an open same-repo PR whose head is exactly SHA,
# authored by QA_GATE_AUTHORS. Any lookup failure refuses (fail closed).
trusted_head() {
  [ -n "${QA_GATE_AUTHORS:-}" ] && [ -n "${QA_GATE_AUTHORS//[, ]/}" ] || { echo "gate: QA_GATE_AUTHORS is empty or unset: refusing (or pass --trust-operator)" >&2; return 1; }
  command -v gh >/dev/null 2>&1 || { echo "gate: gh is needed to verify the PR of $1 (or pass --trust-operator)" >&2; return 1; }
  gh api "repos/$QA_GATE_REPO/commits/$1/pulls" 2>/dev/null | QA_GATE_AUTHORS=$QA_GATE_AUTHORS python3 -I -c '
import json, os, sys
repo, sha = sys.argv[1:]
authors = {a.strip().lower() for a in os.environ["QA_GATE_AUTHORS"].split(",") if a.strip()}
try:
    prs = json.load(sys.stdin)
except Exception:
    sys.exit(1)
for p in prs:
    hr = (p["head"].get("repo") or {}).get("full_name")
    if p["state"] == "open" and p["head"]["sha"] == sha and hr == repo and (p.get("user") or {}).get("login", "").lower() in authors:
        sys.exit(0)
sys.exit(1)' "$QA_GATE_REPO" "$1" || { echo "gate: $1 is not the head of an open same-repo PR by QA_GATE_AUTHORS: refusing (or pass --trust-operator)" >&2; return 1; }
}

case "${1:-}" in
  --poll) case "${2:-}" in "") poll 0 ;; --dry) poll 1 ;; *) echo "usage: --poll [--dry]" >&2; exit 1 ;; esac; exit $? ;;
  --dry) [ "${2:-}" = --poll ] && { poll 1; exit $?; }; echo "usage: --poll [--dry]" >&2; exit 1 ;;
  "" | -h | --help) sed -n 2,45p "$0"; exit 1 ;;
  *)
    trust=0; [ "$1" = --trust-operator ] && { trust=1; shift; }
    hex40 "${1:-}" || { echo "gate: head sha must be 40 hex chars" >&2; exit 1; }
    [ "$trust" = 1 ] || trusted_head "$1" || exit 1
    [ -z "${2:-}" ] || hex40 "$2" || { echo "gate: base sha must be 40 hex chars" >&2; exit 1; }
    base=${2:-}
    [ -n "$base" ] || base=$(QA_MB_STRICT=1 merge_base "$1")
    [ -n "$base" ] || { echo "gate: ${1:0:8} cannot resolve base (compare lookup failed); pass a base sha or retry" >&2; exit 3; }
    gate_one "$1" "$base"; exit $? ;;
esac
