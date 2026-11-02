#!/usr/bin/env bash
# qa-auto: independent check that Prufyx never reports a wrong PASS after a data/knowledge merge on main.
# Runs on the Docker host (not a laptop): Go builds happen in the devbox container, everything else is
# python3 + git on the host. Builds main at a sha, regenerates the coverage report, then runs
#   crd_oracle.py   served CRD GVKs at real upstream tags vs `prufyx scan`
#   k8s_oracle.py   swagger removed-API sets vs scan (range, single GVK) and `plan` stages
#   rules_oracle.py every forbid_predicate_value / forbid_set_member rule: trigger must BLOCK, then wrapper/obfuscation corpus must stay non-PASS
#   kind_probe.py   one kind cluster qa-auto-<sha8>: removed built-in APIs, live CRD dumps, assess
# and writes one summary + one verdict line:  WRONGPASS=n MISMATCH=n NEWMISMATCH=n ERR=n ...
# WRONGPASS = a served GVK/API is gone at the target version and scan/plan exits 0 or says PASS.
#
# Parameters (environment):
#   QA_SHA            commit to check (default: tip of main on QA_REPO_URL)
#   QA_REPO_URL       default https://github.com/prufyx/prufyx.git
#   QA_MODE           auto (default) | full | incremental. auto = full when nothing is green yet, the last full
#                     run is older than QA_FULL_EVERY_H (24), or non-test code changed; else only changed projects
#   QA_POLL=1         do nothing unless main has a sha not yet checked (what the timer uses)
#   QA_FORCE=1        run even if this sha was checked
#   QA_WORK_ROOT      default ${TMPDIR:-/tmp}/qa-auto; per-run scratch QA_WORK_ROOT/qa-auto-run-*, removed at exit
#   QA_STATE          persistent state (default QA_WORK_ROOT/qa-auto-state): status.json, last_green, alarms/,
#                     results/, known-mismatch.json (baseline), cache/ (bare upstream clones, swagger)
#   QA_DEVBOX         wrapper "devbox -w DIR cmd..." that runs cmd in a toolchain container with DIR mounted (default: devbox on PATH)
#   QA_RUNBOX         command prefix that runs a binary built from the PR head (prufyx, crdgvk) in a throwaway sandbox (no network,
#                     read-only tree, no state, no secrets); exported QA_BOX_DIR = the per-run scratch it may mount. REQUIRED in PR/gate
#                     mode (QA_BASE), which also accepts DATA-only diffs: any other path => exit 3 "code change in bot batch"
#   QA_MAXLOAD        skip (exit 75) when the 1-minute load is not below this (default 8)
#   QA_JOBS           parallel projects in the CRD oracle (default 3)
#   QA_BASE           PR/batch mode (with QA_SHA = the head): diff QA_BASE..QA_SHA selects the work. Changed projects drive the
#                     crd/k8s suites (select_projects.py), changed rule ids of cli/internal/cncfcheck/data/rules.json drive the
#                     rules suite (scripts/qa-auto/rules_oracle.py, run when present, else a counted "rules(absent)" skip; the ids
#                     reach it as QA_RULES_IDS=comma list and QA_RULES_ALL=1 when the diff cannot be narrowed), and the fast
#                     review suite always runs. last_green is not used. Ad-hoc. A diff that touches code/tooling selects a full run.
#   QA_PROJECTS       comma list: check only these projects (ad-hoc runs and seeded-failure proofs)
#   QA_DB_SUITE       path of the db suite run.sh [SHA] [OUTDIR]; QA_DB=1 forces it (nightly); STATE/db-allow.json = allowed failing ids
#   STATE/review-allow.json  allowed open review findings {"ID": {"wi": "WI-n", "reason": ...}}; ids outside the review findings are refused, a stale entry alarms
#   STATE/rules-allow.json   allowed documented PASS cases {"<rule id>#<variant>" | "*#<variant>": {"ref": ..., "reason": ...}}; list only shrinks, a stale entry alarms
#   QA_NO_KIND=1      skip the kind probes
#   QA_ALARM_HOOK     executable called with the alarm file path when an alarm is raised
#   QA_PRE_BUILD      shell script run in the scratch checkout before the build (seeded-failure proofs only)
# Exit: 0 green, 2 alarm, 3 inconclusive (errors), 4 green-partial (a suite was skipped), 75 busy/load, 1 setup failure.
# Ad-hoc runs (QA_PROJECTS, QA_SHA, QA_PRE_BUILD or QA_NO_KIND set) never update last_green/last_checked/last_full/status.json.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${QA_REPO_URL:=https://github.com/prufyx/prufyx.git}"
: "${QA_WORK_ROOT:=${TMPDIR:-/tmp}/qa-auto}"
: "${QA_STATE:=$QA_WORK_ROOT/qa-auto-state}"
: "${QA_DEVBOX:=devbox}"
: "${QA_MAXLOAD:=8}"
: "${QA_MODE:=auto}"
: "${QA_FULL_EVERY_H:=24}"
: "${QA_JOBS:=3}"
export QA_DEVBOX QA_JOBS QA_RUNBOX
mkdir -p "$QA_STATE/results" "$QA_STATE/cache"
# ad-hoc (parameterized) runs never move last_green/last_checked/last_full or the polled status.json:
# a seeded-failure build or a one-project run must not become the baseline of later incremental runs.
ADHOC=0; for v in QA_PROJECTS QA_SHA QA_PRE_BUILD QA_NO_KIND QA_BASE; do [ -n "${!v:-}" ] && ADHOC=1; done
adhoc_flag=(); [ "$ADHOC" = 1 ] && adhoc_flag=(--adhoc)

exec 9>"$QA_STATE/lock"
flock -n 9 || { echo "qa-auto: another run holds the lock"; exit 75; }
load=$(cut -d' ' -f1 /proc/loadavg)
awk -v l="$load" -v m="$QA_MAXLOAD" 'BEGIN{exit !(l<m)}' || { echo "qa-auto: load $load >= $QA_MAXLOAD, skipped"; exit 75; }

sha=${QA_SHA:-$(git ls-remote "$QA_REPO_URL" refs/heads/main | cut -f1)}
[ -n "$sha" ] || { echo "qa-auto: cannot resolve main"; exit 1; }
s8=${sha:0:8}
if [ "${QA_POLL:-0}" = 1 ] && [ "${QA_FORCE:-0}" != 1 ] && [ "$(cat "$QA_STATE/last_checked" 2>/dev/null)" = "$sha" ]; then
  echo "qa-auto: $s8 already checked"; exit 0
fi

RUN=$QA_WORK_ROOT/qa-auto-run-$s8-$$
OUT=$QA_STATE/results/$(date -u +%Y%m%dT%H%M%S)-$s8
mkdir -p "$RUN" "$OUT"
export QA_BOX_DIR=$RUN   # the only directory a sandbox (QA_DEVBOX/QA_RUNBOX wrappers) may mount: per-run scratch, deleted at exit
cleanup() {
  [ "${QA_NO_KIND:-0}" = 1 ] || "$QA_DEVBOX" -w "$RUN" kind delete cluster --name "qa-auto-$s8" >/dev/null 2>&1 </dev/null || true
  rm -rf "$RUN"
}
trap cleanup EXIT
trap 'exit 143' TERM INT
log() { echo "qa-auto: $*" >&2; }
t0=$(date +%s)

# 1. source at sha (+ last green for the diff)
git init -q "$RUN/src" && cd "$RUN/src" || exit 1
git fetch -q --depth 1 "$QA_REPO_URL" "$sha" && git checkout -q FETCH_HEAD || { log "fetch $sha failed"; exit 1; }
lg=$(cat "$QA_STATE/last_green" 2>/dev/null || true)
: >"$RUN/changed"
GATE=0; base_sha=""
if [ -n "${QA_BASE:-}" ]; then
  # PR mode: the base is given, last_green is irrelevant
  GATE=1
  git fetch -q --depth 1 "$QA_REPO_URL" "$QA_BASE" && base_sha=$(git rev-parse FETCH_HEAD) \
    && git diff --name-only --no-renames "$base_sha" "$sha" >"$RUN/changed" \
    && git diff --raw --no-renames "$base_sha" "$sha" >"$RUN/changed.raw" || { log "fetch/diff base $QA_BASE failed"; exit 1; }
  lg=$base_sha
  # SECURITY: a bot/onboarding batch is generated from untrusted upstream input under a trusted login, so the author
  # allow-list does not bound its CONTENT. Gate mode accepts DATA only; any other path (Go, vendor, go.mod, scripts,
  # workflows, symlinks, odd file names) is refused, never downgraded to a full run.
  bad=$(python3 -I - "$RUN/changed.raw" <<'PY'
import re, sys
OK = [r"cli/internal/(?:[\w.-]+/)*data/[\w.-]+\.json",
      r"cli/internal/extract/crdversions/target-[\w.-]+\.json",
      r"cli/internal/customresources/table\.json",
      r"cli/internal/maintainer/coveragereport/testdata/lines-[\w.-]+\.json",
      r"cli/knowledge/(?:[\w.-]+/)*[\w.-]+\.(?:json|txt|md)",
      r"changelog\.d/[\w.-]+\.md",
      r"(?:cli/)?docs/(?:[\w.-]+/)*[\w.-]+\.(?:json|md)",
      r"(?:[\w.-]+/)*[\w.-]+\.md"]
OK = [re.compile(x, re.A) for x in OK]
bad = []
for line in open(sys.argv[1]).read().split("\n"):
    if not line:
        continue
    try:
        meta, path = line.split("\t", 1)
        dmode = meta.split()[1]
    except Exception:
        bad.append(line[:80]); continue
    if ".." in path.split("/") or dmode not in ("100644", "000000") or not any(r.fullmatch(path) for r in OK):
        bad.append(path)
print(" ".join(bad[:10]))
sys.exit(1 if bad else 0)
PY
  ) || { log "code change in bot batch (not data-only): $bad"; exit 3; }
  # a target-*.json decides which upstream repo the oracle clones: its repo must not change, and a new target may only name a
  # repo already known at the base (another target's repo) or listed in QA_GATE_REPOS (comma list owner/name, added after review)
  bad=$(QA_GATE_REPOS=${QA_GATE_REPOS:-} python3 -I - "$RUN/src" "$base_sha" "$RUN/changed" <<'PY'
import json, os, re, subprocess, sys
src, base, changed = sys.argv[1:]
TD = "cli/internal/extract/crdversions/"
def show(rev, path):
    r = subprocess.run(["git", "-C", src, "show", f"{rev}:{path}"], capture_output=True, text=True)
    return None if r.returncode else r.stdout
def repo_of(txt):
    r = json.loads(txt)["target"]["repo"]
    r = r[len("github.com/"):] if r.startswith("github.com/") else r
    if not re.fullmatch(r"[A-Za-z0-9_][\w.-]*/[A-Za-z0-9_][\w.-]*", r, re.A):
        raise ValueError("bad repo")
    return r
try:
    known = {x.strip() for x in os.environ.get("QA_GATE_REPOS", "").split(",") if x.strip()}
    ls = subprocess.run(["git", "-C", src, "ls-tree", "--name-only", base, TD], capture_output=True, text=True).stdout.split()
    for f in ls:
        if re.fullmatch(re.escape(TD) + r"target-[\w.-]+\.json", f, re.A):
            t = show(base, f)
            if t:
                try: known.add(repo_of(t))
                except Exception: pass
    bad = []
    for p in open(changed).read().split("\n"):
        if re.fullmatch(re.escape(TD) + r"target-[\w.-]+\.json", p, re.A):
            head = show("HEAD", p)
            if head is None:
                continue  # deleted
            hr = repo_of(head)
            old = show(base, p)
            if old is not None:
                if repo_of(old) != hr:
                    bad.append(f"{p}: repo changed")
            elif hr not in known:
                bad.append(f"{p}: new repo {hr} not known")
    print(" ".join(bad[:10]))
    sys.exit(1 if bad else 0)
except Exception as e:
    print(f"target check failed: {type(e).__name__}")
    sys.exit(1)
PY
  ) || { log "code change in bot batch (target repo not trusted): $bad"; exit 3; }
  [ -n "${QA_RUNBOX:-}" ] || { log "gate mode needs QA_RUNBOX (sandbox for head-built binaries): refusing"; exit 3; }
elif [ -n "$lg" ] && git fetch -q --depth 1 "$QA_REPO_URL" "$lg" 2>/dev/null; then
  git diff --name-only FETCH_HEAD "$sha" >"$RUN/changed" 2>/dev/null || lg=""
else
  lg=""
fi
last_full=$(cat "$QA_STATE/last_full" 2>/dev/null || echo 0)
mode=$QA_MODE
if [ "$mode" = auto ]; then
  mode=incremental
  { [ -z "$lg" ] || [ $(( $(date +%s) - last_full )) -gt $(( QA_FULL_EVERY_H * 3600 )) ]; } && mode=full
fi
sel=$(python3 -I "$HERE/select_projects.py" --changed "$RUN/changed" --src "$RUN/src") || sel='{"mode":"full","projects":[],"relevant":true,"reasons":["select failed"]}'
selmode=$(python3 -I -c 'import json,sys;print(json.loads(sys.argv[1])["mode"])' "$sel")
projects=$(python3 -I -c 'import json,sys;print(",".join(json.loads(sys.argv[1])["projects"]))' "$sel")
[ "$selmode" = full ] && mode=full
[ "$GATE" = 1 ] && [ "$selmode" != full ] && mode=incremental
if [ -n "${QA_PROJECTS:-}" ]; then mode=incremental; selmode=incremental; projects=$QA_PROJECTS; fi
echo "$sel" >"$OUT/select.json"
if [ "$mode" = incremental ] && [ "$selmode" = none ] && [ "$GATE" = 0 ]; then
  log "$s8: nothing relevant changed since ${lg:0:8}; recording green"
  python3 -I -c 'import json,sys;json.dump([],open(sys.argv[1],"w"))' "$OUT/none.cases.json"
  python3 "$HERE/summarize.py" --dir "$OUT" --state "$QA_STATE" --sha "$sha" --mode none --note "no relevant change" "${adhoc_flag[@]}"
  rc=$?
  if [ "$ADHOC" = 0 ]; then
    echo "$sha" >"$QA_STATE/last_checked"; [ $rc = 0 ] && echo "$sha" >"$QA_STATE/last_green"
  fi
  exit $rc
fi

# 2. build prufyx + helper in the devbox
mkdir -p "$RUN/src/cli/cmd/crdgvkqa" "$RUN/bin" "$RUN/tmp"
cp "$HERE/crdgvk.go" "$RUN/src/cli/cmd/crdgvkqa/main.go"
if [ -n "${QA_PRE_BUILD:-}" ]; then (cd "$RUN/src" && sh "$QA_PRE_BUILD") || { log "pre-build hook failed"; exit 1; }; fi
log "$s8 mode=$mode build"
"$QA_DEVBOX" -w "$RUN/src/cli" sh -c 'GOFLAGS=-mod=vendor go build -o "$1/bin/prufyx" ./cmd/prufyx-community && GOFLAGS=-mod=vendor go build -o "$1/bin/crdgvk" ./cmd/crdgvkqa' _ "$RUN" </dev/null >"$RUN/build.log" 2>&1 9>&- \
  || { tail -20 "$RUN/build.log" >&2; log "build failed"; exit 1; }

# 3. coverage report (pairs come from here; every pair is checked regardless of its status)
export QA_NOW=${QA_NOW:-$(date -u -d '+1 day' +%Y-%m-%dT00:00:00Z)}
L=$(ls "$RUN"/src/cli/internal/maintainer/coveragereport/testdata/lines-*.json 2>/dev/null | tail -1)
export QA_COV=""
if [ -n "$L" ] && "$QA_DEVBOX" -w "$RUN/src/cli" sh -c 'GOFLAGS=-mod=vendor go run ./cmd/prufyx-maintainer coverage report --lines "$1" --now "$2" --window ALL --json-out "$3"' _ "${L#"$RUN/src/cli/"}" "$QA_NOW" "$RUN/cov.json" </dev/null >"$RUN/cov.log" 2>&1 9>&-; then
  QA_COV=$RUN/cov.json
else
  log "coverage report failed; pairs derived from upstream tags"
fi

# 4. suites
export QA_BIN=$RUN/bin/prufyx QA_CRDGVK=$RUN/bin/crdgvk QA_SRC=$RUN/src QA_CACHE=$QA_STATE/cache QA_TMP=$RUN/tmp
cd "$HERE" || exit 1
if [ "$mode" = full ]; then sel_args=(--all); else sel_args=(--projects "$projects"); fi
if [ "$GATE" = 1 ] && [ "$mode" != full ] && [ -z "$projects" ]; then
  # gate mode only: nothing project-specific changed (crd_oracle would treat an empty list as "all"): one counted OK case, not a silent skip
  python3 -I -c 'import json,sys;json.dump([{"suite":"crd","key":"no-changed-projects","wrongpass":False,"mismatch":False,"error":False,"detail":{}}],open(sys.argv[1],"w"))' "$OUT/crd.cases.json"
else
  python3 -X utf8 crd_oracle.py "${sel_args[@]}" --out "$OUT/crd.cases.json" >"$OUT/crd.log" 2>&1 9>&- || log "crd oracle crashed"
fi
python3 -X utf8 k8s_oracle.py --out "$OUT/k8s.cases.json" >"$OUT/k8s.log" 2>&1 9>&- || log "k8s oracle crashed"
skipped=()
placeholder() { # FILE SUITE: error case so a crashed or empty suite can never be green
  python3 -I -c 'import json,sys;json.dump([{"suite":sys.argv[2],"key":"suite-crashed","wrongpass":False,"mismatch":False,"error":True,"detail":{}}],open(sys.argv[1],"w"))' "$1" "$2"
}
if [ "${QA_NO_KIND:-0}" = 1 ]; then
  skipped+=(kind)
else
  nk=$("$QA_DEVBOX" kind get clusters </dev/null 2>/dev/null | grep -c '^qa-' || true)
  load=$(cut -d' ' -f1 /proc/loadavg)
  if [ "${nk:-0}" -lt 3 ] && awk -v l="$load" -v m="$QA_MAXLOAD" 'BEGIN{exit !(l<m)}'; then
    python3 -X utf8 kind_probe.py --sha8 "$s8" --crd-cases "$OUT/crd.cases.json" --out "$OUT/kind.cases.json" >"$OUT/kind.log" 2>&1 9>&- || log "kind probe crashed"
  else
    log "kind probes skipped (qa clusters=$nk load=$load)"
    skipped+=(kind)
  fi
fi
[ "${QA_NO_KIND:-0}" = 1 ] || [[ " ${skipped[*]:-} " == *" kind "* ]] || [ -s "$OUT/kind.cases.json" ] || placeholder "$OUT/kind.cases.json" kind
# a crashed suite leaves no cases file: that is an error case, never a silent green
for s in crd k8s; do
  [ -s "$OUT/$s.cases.json" ] || placeholder "$OUT/$s.cases.json" "$s"
done

# 4b. buildpacks #325 end-to-end (11 cases, seconds)
python3 -X utf8 bp325.py "$QA_BIN" "$RUN/tmp/bp325" --cases "$OUT/bp325.cases.json" >"$OUT/bp325.log" 2>&1 9>&- || log "bp325 crashed"
[ -s "$OUT/bp325.cases.json" ] || placeholder "$OUT/bp325.cases.json" bp325

# 4d. review cases (R1-R4 from an independent review; seconds to a minute). STATE/review-allow.json = allow-listed open
# findings {"ID": {"wi": "WI-1", "reason": "..."}}; a stale entry (case now passes) alarms, an empty list is the release gate.
QA_STATE=$QA_STATE QA_DEVBOX=$QA_DEVBOX python3 -X utf8 review_cases.py --out "$OUT/review.cases.json" --allow "$QA_STATE/review-allow.json" >"$OUT/review.log" 2>&1 9>&- || log "review cases crashed"
[ -s "$OUT/review.cases.json" ] || placeholder "$OUT/review.cases.json" review

if [ "$GATE" != 1 ]; then
# 4e. rules suite (trigger per rule entry must BLOCK, then the wrapper/obfuscation corpus must stay non-PASS; QA_PROJECTS narrows it)
QA_STATE=$QA_STATE python3 -X utf8 rules_oracle.py --out "$OUT/rules.cases.json" --allow "$QA_STATE/rules-allow.json" >"$OUT/rules.log" 2>&1 || log "rules suite crashed"
[ -s "$OUT/rules.cases.json" ] || placeholder "$OUT/rules.cases.json" rules
fi
# 4e. rules suite, PR mode only: changed rule ids (by rule.id) between base and head
if [ "$GATE" = 1 ]; then
  rf=cli/internal/cncfcheck/data/rules.json
  # any failure to read/parse rules.json (or an entry without rule/id) means ALL, never "no changed rules";
  # ids = union of base and head ids whose entry differs, so removed and added rules count too
  ids=$(python3 -I - "$RUN/src" "$base_sha" "$sha" "$rf" <<'PY'
import json, subprocess, sys
src, base, head, rf = sys.argv[1:]
def load(rev):
    r = subprocess.run(["git", "-C", src, "show", f"{rev}:{rf}"], capture_output=True, text=True)
    if r.returncode:
        return None
    return {e["rule"]["id"]: json.dumps(e, sort_keys=True) for e in json.loads(r.stdout).get("entries", [])}
try:
    b, h = load(base), load(head)
    if b is None or h is None:
        print("ALL")
    else:
        print(",".join(sorted(i for i in set(b) | set(h) if b.get(i) != h.get(i))))
except Exception:
    print("ALL")
PY
  ) || ids=ALL
  if [ "$ids" = ALL ] || [ -n "$ids" ]; then
    if [ -f "$HERE/rules_oracle.py" ]; then
      export QA_RULES_IDS=$([ "$ids" = ALL ] && echo "" || echo "$ids") QA_RULES_ALL=$([ "$ids" = ALL ] && echo 1 || echo 0)
      python3 -X utf8 rules_oracle.py --out "$OUT/rules.cases.json" >"$OUT/rules.log" 2>&1 9>&- || log "rules oracle crashed"
      [ -s "$OUT/rules.cases.json" ] || placeholder "$OUT/rules.cases.json" rules
    else
      # changed rules and no oracle to check them: inconclusive, never an informational skip
      log "rules changed ($ids) but scripts/qa-auto/rules_oracle.py is missing"
      python3 -I -c 'import json,sys;json.dump([{"suite":"rules","key":"rules-changed-oracle-absent","wrongpass":False,"mismatch":False,"error":True,"detail":{"ids":sys.argv[2][:300]}}],open(sys.argv[1],"w"))' "$OUT/rules.cases.json" "$ids"
    fi
  else
    log "rules: no changed rule ids"
    python3 -I -c 'import json,sys;json.dump([{"suite":"rules","key":"no-changed-rules","wrongpass":False,"mismatch":False,"error":False,"detail":{}}],open(sys.argv[1],"w"))' "$OUT/rules.cases.json"
    [ -f "$HERE/rules_oracle.py" ] || skipped+=("rules(absent)")
  fi
fi

# 4c. db suite (slow, tens of minutes when the host runs a job queue): only for db/knowledge diffs or QA_DB=1 (nightly),
# never in the fast path. QA_DB_SUITE = path to the db suite run.sh, supplied by the operator (any job queueing is the
# suite's own concern).
dbsel=$(python3 -I -c 'import json,sys;print(int(bool(json.loads(sys.argv[1]).get("db"))))' "$sel")
if [ -n "${QA_DB_SUITE:-}" ] && [ -x "$QA_DB_SUITE" ] && { [ "${QA_DB:-0}" = 1 ] || [ "$dbsel" = 1 ]; }; then
  log "db suite"
  "$QA_DB_SUITE" "$sha" "$OUT/db" >"$OUT/db.log" 2>&1 9>&- || true
  python3 "$HERE/db_check.py" --json "$OUT/db/dbqa.json" --allow "$QA_STATE/db-allow.json" --out "$OUT/db.cases.json" >>"$OUT/db.log" 2>&1
  [ -s "$OUT/db.cases.json" ] || placeholder "$OUT/db.cases.json" db
fi
printf '%s\n' "${skipped[@]:-}" | python3 -I -c 'import json,sys;json.dump([l.strip() for l in sys.stdin if l.strip()],open(sys.argv[1],"w"))' "$OUT/skipped.json"

# 5. verdict, state, alarm
python3 "$HERE/summarize.py" --dir "$OUT" --state "$QA_STATE" --sha "$sha" --mode "$mode" --note "$(( $(date +%s) - t0 ))s" "${adhoc_flag[@]}"
rc=$?
if [ "$ADHOC" = 0 ]; then
  # retry (poll again) after setup/inconclusive runs: last_checked only for green, alarm and partial
  case $rc in 0|2|4) echo "$sha" >"$QA_STATE/last_checked";; esac
  if [ $rc = 0 ]; then
    echo "$sha" >"$QA_STATE/last_green"
    [ "$mode" = full ] && date +%s >"$QA_STATE/last_full"
  fi
fi
if [ $rc = 2 ]; then
  log "ALARM: $QA_STATE/alarms/$s8.alarm.json"
  if [ -n "${QA_ALARM_HOOK:-}" ] && [ -x "$QA_ALARM_HOOK" ]; then
    "$QA_ALARM_HOOK" "$QA_STATE/alarms/$s8.alarm.json" || log "alarm hook failed with exit $?"
  fi
fi
ls -1dt "$QA_STATE"/results/*/ 2>/dev/null | tail -n +21 | xargs -r rm -rf
exit $rc
