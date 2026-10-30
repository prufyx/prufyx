#!/usr/bin/env bash
# qa-auto: independent check that Prufyx never reports a wrong PASS after a data/knowledge merge on main.
# Runs on the Docker host (not a laptop): Go builds happen in the devbox container, everything else is
# python3 + git on the host. Builds main at a sha, regenerates the coverage report, then runs
#   crd_oracle.py   served CRD GVKs at real upstream tags vs `prufyx scan`
#   k8s_oracle.py   swagger removed-API sets vs scan (range, single GVK) and `plan` stages
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
#   QA_WORK_ROOT      default /opt/prufyx/work; per-run scratch QA_WORK_ROOT/qa-auto-run-*, removed at exit
#   QA_STATE          persistent state (default QA_WORK_ROOT/qa-auto-state): status.json, last_green, alarms/,
#                     results/, known-mismatch.json (baseline), cache/ (bare upstream clones, swagger)
#   QA_DEVBOX         default /opt/prufyx/bin/devbox
#   QA_MAXLOAD        skip (exit 75) when the 1-minute load is not below this (default 8)
#   QA_JOBS           parallel projects in the CRD oracle (default 3)
#   QA_PROJECTS       comma list: check only these projects (ad-hoc runs and seeded-failure proofs)
#   QA_DB_SUITE       path of the db suite run.sh [SHA] [OUTDIR]; QA_DB=1 forces it (nightly); STATE/db-allow.json = allowed failing ids
#   QA_NO_KIND=1      skip the kind probes
#   QA_ALARM_HOOK     executable called with the alarm file path when an alarm is raised
#   QA_PRE_BUILD      shell script run in the scratch checkout before the build (seeded-failure proofs only)
# Exit: 0 green, 2 alarm, 3 inconclusive (errors), 4 green-partial (a suite was skipped), 75 busy/load, 1 setup failure.
# Ad-hoc runs (QA_PROJECTS, QA_SHA, QA_PRE_BUILD or QA_NO_KIND set) never update last_green/last_checked/last_full/status.json.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${QA_REPO_URL:=https://github.com/prufyx/prufyx.git}"
: "${QA_WORK_ROOT:=/opt/prufyx/work}"
: "${QA_STATE:=$QA_WORK_ROOT/qa-auto-state}"
: "${QA_DEVBOX:=/opt/prufyx/bin/devbox}"
: "${QA_MAXLOAD:=8}"
: "${QA_MODE:=auto}"
: "${QA_FULL_EVERY_H:=24}"
: "${QA_JOBS:=3}"
export QA_DEVBOX QA_JOBS
mkdir -p "$QA_STATE/results" "$QA_STATE/cache"
# ad-hoc (parameterized) runs never move last_green/last_checked/last_full or the polled status.json:
# a seeded-failure build or a one-project run must not become the baseline of later incremental runs.
ADHOC=0; for v in QA_PROJECTS QA_SHA QA_PRE_BUILD QA_NO_KIND; do [ -n "${!v:-}" ] && ADHOC=1; done
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
cleanup() {
  "$QA_DEVBOX" -w "$RUN" kind delete cluster --name "qa-auto-$s8" >/dev/null 2>&1 </dev/null || true
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
if [ -n "$lg" ] && git fetch -q --depth 1 "$QA_REPO_URL" "$lg" 2>/dev/null; then
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
selmode=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["mode"])' "$sel")
projects=$(python3 -c 'import json,sys;print(",".join(json.loads(sys.argv[1])["projects"]))' "$sel")
[ "$selmode" = full ] && mode=full
if [ -n "${QA_PROJECTS:-}" ]; then mode=incremental; selmode=incremental; projects=$QA_PROJECTS; fi
echo "$sel" >"$OUT/select.json"
if [ "$mode" = incremental ] && [ "$selmode" = none ]; then
  log "$s8: nothing relevant changed since ${lg:0:8}; recording green"
  python3 -c 'import json,sys;json.dump([],open(sys.argv[1],"w"))' "$OUT/none.cases.json"
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
"$QA_DEVBOX" -w "$RUN/src/cli" sh -c 'GOFLAGS=-mod=vendor go build -o "$1/bin/prufyx" ./cmd/prufyx-community && GOFLAGS=-mod=vendor go build -o "$1/bin/crdgvk" ./cmd/crdgvkqa' _ "$RUN" </dev/null >"$RUN/build.log" 2>&1 \
  || { tail -20 "$RUN/build.log" >&2; log "build failed"; exit 1; }

# 3. coverage report (pairs come from here; every pair is checked regardless of its status)
export QA_NOW=${QA_NOW:-$(date -u -d '+1 day' +%Y-%m-%dT00:00:00Z)}
L=$(ls "$RUN"/src/cli/internal/maintainer/coveragereport/testdata/lines-*.json 2>/dev/null | tail -1)
export QA_COV=""
if [ -n "$L" ] && "$QA_DEVBOX" -w "$RUN/src/cli" sh -c 'GOFLAGS=-mod=vendor go run ./cmd/prufyx-maintainer coverage report --lines "$1" --now "$2" --window ALL --json-out "$3"' _ "${L#"$RUN/src/cli/"}" "$QA_NOW" "$RUN/cov.json" </dev/null >"$RUN/cov.log" 2>&1; then
  QA_COV=$RUN/cov.json
else
  log "coverage report failed; pairs derived from upstream tags"
fi

# 4. suites
export QA_BIN=$RUN/bin/prufyx QA_CRDGVK=$RUN/bin/crdgvk QA_SRC=$RUN/src QA_CACHE=$QA_STATE/cache QA_TMP=$RUN/tmp
cd "$HERE" || exit 1
if [ "$mode" = full ]; then sel_args=(--all); else sel_args=(--projects "$projects"); fi
python3 -X utf8 crd_oracle.py "${sel_args[@]}" --out "$OUT/crd.cases.json" >"$OUT/crd.log" 2>&1 || log "crd oracle crashed"
python3 -X utf8 k8s_oracle.py --out "$OUT/k8s.cases.json" >"$OUT/k8s.log" 2>&1 || log "k8s oracle crashed"
skipped=()
placeholder() { # FILE SUITE: error case so a crashed or empty suite can never be green
  python3 -c 'import json,sys;json.dump([{"suite":sys.argv[2],"key":"suite-crashed","wrongpass":False,"mismatch":False,"error":True,"detail":{}}],open(sys.argv[1],"w"))' "$1" "$2"
}
if [ "${QA_NO_KIND:-0}" = 1 ]; then
  skipped+=(kind)
else
  nk=$("$QA_DEVBOX" kind get clusters </dev/null 2>/dev/null | grep -c '^qa-' || true)
  load=$(cut -d' ' -f1 /proc/loadavg)
  if [ "${nk:-0}" -lt 3 ] && awk -v l="$load" -v m="$QA_MAXLOAD" 'BEGIN{exit !(l<m)}'; then
    python3 -X utf8 kind_probe.py --sha8 "$s8" --crd-cases "$OUT/crd.cases.json" --out "$OUT/kind.cases.json" >"$OUT/kind.log" 2>&1 || log "kind probe crashed"
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
python3 -X utf8 bp325.py "$QA_BIN" "$RUN/tmp/bp325" --cases "$OUT/bp325.cases.json" >"$OUT/bp325.log" 2>&1 || log "bp325 crashed"
[ -s "$OUT/bp325.cases.json" ] || placeholder "$OUT/bp325.cases.json" bp325

# 4c. db suite (slow, tens of minutes when the host runs a job queue): only for db/knowledge diffs or QA_DB=1 (nightly),
# never in the fast path. QA_DB_SUITE = path to the db suite run.sh, supplied by the operator. If the caller already holds a
# job slot, export VKR_SLOT_HELD=1 so the suite does not queue for a second one.
dbsel=$(python3 -c 'import json,sys;print(int(bool(json.loads(sys.argv[1]).get("db"))))' "$sel")
if [ -n "${QA_DB_SUITE:-}" ] && [ -x "$QA_DB_SUITE" ] && { [ "${QA_DB:-0}" = 1 ] || [ "$dbsel" = 1 ]; }; then
  log "db suite"
  "$QA_DB_SUITE" "$sha" "$OUT/db" >"$OUT/db.log" 2>&1 || true
  python3 "$HERE/db_check.py" --json "$OUT/db/dbqa.json" --allow "$QA_STATE/db-allow.json" --out "$OUT/db.cases.json" >>"$OUT/db.log" 2>&1
  [ -s "$OUT/db.cases.json" ] || placeholder "$OUT/db.cases.json" db
fi
printf '%s\n' "${skipped[@]:-}" | python3 -c 'import json,sys;json.dump([l.strip() for l in sys.stdin if l.strip()],open(sys.argv[1],"w"))' "$OUT/skipped.json"

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
