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
#   QA_NO_KIND=1      skip the kind probes
#   QA_ALARM_HOOK     executable called with the alarm file path when an alarm is raised
#   QA_PRE_BUILD      shell script run in the scratch checkout before the build (seeded-failure proofs only)
# Exit: 0 green, 2 alarm, 3 inconclusive (infra errors), 75 busy/load, 1 setup failure.
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
  python3 "$HERE/summarize.py" --dir "$OUT" --state "$QA_STATE" --sha "$sha" --mode none --note "no relevant change"
  rc=$?; echo "$sha" >"$QA_STATE/last_checked"; [ $rc = 0 ] && echo "$sha" >"$QA_STATE/last_green"; exit $rc
fi

# 2. build prufyx + helper in the devbox
mkdir -p "$RUN/src/cli/cmd/crdgvkqa" "$RUN/bin" "$RUN/tmp"
cp "$HERE/crdgvk.go" "$RUN/src/cli/cmd/crdgvkqa/main.go"
if [ -n "${QA_PRE_BUILD:-}" ]; then (cd "$RUN/src" && sh "$QA_PRE_BUILD") || { log "pre-build hook failed"; exit 1; }; fi
log "$s8 mode=$mode build"
"$QA_DEVBOX" -w "$RUN/src/cli" sh -c "GOFLAGS=-mod=vendor go build -o $RUN/bin/prufyx ./cmd/prufyx-community && GOFLAGS=-mod=vendor go build -o $RUN/bin/crdgvk ./cmd/crdgvkqa" </dev/null >"$RUN/build.log" 2>&1 \
  || { tail -20 "$RUN/build.log" >&2; log "build failed"; exit 1; }

# 3. coverage report (pairs come from here; every pair is checked regardless of its status)
export QA_NOW=${QA_NOW:-$(date -u -d '+1 day' +%Y-%m-%dT00:00:00Z)}
L=$(ls "$RUN"/src/cli/internal/maintainer/coveragereport/testdata/lines-*.json 2>/dev/null | tail -1)
export QA_COV=""
if [ -n "$L" ] && "$QA_DEVBOX" -w "$RUN/src/cli" sh -c "GOFLAGS=-mod=vendor go run ./cmd/prufyx-maintainer coverage report --lines ${L#"$RUN/src/cli/"} --now $QA_NOW --window ALL --json-out $RUN/cov.json" </dev/null >"$RUN/cov.log" 2>&1; then
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
if [ "${QA_NO_KIND:-0}" != 1 ]; then
  nk=$("$QA_DEVBOX" kind get clusters </dev/null 2>/dev/null | grep -c '^qa-' || true)
  load=$(cut -d' ' -f1 /proc/loadavg)
  if [ "${nk:-0}" -lt 3 ] && awk -v l="$load" -v m="$QA_MAXLOAD" 'BEGIN{exit !(l<m)}'; then
    python3 -X utf8 kind_probe.py --sha8 "$s8" --crd-cases "$OUT/crd.cases.json" --out "$OUT/kind.cases.json" >"$OUT/kind.log" 2>&1 || log "kind probe crashed"
  else
    log "kind probes skipped (qa clusters=$nk load=$load)"
  fi
fi
# a crashed suite leaves no cases file: that is an error case, never a silent green
for s in crd k8s; do
  [ -s "$OUT/$s.cases.json" ] || python3 -c 'import json,sys;json.dump([{"suite":sys.argv[2],"key":"suite-crashed","wrongpass":False,"mismatch":False,"error":True,"detail":{}}],open(sys.argv[1],"w"))' "$OUT/$s.cases.json" "$s"
done

# 5. verdict, state, alarm
python3 "$HERE/summarize.py" --dir "$OUT" --state "$QA_STATE" --sha "$sha" --mode "$mode" --note "$(( $(date +%s) - t0 ))s"
rc=$?
echo "$sha" >"$QA_STATE/last_checked"
if [ $rc = 0 ]; then
  echo "$sha" >"$QA_STATE/last_green"
  [ "$mode" = full ] && date +%s >"$QA_STATE/last_full"
fi
if [ $rc = 2 ]; then
  log "ALARM: $QA_STATE/alarms/$s8.alarm.json"
  [ -n "${QA_ALARM_HOOK:-}" ] && [ -x "$QA_ALARM_HOOK" ] && "$QA_ALARM_HOOK" "$QA_STATE/alarms/$s8.alarm.json" || true
fi
ls -1dt "$QA_STATE"/results/*/ 2>/dev/null | tail -n +21 | xargs -r rm -rf
exit $rc
