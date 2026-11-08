#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Tests of scripts/knowledge-daily.sh (fake gh, fixture git repository) and
# static checks of .github/workflows/knowledge-publish.yml, including negative
# cases: a refusal path that is not exercised here is not considered tested.
# Needs bash, jq, git, python3 with PyYAML. Usage: bash scripts/knowledge-daily-test.sh
set -uo pipefail
export LC_ALL=C
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
daily="${here}/knowledge-daily.sh"
wf="${here}/../.github/workflows/knowledge-publish.yml"
root="$(mktemp -d)"
trap 'rm -rf "${root}"' EXIT
pass=0
failn=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1: $2"; }

# ---- fake gh: GET serves fixtures/<endpoint with / ? = & as _>.json, others are logged only
mkdir -p "${root}/bin"
cat > "${root}/bin/gh" <<'EOF'
#!/usr/bin/env bash
shift # api
method=GET
ep=""
while [ $# -gt 0 ]; do
  case "$1" in
    -X) method="$2"; shift 2 ;;
    --paginate) shift ;;
    -*) shift ;;
    *) ep="$1"; shift ;;
  esac
done
echo "${method} ${ep}" >> "${FAKE_LOG}"
if [ "${method}" != GET ]; then echo '{}'; exit 0; fi
f="${FAKE_DIR}/$(printf '%s' "${ep}" | tr '/?=&' '____').json"
[ -f "${f}" ] || exit 1
cat "${f}"
EOF
chmod +x "${root}/bin/gh"
export PATH="${root}/bin:${PATH}"
export GH_REPO="prufyx/prufyx"
export FAKE_LOG="${root}/log"
: > "${FAKE_LOG}"

fx() { # endpoint json
  printf '%s' "$2" > "${FAKE_DIR}/$(printf '%s' "$1" | tr '/?=&' '____').json"
}
newfake() { FAKE_DIR="${root}/fx$1"; export FAKE_DIR; rm -rf "${FAKE_DIR}"; mkdir -p "${FAKE_DIR}"; : > "${FAKE_LOG}"; }
run() { # captures stdout+stderr in ${root}/out, returns exit code
  : > "${root}/gho"
  GITHUB_OUTPUT="${root}/gho" bash "${daily}" "$@" > "${root}/out" 2>&1
}
expect_ok() { if run "${@:2}"; then ok "$1"; else bad "$1" "exit non-zero: $(head -c 300 "${root}/out")"; fi; }
expect_fail() { if run "${@:2}"; then bad "$1" "expected a refusal"; else ok "$1"; fi; }
gho() { grep "^$1=" "${root}/gho" | tail -n1 | cut -d= -f2-; }

# ================================================================ gate
good_env() { # name reviewer(0|1)
  local rules='[]'
  [ "$2" = 1 ] && rules='[{"type":"required_reviewers","prevent_self_review":false,"reviewers":[{"type":"User","reviewer":{"login":"airstand"}}]}]'
  fx "repos/prufyx/prufyx/environments/$1" "{\"name\":\"$1\",\"protection_rules\":${rules},\"deployment_branch_policy\":{\"protected_branches\":false,\"custom_branch_policies\":true}}"
  fx "repos/prufyx/prufyx/environments/$1/deployment-branch-policies" '{"total_count":1,"branch_policies":[{"name":"main","type":"branch"}]}'
}
good_gate() {
  newfake gate
  good_env knowledge-release 1
  good_env knowledge-refresh 0
  fx "repos/prufyx/prufyx/actions/secrets?per_page=100" '{"total_count":1,"secrets":[{"name":"OTHER"}]}'
}
good_gate
expect_ok "gate: complete setup passes" gate
[ "$(gho gate_ok)" = true ] && ok "gate: gate_ok=true" || bad "gate: gate_ok=true" "$(cat "${root}/gho")"
grep -q '^GET ' "${FAKE_LOG}" && ! grep -q '^\(POST\|PUT\|PATCH\|DELETE\) ' "${FAKE_LOG}" && ok "gate: read-only calls" || bad "gate: read-only calls" "$(cat "${FAKE_LOG}")"

neg_gate() { # name mutate-command
  good_gate
  eval "$2"
  expect_fail "gate: $1 refused" gate
  [ "$(gho gate_ok)" = false ] && ok "gate: $1 gate_ok=false" || bad "gate: $1 gate_ok=false" "$(cat "${root}/gho")"
  DRY_RUN=true run gate && [ "$(gho gate_ok)" = false ] && grep -q '::warning::' "${root}/out" && ok "gate: $1 dry run warns, gate_ok=false" || bad "gate: $1 dry run" "$(head -c 300 "${root}/out")"
}
neg_gate "no reviewer" 'good_env knowledge-release 0'
neg_gate "other reviewer login" 'fx "repos/prufyx/prufyx/environments/knowledge-release" "{\"name\":\"knowledge-release\",\"protection_rules\":[{\"type\":\"required_reviewers\",\"reviewers\":[{\"type\":\"User\",\"reviewer\":{\"login\":\"someone\"}}]}],\"deployment_branch_policy\":{\"protected_branches\":false,\"custom_branch_policies\":true}}"'
neg_gate "prevent_self_review on" 'fx "repos/prufyx/prufyx/environments/knowledge-release" "{\"name\":\"knowledge-release\",\"protection_rules\":[{\"type\":\"required_reviewers\",\"prevent_self_review\":true,\"reviewers\":[{\"type\":\"User\",\"reviewer\":{\"login\":\"airstand\"}}]}],\"deployment_branch_policy\":{\"protected_branches\":false,\"custom_branch_policies\":true}}"'
neg_gate "branch policy not main" 'fx "repos/prufyx/prufyx/environments/knowledge-release/deployment-branch-policies" "{\"branch_policies\":[{\"name\":\"develop\",\"type\":\"branch\"}]}"'
neg_gate "two branch policies" 'fx "repos/prufyx/prufyx/environments/knowledge-release/deployment-branch-policies" "{\"branch_policies\":[{\"name\":\"main\"},{\"name\":\"dev\"}]}"'
neg_gate "no branch policy at all" 'fx "repos/prufyx/prufyx/environments/knowledge-release" "{\"name\":\"knowledge-release\",\"protection_rules\":[{\"type\":\"required_reviewers\",\"reviewers\":[{\"type\":\"User\",\"reviewer\":{\"login\":\"airstand\"}}]}],\"deployment_branch_policy\":null}"'
neg_gate "refresh has a reviewer" 'good_env knowledge-refresh 1'
neg_gate "refresh missing" 'rm "${FAKE_DIR}/repos_prufyx_prufyx_environments_knowledge-refresh.json"'
neg_gate "release env unreadable" 'rm "${FAKE_DIR}/repos_prufyx_prufyx_environments_knowledge-release.json"'
neg_gate "repo secret shadows a key name" 'fx "repos/prufyx/prufyx/actions/secrets?per_page=100" "{\"secrets\":[{\"name\":\"KNOWLEDGE_TIMESTAMP_KEY\"}]}"'
neg_gate "repo secrets unreadable" 'rm "${FAKE_DIR}/repos_prufyx_prufyx_actions_secrets_per_page_100.json"'
neg_gate "garbage environment json" 'fx "repos/prufyx/prufyx/environments/knowledge-release" "not json"'
GH_REPO="bad repo" expect_fail "gate: malformed GH_REPO refused" gate

# ================================================================ pending
now=1800000000
iso() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; }
runs_fx() { # status json-rows
  fx "repos/prufyx/prufyx/actions/workflows/knowledge-publish.yml/runs?status=$1&per_page=100" "{\"workflow_runs\":$2}"
}
base_pending() { newfake pend; runs_fx queued '[]'; runs_fx in_progress '[]'; runs_fx waiting '[]'; }
export KNOWLEDGE_DAILY_NOW="${now}"
export RUN_ID=100
base_pending
expect_ok "pending: nothing pending" pending
[ -z "$(gho pending)" ] && [ -z "$(gho stale)" ] && ok "pending: empty outputs" || bad "pending: empty outputs" "$(cat "${root}/gho")"
base_pending; runs_fx waiting "[{\"id\":7,\"created_at\":\"$(iso $((now - 3600)))\"}]"
expect_ok "pending: young waiting run" pending
[ "$(gho pending)" = 7 ] && [ -z "$(gho stale)" ] && ok "pending: young run is the blocker" || bad "pending: young run" "$(cat "${root}/gho")"
base_pending; runs_fx waiting "[{\"id\":7,\"created_at\":\"$(iso $((now - 27 * 3600)))\"}]"
expect_ok "pending: old waiting run" pending
[ -z "$(gho pending)" ] && [ "$(gho stale)" = 7 ] && ok "pending: old run is stale, not a blocker" || bad "pending: old run" "$(cat "${root}/gho")"
base_pending; runs_fx waiting "[{\"id\":7,\"created_at\":\"$(iso $((now - 27 * 3600)))\"},{\"id\":8,\"created_at\":\"$(iso $((now - 3600)))\"}]"
run pending; [ "$(gho pending)" = 8 ] && [ "$(gho stale)" = 7 ] && ok "pending: young blocks even when an old one exists" || bad "pending: mixed" "$(cat "${root}/gho")"
base_pending; runs_fx in_progress '[{"id":100,"created_at":"2027-01-01T00:00:00Z"}]'
run pending; [ -z "$(gho pending)" ] && ok "pending: this run is excluded" || bad "pending: self" "$(cat "${root}/gho")"
base_pending; rm "${FAKE_DIR}/repos_prufyx_prufyx_actions_workflows_knowledge-publish.yml_runs_status_queued_per_page_100.json"
expect_fail "pending: API failure refuses (fail closed)" pending
base_pending; runs_fx queued '[{"id":"1;x","created_at":"2027-01-01T00:00:00Z"}]'
expect_fail "pending: non-numeric run id refused" pending
base_pending; runs_fx queued '[{"id":9,"created_at":"yesterday-ish"}]'
expect_fail "pending: unreadable creation time refused" pending
RUN_ID=abc expect_fail "pending: bad RUN_ID refused" pending

# ================================================================ cancel
export STALE_IDS="7"
run_fx() { fx "repos/prufyx/prufyx/actions/runs/$1" "{\"id\":$1,\"path\":\"$2\",\"status\":\"$3\",\"created_at\":\"$(iso $4)\"}"; }
newfake cancel; run_fx 7 .github/workflows/knowledge-publish.yml waiting $((now - 27 * 3600))
expect_ok "cancel: old waiting run cancelled" cancel
grep -q '^POST repos/prufyx/prufyx/actions/runs/7/cancel$' "${FAKE_LOG}" && ok "cancel: POST issued" || bad "cancel: POST issued" "$(cat "${FAKE_LOG}")"
newfake cancel; run_fx 7 .github/workflows/knowledge-publish.yml waiting $((now - 3600))
expect_ok "cancel: young run left alone" cancel
! grep -q '^POST' "${FAKE_LOG}" && ok "cancel: no POST for a young run" || bad "cancel: young" "$(cat "${FAKE_LOG}")"
newfake cancel; run_fx 7 .github/workflows/ci.yml waiting $((now - 27 * 3600))
expect_fail "cancel: run of another workflow refused" cancel
! grep -q '^POST' "${FAKE_LOG}" && ok "cancel: no POST for another workflow" || bad "cancel: other workflow" "$(cat "${FAKE_LOG}")"
newfake cancel; run_fx 7 .github/workflows/knowledge-publish.yml completed $((now - 27 * 3600))
expect_ok "cancel: completed run left alone" cancel
! grep -q '^POST' "${FAKE_LOG}" && ok "cancel: no POST for a completed run" || bad "cancel: completed" "$(cat "${FAKE_LOG}")"
newfake cancel
expect_fail "cancel: unreadable run refused" cancel
STALE_IDS="7;rm" expect_fail "cancel: non-numeric id refused" cancel
STALE_IDS="100" expect_fail "cancel: own run id refused" cancel
! grep -q '^POST' "${FAKE_LOG}" && ok "cancel: nothing cancelled on refusals" || bad "cancel: refusals" "$(cat "${FAKE_LOG}")"
unset STALE_IDS

# ================================================================ latest-run
newfake latest
fx "repos/prufyx/prufyx/actions/workflows/knowledge-publish.yml/runs?branch=main&status=success&per_page=100" '{"workflow_runs":[{"id":10},{"id":9}]}'
h="$(printf 'a%.0s' $(seq 64))"
fx "repos/prufyx/prufyx/actions/runs/10/artifacts?per_page=100" "{\"artifacts\":[{\"name\":\"knowledge-3-${h}\",\"expired\":true}]}"
fx "repos/prufyx/prufyx/actions/runs/9/artifacts?per_page=100" "{\"artifacts\":[{\"name\":\"knowledge-2-${h}\",\"expired\":false},{\"name\":\"other\",\"expired\":false}]}"
run latest-run; [ "$(cat "${root}/out")" = 9 ] && ok "latest-run: skips an expired artifact" || bad "latest-run" "$(cat "${root}/out")"
fx "repos/prufyx/prufyx/actions/runs/9/artifacts?per_page=100" '{"artifacts":[{"name":"knowledge-2-xyz","expired":false}]}'
run latest-run; [ -z "$(cat "${root}/out")" ] && ok "latest-run: a name that is not knowledge-N-sha256 does not count" || bad "latest-run: name" "$(cat "${root}/out")"
rm "${FAKE_DIR}/repos_prufyx_prufyx_actions_runs_9_artifacts_per_page_100.json"
expect_fail "latest-run: artifact API failure refused" latest-run

# ================================================================ has-content
pk() { cat > "${root}/packet.json" <<EOF
{"schema":"prufyx.io/knowledge-packet/v1","sourceCommit":"$(printf 'c%.0s' $(seq 40))","entries":$1,"directCommits":$2,"summary":{"unverified":${3:-0},"trustPath":${4:-0}}}
EOF
}
pk '[]' '[]'; run has-content "${root}/packet.json" state; [ "$(cat "${root}/out")" = false ] && ok "has-content: empty range is false" || bad "has-content: empty" "$(cat "${root}/out")"
pk '[{"class":"NON-DATA","files":["README.md","cli/docs/x.md"]}]' '[]'; run has-content "${root}/packet.json" state; [ "$(cat "${root}/out")" = false ] && ok "has-content: docs-only range is false" || bad "has-content: docs" "$(cat "${root}/out")"
pk '[{"class":"DATA","files":["cli/knowledge/onboarding/x.json"]}]' '[]'; run has-content "${root}/packet.json" state; [ "$(cat "${root}/out")" = true ] && ok "has-content: knowledge path is true" || bad "has-content: knowledge" "$(cat "${root}/out")"
pk '[{"class":"NON-DATA","files":["cli/internal/constraintengine/a.go"]}]' '[]'; run has-content "${root}/packet.json" state; [ "$(cat "${root}/out")" = true ] && ok "has-content: engine path is true" || bad "has-content: engine" "$(cat "${root}/out")"
pk '[{"class":"TRUST-PATH","files":[".github/workflows/x.yml"]}]' '[]'; run has-content "${root}/packet.json" state; [ "$(cat "${root}/out")" = true ] && ok "has-content: trust-path is true" || bad "has-content: trust-path" "$(cat "${root}/out")"
pk '[]' '["abc"]'; run has-content "${root}/packet.json" state; [ "$(cat "${root}/out")" = true ] && ok "has-content: direct commit is true" || bad "has-content: direct" "$(cat "${root}/out")"
pk '[]' '[]' 1; run has-content "${root}/packet.json" state; [ "$(cat "${root}/out")" = true ] && ok "has-content: unverified is true" || bad "has-content: unverified" "$(cat "${root}/out")"
pk '[]' '[]'; run has-content "${root}/packet.json" capability; [ "$(cat "${root}/out")" = true ] && ok "has-content: capability mode is true" || bad "has-content: capability" "$(cat "${root}/out")"
expect_fail "has-content: unknown mode refused" has-content "${root}/packet.json" bogus
echo '{"schema":"other"}' > "${root}/notpacket.json"
expect_fail "has-content: not a packet refused" has-content "${root}/notpacket.json" state

# ================================================================ plan-json and sign-check
sha() { printf 'sha256:%s' "$(printf '%s' "$1" | sha256sum | cut -d' ' -f1)"; }
src="$(printf 'c%.0s' $(seq 40))"
pk '[{"class":"DATA","files":["cli/knowledge/a.json"]}]' '[]'
planenv() {
  export MODE=state SOURCE_COMMIT="${src}" REVISION=5 MIN_VERSION=9 EXPIRES=2027-01-30T00:00:00Z \
    CONTENT_DIGEST="$(sha c)" INDEX_DIGEST="$(sha i)" PACKET="${root}/packet.json" CREATED_EPOCH="${now}" RUN_ID=100 HAS_CONTENT=true DRY_RUN=false \
    PREV_REVISION=4 PREV_TUF=8 PREV_PACKAGE_DIGEST="$(sha p)" PREV_TARGETS_DIGEST="$(sha t)" PREV_SNAPSHOT_DIGEST="$(sha s)" PREV_INDEX_SHA="$(sha x)" PREV_RUN_ID=55
}
planenv
expect_ok "plan-json: valid plan written" plan-json "${root}/plan.json"
[ "$(jq -r '.mode,.revision,.previous.runId,.hasContent' "${root}/plan.json" | paste -sd,)" = "state,5,55,true" ] && ok "plan-json: fields" || bad "plan-json: fields" "$(cat "${root}/plan.json")"
planenv; PREV_PACKAGE_DIGEST="sha256:zz" expect_fail "plan-json: bad previous digest refused" plan-json "${root}/p2.json"
planenv; CONTENT_DIGEST="sha256:abc" expect_fail "plan-json: bad content digest refused" plan-json "${root}/p2.json"
planenv; EXPIRES="2027-01-30" expect_fail "plan-json: non-UTC expiry refused" plan-json "${root}/p2.json"
planenv; SOURCE_COMMIT="main" expect_fail "plan-json: non-sha source refused" plan-json "${root}/p2.json"
planenv; MODE=weird expect_fail "plan-json: unknown mode refused" plan-json "${root}/p2.json"
planenv; MODE=first PREV_RUN_ID= expect_ok "plan-json: first release needs no previous" plan-json "${root}/p3.json"
planenv; unset PREV_INDEX_SHA; expect_fail "plan-json: state mode without previous index refused" plan-json "${root}/p2.json"

signenv() { export GITHUB_RUN_ATTEMPT=1 GITHUB_SHA="${src}" KNOWLEDGE_DAILY_NOW=$((now + 3600)); }
signenv
expect_ok "sign-check: valid plan accepted" sign-check "${root}/plan.json" "${root}/packet.json"
GITHUB_RUN_ATTEMPT=2 expect_fail "sign-check: run attempt 2 refused" sign-check "${root}/plan.json" "${root}/packet.json"
GITHUB_RUN_ATTEMPT= expect_fail "sign-check: empty run attempt refused" sign-check "${root}/plan.json" "${root}/packet.json"
GITHUB_SHA="$(printf 'd%.0s' $(seq 40))" expect_fail "sign-check: other commit refused" sign-check "${root}/plan.json" "${root}/packet.json"
KNOWLEDGE_DAILY_NOW=$((now + 49 * 3600)) expect_fail "sign-check: plan older than 48 h refused" sign-check "${root}/plan.json" "${root}/packet.json"
KNOWLEDGE_DAILY_NOW=$((now - 5)) expect_fail "sign-check: plan from the future refused" sign-check "${root}/plan.json" "${root}/packet.json"
cp "${root}/packet.json" "${root}/packet.orig"; pk '[]' '[]'
expect_fail "sign-check: changed packet refused" sign-check "${root}/plan.json" "${root}/packet.json"
cp "${root}/packet.orig" "${root}/packet.json"
planenv; DRY_RUN=true bash "${daily}" plan-json "${root}/dry.json"
expect_fail "sign-check: plan made in a dry run refused" sign-check "${root}/dry.json" "${root}/packet.json"
planenv; HAS_CONTENT=false bash "${daily}" plan-json "${root}/empty.json"
expect_fail "sign-check: plan without content refused" sign-check "${root}/empty.json" "${root}/packet.json"
jq '.schema="x"' "${root}/plan.json" > "${root}/ws.json"
expect_fail "sign-check: wrong plan schema refused" sign-check "${root}/ws.json" "${root}/packet.json"
jq '.indexDigest="sha256:1"' "${root}/plan.json" > "${root}/wd.json"
expect_fail "sign-check: malformed digest refused" sign-check "${root}/wd.json" "${root}/packet.json"
expect_fail "sign-check: missing plan refused" sign-check "${root}/nonexistent.json" "${root}/packet.json"
unset MODE SOURCE_COMMIT REVISION MIN_VERSION EXPIRES CONTENT_DIGEST INDEX_DIGEST PACKET CREATED_EPOCH HAS_CONTENT DRY_RUN PREV_REVISION PREV_TUF PREV_PACKAGE_DIGEST PREV_TARGETS_DIGEST PREV_SNAPSHOT_DIGEST PREV_RUN_ID

# ================================================================ collect (fixture git repo)
repo="${root}/repo"
git init -q -b main "${repo}"
git -C "${repo}" config user.email t@example.invalid; git -C "${repo}" config user.name t
echo a > "${repo}/a"; git -C "${repo}" add a; git -C "${repo}" commit -qm base
base="$(git -C "${repo}" rev-parse HEAD)"
git -C "${repo}" checkout -q -b feat; echo b > "${repo}/b"; git -C "${repo}" add b; git -C "${repo}" commit -qm feat
headsha="$(git -C "${repo}" rev-parse HEAD)"
git -C "${repo}" checkout -q main; git -C "${repo}" merge -q --no-ff feat -m "Merge pull request #5 from prufyx/factory/export-abc123"
head="$(git -C "${repo}" rev-parse HEAD)"
col() { newfake collect
  fx "repos/prufyx/prufyx/pulls/5" "{\"head\":{\"sha\":\"${headsha}\",\"ref\":\"factory/export-abc123\"},\"user\":{\"login\":\"prufyx-bot\"},\"title\":\"data\"}"
  fx "repos/prufyx/prufyx/issues/5/comments?per_page=100" '[{"user":{"login":"airstand","id":11156623},"created_at":"2027-01-01T00:00:00Z","updated_at":"2027-01-01T00:00:00Z","body":"hi"}]'
  fx "repos/prufyx/prufyx/commits/${headsha}/statuses?per_page=100" '[{"id":1,"context":"qa-gate","state":"success","creator":{"login":"airstand","id":11156623}}]'
  fx "repos/prufyx/prufyx/commits/${headsha}/check-runs?per_page=100" '{"check_runs":[{"name":"ci","conclusion":"success"},{"name":"run","conclusion":null}]}'
}
col
expect_ok "collect: one merged pull request" collect "${repo}" "${base}" "${head}" "${root}/in.json"
jq -e --arg h "${headsha}" '.schema == "prufyx.io/knowledge-packet-input/v2" and (.prs | length) == 1 and .prs[0].number == 5 and .prs[0].head == $h and .prs[0].author == "prufyx-bot"
  and .prs[0].comments[0].authorId == 11156623 and .prs[0].statuses[0].creatorId == 11156623 and .prs[0].checks[1].conclusion == ""' "${root}/in.json" > /dev/null && ok "collect: input v2 fields (ids, updatedAt source, checks)" || bad "collect: fields" "$(cat "${root}/in.json")"
col; rm "${FAKE_DIR}/repos_prufyx_prufyx_pulls_5.json"
expect_fail "collect: unreadable pull request refused" collect "${repo}" "${base}" "${head}" "${root}/in2.json"
col; rm "${FAKE_DIR}/repos_prufyx_prufyx_issues_5_comments_per_page_100.json"
expect_fail "collect: unreadable comments refused" collect "${repo}" "${base}" "${head}" "${root}/in2.json"
col; fx "repos/prufyx/prufyx/pulls/5" '{"head":{"sha":"short","ref":"x"},"user":{"login":"u"},"title":"t"}'
expect_fail "collect: bad head sha refused" collect "${repo}" "${base}" "${head}" "${root}/in2.json"
col; expect_fail "collect: non-sha base refused" collect "${repo}" main "${head}" "${root}/in2.json"
git -C "${repo}" checkout -q feat; echo c > "${repo}/c"; git -C "${repo}" add c; git -C "${repo}" commit -qm more; git -C "${repo}" checkout -q main
git -C "${repo}" merge -q --no-ff feat -m "odd merge subject"; head2="$(git -C "${repo}" rev-parse HEAD)"
col; fx "repos/prufyx/prufyx/commits/${head2}/pulls" '[]'
expect_ok "collect: merge without a number is skipped with a warning" collect "${repo}" "${head}" "${head2}" "${root}/in3.json"
[ "$(jq '.prs | length' "${root}/in3.json")" = 0 ] && grep -q '::warning::' "${root}/out" && ok "collect: skipped merge warns, no input entry" || bad "collect: skipped" "$(cat "${root}/out")"
col; rm -f "${FAKE_DIR}/repos_prufyx_prufyx_commits_${head2}_pulls.json"
expect_fail "collect: unresolvable merge refused (API failure)" collect "${repo}" "${head}" "${head2}" "${root}/in3.json"

# ================================================================ static workflow checks
cat > "${root}/static.py" <<'EOF'
import re, sys, yaml
raw = open(sys.argv[1]).read()
d = yaml.safe_load(raw)
on = d.get(True, d.get("on"))
errs = []
def e(m): errs.append(m)
if "push" in on or "pull_request" in on or "pull_request_target" in on: e("trigger: push/pull_request present")
if not any("17 5 * * *" == s["cron"] for s in on.get("schedule", [])): e("trigger: no daily schedule")
inp = on["workflow_dispatch"]["inputs"]
if inp.get("dry_run", {}).get("default") is not True or inp["dry_run"].get("type") != "boolean": e("dry_run input missing or not default true")
if "concurrency" in d: e("workflow-level concurrency present (blocks the stale cancel)")
if d.get("permissions") != {}: e("workflow default permissions are not empty")
jobs = d["jobs"]
for n in ("plan", "cancel-stale", "token-probe", "sign", "deploy"):
    if n not in jobs: e("job missing: " + n)
plan, cancel, sign, deploy = (jobs.get(n, {}) for n in ("plan", "cancel-stale", "sign", "deploy"))
if "environment" in plan: e("plan has an environment")
if sign.get("environment") != "knowledge-release": e("sign environment is not knowledge-release")
if "!inputs.dry_run" not in str(sign.get("if")): e("sign has no !inputs.dry_run condition")
if "sign_ok == 'true'" not in str(sign.get("if")): e("sign does not require the plan decision")
if sign.get("needs") != "plan": e("sign does not need plan")
for n, j in jobs.items():
    p = j.get("permissions")
    if not isinstance(p, dict) or not p: e(n + ": no explicit permissions")
    for k, v in (p or {}).items():
        if v == "write" and not ((n in ("cancel-stale", "token-probe") and k == "actions") or (n == "deploy" and k in ("pages", "id-token"))):
            e("%s: unexpected write permission %s" % (n, k))
if jobs["cancel-stale"]["permissions"].get("actions") != "write": e("cancel job lacks actions:write")
if set(cancel.get("permissions", {})) != {"actions", "contents"}: e("cancel job permissions are not minimal")
probe = jobs.get("token-probe", {})
if set(probe.get("permissions", {})) != {"actions"}: e("probe job permissions are not minimal")
if "inputs.dry_run" not in str(probe.get("if")): e("probe job is not dry-run only")
if probe.get("environment"): e("probe has an environment")
# secrets only in the sign job, only in one step
for n, j in jobs.items():
    steps_with = [s.get("name") for s in j.get("steps", []) if "secrets." in yaml.safe_dump(s)]
    if n == "sign":
        if steps_with != ["Sign"]: e("sign: secrets outside the Sign step: %s" % steps_with)
    elif steps_with: e("%s: uses secrets" % n)
if "secrets." in yaml.safe_dump({k: v for k, v in d.items() if k != "jobs"}).replace("secrets.KNOWLEDGE", ""): e("secrets at top level")
# no secret echoed
for s in sign.get("steps", []):
    if s.get("name") == "Sign":
        r = s["run"]
        for v in ("TARGETS_KEY", "SNAPSHOT_KEY", "TIMESTAMP_KEY", "PASSPHRASE"):
            for line in r.split("\n"):
                if re.search(r"\becho\b.*\$\{?%s\b" % v, line): e("Sign echoes " + v)
        for flag in ("--expect-content-digest \"", "--expect-previous-package-digest \"", "--expect-index-digest \"", "--expires \"", "knowledge-publish release"):
            if flag not in r: e("Sign lacks " + flag.strip(' "'))
        if "--no-ci" in r or "GITHUB_ACTIONS=false" in r or "CI=false" in r: e("Sign weakens CI mode")
all_lines = [l.strip() for l in raw.split("\n") if not l.strip().startswith("#")]
cmds, cur = [], ""
for l in all_lines:
    if not cur and not re.search(r"knowledge-publish (release|refresh-timestamp)\b", l): continue
    cur += " " + l
    if not l.endswith("\\"): cmds.append(cur); cur = ""
if not cmds: e("no signing call in the workflow")
for c in cmds:
    if not re.search(r"\s--ci(\s|$)", c): e("signing call lacks --ci: " + c[:80])
all_text = raw
for flag in ("content-digest", "live-state", "deploy-guard", "knowledge-packet", "--trusted-user-ids", "minNextVersion", "sign-check", "targetDigest // .bundleDigest"):
    if flag not in all_text: e("workflow lacks " + flag)
if "run_number" in all_text: e("the run_number deploy guard is still there")
if "pull_request_target" in all_text: e("pull_request_target")
if "cancel-in-progress: true" in all_text: e("cancel-in-progress true")
# every action pinned
for m in re.finditer(r"^\s*(?:- )?uses:\s*(\S+)", raw, re.M):
    if not re.match(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$", m.group(1)): e("unpinned action " + m.group(1))
# oldest supported client verification kept
for s in ("Read the oldest supported client pin", "Check out the oldest supported client", "Verify with the oldest supported client"):
    if s not in [x.get("name") for x in sign.get("steps", [])]: e("sign lacks step: " + s)
# deploy has no key and uses the mutex
if deploy.get("concurrency", {}).get("group") != "knowledge-deploy": e("deploy has no knowledge-deploy group")
if sign.get("concurrency", {}).get("cancel-in-progress") is not False: e("sign concurrency missing or cancels")
# sign steps order: sign-check before the Sign step, Sign before verify
names = [s.get("name") for s in sign.get("steps", [])]
if not (names.index("Check the plan") < names.index("Re-derive state, digests and version") < names.index("Sign") < names.index("Verify the signed package")): e("sign step order")
# plan gate before any other plan step that reads the API for the packet
pn = [s.get("name") for s in plan.get("steps", [])]
if pn.index("Self-check the approval gate") > 1: e("gate self-check is not the first plan step after checkout")
print("\n".join(errs))
sys.exit(1 if errs else 0)
EOF
static() { python3 -I "${root}/static.py" "$1"; }
if python3 -I -c 'import yaml' 2> /dev/null; then
  out="$(static "${wf}")" && ok "workflow: static contract holds" || bad "workflow: static contract" "${out}"
  mut() { # name sed-expression expected-substring
    sed -e "$2" "${wf}" > "${root}/mut.yml"
    if cmp -s "${wf}" "${root}/mut.yml"; then bad "workflow mutation: $1" "mutation did not change the file"; return; fi
    local o
    if o="$(static "${root}/mut.yml" 2>&1)"; then bad "workflow mutation: $1" "checker accepted it"; else
      case "${o}" in *"$3"*) ok "workflow mutation refused: $1" ;; *) bad "workflow mutation: $1" "wrong reason: ${o}" ;; esac
    fi
  }
  mut "push trigger returns" 's/^on:$/on:\n  push:\n    branches: [main]/' "trigger: push"
  mut "workflow concurrency returns" 's/^permissions: {}$/permissions: {}\nconcurrency:\n  group: x/' "workflow-level concurrency"
  mut "sign loses its environment" 's/^    environment: knowledge-release$/    environment: github-pages/' "sign environment"
  mut "sign runs in dry runs" 's/if: ${{ !inputs.dry_run \&\& /if: ${{ /' "!inputs.dry_run"
  mut "dry_run defaults to false" '/dry_run:/,/default/ s/default: true/default: false/' "dry_run input"
  mut "unpinned action" '0,/actions\/setup-go@[0-9a-f]\{40\}/ s/actions\/setup-go@[0-9a-f]\{40\}/actions\/setup-go@v5/' "unpinned action"
  mut "run_number guard back" 's/Refuse unless the candidate follows the live package/Refuse unless this is the latest run ${{ github.run_number }}/' "run_number"
  mut "key secret in the plan job" '0,/GH_TOKEN: ${{ github.token }}/ s/GH_TOKEN: ${{ github.token }}/GH_TOKEN: ${{ secrets.KNOWLEDGE_TIMESTAMP_KEY }}/' "plan: uses secrets"
  mut "release without --ci" 's/knowledge-publish release --ci /knowledge-publish release /' "signing call lacks --ci"
  mut "release without expires" 's/            --expires "${EXPIRES}" \\//' "Sign lacks --expires"
  mut "release without index digest" 's/--expect-index-digest/--no-index-digest/' "Sign lacks --expect-index-digest"
  mut "cancel job gets contents write" '/^  cancel-stale:/,/^  sign:/ s/contents: read/contents: write/' "unexpected write permission contents"
  mut "plan job gets id-token write" '/^  plan:/,/^  cancel-stale:/ s/statuses: read/id-token: write/' "unexpected write permission id-token"
  mut "cancel-in-progress true" '0,/cancel-in-progress: false/ s/cancel-in-progress: false/cancel-in-progress: true/' "cancel-in-progress"
else
  bad "workflow: static checks" "python3 with PyYAML is required"
fi

echo "knowledge-daily tests: ${pass} passed, ${failn} failed"
[ "${failn}" -eq 0 ]
