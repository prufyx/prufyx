#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Guards of the daily knowledge publish workflow (.github/workflows/knowledge-publish.yml).
# Every subcommand fails closed: any unreadable input, API error or unexpected
# shape is a refusal (exit 1). No subcommand reads, prints or needs a key.
#
#   gate        self-check of the approval gate and the key environments
#   pending     one-pending-run rule: young waiting run => skip, old => stale list
#   cancel      cancel the listed runs of THIS workflow if still older than the limit
#   live-runs   the newest live artifact of each family (content runs of this
#               workflow, refresh runs of knowledge-refresh.yml) and the live package
#   check-live  refuse unless both families still have exactly the runs the plan recorded
#   trusted-ids numeric ids whose markers count (pinned here, the lookup only cross-checks)
#   collect     read the merged pull requests of a range into the packet input file
#   has-content decide from a packet whether anything can change the knowledge
#   plan-json   write the plan file that binds the approval to the signature
#   sign-check  checks the sign job runs before any key is read
#
# Needs: bash, jq, git, gh (GH_TOKEN). GH_REPO=owner/repo.
# Subcommands that write step outputs append to GITHUB_OUTPUT.
set -euo pipefail
umask 077
export LC_ALL=C

WORKFLOW_FILE="knowledge-publish.yml"
REFRESH_WORKFLOW_FILE="knowledge-refresh.yml"
CONTENT_ARTIFACT_RE='^knowledge-[0-9]+-[0-9a-f]{64}$'
REFRESH_ARTIFACT_RE='^knowledge-refresh-[0-9]+-[0-9]+-[0-9a-f]{64}$'
# Trusted marker authors, by numeric account id: a login can be renamed or
# re-registered, an id cannot. The lookup of the login only cross-checks these
# constants and fails closed on any difference. An empty bot id would mean no
# bot-trusted markers; it is set because the account exists.
OWNER_LOGIN="airstand"
OWNER_USER_ID=11156623
BOT_LOGIN="prufyx-bot"
BOT_USER_ID=343087959
KEY_ENV="knowledge-release"
REFRESH_ENV="knowledge-refresh"
MAX_AGE_HOURS_DEFAULT=26
PLAN_MAX_AGE_SECONDS=172800
PLAN_SCHEMA="prufyx.io/knowledge-plan/v1"

die() { echo "::error::$*"; exit 1; }
out() { if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "$1" >> "${GITHUB_OUTPUT}"; else echo "$1"; fi; }
need_repo() { [[ "${GH_REPO:-}" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || die "GH_REPO is not owner/repo."; }
now_epoch() { echo "${KNOWLEDGE_DAILY_NOW:-$(date -u +%s)}"; }
gh_get() { gh api -X GET "$@"; }
is_pos_int() { [[ "$1" =~ ^[1-9][0-9]{0,17}$ ]]; }
is_digest() { [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]; }
is_sha40() { [[ "$1" =~ ^[0-9a-f]{40}$ ]]; }

# ---------------------------------------------------------------- gate
# Requires: knowledge-release has a required reviewer (login REVIEWER_LOGIN,
# default airstand), prevent_self_review off (the schedule actor is the only
# reviewer), the deployment branch policy is exactly main; knowledge-refresh
# exists, has no reviewer and is limited to main. It does not list repository
# secrets (the job token has no such scope, so the call could only fail): the
# presence of the key secrets is owner-verified, and the Sign step refuses an
# empty key input before it writes any key file. DRY_RUN=true turns a failed self-check into a warning, and
# the caller still never signs (gate_ok=false).
cmd_gate() {
  need_repo
  local reviewer="${REVIEWER_LOGIN:-airstand}" dry="${DRY_RUN:-false}"
  local problems=() j p
  env_checks() { # name expect_reviewer(true|false)
    local name="$1" want="$2"
    if ! j="$(gh_get "repos/${GH_REPO}/environments/${name}" 2>/dev/null)" || ! jq -e 'type == "object" and has("name")' <<< "${j}" > /dev/null 2>&1; then
      problems+=("environment ${name} cannot be read or does not exist")
      return
    fi
    if [ "${want}" = true ]; then
      jq -e --arg l "${reviewer}" '[.protection_rules[]? | select(.type == "required_reviewers") | .reviewers[]? | select(.type == "User" and .reviewer.login == $l)] | length > 0' <<< "${j}" > /dev/null \
        || problems+=("environment ${name} has no required reviewer ${reviewer}")
      jq -e '[.protection_rules[]? | select(.type == "required_reviewers") | select(.prevent_self_review == true)] | length == 0' <<< "${j}" > /dev/null \
        || problems+=("environment ${name} has prevent_self_review on; the only reviewer would be locked out")
    else
      jq -e '[.protection_rules[]? | select(.type == "required_reviewers")] | length == 0' <<< "${j}" > /dev/null \
        || problems+=("environment ${name} must have no reviewer")
    fi
    jq -e '.deployment_branch_policy.custom_branch_policies == true and (.deployment_branch_policy.protected_branches // false) == false' <<< "${j}" > /dev/null \
      || problems+=("environment ${name} has no custom deployment branch policy")
    if ! p="$(gh_get "repos/${GH_REPO}/environments/${name}/deployment-branch-policies" 2>/dev/null)" \
       || ! jq -e '(.branch_policies | length) == 1 and .branch_policies[0].name == "main" and ((.branch_policies[0].type // "branch") == "branch")' <<< "${p}" > /dev/null 2>&1; then
      problems+=("environment ${name} deployment branch policy is not exactly main")
    fi
  }
  env_checks "${KEY_ENV}" true
  env_checks "${REFRESH_ENV}" false
  if [ "${#problems[@]}" -eq 0 ]; then
    echo "gate self-check: OK"
    out "gate_ok=true"
    return 0
  fi
  local x level=error
  [ "${dry}" = true ] && level=warning
  for x in "${problems[@]}"; do echo "::${level}::gate self-check: ${x}"; done
  out "gate_ok=false"
  if [ "${dry}" = true ]; then
    echo "gate self-check failed; dry run continues without any possibility to sign."
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------- pending
# RUN_ID is this run. Writes pending=<id or empty> and stale=<ids, space separated>.
cmd_pending() {
  need_repo
  local self="${RUN_ID:?}" limit="${MAX_AGE_HOURS:-${MAX_AGE_HOURS_DEFAULT}}" now st rows pending="" stale=""
  is_pos_int "${self}" || die "RUN_ID is not a number."
  is_pos_int "${limit}" || die "MAX_AGE_HOURS is not a number."
  now="$(now_epoch)"
  for st in queued in_progress waiting; do
    rows="$(gh_get "repos/${GH_REPO}/actions/workflows/${WORKFLOW_FILE}/runs?status=${st}&per_page=100" | jq -r '.workflow_runs[] | [.id, .created_at] | @tsv')" \
      || die "cannot list ${st} runs; refusing to continue."
    local id created ce
    while IFS=$'\t' read -r id created; do
      [ -n "${id}" ] || continue
      [ "${id}" != "${self}" ] || continue
      is_pos_int "${id}" || die "run id ${id} is not a number."
      ce="$(date -u -d "${created}" +%s)" || die "run ${id} has an unreadable creation time."
      if [ $((now - ce)) -gt $((limit * 3600)) ]; then
        stale="${stale:+${stale} }${id}"
      elif [ -z "${pending}" ]; then
        pending="${id}"
      fi
    done <<< "${rows}"
  done
  out "pending=${pending}"
  out "stale=${stale}"
  if [ -n "${pending}" ]; then echo "run ${pending} is awaiting approval or still running (younger than ${limit} h)"; fi
  if [ -n "${stale}" ]; then echo "stale runs (older than ${limit} h): ${stale}"; fi
}

# ---------------------------------------------------------------- cancel
# STALE_IDS from the plan job is only a hint: every id is read again and is
# cancelled only if it is a run of THIS workflow, not this run, still
# queued/in_progress/waiting and older than the limit.
cmd_cancel() {
  need_repo
  local self="${RUN_ID:?}" limit="${MAX_AGE_HOURS:-${MAX_AGE_HOURS_DEFAULT}}" now id r path status created ce
  is_pos_int "${limit}" || die "MAX_AGE_HOURS is not a number."
  now="$(now_epoch)"
  for id in ${STALE_IDS:-}; do
    is_pos_int "${id}" || die "stale id ${id} is not a number; nothing cancelled."
    [ "${id}" != "${self}" ] || die "this run is in its own stale list; nothing cancelled."
    r="$(gh_get "repos/${GH_REPO}/actions/runs/${id}")" || die "cannot read run ${id}."
    path="$(jq -r '.path' <<< "${r}")"
    status="$(jq -r '.status' <<< "${r}")"
    created="$(jq -r '.created_at' <<< "${r}")"
    [ "${path}" = ".github/workflows/${WORKFLOW_FILE}" ] || die "run ${id} is not a run of this workflow; nothing cancelled."
    case "${status}" in queued | in_progress | waiting) ;; *) echo "run ${id} is ${status}; left alone."; continue ;; esac
    ce="$(date -u -d "${created}" +%s)" || die "run ${id} has an unreadable creation time."
    [ $((now - ce)) -gt $((limit * 3600)) ] || { echo "run ${id} is younger than ${limit} h; left alone."; continue; }
    gh api -X POST "repos/${GH_REPO}/actions/runs/${id}/cancel" > /dev/null || die "cancelling run ${id} failed."
    echo "cancelled run ${id} (older than ${limit} h)"
  done
}

# ---------------------------------------------------------------- live-runs
# Two artifact families carry the published state: content runs (this workflow,
# knowledge-<revision>-<sha256>) and refresh runs (knowledge-refresh.yml,
# knowledge-refresh-<revision>-<timestamp version>-<sha256>). A refresh keeps the
# revision and the targets and only renews the timestamp, so the live package
# is the newest across both: a refresh of revision R is newer than the content
# run of R, a content run of R+1 is newer than any refresh of R.
family_newest() { # workflow-file artifact-regex -> "run|sha|artifact" of the newest successful main run with a live matching artifact; empty if none
  local runs id sha art
  # Paginated, newest first: the run that holds the live package can sit behind
  # many successful runs without an artifact (plan-only days).
  runs="$(gh_get --paginate "repos/${GH_REPO}/actions/workflows/$1/runs?branch=main&status=success&per_page=100" | jq -r '.workflow_runs[] | [.id, (.head_sha // "")] | @tsv')" \
    || die "cannot list the successful runs of $1."
  while IFS=$'\t' read -r id sha; do
    [ -n "${id}" ] || continue
    is_pos_int "${id}" || die "run id ${id} is not a number."
    art="$(gh_get "repos/${GH_REPO}/actions/runs/${id}/artifacts?per_page=100" \
      | jq -r --arg re "$2" '[.artifacts[] | select(.expired == false) | select(.name | test($re))] | (first // empty) | .name')" \
      || die "cannot list the artifacts of run ${id}."
    if [ -n "${art}" ]; then printf '%s|%s|%s\n' "${id}" "${sha}" "${art}"; return 0; fi
  done <<< "${runs}"
  return 0
}

cmd_live_runs() {
  need_repo
  local c r crun csha cart rrun rsha rart crev="" rrev="" rtuf="" rest family="none" lrun="" lart="" ldigest="" lrev=""
  c="$(family_newest "${WORKFLOW_FILE}" "${CONTENT_ARTIFACT_RE}")" || exit 1
  r="$(family_newest "${REFRESH_WORKFLOW_FILE}" "${REFRESH_ARTIFACT_RE}")" || exit 1
  IFS='|' read -r crun csha cart <<< "${c}"
  IFS='|' read -r rrun rsha rart <<< "${r}"
  if [ -n "${cart}" ]; then rest="${cart#knowledge-}"; crev="${rest%%-*}"; fi
  if [ -n "${rart}" ]; then rest="${rart#knowledge-refresh-}"; rrev="${rest%%-*}"; rest="${rest#*-}"; rtuf="${rest%%-*}"; fi
  # A live refresh artifact whose content run is gone (retention, the >90 day
  # case) is not a live package: nothing can be derived from it, only the
  # recovery inputs can sign over that state. The family is reported as
  # refresh-orphan so that recovery can record and accept it and every other
  # mode refuses it by name; live stays empty.
  if [ -n "${rart}" ] && [ -z "${cart}" ]; then family="refresh-orphan"; fi
  if [ -n "${rart}" ] && [ -n "${cart}" ] && [ "${rrev}" -gt "${crev}" ]; then
    die "the newest refresh (revision ${rrev}) is for a newer revision than the newest content run (revision ${crev}); the state is inconsistent, use the recovery inputs."
  fi
  if [ -n "${cart}" ]; then
    family=content; lrun="${crun}"; lart="${cart}"; lrev="${crev}"
    if [ -n "${rart}" ] && [ "${rrev}" -ge "${crev}" ]; then family=refresh; lrun="${rrun}"; lart="${rart}"; lrev="${rrev}"; fi
    ldigest="sha256:${lart##*-}"
  fi
  jq -n --arg crun "${crun}" --arg csha "${csha}" --arg cart "${cart}" --arg rrun "${rrun}" --arg rart "${rart}" \
    --arg crev "${crev}" --arg rrev "${rrev}" --arg fam "${family}" --arg lrun "${lrun}" --arg lart "${lart}" --arg ldig "${ldigest}" --arg lrev "${lrev}" --arg rtuf "${rtuf}" \
    '{content: {runId: $crun, sha: $csha, artifact: $cart, revision: $crev}, refresh: {runId: $rrun, artifact: $rart, revision: $rrev, tufVersion: $rtuf},
      live: {family: $fam, runId: $lrun, artifact: $lart, digest: $ldig, revision: $lrev}}'
}

# check-live PLAN: sign and deploy call this. The run of each family must be
# exactly the one the plan recorded, unconditionally: an empty record equals an
# empty family (first release, recovery) and nothing else; a refresh or content
# run that appeared after the plan, or one that vanished, is a moved state and
# the next plan replans. The live artifact must also be the package the plan
# holds (digest in its name), so deploy and release are checked against the
# real live package, never a stale copy.
cmd_check_live() {
  need_repo
  local plan="${1:?}" live rec_c rec_r mode digest act_c act_r fam
  jq -e '.previous | type == "object"' "${plan}" > /dev/null 2>&1 || die "check-live: the plan has no previous state."
  rec_c="$(jq -r '.previous.contentRunId // ""' "${plan}")"
  rec_r="$(jq -r '.previous.refreshRunId // ""' "${plan}")"
  mode="$(jq -r '.mode // ""' "${plan}")"
  digest="$(jq -r '.previous.packageDigest // ""' "${plan}")"
  live="$(cmd_live_runs)" || die "check-live: the live state cannot be read."
  act_c="$(jq -r '.content.runId' <<< "${live}")"
  act_r="$(jq -r '.refresh.runId' <<< "${live}")"
  fam="$(jq -r '.live.family' <<< "${live}")"
  [ "${act_c}" = "${rec_c}" ] || die "the published state moved since the plan: the newest content run is '${act_c}', the plan saw '${rec_c}'; the next plan replans."
  [ "${act_r}" = "${rec_r}" ] || die "the published state moved since the plan: the newest refresh run is '${act_r}', the plan saw '${rec_r}'; the next plan replans."
  case "${mode}" in
    first) [ "${fam}" = none ] || die "a first plan, but a live package or an orphan refresh artifact exists (${fam})." ;;
    recovery)
      # An orphan refresh (its content run expired) is the expected state of a
      # recovery: the plan recorded that refresh run (checked above), so it is
      # the same state; a real live package is not.
      case "${fam}" in none | refresh-orphan) ;; *) die "a recovery plan, but a live package exists (${fam} run $(jq -r '.live.runId' <<< "${live}"))." ;; esac ;;
    state | capability)
      [ "${fam}" != none ] && [ "${fam}" != refresh-orphan ] || die "a ${mode} plan, but no live package exists (${fam})."
      [ "$(jq -r '.live.digest' <<< "${live}")" = "${digest}" ] || die "the live ${fam} package is not the package the plan holds; the next plan replans." ;;
    *) die "check-live: unknown mode '${mode}'." ;;
  esac
  echo "check-live: OK (live ${fam})"
}

# ---------------------------------------------------------------- trusted-ids
# Prints the comma separated numeric ids whose gate and review markers count.
# The ids are constants; a lookup of each login must return exactly that id,
# otherwise (rename, re-registration, unreadable answer) nothing is trusted.
cmd_trusted_ids() {
  need_repo
  local pairs=("${OWNER_LOGIN}:${OWNER_USER_ID}") got ids="" pair login want
  if [ -n "${BOT_USER_ID}" ]; then pairs+=("${BOT_LOGIN}:${BOT_USER_ID}"); fi
  for pair in "${pairs[@]}"; do
    login="${pair%%:*}"; want="${pair#*:}"
    is_pos_int "${want}" || die "the pinned id of ${login} is malformed."
    got="$(gh_get "users/${login}" | jq -er 'select(.id | type == "number") | .id')" || die "cannot look up ${login} to cross-check its pinned id."
    [ "${got}" = "${want}" ] || die "the login ${login} now resolves to id ${got}, not the pinned ${want}; no marker is trusted."
    ids="${ids:+${ids},}${want}"
  done
  echo "${ids}"
}

# ---------------------------------------------------------------- collect
# collect REPO_DIR BASE HEAD OUTFILE: input file of the packet generator
# (schema prufyx.io/knowledge-packet-input/v2) for the merges of BASE..HEAD.
cmd_collect() {
  need_repo
  local dir="${1:?}" base="${2:?}" head="${3:?}" outfile="${4:?}"
  is_sha40 "${base}" && is_sha40 "${head}" || die "collect: base and head must be 40-hex commits."
  local tmp merges m subject num pr n
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' RETURN
  : > "${tmp}/prs"
  merges="$(git -C "${dir}" rev-list --first-parent --merges --reverse "${base}..${head}")" || die "collect: range not readable."
  for m in ${merges}; do
    subject="$(git -C "${dir}" log -1 --format=%s "${m}")"
    if [[ "${subject}" =~ ^Merge\ pull\ request\ \#([0-9]+)\ from\  ]]; then
      num="${BASH_REMATCH[1]}"
    else
      num="$(gh_get "repos/${GH_REPO}/commits/${m}/pulls" | jq -r '.[0].number // empty')" || die "collect: cannot resolve the pull request of ${m:0:8}."
      if [ -z "${num}" ]; then echo "::warning::merge ${m:0:8} has no pull request number; the packet lists it without input."; continue; fi
    fi
    is_pos_int "${num}" || die "collect: bad pull request number for ${m:0:8}."
    pr="$(gh_get "repos/${GH_REPO}/pulls/${num}")" || die "collect: cannot read pull request ${num}."
    local headsha author ref title
    headsha="$(jq -r '.head.sha' <<< "${pr}")"
    author="$(jq -r '.user.login' <<< "${pr}")"
    ref="$(jq -r '.head.ref' <<< "${pr}")"
    title="$(jq -r '.title' <<< "${pr}")"
    is_sha40 "${headsha}" || die "collect: pull request ${num} has no head sha."
    gh api --paginate -X GET "repos/${GH_REPO}/issues/${num}/comments?per_page=100" | jq -s 'add // [] | map({author: .user.login, authorId: .user.id, createdAt: .created_at, updatedAt: .updated_at, body: .body})' > "${tmp}/c" \
      || die "collect: cannot read comments of ${num}."
    gh api --paginate -X GET "repos/${GH_REPO}/commits/${headsha}/statuses?per_page=100" | jq -s 'add // [] | map({id: .id, context: .context, state: .state, creator: .creator.login, creatorId: .creator.id})' > "${tmp}/s" \
      || die "collect: cannot read statuses of ${num}."
    gh api --paginate -X GET "repos/${GH_REPO}/commits/${headsha}/check-runs?per_page=100" | jq -s '[.[].check_runs[]? | {name: .name, conclusion: (.conclusion // "")}]' > "${tmp}/k" \
      || die "collect: cannot read check runs of ${num}."
    jq -c -n --argjson number "${num}" --arg head "${headsha}" --arg author "${author}" --arg ref "${ref}" --arg title "${title}" \
      --slurpfile c "${tmp}/c" --slurpfile s "${tmp}/s" --slurpfile k "${tmp}/k" \
      '{number: $number, head: $head, author: $author, ref: $ref, title: $title, comments: $c[0], statuses: $s[0], checks: $k[0]}' >> "${tmp}/prs"
  done
  jq -s '{schema: "prufyx.io/knowledge-packet-input/v2", prs: .}' "${tmp}/prs" > "${outfile}"
  n="$(jq '.prs | length' "${outfile}")"
  echo "collect: ${n} pull requests"
}

# ---------------------------------------------------------------- has-content
# has-content PACKET MODE: prints true when the range can change what is published.
# The paths are the former push triggers and every other input of the engine
# capability or the exported knowledge: a path that is missing here would let a
# real change wait for the next refresh without an approval request.
cmd_has_content() {
  local packet="${1:?}" mode="${2:?}"
  jq -e '.schema == "prufyx.io/knowledge-packet/v1" and (.entries | type == "array")' "${packet}" > /dev/null || die "has-content: not a packet."
  case "${mode}" in first | capability | recovery) echo true; return 0 ;; state) ;; *) die "has-content: unknown mode ${mode}." ;; esac
  if jq -e '
      ((.directCommits | length) > 0)
      or ((.summary.unverified // 0) > 0) or ((.summary.trustPath // 0) > 0)
      or ([.entries[] | select(.class == "TRUST-PATH")] | length > 0)
      or ([.entries[] | .files[]? | select(test("^cli/(knowledge/|internal/customresources/(table|guard)\\.json$|internal/[a-z0-9]+/data/|internal/constraintengine/)"))] | length > 0)
    ' "${packet}" > /dev/null; then echo true; else echo false; fi
}

# ---------------------------------------------------------------- plan-json
# plan-json OUTFILE; all values from the environment, all validated.
cmd_plan_json() {
  local outfile="${1:?}"
  : "${MODE:?}" "${SOURCE_COMMIT:?}" "${REVISION:?}" "${MIN_VERSION:?}" "${EXPIRES:?}" "${CONTENT_DIGEST:?}" "${INDEX_DIGEST:?}" "${PACKET:?}" "${CREATED_EPOCH:?}" "${RUN_ID:?}"
  case "${MODE}" in first | state | capability | recovery) ;; *) die "plan-json: bad mode." ;; esac
  is_sha40 "${SOURCE_COMMIT}" || die "plan-json: bad source commit."
  is_pos_int "${REVISION}" && is_pos_int "${MIN_VERSION}" && is_pos_int "${CREATED_EPOCH}" && is_pos_int "${RUN_ID}" || die "plan-json: bad number."
  is_digest "${CONTENT_DIGEST}" && is_digest "${INDEX_DIGEST}" || die "plan-json: bad digest."
  [[ "${EXPIRES}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || die "plan-json: expires is not exact UTC."
  local entries_digest
  entries_digest="$(jq -er '.entriesDigest' "${PACKET}")" || die "plan-json: the packet has no entriesDigest."
  is_digest "${entries_digest}" || die "plan-json: bad entriesDigest."
  [ -z "${PREV_CONTENT_RUN_ID:-}" ] || is_pos_int "${PREV_CONTENT_RUN_ID}" || die "plan-json: bad previous content run id."
  [ -z "${PREV_REFRESH_RUN_ID:-}" ] || is_pos_int "${PREV_REFRESH_RUN_ID}" || die "plan-json: bad previous refresh run id."
  case "${MODE}" in state | capability) [ -n "${PREV_CONTENT_RUN_ID:-}" ] || die "plan-json: ${MODE} mode needs the content run of the previous package." ;; esac
  if [ "${MODE}" != first ]; then
    : "${PREV_REVISION:?}" "${PREV_TUF:?}" "${PREV_PACKAGE_DIGEST:?}" "${PREV_TARGETS_DIGEST:?}" "${PREV_SNAPSHOT_DIGEST:?}" "${PREV_INDEX_SHA:?}"
    is_pos_int "${PREV_REVISION}" && is_pos_int "${PREV_TUF}" || die "plan-json: bad previous number."
    is_digest "${PREV_PACKAGE_DIGEST}" && is_digest "${PREV_TARGETS_DIGEST}" && is_digest "${PREV_SNAPSHOT_DIGEST}" && is_digest "${PREV_INDEX_SHA}" || die "plan-json: bad previous digest."
  fi
  local packet_sha
  packet_sha="sha256:$(sha256sum "${PACKET}" | cut -d' ' -f1)"
  jq -n --arg schema "${PLAN_SCHEMA}" --arg mode "${MODE}" --arg src "${SOURCE_COMMIT}" --argjson rev "${REVISION}" --argjson minv "${MIN_VERSION}" \
    --arg exp "${EXPIRES}" --arg cd "${CONTENT_DIGEST}" --arg ed "${entries_digest}" --arg id "${INDEX_DIGEST}" --arg psha "${packet_sha}" --argjson created "${CREATED_EPOCH}" \
    --argjson run "${RUN_ID}" --arg hc "${HAS_CONTENT:-true}" --arg dry "${DRY_RUN:-false}" \
    --arg pcrun "${PREV_CONTENT_RUN_ID:-}" --arg prrun "${PREV_REFRESH_RUN_ID:-}" --arg prev "${PREV_REVISION:-0}" --arg ptuf "${PREV_TUF:-0}" --arg ppd "${PREV_PACKAGE_DIGEST:-}" \
    --arg ptd "${PREV_TARGETS_DIGEST:-}" --arg psd "${PREV_SNAPSHOT_DIGEST:-}" --arg pis "${PREV_INDEX_SHA:-}" \
    '{schema: $schema, mode: $mode, sourceCommit: $src, revision: $rev, minTufVersion: $minv, expires: $exp, contentDigest: $cd, entriesDigest: $ed, indexDigest: $id,
      packetSha256: $psha, createdEpoch: $created, planRunId: $run, hasContent: ($hc == "true"), dryRun: ($dry == "true"),
      previous: {contentRunId: $pcrun, refreshRunId: $prrun, revision: ($prev | tonumber), tufVersion: ($ptuf | tonumber), packageDigest: $ppd, targetsDigest: $ptd, snapshotDigest: $psd, indexSha256: $pis}}' > "${outfile}"
}

# ---------------------------------------------------------------- sign-check
# sign-check PLAN PACKET: run before any key is read.
cmd_sign_check() {
  local plan="${1:?}" packet="${2:?}"
  [ "${GITHUB_RUN_ATTEMPT:-}" = 1 ] || die "sign refused: run attempt is '${GITHUB_RUN_ATTEMPT:-}', an approved run is never replayed."
  is_sha40 "${GITHUB_SHA:-}" || die "sign refused: GITHUB_SHA is not a commit."
  jq -e --arg s "${PLAN_SCHEMA}" '.schema == $s' "${plan}" > /dev/null 2>&1 || die "sign refused: the plan file has the wrong schema."
  [ "$(jq -r '.sourceCommit' "${plan}")" = "${GITHUB_SHA}" ] || die "sign refused: the plan was made for another commit than this run."
  [ "$(jq -r '.dryRun' "${plan}")" = false ] || die "sign refused: the plan was made in a dry run."
  [ "$(jq -r '.hasContent' "${plan}")" = true ] || die "sign refused: the plan says nothing changes."
  [ "$(jq -r '.packetSha256' "${plan}")" = "sha256:$(sha256sum "${packet}" | cut -d' ' -f1)" ] || die "sign refused: packet.json differs from the one the plan describes."
  jq -e '.schema == "prufyx.io/knowledge-packet/v1" and .sourceCommit == $s' --arg s "${GITHUB_SHA}" "${packet}" > /dev/null 2>&1 || die "sign refused: packet.json is not the packet of this commit."
  jq -e '(.entriesDigest | type == "string") and (.entriesDigest | test("^sha256:[0-9a-f]{64}$"))' "${plan}" > /dev/null 2>&1 || die "sign refused: the plan has no well-formed entriesDigest."
  [ "$(jq -r '.entriesDigest' "${plan}")" = "$(jq -r '.entriesDigest' "${packet}")" ] || die "sign refused: the packet entriesDigest differs from the plan."
  local created now
  created="$(jq -r '.createdEpoch' "${plan}")"
  is_pos_int "${created}" || die "sign refused: the plan has no creation time."
  now="$(now_epoch)"
  [ "${now}" -ge "${created}" ] || die "sign refused: the plan is dated in the future."
  [ $((now - created)) -lt "${PLAN_MAX_AGE_SECONDS}" ] || die "sign refused: the plan is older than 48 hours; the next plan replaces it."
  jq -e '(.contentDigest | test("^sha256:[0-9a-f]{64}$")) and (.indexDigest | test("^sha256:[0-9a-f]{64}$")) and (.revision >= 1) and (.minTufVersion >= 1)
         and (.expires | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))' "${plan}" > /dev/null || die "sign refused: the plan has malformed digests, versions or expiry."
  echo "sign-check: OK"
}

sub="${1:-}"
[ $# -gt 0 ] && shift
case "${sub}" in
  gate) cmd_gate "$@" ;;
  pending) cmd_pending "$@" ;;
  cancel) cmd_cancel "$@" ;;
  live-runs) cmd_live_runs "$@" ;;
  check-live) cmd_check_live "$@" ;;
  trusted-ids) cmd_trusted_ids "$@" ;;
  collect) cmd_collect "$@" ;;
  has-content) cmd_has_content "$@" ;;
  plan-json) cmd_plan_json "$@" ;;
  sign-check) cmd_sign_check "$@" ;;
  *) echo "usage: knowledge-daily.sh gate|pending|cancel|live-runs|check-live|trusted-ids|collect|has-content|plan-json|sign-check" >&2; exit 2 ;;
esac
