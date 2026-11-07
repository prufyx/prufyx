#!/usr/bin/env bash
# Merge policy for a merge queue run. Every failure path exits 1 (fail closed).
# Run from a full-history checkout of the queue commit (merge_group head_sha).
# Inputs (environment, never interpolated into a script):
#   QUEUE_REF       github.ref
#   QUEUE_SHA       github.sha
#   MQ_BASE_REF     merge_group.base_ref
#   MQ_BASE_SHA     merge_group.base_sha
#   MQ_HEAD_REF     merge_group.head_ref
#   MQ_HEAD_SHA     merge_group.head_sha
#   REPO            owner/name
# The pull request API is read through `gh api` (GH_TOKEN in the environment).
set -euo pipefail

fail() {
  echo "::error title=Merge policy::$1"
  exit 1
}

for v in QUEUE_REF QUEUE_SHA MQ_BASE_REF MQ_BASE_SHA MQ_HEAD_REF MQ_HEAD_SHA REPO; do
  [ -n "${!v:-}" ] || fail "missing input ${v}"
done

# a. the queue ref and the event describe the same commit on main
re='^refs/heads/gh-readonly-queue/main/pr-([0-9]+)-([0-9a-f]{40})$'
[[ "${QUEUE_REF}" =~ ${re} ]] || fail "unexpected queue ref shape: ${QUEUE_REF}"
pr="${BASH_REMATCH[1]}"
[ "${MQ_HEAD_REF}" = "${QUEUE_REF}" ] || fail "merge_group head_ref differs from the run ref"
[ "${QUEUE_SHA}" = "${MQ_HEAD_SHA}" ] || fail "run sha ${QUEUE_SHA} is not the merge_group head sha ${MQ_HEAD_SHA}"
[ "${MQ_BASE_REF}" = "refs/heads/main" ] || fail "merge_group base_ref is not refs/heads/main: ${MQ_BASE_REF}"
[[ "${MQ_BASE_SHA}" =~ ^[0-9a-f]{40}$ ]] || fail "merge_group base_sha is not a full sha"
[[ "${MQ_HEAD_SHA}" =~ ^[0-9a-f]{40}$ ]] || fail "merge_group head_sha is not a full sha"

# b. the checkout is the queue commit: a merge of exactly (base, pull request head)
head_now="$(git rev-parse HEAD)" || fail "no checkout"
[ "${head_now}" = "${MQ_HEAD_SHA}" ] || fail "checkout ${head_now} is not the merge_group head sha"
parents="$(git rev-list --parents -n 1 "${MQ_HEAD_SHA}")" || fail "cannot read the queue commit"
read -r -a parts <<< "${parents}"
[ "${#parts[@]}" -eq 3 ] || fail "queue commit must have exactly 2 parents, has $((${#parts[@]} - 1))"
p1="${parts[1]}"
x="${parts[2]}"
[ "${p1}" = "${MQ_BASE_SHA}" ] || fail "first parent ${p1} is not the merge_group base sha ${MQ_BASE_SHA}"

# c. the pull request is open, targets main, comes from a topic branch, and is at X
json="$(gh api "repos/${REPO}/pulls/${pr}")" || fail "cannot read pull request ${pr}"
# field NAME PATH: set NAME from the payload; a missing or null value fails (the
# error is printed here, outside a command substitution, so it is not swallowed).
field() {
  local val
  val="$(printf '%s' "${json}" | jq -er "$2" 2>/dev/null)" || fail "pull request ${pr}: missing $2"
  printf -v "$1" '%s' "${val}"
}
field state .state
field base_ref .base.ref
field head_ref .head.ref
field head_sha .head.sha
field commits .commits
[ "${state}" = "open" ] || fail "pull request ${pr} is ${state}, not open"
[ "${base_ref}" = "main" ] || fail "pull request ${pr} targets ${base_ref}, not main"
[ "${head_ref}" != "main" ] || fail "pull request ${pr} comes from main, not a topic branch"
[ "${head_sha}" = "${x}" ] || fail "pull request head ${head_sha} is not the queued second parent ${x}"
[[ "${commits}" =~ ^[0-9]+$ ]] || fail "pull request ${pr}: bad commit count"

# d. the pull request's own commits are linear and complete
merges="$(git rev-list --merges "${x}" "^${MQ_BASE_SHA}")" || fail "cannot list the pull request commits"
if [ -n "${merges}" ]; then
  printf '%s\n' "${merges}"
  fail "the pull request contains merge commits: rebase onto origin/main; never merge main into a branch"
fi
own="$(git rev-list --count "${x}" "^${MQ_BASE_SHA}")" || fail "cannot count the pull request commits"
[ "${own}" = "${commits}" ] || fail "pull request has ${commits} commits by the API but ${own} on the queue chain"

# e. the queue chain contains the current main tip
git fetch --no-tags origin main:refs/remotes/origin/main || fail "cannot fetch main"
git merge-base --is-ancestor refs/remotes/origin/main "${MQ_BASE_SHA}" \
  || fail "the queue base does not contain the main tip"

echo "queue commit ${MQ_HEAD_SHA}: pull request ${pr} (${commits} commits) on ${MQ_BASE_SHA}"
