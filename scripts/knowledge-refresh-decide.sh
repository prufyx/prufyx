#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Decision of the timestamp-only refresh workflow (see cli/docs/knowledge-publisher.md,
# "Timestamp refresh"). It reads the verified state of the live package and the
# list of pending runs of the content workflow, signs nothing and holds no
# secret. Fail closed: any unreadable input is exit 1 and no output.
#
# Environment:
#   LIVE_STATE        file with the JSON of `knowledge-publish live-state`
#   PENDING_RUNS      file with a JSON array of {id, status, created_at} for the
#                     runs of knowledge-publish.yml that are queued, in_progress
#                     or waiting
#   THRESHOLD_DAYS    refresh when the live timestamp has fewer days left (default 7, 1..13)
#   NOW               epoch seconds (tests only)
#   GITHUB_OUTPUT     output file
#   GITHUB_STEP_SUMMARY  optional summary file
#
# Outputs: action=refresh|skip, reason, alarm=true|false, alarm_text.
# Rules:
#   - a content run is pending and the live timestamp has more than 3 days left:
#     skip (the content release renews every role; a refresh must never block it)
#   - the live timestamp has THRESHOLD_DAYS or more left: skip (not due)
#   - otherwise refresh
# Alarms (independent of the action): a run has waited for approval for more than
# 48 hours; targets or snapshot expire in under 5 days (only a content release
# can renew them).
set -euo pipefail
export LC_ALL=C
fail() { echo "knowledge-refresh-decide: $*" >&2; exit 1; }

: "${LIVE_STATE:?}" "${PENDING_RUNS:?}" "${GITHUB_OUTPUT:?}"
threshold="${THRESHOLD_DAYS:-7}"
[[ "${threshold}" =~ ^([1-9]|1[0-3])$ ]] || fail "THRESHOLD_DAYS must be an integer from 1 to 13"
now="${NOW:-$(date -u +%s)}"
[[ "${now}" =~ ^[0-9]+$ ]] || fail "NOW is not an epoch"
[ -f "${LIVE_STATE}" ] && [ -f "${PENDING_RUNS}" ] || fail "input file missing"
jq -e 'type == "array"' "${PENDING_RUNS}" > /dev/null || fail "pending runs are not a JSON array"

epoch() { date -u -d "$1" +%s 2>/dev/null; }
field() { jq -er "$1 | select(type == \"string\" and length > 0)" "${LIVE_STATE}" 2>/dev/null || fail "live state lacks $1"; }
ts_e="$(epoch "$(field .timestampExpires)")" || fail "unreadable timestamp expiry"
tg_e="$(epoch "$(field .targetsExpires)")" || fail "unreadable targets expiry"
sn_e="$(epoch "$(field .snapshotExpires)")" || fail "unreadable snapshot expiry"
field .packageDigest > /dev/null

day=86400
ts_left=$((ts_e - now))
content_e=$((tg_e < sn_e ? tg_e : sn_e))
content_left=$((content_e - now))
[ "${ts_left}" -gt 0 ] && [ "${content_left}" -gt 0 ] || fail "the live metadata is already expired: only a content release or the recovery runbook can help"

pending="$(jq 'length' "${PENDING_RUNS}")"
oldest_wait=0
wait_ids=""
while IFS=$'\t' read -r id status created; do
  [ -n "${id}" ] || continue
  [[ "${id}" =~ ^[0-9]+$ ]] || fail "run id is not numeric"
  c="$(epoch "${created}")" || fail "unreadable run time"
  if [ "${status}" = waiting ]; then
    age=$((now - c))
    [ "${age}" -le "${oldest_wait}" ] || oldest_wait="${age}"
    wait_ids="${wait_ids:+${wait_ids},}${id}"
  fi
done < <(jq -r '.[] | [(.id // "" | tostring), (.status // ""), (.created_at // "")] | @tsv' "${PENDING_RUNS}")

action=refresh
reason="live timestamp has $((ts_left / day)) days left, under the threshold of ${threshold}"
if [ "${pending}" -gt 0 ] && [ "${ts_left}" -gt $((3 * day)) ]; then
  action=skip
  reason="a content run is pending and the live timestamp still has $((ts_left / day)) days left: nothing signed"
elif [ "${ts_left}" -ge $((threshold * day)) ]; then
  action=skip
  reason="live timestamp has $((ts_left / day)) days left, not under the threshold of ${threshold}: nothing to do"
fi

alarms=()
if [ "${oldest_wait}" -gt $((48 * 3600)) ]; then
  alarms+=("a content release has waited for approval for $((oldest_wait / 3600)) hours (run ${wait_ids})")
fi
if [ "${content_left}" -lt $((5 * day)) ]; then
  alarms+=("live targets or snapshot expire in $((content_left / day)) days: only a content release can renew them, approve or start one now")
fi
alarm=false
alarm_text=""
if [ "${#alarms[@]}" -gt 0 ]; then
  alarm=true
  alarm_text="$(printf '%s; ' "${alarms[@]}")"
  alarm_text="${alarm_text%; }"
fi

{
  echo "action=${action}"
  echo "reason=${reason}"
  echo "alarm=${alarm}"
  echo "alarm_text=${alarm_text}"
} >> "${GITHUB_OUTPUT}"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Knowledge timestamp refresh: decision"
    echo ""
    echo "- action: ${action}"
    echo "- reason: ${reason}"
    echo "- pending content runs: ${pending}"
    [ "${alarm}" = false ] || echo "- ALARM: ${alarm_text}"
  } >> "${GITHUB_STEP_SUMMARY}"
fi
echo "knowledge-refresh-decide: ${action}: ${reason}"
