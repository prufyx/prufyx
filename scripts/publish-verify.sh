#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Read-only self-check of the live knowledge feed (see
# cli/docs/knowledge-publisher.md, "Publish self-check"). It needs no secret and
# no human: it fetches the public feed, verifies it with the pinned root exactly
# as `prufyx db update` does, and prints ONE line. Exit 0: "publish-verify: OK
# ..."; exit 1: "publish-verify: FAIL <reasons>"; exit 2: bad usage.
#
# FAIL reasons (all that apply, joined by "; "):
#   feed unreachable / feed does not verify
#   feed age > 8 days
#   timestamp expires in < 5 days
#   timestamp expiry beyond the 14 day cap / targets or snapshot expiry beyond the 21 day cap
#   verified feed without a readable targets or snapshot expiry
#   no successful Knowledge publish run on main / last one older than 8 days
#   feed not newer than the newest cli/knowledge merge on main
#
# Usage: publish-verify.sh --bin PRUFYX --root FILE --root-digest sha256:HEX --repo OWNER/REPO
#                          --git DIR [--git-ref REF] [--feed URL]
#   --git DIR is a checkout with full history (fetch-depth 0); the newest
#   knowledge merge is the first-parent commit of REF (default origin/main)
#   that touched cli/knowledge, i.e. the merge commit, not the branch commit.
# Env:   GH_TOKEN (optional, raises the API rate limit; read-only use),
#        PUBLISH_VERIFY_API (default https://api.github.com),
#        PUBLISH_VERIFY_NOW (epoch seconds, tests only).
set -uo pipefail
export LC_ALL=C

MAX_AGE_DAYS=8
MIN_EXPIRY_DAYS=5
MERGE_GRACE_SECONDS=108000 # 30 h: a merge is published by the next daily run (05:17 UTC) plus its approval
TS_CAP_DAYS=14             # timestamp expiry = min(signing time + 14d, targets expiry)
TARGETS_CAP_DAYS=21        # targets and snapshot expiry = min(content signing time + 21d, evidence expiry)
CAP_SLACK_SECONDS=3600     # clock and rounding slack for the cap checks
FEED_DEFAULT="https://prufyx.github.io/prufyx/knowledge/cncf-projects.tar"
MAX_BYTES=8388608

bin="" root="" rdigest="" repo="" gitdir="" gitref="origin/main" feed="${FEED_DEFAULT}"
while [ $# -gt 0 ]; do
  case "$1" in
    --bin) bin="${2:-}"; shift 2 ;;
    --root) root="${2:-}"; shift 2 ;;
    --root-digest) rdigest="${2:-}"; shift 2 ;;
    --repo) repo="${2:-}"; shift 2 ;;
    --git) gitdir="${2:-}"; shift 2 ;;
    --git-ref) gitref="${2:-}"; shift 2 ;;
    --feed) feed="${2:-}"; shift 2 ;;
    *) echo "publish-verify: usage error: unknown argument" >&2; exit 2 ;;
  esac
done
if [ -z "${bin}" ] || [ -z "${root}" ] || [ -z "${rdigest}" ] || [ -z "${gitdir}" ] || ! [[ "${repo}" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]; then
  echo "publish-verify: usage error: --bin, --root, --root-digest and --repo OWNER/REPO and --git are required" >&2
  exit 2
fi
if ! [[ "${feed}" =~ ^https://[A-Za-z0-9._~/-]+$ ]]; then
  echo "publish-verify: usage error: --feed must be a plain https URL" >&2
  exit 2
fi

api="${PUBLISH_VERIFY_API:-https://api.github.com}"
now="${PUBLISH_VERIFY_NOW:-$(date -u +%s)}"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
fails=()
fail() { fails+=("$1"); }
finish() {
  if [ "${#fails[@]}" -eq 0 ]; then
    echo "publish-verify: OK $1"
    exit 0
  fi
  local IFS=';'
  local joined="${fails[*]}"
  echo "publish-verify: FAIL ${joined//;/; }"
  exit 1
}
epoch() { date -u -d "$1" +%s 2>/dev/null; }

gh_get() { # path -> body on stdout; non-zero on any failure
  local auth=()
  [ -z "${GH_TOKEN:-}" ] || auth=(-H "Authorization: Bearer ${GH_TOKEN}")
  curl --proto '=https' --max-redirs 0 --max-time 30 -fsS \
    -H "Accept: application/vnd.github+json" "${auth[@]}" -- "${api}/repos/${repo}/$1"
}

# 1. The live feed, verified with the pinned root.
if ! curl --proto '=https' --max-redirs 0 --max-filesize "${MAX_BYTES}" --max-time 60 -fsS \
     -D "${work}/headers" -o "${work}/feed.tar" -- "${feed}" 2>/dev/null; then
  fail "feed unreachable"
  finish ""
fi
receipt="$("${bin}" db verify "${work}/feed.tar" --profile cncf-projects \
  --bootstrap-root "${root}" --bootstrap-root-digest "${rdigest}" --format json 2>/dev/null)" || receipt=""
if [ -z "${receipt}" ] || ! jq -e '.status == "VERIFIED"' <<< "${receipt}" > /dev/null 2>&1; then
  fail "feed does not verify against the pinned root (invalid or timestamp expired)"
  finish ""
fi
revision="$(jq -r '.knowledgeRevision' <<< "${receipt}")"
expires="$(jq -r '.timestamp.expires' <<< "${receipt}")"
evidence="$(jq -r '.evidenceExpiresAt // empty' <<< "${receipt}")"
exp_e="$(epoch "${expires}")" || exp_e=""
if [ -z "${exp_e}" ]; then
  fail "verified feed has no readable timestamp expiry"
  finish ""
fi
tgt_x="$(jq -r '.targets.expires // empty' <<< "${receipt}")"
snap_x="$(jq -r '.snapshot.expires // empty' <<< "${receipt}")"
tgt_e=""; snap_e=""
[ -z "${tgt_x}" ] || tgt_e="$(epoch "${tgt_x}")" || tgt_e=""
[ -z "${snap_x}" ] || snap_e="$(epoch "${snap_x}")" || snap_e=""
if [ -z "${tgt_e}" ] || [ -z "${snap_e}" ]; then
  fail "verified feed has no readable targets or snapshot expiry"
  finish ""
fi
role_e="${tgt_e}"
[ "${snap_e}" -ge "${role_e}" ] || role_e="${snap_e}"

# 2. Expiry margin.
left=$((exp_e - now))
if [ "${left}" -lt $((MIN_EXPIRY_DAYS * 86400)) ]; then
  fail "timestamp expires in $((left / 86400)) days (${expires}), minimum ${MIN_EXPIRY_DAYS}"
fi

# Caps: the publisher never signs a timestamp beyond 14 days or targets and
# snapshot beyond 21 days; a verified feed beyond a cap was not signed by it.
if [ $((exp_e - now)) -gt $((TS_CAP_DAYS * 86400 + CAP_SLACK_SECONDS)) ]; then
  fail "timestamp expiry ${expires} is more than the ${TS_CAP_DAYS} day cap away"
fi
if [ $((role_e - now)) -gt $((TARGETS_CAP_DAYS * 86400 + CAP_SLACK_SECONDS)) ]; then
  fail "targets and snapshot expiry is more than the ${TARGETS_CAP_DAYS} day cap away"
fi

# 3. Two signing times, both from the verified metadata when a cap was the
# binding expiry, else the Last-Modified of the deploy as the proxy:
#   signed          the timestamp: expiry - 14d when the 14 day cap bound, that is
#                   the timestamp expires before targets, snapshot and evidence. A
#                   content release or a timestamp refresh both set it. Feed age.
#   content_signed  targets and snapshot: expiry - 21d when the 21 day cap bound
#                   (expiry before the evidence expiry) and the timestamp was not
#                   itself capped by the targets (equal expiry also is the former
#                   layout, with one 14 day expiry for every role, and then the
#                   deploy time is used). Compared with the newest merge.
signed=""
content_signed=""
ev_e=""
[ -z "${evidence}" ] || ev_e="$(epoch "${evidence}")" || ev_e=""
lm="$(grep -i '^last-modified:' "${work}/headers" | tail -n 1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//')"
lm_e=""
[ -z "${lm}" ] || lm_e="$(epoch "${lm}")" || lm_e=""
if [ "${exp_e}" -lt "${role_e}" ] && [ -n "${ev_e}" ] && [ "${exp_e}" -lt "${ev_e}" ]; then
  signed=$((exp_e - TS_CAP_DAYS * 86400))
else
  signed="${lm_e}"
fi
if [ "${tgt_e}" -ne "${exp_e}" ] && [ -n "${ev_e}" ] && [ "${tgt_e}" -lt "${ev_e}" ]; then
  content_signed=$((tgt_e - TARGETS_CAP_DAYS * 86400))
else
  content_signed="${lm_e}"
fi
if [ -z "${signed}" ]; then
  fail "feed age unknown (no cap-bound expiry, no Last-Modified)"
else
  age=$((now - signed))
  if [ "${age}" -gt $((MAX_AGE_DAYS * 86400)) ]; then
    fail "feed age $((age / 86400)) days, maximum ${MAX_AGE_DAYS}"
  fi
fi

# 4. Last successful Knowledge publish run on main.
run_started=""
runs="$(gh_get "actions/workflows/knowledge-publish.yml/runs?branch=main&status=success&per_page=1")" || runs=""
if [ -z "${runs}" ]; then
  fail "cannot read the Knowledge publish runs"
else
  run_started="$(jq -r '.workflow_runs[0].run_started_at // empty' <<< "${runs}")"
  if [ -z "${run_started}" ]; then
    fail "no successful Knowledge publish run on main"
  else
    rs_e="$(epoch "${run_started}")" || rs_e=""
    if [ -z "${rs_e}" ]; then
      fail "last Knowledge publish run has no readable time"
    elif [ $((now - rs_e)) -gt $((MAX_AGE_DAYS * 86400)) ]; then
      fail "last successful Knowledge publish run on main is $(((now - rs_e) / 86400)) days old, maximum ${MAX_AGE_DAYS}"
    fi
  fi
fi

# 5. The feed must be newer than the newest knowledge merge on main. The merge
# time is the committer time of the first-parent commit of main that touched
# cli/knowledge (the no-ff merge commit; the GitHub commits API would return
# the older branch commit). A merge younger than the grace window is still
# being published; a later successful run that skipped the deploy (unchanged
# bundle) also accounts for the merge.
m_e="$(git -C "${gitdir}" log --first-parent -1 --format=%ct "${gitref}" -- cli/knowledge 2>/dev/null)" || m_e="__err__"
if [ "${m_e}" = "__err__" ] || { [ -n "${m_e}" ] && ! [[ "${m_e}" =~ ^[0-9]+$ ]]; }; then
  fail "cannot read the newest knowledge merge on main from the checkout"
elif [ -n "${m_e}" ]; then
  if [ -n "${content_signed}" ] && [ "${content_signed}" -lt "${m_e}" ] && [ $((now - m_e)) -gt "${MERGE_GRACE_SECONDS}" ] \
       && { [ -z "${rs_e:-}" ] || [ "${rs_e}" -lt "${m_e}" ]; }; then
    fail "feed not newer than the newest knowledge merge on main ($(date -u -d "@${m_e}" +%Y-%m-%dT%H:%M:%SZ)) and no later successful publish run"
  fi
fi

finish "revision ${revision}, signed $(date -u -d "@${signed:-0}" +%Y-%m-%dT%H:%M:%SZ), expires ${expires}"
