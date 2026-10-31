#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Reads the verification receipt of the previous knowledge package and writes
# the publish state (revision, TUF version, rule digest, index) as step
# outputs. Used by the "Find and verify the previous state" step and, after a
# capability change, by the step that verifies the package with the client
# that produced it. It verifies nothing itself: the receipt is the result of
# `prufyx db verify` against the pinned root.
#
# Environment:
#   PKG              previous package (tar)
#   RECEIPT          file holding the JSON receipt of `db verify`
#   MODE             state | recovery | capability (written to the output)
#   CREATED          creation time of the artifact (RFC 3339) or empty
#   PREV_TUF         recovery only: TUF version the operator stated
#   STATE_DIR        existing private directory for the extracted index
#   MAX_INDEX_BYTES  size cap of the index
#   GITHUB_OUTPUT    output file
set -euo pipefail
umask 077
fail() { echo "::error::$*"; exit 1; }

: "${PKG:?}" "${RECEIPT:?}" "${MODE:?}" "${STATE_DIR:?}" "${MAX_INDEX_BYTES:?}" "${GITHUB_OUTPUT:?}"
CREATED="${CREATED:-}"
PREV_TUF="${PREV_TUF:-}"

revision="$(jq -r '.knowledgeRevision' "${RECEIPT}")"
tuf="$(jq -r '.timestamp.version' "${RECEIPT}")"
rules="$(jq -r '.ruleDigest' "${RECEIPT}")"
[[ "${revision}" =~ ^[1-9][0-9]{0,17}$ ]] || fail "previous revision is not a positive integer."
[[ "${tuf}" =~ ^[1-9][0-9]{0,17}$ ]] || fail "previous TUF version is not a positive integer."
if [ "${MODE}" = recovery ] && [ "${tuf}" != "${PREV_TUF}" ]; then
  fail "previous_tuf_version does not match the verified package."
fi

# Exactly one index member, extracted with a size cap (the member name is
# matched against a strict pattern; nothing is unpacked to disk).
members="$(tar -tf "${PKG}" | head -n 1000 | grep -E '^targets/knowledge/cncf/[0-9a-f]{64}\.index\.v1\.json$' || true)"
[ "$(grep -c . <<< "${members}")" = 1 ] || fail "previous package does not hold exactly one index."
tar -xOf "${PKG}" --no-wildcards -- "${members}" | head -c $((MAX_INDEX_BYTES + 1)) > "${STATE_DIR}/index.json"
[ "$(stat -c %s "${STATE_DIR}/index.json")" -le "${MAX_INDEX_BYTES}" ] || fail "previous index is larger than the limit."
[ -s "${STATE_DIR}/index.json" ] || fail "previous index is empty."

created_epoch=""
[ -z "${CREATED}" ] || created_epoch="$(date -u -d "${CREATED}" +%s)"
{
  echo "mode=${MODE}"
  echo "revision=${revision}"
  echo "tuf=${tuf}"
  echo "rules=${rules}"
  echo "created_epoch=${created_epoch}"
  echo "index=${STATE_DIR}/index.json"
} >> "${GITHUB_OUTPUT}"
