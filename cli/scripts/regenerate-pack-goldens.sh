#!/usr/bin/env sh
# Regenerate the test artefacts that follow the bytes of the embedded CNCF rule
# pack (internal/cncfcheck/data/rules.json), compare them with what they were
# by meaning, then run the tests that read them.
#
# Run it after the shipped pack changes (for example when the mechanical
# Kubernetes API-removal rules replace the reviewed ones), from any directory:
#
#   cli/scripts/regenerate-pack-goldens.sh [--no-test] [--allow-semantic-change]
#
# What it rewrites, and nothing else:
#   - the pinned pack digest in internal/cncfcheck/set_rules_test.go
#     (embeddedPackSHA256, the tripwire the synthetic-rule tests rely on); the
#     old and the new value are printed;
#   - the scan report goldens (internal/scanrun/testdata, `go test -update`) and,
#     because they render those reports, the scanreport goldens
#     (internal/scanreport/testdata);
#   - the knowledge-age goldens of `check` (internal/communityapp/testdata,
#     `go test -update-age`).
# The rule-id, clock, count and basis expectations of the tests are not
# goldens: they follow the pack by themselves (internal/extract/supersedeids).
#
# A golden test in -update mode cannot fail on a changed output, so this
# script is what guards the goldens. It snapshots them before the rewrite, and
# afterwards prints, for every golden whose text changed, the verdicts,
# statuses, exit codes and hop states before and after
# (scripts/goldensemantics). It exits 3 and runs no tests when any of them
# differs, unless --allow-semantic-change is given: a rule pack change that
# turns a BLOCKED into a PASS (or adds or removes a finding, a gap, a golden)
# must be accepted on purpose, after reading the lines it prints. Ids, reason
# codes, basis, citations, fix text, dates and digests may change freely.
# The snapshot is of the files as they are when the script starts: commit or
# stash goldens you changed by hand first.
#
#   --no-test                stop after regenerating and comparing
#   --allow-semantic-change  accept a semantic difference (it is still printed)
#   --compare BEFORE AFTER   only compare two directories of goldens (the
#                            comparison step on its own; used by its test)
#
# GO_TEST_TIMEOUT (default 90m) is the per-package test timeout.
set -eu

cd "$(dirname "$0")/.."
export GOFLAGS="${GOFLAGS:--mod=vendor}"
timeout="${GO_TEST_TIMEOUT:-90m}"

no_test=0
allow=""
compare=0
while [ $# -gt 0 ]; do
  case "$1" in
    --no-test) no_test=1 ;;
    --allow-semantic-change) allow="-allow-semantic-change" ;;
    --compare) compare=1; shift; break ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$compare" -eq 1 ]; then
  [ $# -ge 2 ] || { echo "usage: $0 --compare BEFORE_DIR AFTER_DIR [--allow-semantic-change]" >&2; exit 2; }
  before_dir=$1
  after_dir=$2
  shift 2
  for extra in "$@"; do
    case "$extra" in
      --allow-semantic-change) allow="-allow-semantic-change" ;;
      *) echo "unknown argument: $extra" >&2; exit 2 ;;
    esac
  done
  tool=$(mktemp "${TMPDIR:-/tmp}/goldensemantics.XXXXXX")
  trap 'rm -f "$tool"' EXIT INT TERM
  go build -buildvcs=false -o "$tool" ./scripts/goldensemantics
  status=0
  # shellcheck disable=SC2086
  "$tool" $allow "$before_dir" "$after_dir" || status=$?
  exit "$status"
fi

pack=internal/cncfcheck/data/rules.json
pin=internal/cncfcheck/set_rules_test.go
golden_dirs="internal/scanrun/testdata internal/scanreport/testdata internal/communityapp/testdata/knowledge-age"

if command -v sha256sum >/dev/null 2>&1; then
  digest=$(sha256sum "$pack" | cut -d' ' -f1)
else
  digest=$(shasum -a 256 "$pack" | cut -d' ' -f1)
fi
test "${#digest}" -eq 64 || { echo "cannot compute the digest of $pack" >&2; exit 1; }
grep -q 'embeddedPackSHA256 = "[0-9a-f]\{64\}"' "$pin" || { echo "no embeddedPackSHA256 pin in $pin" >&2; exit 1; }
old_digest=$(sed -n 's/.*embeddedPackSHA256 = "\([0-9a-f]\{64\}\)".*/\1/p' "$pin" | head -n 1)

snap=$(mktemp -d "${TMPDIR:-/tmp}/regenerate-pack-goldens.XXXXXX")
trap 'rm -rf "$snap"' EXIT INT TERM
for dir in $golden_dirs; do
  mkdir -p "$snap/before/$dir"
  cp -R "$dir/." "$snap/before/$dir/"
done

sed "s/embeddedPackSHA256 = \"[0-9a-f]\{64\}\"/embeddedPackSHA256 = \"$digest\"/" "$pin" > "$pin.new"
mv "$pin.new" "$pin"
if [ "$old_digest" = "$digest" ]; then
  echo "pack digest pin: sha256:$digest (unchanged)"
else
  echo "pack digest pin: sha256:$old_digest -> sha256:$digest (rewritten)"
fi

go test -count=1 -timeout "$timeout" ./internal/scanrun -update
go test -count=1 -timeout "$timeout" ./internal/scanreport -update
go test -count=1 -timeout "$timeout" ./internal/communityapp -run '^TestCheckOutputUnchangedNearExpiry$' -update-age

for dir in $golden_dirs; do
  mkdir -p "$snap/after/$dir"
  cp -R "$dir/." "$snap/after/$dir/"
done
# (go run would turn the tool's exit code 3 into 1.)
go build -buildvcs=false -o "$snap/goldensemantics" ./scripts/goldensemantics
status=0
# shellcheck disable=SC2086
"$snap/goldensemantics" $allow "$snap/before" "$snap/after" || status=$?
if [ "$status" -ne 0 ]; then
  echo "the goldens are rewritten in the working tree; read 'git diff', then either rerun with --allow-semantic-change or discard them with 'git checkout -- $golden_dirs $pin'" >&2
  exit "$status"
fi

if [ "$no_test" -eq 1 ]; then
  git status --short .
  exit 0
fi

# The tests that read the embedded Kubernetes rules, plain and tagged.
packages="./internal/scanrun/... ./internal/scanreport/... ./internal/cncfcheck/... ./internal/communityapp/... ./internal/maintainer/knowledgegate/... ./internal/extract/extractpack/... ./internal/extract/extractcli/... ./internal/checkroutemetadata/... ./internal/extract/k8sservedapis/..."
# shellcheck disable=SC2086
go test -count=1 -timeout "$timeout" $packages
# shellcheck disable=SC2086
go test -count=1 -timeout "$timeout" -tags prufyx_synthetic_knowledge $packages
