#!/usr/bin/env sh
# Regenerate the test artefacts that follow the bytes of the embedded CNCF rule
# pack (internal/cncfcheck/data/rules.json), then run the tests that read it.
#
# Run it after the shipped pack changes (for example when the mechanical
# Kubernetes API-removal rules replace the reviewed ones), from any directory:
#
#   cli/scripts/regenerate-pack-goldens.sh
#
# What it rewrites, and nothing else:
#   - the pinned pack digest in internal/cncfcheck/set_rules_test.go
#     (embeddedPackSHA256, the tripwire the synthetic-rule tests rely on);
#   - the scan report goldens (internal/scanrun/testdata, `go test -update`) and,
#     because they render those reports, the scanreport goldens
#     (internal/scanreport/testdata);
#   - the knowledge-age goldens of `check` (internal/communityapp/testdata,
#     `go test -update-age`).
# The rule-id, clock, count and basis expectations of the tests are not
# goldens: they follow the pack by themselves (internal/extract/supersedeids).
# Review the diff it leaves with `git diff --stat`: only those files change.
#
# With --no-test it stops after regenerating. GO_TEST_TIMEOUT (default 90m) is the
# per-package test timeout.
set -eu

cd "$(dirname "$0")/.."
export GOFLAGS="${GOFLAGS:--mod=vendor}"
timeout="${GO_TEST_TIMEOUT:-90m}"

pack=internal/cncfcheck/data/rules.json
pin=internal/cncfcheck/set_rules_test.go
if command -v sha256sum >/dev/null 2>&1; then
  digest=$(sha256sum "$pack" | cut -d' ' -f1)
else
  digest=$(shasum -a 256 "$pack" | cut -d' ' -f1)
fi
test "${#digest}" -eq 64 || { echo "cannot compute the digest of $pack" >&2; exit 1; }
grep -q 'embeddedPackSHA256 = "[0-9a-f]\{64\}"' "$pin" || { echo "no embeddedPackSHA256 pin in $pin" >&2; exit 1; }
sed "s/embeddedPackSHA256 = \"[0-9a-f]\{64\}\"/embeddedPackSHA256 = \"$digest\"/" "$pin" > "$pin.new"
mv "$pin.new" "$pin"
echo "pack digest pin: sha256:$digest"

go test -count=1 -timeout "$timeout" ./internal/scanrun -update
go test -count=1 -timeout "$timeout" ./internal/scanreport -update
go test -count=1 -timeout "$timeout" ./internal/communityapp -run '^TestCheckOutputUnchangedNearExpiry$' -update-age

if [ "${1:-}" = "--no-test" ]; then
  git status --short .
  exit 0
fi

# The tests that read the embedded Kubernetes rules, plain and tagged.
packages="./internal/scanrun/... ./internal/scanreport/... ./internal/cncfcheck/... ./internal/communityapp/... ./internal/maintainer/knowledgegate/... ./internal/extract/extractpack/... ./internal/extract/extractcli/... ./internal/checkroutemetadata/... ./internal/extract/k8sservedapis/..."
# shellcheck disable=SC2086
go test -count=1 -timeout "$timeout" $packages
# shellcheck disable=SC2086
go test -count=1 -timeout "$timeout" -tags prufyx_synthetic_knowledge $packages
