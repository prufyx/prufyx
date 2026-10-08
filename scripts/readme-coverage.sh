#!/usr/bin/env sh
# Regenerates the coverage block of README.md between the markers
#   <!-- coverage:begin -->  and  <!-- coverage:end -->
# from the embedded knowledge: `prufyx-maintainer coverage report` plus the
# generated support inventory. Nothing in the block is typed by hand.
#
# usage: scripts/readme-coverage.sh [--check] [--lines FILE] [--now RFC3339]
#   --check  do not write; exit 1 if README.md differs from the generated block
#   --lines  offline release-lines snapshot (default: the committed snapshot)
#   --now    evaluation time (default: the snapshot's captured date, 12:00:00Z)
# Requires go (vendored build, offline) and jq.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
lines="$root/cli/internal/maintainer/coveragereport/testdata/lines-2026-10-08.json"
now=""
check=0
while [ $# -gt 0 ]; do
  case "$1" in
    --check) check=1 ;;
    --lines) lines="$2"; shift ;;
    --now) now="$2"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
[ -n "$now" ] || now="$(jq -r '.capturedOn' "$lines")T12:00:00Z"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(cd "$root/cli" && GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off \
  GOFLAGS='-mod=vendor -buildvcs=false' \
  go run ./cmd/prufyx-maintainer coverage report --lines "$lines" --now "$now" \
  --json-out "$tmp/report.json" >/dev/null)

inv="$root/cli/docs/generated/community-support-inventory.json"
jq -r --slurpfile inv "$inv" --arg now "$now" '
  def pct(a; b): if b == 0 then "0%" else ((a * 1000 / b | floor) / 10 | tostring) + "%" end;
  ($inv[0].counts) as $c
  | .fleet as $f
  | (.projects[] | select(.project == "kubernetes")) as $k
  | "Generated on \($now[0:10]) by `scripts/readme-coverage.sh` (do not edit this block by hand).\n"
  + "\n"
  + "| Executable rules | Count |\n| --- | --- |\n"
  + "| CNCF source rules, active | \($c.cncfSourceRules) across \($c.cncfRuleProjects) projects (\($c.cncfSourceRulesWithdrawn) withdrawn, not used) |\n"
  + "| Rules for further, non-CNCF projects | \($c.communityProjectSourceRules) across \($c.communityProjectRuleProjects) projects |\n"
  + "| Projects with at least one executable check | \($c.executableProjects) |\n"
  + "| Projects catalogued with retained public sources | \($c.selectedSourceProjects) (\($c.selectedSourceOnlyProjects) of them source-only, no check) |\n"
  + "\n"
  + "Version-coverage depth, measured over the last five minor upgrades of each of the \($f.projects) projects with a release-line snapshot (\($f.pairs) upgrades between consecutive release lines):\n"
  + "\n"
  + "| Status | Upgrades | Share |\n| --- | --- | --- |\n"
  + "| Decided for the whole release-line pair (A attested, B bounded) | \($f.a + $f.b) | \(pct($f.a + $f.b; $f.pairs)) |\n"
  + "| Rule for one exact version pair only (S) | \($f.s) | \(pct($f.s; $f.pairs)) |\n"
  + "| Gap, no valid rule (G) | \($f.g) | \(pct($f.g; $f.pairs)) |\n"
  + "\n"
  + "Kubernetes: \($k.validRules) valid rules, but \($k.rulesInWindow) fall in its window \($k.window[0]) to \($k.window[-1]); \($k.g) of \($k.a + $k.b + $k.s + $k.g) upgrades in that window are gaps.\n"
  + "\n"
  + "Decided means a valid rule or attestation covers every version of both release lines, so the answer is BLOCKED or UNKNOWN, never a whole-upgrade PASS. An exact-pair rule decides only the versions it names. The metric is defined in the [coverage report guide](cli/docs/coverage-report.md); it is not a statement that any upgrade is safe."
' "$tmp/report.json" > "$tmp/block.md"

begin='<!-- coverage:begin -->'
end='<!-- coverage:end -->'
readme="$root/README.md"
grep -qx "$begin" "$readme" && grep -qx "$end" "$readme" || { echo "markers missing in README.md" >&2; exit 2; }
awk -v b="$begin" -v e="$end" -v blk="$tmp/block.md" '
  $0 == b { print; while ((getline l < blk) > 0) print l; skip = 1; next }
  $0 == e { skip = 0 }
  !skip { print }
' "$readme" > "$tmp/README.new"
if [ "$check" = 1 ]; then
  cmp -s "$readme" "$tmp/README.new" || { echo "README.md coverage block is stale; run scripts/readme-coverage.sh" >&2; exit 1; }
else
  cat "$tmp/README.new" > "$readme"
fi
