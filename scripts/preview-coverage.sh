#!/usr/bin/env sh
# Regenerates the rule-count sentences of cli/docs/CNCF-SOURCE-PREVIEW.md between
# the marker pairs
#   <!-- preview-counts-intro:begin -->  ...  <!-- preview-counts-intro:end -->
#   <!-- preview-counts-pack:begin -->   ...  <!-- preview-counts-pack:end -->
# from the generated support inventory (the same counts scripts/readme-coverage.sh
# uses for README.md). Nothing between the markers is typed by hand.
#
# usage: scripts/preview-coverage.sh [--check]
#   --check  do not write; exit 1 if the document differs from the generated text
# Requires jq.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
inv="$root/cli/docs/generated/community-support-inventory.json"
doc="$root/cli/docs/CNCF-SOURCE-PREVIEW.md"
check=0
while [ $# -gt 0 ]; do
  case "$1" in
    --check) check=1 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
jq -r '.counts | "The current embedded preview has \(.cncfSourceRules) active exact rules across \(.cncfRuleProjects) rule projects (\(.cncfSourceRulesWithdrawn) withdrawn, not used)."' "$inv" > "$tmp/intro.md"
jq -r '.counts | "The embedded CNCF rule pack has \(.cncfSourceRules) active constraints across \(.cncfRuleProjects) rule projects; the separate\ncommunity-project pack has \(.communityProjectSourceRules) constraints across \(.communityProjectRuleProjects) projects."' "$inv" > "$tmp/pack.md"

cp "$doc" "$tmp/doc.0"
for name in intro pack; do
  begin="<!-- preview-counts-$name:begin -->"
  end="<!-- preview-counts-$name:end -->"
  grep -qx "$begin" "$tmp/doc.0" && grep -qx "$end" "$tmp/doc.0" || { echo "markers preview-counts-$name missing in $doc" >&2; exit 2; }
  awk -v b="$begin" -v e="$end" -v blk="$tmp/$name.md" '
    $0 == b { print; while ((getline l < blk) > 0) print l; skip = 1; next }
    $0 == e { skip = 0 }
    !skip { print }
  ' "$tmp/doc.0" > "$tmp/doc.1"
  mv "$tmp/doc.1" "$tmp/doc.0"
done
if [ "$check" = 1 ]; then
  cmp -s "$doc" "$tmp/doc.0" || { echo "CNCF-SOURCE-PREVIEW.md counts are stale; run scripts/preview-coverage.sh" >&2; exit 1; }
else
  cat "$tmp/doc.0" > "$doc"
fi
