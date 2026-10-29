#!/usr/bin/env sh
# Moves the fragments in changelog.d/*.md into CHANGELOG.md.
#
# Each fragment starts with a "### <Section>" line followed by bullets. The
# fragments are grouped by section and inserted right after the
# <!-- release-notes:end --> line of the first (Unreleased) block; the fragment
# files are then deleted. README.md in changelog.d is not a fragment.
#
# usage: scripts/changelog-assemble.sh [--check]
#   --check  validate the fragments only; change nothing
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
dir="$root/changelog.d"
log="$root/CHANGELOG.md"
sections="Added|Changed|Fixed|Security|Documentation|Added (workflows)"
re=$(printf '%s' "$sections" | sed 's/[()]/\\&/g')
check=0
[ $# -le 1 ] || { echo "usage: $0 [--check]" >&2; exit 2; }
case "${1:-}" in
  --check) check=1 ;;
  '') ;;
  *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac
[ -d "$dir" ] || { echo "changelog.d: directory missing" >&2; exit 1; }
nl='
'

set -f
fail=0
files=$(find "$dir" -maxdepth 1 -type f -name '*.md' ! -name README.md | LC_ALL=C sort)
IFS=$nl
for f in $files; do
  base=$(basename "$f" .md)
  case $base in
    *[!a-z0-9-]*|-*|'') echo "changelog.d: bad slug in $f" >&2; fail=1; continue ;;
  esac
  head=$(sed -n '1p' "$f")
  if ! printf '%s\n' "$head" | grep -Eq "^### ($re)$"; then
    echo "changelog.d: $f must start with '### <Section>' ($sections)" >&2; fail=1; continue
  fi
  if ! sed '1d' "$f" | grep -q '^- '; then
    echo "changelog.d: $f has no '- ' bullet" >&2; fail=1
  fi
done
IFS=' 	
'
[ "$fail" -eq 0 ] || exit 1
[ "$check" -eq 1 ] && exit 0
[ -n "$files" ] || { echo "changelog.d: no fragments"; exit 0; }
[ "$(grep -c '^<!-- release-notes:end -->$' "$log")" -ge 1 ] || { echo "CHANGELOG.md: no release-notes:end marker" >&2; exit 1; }

body=$(mktemp)
out=$(mktemp "$log.XXXXXX")
trap 'rm -f "$body" "$out"' EXIT
consumed=0
total=0
IFS=$nl
for f in $files; do total=$((total + 1)); done
IFS=' 	
'
old_ifs=$IFS
IFS='|'
for s in $sections; do
  IFS=$old_ifs
  first=1
  IFS=$nl
  for f in $files; do
    [ "$(sed -n '1p' "$f")" = "### $s" ] || continue
    consumed=$((consumed + 1))
    if [ "$first" -eq 1 ]; then printf '\n### %s\n\n' "$s" >>"$body"; first=0; fi
    awk 'NR > 1' "$f" | sed -e '/./,$!d' >>"$body"
  done
  IFS=$old_ifs
  IFS='|'
done
IFS=$old_ifs

[ "$consumed" -eq "$total" ] || { echo "changelog.d: $((total - consumed)) fragment(s) not assembled; nothing changed" >&2; exit 1; }
awk -v body="$body" '
  !done && $0 == "<!-- release-notes:end -->" {
    print
    while ((getline line < body) > 0) print line
    done = 1; next
  }
  { print }' "$log" >"$out"
mv -f "$out" "$log"
IFS=$nl
for f in $files; do rm -f "$f"; done
