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
check=0
[ "${1:-}" = "--check" ] && check=1

fail=0
files=$(find "$dir" -maxdepth 1 -type f -name '*.md' ! -name README.md | LC_ALL=C sort)
for f in $files; do
  base=$(basename "$f" .md)
  case $base in
    *[!a-z0-9-]*|-*|'') echo "changelog.d: bad slug in $f" >&2; fail=1; continue ;;
  esac
  head=$(sed -n '1p' "$f")
  if ! printf '%s\n' "$head" | grep -Eq "^### ($sections)$"; then
    echo "changelog.d: $f must start with '### <Section>' ($sections)" >&2; fail=1; continue
  fi
  if ! sed '1d' "$f" | grep -q '^- '; then
    echo "changelog.d: $f has no '- ' bullet" >&2; fail=1
  fi
done
[ "$fail" -eq 0 ] || exit 1
[ "$check" -eq 1 ] && exit 0
[ -n "$files" ] || { echo "changelog.d: no fragments"; exit 0; }
[ "$(grep -c '^<!-- release-notes:end -->$' "$log")" -ge 1 ] || { echo "CHANGELOG.md: no release-notes:end marker" >&2; exit 1; }

body=$(mktemp)
trap 'rm -f "$body"' EXIT
old_ifs=$IFS
IFS='|'
for s in $sections; do
  IFS=$old_ifs
  first=1
  for f in $files; do
    [ "$(sed -n '1p' "$f")" = "### $s" ] || continue
    if [ "$first" -eq 1 ]; then printf '\n### %s\n\n' "$s" >>"$body"; first=0; fi
    sed '1d' "$f" | sed -e '/./,$!d' >>"$body"
  done
  IFS='|'
done
IFS=$old_ifs

out=$(mktemp)
awk -v body="$body" '
  !done && $0 == "<!-- release-notes:end -->" {
    print
    while ((getline line < body) > 0) print line
    done = 1; next
  }
  { print }' "$log" >"$out"
cat "$out" >"$log"
rm -f "$out"
for f in $files; do rm -f "$f"; done
