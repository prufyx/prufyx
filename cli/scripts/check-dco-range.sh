#!/usr/bin/env sh
# Validate DCO trailers in a caller-selected, non-empty forward commit range.
set -eu

range=${1-}
case "$range" in
  ''|*...*|*..*..*|*..)
    printf '%s\n' 'usage: check-dco-range.sh <base>..<head>' >&2
    exit 2
    ;;
esac

case "$range" in
  *..*) ;;
  *)
    printf '%s\n' 'usage: check-dco-range.sh <base>..<head>' >&2
    exit 2
    ;;
esac

base=${range%%..*}
head=${range#*..}
repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || {
  printf '%s\n' 'DCO range check must run inside a Git work tree' >&2
  exit 2
}
cd "$repo_root"

git rev-parse --verify --quiet "$base^{commit}" >/dev/null || {
  printf 'invalid base revision: %s\n' "$base" >&2
  exit 2
}
git rev-parse --verify --quiet "$head^{commit}" >/dev/null || {
  printf 'invalid head revision: %s\n' "$head" >&2
  exit 2
}
git merge-base --is-ancestor "$base" "$head" || {
  printf '%s\n' 'revision range must be forward: base must be an ancestor of head' >&2
  exit 2
}

count=$(git rev-list --count "$range")
test "$count" -gt 0 || {
  printf '%s\n' 'revision range selects no commits' >&2
  exit 2
}

status=0
for commit in $(git rev-list --reverse "$range"); do
  if ! git log -1 --format=%B "$commit" | git interpret-trailers --parse | \
    awk '/^Signed-off-by: .+ <[^<>]+>$/ { found = 1 } END { exit !found }'; then
    printf '%s is missing a Signed-off-by trailer\n' "$commit" >&2
    status=1
  fi
done
exit "$status"
