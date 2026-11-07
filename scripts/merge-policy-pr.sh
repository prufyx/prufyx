#!/usr/bin/env bash
# Merge policy for a pull request run, from a full-history checkout of the
# pull request head. Fails closed (exit 1). The branch may be behind main (the
# merge queue re-validates the combined commit); it may not contain merge
# commits and must share history with main.
set -euo pipefail

fix="rebase onto origin/main (git rebase origin/main && git push --force-with-lease); never merge main into a branch"
git fetch --no-tags origin main:refs/remotes/origin/main
base="$(git merge-base origin/main HEAD)" || {
  echo "::error title=Merge policy::the branch shares no history with main"
  exit 1
}
merges="$(git rev-list --merges "${base}..HEAD")"
if [ -n "${merges}" ]; then
  echo "::error title=Merge policy::the pull request contains merge commits: ${fix}"
  printf '%s\n' "${merges}"
  exit 1
fi
if ! git merge-base --is-ancestor "${base}" refs/remotes/origin/main; then
  echo "::error title=Merge policy::merge base ${base} is not on main"
  exit 1
fi
echo "linear branch from main commit ${base}"
