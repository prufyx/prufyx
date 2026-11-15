# verify-pr: regenerate check of a data PR (report only)

Status: implemented, locally verified, report only. It is not a required
check, it is not wired into any workflow, and it never makes a PR eligible for
auto-merge.

## What it checks

`prufyx-maintainer target-draft verify-pr --base DIR --head DIR --changed-paths FILE`

- `DIR` are exported trees of the PR base and head (files read as data; nothing
  from them is executed).
- `FILE` is the output of `git diff --raw -z --no-abbrev --no-renames BASE HEAD`.
  Only added or modified regular files (mode 100644) are accepted; deletes,
  renames, copies, mode and type changes, links and submodules fail.
- Build the tool from the base branch, never from the PR head, so a PR cannot
  change the check that judges it.

A data PR touches exactly one directory, `cli/knowledge/target-recipes/<slug>/`,
holding `recipe.json`, optional `rules.json`, `facts.bundle`, `target-<slug>.json`,
`report.json`, `table-row.json` and `changelog.md`. Any other changed path, or a
second slug, fails.

The check then:

1. parses `recipe.json` and `rules.json` strictly and refuses any exclusion;
2. checks `facts.bundle` against the recipe's `factBundleDigest`, verifies every
   object hash, the commit and tree chains, and the recipe's per-tag commits;
3. regenerates the target from the bundle (the generator of this build) with
   zero typed stops, twice, byte-identical;
4. compares the target (half A or B named by the recipe), the report, the table
   row and the changelog byte for byte;
5. runs wrong-target seeds (path, min-from, attest) through the same
   comparison; each must be rejected.

## Exit codes

- 0: every assertion held (report only).
- 1: an assertion failed; the line `FAIL <code>: <detail>` names the typed reason.
- 2: usage or I/O error, or a seed that could not run.

Anything that cannot be verified is non-zero.

## How to read the result

- `upstream binding: not verified` is printed on every run. The bundle is shown
  to be internally consistent and to regenerate the PR's files. It is NOT shown
  to come from the real upstream repository at the claimed tags: anyone can
  build a consistent bundle of any content. Do not read a pass as authenticity.
- `recipe new|unchanged|changed against base`: a new or changed recipe is a
  human judgment (which repo, tags, rules). It is listed as a reason against
  eligibility.
- `auto-merge: not eligible` is printed always in this version.
- Not proved: that the upstream facts are right, that the chosen source is the
  right one for the project, or any reproduced test.

## Input binding and canonical forms

- `recipe.json` and `rules.json` must be byte-identical to their own canonical
  re-marshal (one-space indent, final newline). Duplicate or differently cased
  keys, which a lenient decoder would resolve silently, are refused.
- The tool compares the base and head exports itself: they must be identical
  outside the recipe directory, every base file of the recipe directory must
  survive, and `--changed-paths` must name exactly the recipe files that
  differ. It still cannot know that the exports and the list come from the
  two commits the caller means; see the requirements below.
- The replay expands trees under a total entry budget; a bundle that fans out
  past it is refused.

## Requirements for the workflow that will run this (not in this change)

- Compute the diff, both exports and the tool input from the same two commit
  ids in one step; re-resolve the head id and compare before any merge.
- Build the tool from the base ref, never from the head, and do not use the
  head's workflow or script copies.
- Exit 0 means only "assertions held". It is never merge or auto-merge
  eligibility: that needs the upstream binding and the recipe-identity rule.
- The verifier and the recipe directory must be owner-only in CODEOWNERS
  (`verify.go`, `factsource.go`, `cli/knowledge/target-recipes/`) before the
  check gates anything; the path allowlist only protects data changes, not a
  change to the verifier itself.
- The target copy in the recipe directory is a second source of truth beside
  the target the product reads. A later change must add exactly the real
  target path to the allowlist, assert it is byte-equal to the verified half,
  drop the in-recipe copy or require both equal, and add a repository test
  that every recipe has a matching real target and the reverse. Nothing may
  read the recipe directory as knowledge.
