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
