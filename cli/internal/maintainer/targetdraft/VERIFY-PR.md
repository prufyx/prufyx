# verify-pr: regenerate check and upstream binding of a data PR (report only)

Status: implemented, locally verified, report only. It is not a required
check, it is not wired into any workflow, and it never merges anything. Exit 0
is never merge authority.

## What it checks

`prufyx-maintainer target-draft verify-pr --base DIR --head DIR --changed-paths FILE [--upstream-binding off|ls-remote --base-sha SHA --head-sha SHA] [--require-eligible] [--json]`

- `DIR` are exported trees of the PR base and head (files read as data; nothing
  from them is executed).
- `FILE` is the output of `git diff --raw -z --no-abbrev --no-renames BASE HEAD`.
  Only added or modified regular files with mode 100644 (an `M` must be
  100644 to 100644, an `A` must come from mode 000000) are accepted; deletes,
  renames, copies, mode and type changes, links and submodules fail.
- Build the tool from the base branch, never from the PR head, so a PR cannot
  change the check that judges it.

A data PR touches exactly one slug: the directory
`cli/knowledge/target-recipes/<slug>/` (`recipe.json`, optional `rules.json`,
`facts.bundle`, `report.json`, `table-row.json`, `changelog.md`) and exactly one
path outside it, the real target `cli/internal/extract/crdversions/target-<slug>.json`.
That path is built by the tool from the slug, never taken from the diff. The
real target must be byte-equal to the regenerated half named by the recipe.
The recipe directory holds no copy of the target (a copy is refused). Any other
changed path, any other file in `crdversions`, or a second slug fails. No file
in the recipe directory or the real target may be executable.

The check then:

1. parses `recipe.json` and `rules.json` strictly and refuses any exclusion;
2. checks `facts.bundle` against the recipe's `factBundleDigest`, verifies every
   object hash, the commit and tree chains, and the recipe's per-tag commits;
3. regenerates the target from the bundle (the generator of this build) with
   zero typed stops, twice, byte-identical;
4. compares the real target (half A or B named by the recipe), the report, the
   table row and the changelog byte for byte;
5. runs wrong-target seeds (path, min-from, attest) through the same
   comparison; each must be rejected;
6. only with `--upstream-binding ls-remote`, and only after all of the above
   passed: the upstream binding below.

## Upstream binding (B1)

One `git ls-remote --tags` of `https://github.com/<owner>/<name>.git` (the host
is a constant; the repository comes from the recipe and is validated first) for
exactly the recipe's window tags (`refs/tags/<tag>` and its peeled
`refs/tags/<tag>^{}`). No clone, no token, redirects off, https only. The git
process is started by the tool with a fixed argument vector (no shell) and a
cleared environment: a fixed `PATH`, `LC_ALL=C`, no prompts, no global or
system git configuration, no proxy or credential variables, `HOME` and the
working directory an empty temporary directory. 60 s timeout per attempt,
3 attempts with 5 s and 15 s waits on transient errors only.

For every window tag the peeled commit (the `^{}` line for an annotated tag,
else the tag line) must equal the recipe commit and the bundle commit. Typed
failures, all fail-closed:

| code | meaning | exit |
|---|---|---|
| `binding-input` | repo, tag or commit refused before any exec (exit 2 when the base or head id is missing or malformed) | 1 or 2 |
| `binding-mismatch` | a tag resolves to another commit (moved upstream) | 1 |
| `binding-missing` | a window tag is not upstream | 1 |
| `binding-malformed` | empty, truncated, oversize, duplicate, unexpected or badly formed answer | 1 |
| `binding-hashalgo` | 64-hex object ids | 1 |
| `binding-redirect` | the repository URL redirects (renamed or moved) | 1 |
| `binding-unavailable` | not readable without credentials, or missing: exit 1; network, rate limit, 5xx, timeout, TLS, git missing, unknown git failure: exit 2 (no verdict) | 1 or 2 |

There is no skip, no warning, no cached result and no fallback host. An empty
answer is never read as "no tags". The result is bound to the head commit id
passed with `--head-sha`; `--base-sha` and `--head-sha` are required with the
binding and echoed back.

Honest limits. The binding adds trust in: github.com serving the real refs
(TLS and git smart-HTTP) and SHA-1 collision resistance. It proves that a listed
tag exists at that commit; it does not prove that no newer tag exists. A
maintainer who force-moves a tag after merge is only caught by a later run of
the same check. The runner's network egress cannot be restricted to a host list
on hosted runners; the allowlist is enforced in code (URL built from a constant
host, `GIT_ALLOW_PROTOCOL=https`, redirects off, exact ref names).

## Exit codes

- 0: every assertion held (report only; never merge authority).
- 1: an assertion failed; the line `FAIL <code>: <detail>` names the typed reason.
- 2: usage or I/O error, no verdict (binding unreachable), or a seed that could
  not run.
- 3: only with `--require-eligible`: valid, but not in the eligible class (the
  binding was not verified, or the recipe is new or changed against base): a
  human decides.

Anything that cannot be verified is non-zero.

## How to read the result

- `upstream binding: not verified` is printed unless the binding ran and held.
  Without it the bundle is shown to be internally consistent and to regenerate
  the PR's files; it is NOT shown to come from the real upstream repository.
- `upstream binding: verified ...` names the repository, the tag count, how many
  tags were annotated or lightweight, the head id and a digest over the
  repository and the tag-to-commit list (`bindingDigest`).
- `recipe new|unchanged|changed against base`: a new or changed recipe is a
  human judgment (which repo, tags, rules).
- `eligible-class: yes` means: assertions held, binding verified for the head id,
  recipe unchanged against base. It is a label for a separate decision. The tool
  never merges and always prints `auto-merge: not eligible`; `AutoMerge` is
  never true in any output.
- `--json` prints one more line, `result-json: {...}` (compact JSON,
  `prufyx.io/verify-pr-result/v1`: base and head ids, outcome, failure code,
  slug, half, recipe change, binding result and digest, `eligible`,
  `autoMerge: false`), also on failure. The tool writes no files. Consumers must
  compare `headSha` with the head they mean and must not read exit 0 as
  eligibility.
- Consumers read the exit code plus the one `result-json:` line; the failure
  detail is printed quoted, so caller-controlled text (file names) cannot start
  a line of its own. Ignore any other line that merely looks like a result.
- `--base-sha` and `--head-sha` are asserted by the caller; the tool cannot check
  them. The workflow must export the head tree from exactly that sha and match
  it to the PR head it is judging.
- Not proved: that the upstream facts are right, that the chosen source is the
  right one for the project, or any reproduced test.

## Input binding and canonical forms

- `recipe.json` and `rules.json` must be byte-identical to their own canonical
  re-marshal (one-space indent, final newline). Duplicate or differently cased
  keys, which a lenient decoder would resolve silently, are refused.
- The tool compares the base and head exports itself: they must be identical
  outside the recipe directory and the one real target, every base file of the
  recipe directory must survive, and `--changed-paths` must name exactly the
  files that differ (a mode difference counts). It still cannot know that the
  exports and the list come from the two commits the caller means; see the
  requirements below.
- The replay expands trees under a total entry budget and a total path-byte
  budget; a bundle that fans out past either is refused.

## Requirements for the workflow that will run this (not in this change)

- Compute the diff, both exports and the tool input from the same two commit
  ids in one step; pass both ids to the tool; re-resolve the head id and compare
  before any merge.
- Build the tool from the base ref, never from the head, and do not use the
  head's workflow or script copies.
- Exit 0 means only "assertions held". It is never merge or auto-merge
  eligibility: use `--require-eligible` (exit 3 is a valid human-class result).
- The whole `targetdraft` directory, the command wiring file
  (`cli/cmd/prufyx-maintainer/main.go`) and `cli/knowledge/target-recipes/` are
  owner-only in CODEOWNERS, pinned by a test; the path allowlist only
  protects data changes, not a change to the verifier itself.
- Nothing may read the recipe directory as knowledge. A repository test checks
  that every recipe has a matching real target that is byte-equal to its
  regeneration (hand-made targets without a recipe stay valid and outside this
  class).
