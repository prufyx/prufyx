# Range proposer

`prufyx-maintainer range-propose` lists candidate version ranges for rules that
still cover one exact version pair. It is a reading aid for a reviewer.

Every output is **span-stable only; behaviour, absence of reintroduction and
decision impact not checked**. A candidate is not evidence, not a rule and not
a statement that an upgrade is safe. The command writes no rule pack, signs and
publishes nothing, opens no pull request and uses no network.

## Run

```sh
prufyx-maintainer range-propose \
  --rules-repo /path/to/prufyx --rules-commit <40 hex> \
  --repos /path/to/projects.json \
  --out /path/outside/any/git/work/tree [--gaps /path/to/rule-ids.txt]
```

Build the command with `go build` in a clean checkout. The run is refused when
the binary does not record an unmodified commit, which includes `go run`, a
modified tree and a build with `-buildvcs=false`. The output records that commit
and the evaluation time, which is the clock's.

The rule pack is read from `cli/internal/cncfcheck/data/rules.json` at the
named commit. Candidates are active rules without a `range`. `--gaps` lists rule
ids, one per line, that come first in the output; the others follow by id.

`projects.json` names, per rule project, the subject repository, a local bare
clone and the tag prefix. The subject repository is never guessed from a rule's
sources.

```json
{
  "projects": {
    "example": {
      "repo": "example-org/example",
      "path": "/path/to/example.git",
      "tagPrefix": "v",
      "tags": [{"tag": "v1.4.0", "commit": "<40 hex>"}]
    }
  }
}
```

`tags` is optional. When present it must equal the final release tags the clone
holds for each line that is read.

The command exits 0 when the run completes, whatever the rules showed, and 2 on
a bad invocation or input.

## What is compared

For the line of the rule's `from` version and the line of its `to` version:

- A source counts when it is in the subject repository, is not a changelog or
  release note file, and its revision is the commit of a release tag of one of
  the two lines.
- The cited file at the cited revision must match `contentDigest`, and the
  cited lines must exist.
- At every release tag of the line, the cited lines must occur exactly once as
  whole lines, byte for byte, in a file identical to the cited one. A moved
  span, a change elsewhere in the file, a second occurrence, a missing path, a
  symbolic link, a binary file or a file over 8 MiB is not stable. Line endings
  and a missing final newline count.

Release notes are recognised only by a text file name or directory such as
`CHANGELOG*`, `CHANGES`, `NEWS`, `HISTORY` or `release-notes/`. Every other
file counts as code. A source that is not a release note and cannot be checked
(another repository, an untagged revision, a revision outside both lines) sends
the whole rule to review. The tool does not look for new sources.

A range is proposed only for `forbid_predicate_value` and `forbid_set_member`
rules without `appliesWhen`, under a time lease, whose constrained fact belongs
to the subject component. A pinned or unknown lease and a cross-component rule
need review.

## Results

The output directory must be new or empty and outside every git work tree. It
receives:

- `proposals.json`: rules with at least one counted, stable source on **both**
  sides. Each entry has the status `unreviewed-proposal`, a `candidateRange`,
  the observations per tag, the digest of the pack entry and of each tag list,
  and, when the cited revision is not the highest tag of its line, where the
  span was found at that tag.
- `needs-review.json`: rules with typed reasons and observations but no range,
  and refused rules with a typed code.
- `summary.txt`: the same in short form.

The `candidateRange` is refused by the rule engine as written: it carries a
`reviewStatus` field. For adjacent minor lines of one major, `from.lt` and
`to.gte` also carry the placeholder basis `REVIEWER_MUST_DECIDE` and no source,
because the tool does not observe in which release the behaviour changed. It
never sets `REMOVED_IN_RELEASE` or `CHANGED_IN_RELEASE`. Other line pairs,
including a new major, keep the `from` side at exactly the rule's `from` version
(`ANCHOR_ONLY`) and get `TARGET_SERIES` for the `to` side.

**Upstream minimum source version not checked.** The tool reads no upgrade
guide, so `from.gte` is always the rule's own `from` version, with basis
`ANCHOR_ONLY`, never an earlier patch. Every candidate carries the flag
`upstream-minimum-source-version-not-checked`. Before a candidate becomes a rule
pack change, a reviewer records the upgrade guide's minimum source version for
the target line and checks the other rules of the same component and version
pair for such a floor. Lowering `from.gte` needs a reviewed source that states
it.

A candidate that would overlap another rule or candidate on the same constraint
key is refused. The effect of a range on decisions is not computed.

A candidate range also covers patch releases that do not exist yet and tags the
clone does not hold.

## Refusals

A rule is refused, never treated as unchanged, when among others:

- its evidence has expired, is dated after the evaluation time or does not give
  a UTC window, whatever its lease;
- it cites no source, a source URL is not a pinned `github.com` or
  `raw.githubusercontent.com` file at the source revision, or a cited reference
  does not verify;
- the clone is missing, not bare, shallow, grafted, partial or borrows objects
  from another directory, or an object is missing;
- a tag names one of the two lines but is neither `PREFIX X.Y.Z` nor an
  `-alpha`, `-beta` or `-rc` pre-release (this includes tags of sub-modules);
- a line has no tag, lacks `X.Y.0`, the anchor release or a patch number, or
  differs from the expected list;
- one commit carries release tags of two lines.

The tool cannot see a release that the clone does not have. Fetch all tags
before a run, or pass the expected list.
