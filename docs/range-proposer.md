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
including a new major, get `UPGRADE_FROM_SERIES` and `TARGET_SERIES`.

A candidate that would overlap another rule or candidate on the same constraint
key is refused. The effect of a range on decisions is not computed.

A candidate range also covers patch releases that do not exist yet and tags the
clone does not hold.

## Refusals

A rule is refused, never treated as unchanged, when among others:

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
