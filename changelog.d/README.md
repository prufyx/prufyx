# Changelog fragments

Each pull request that changes user-visible behaviour adds one file
`changelog.d/<short-slug>.md` instead of editing `CHANGELOG.md`. This keeps
parallel pull requests from conflicting on the changelog.

Format:

```markdown
### Added

- What a user can now do, in one or two sentences.
```

The first line is `### ` plus one of `Added`, `Changed`, `Fixed`, `Security`,
`Documentation`, or `Added (workflows)`. The rest is one or more bullets
written as in `CHANGELOG.md`. The slug is lowercase letters, digits and `-`.

At release cut, `scripts/changelog-assemble.sh` moves the fragments into
`CHANGELOG.md` under `## [Unreleased]` (after the generated block, grouped by
section) and deletes them. `scripts/changelog-assemble.sh --check` validates
the fragments without changing anything.
