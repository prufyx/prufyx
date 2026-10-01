# Community rule candidates

Put one candidate file per pull request here, named `<project>-<short-description>.json`
(for example `argo-workflows-basehref-flag.json`).

Each file is a JSON array of one or more entries in the pack entry schema
(`project`, `description`, `requiredFacts`, `rule`). See
[`cli/docs/contributing-rules.md`](../docs/contributing-rules.md) for the full
walkthrough, including how to run the validator before opening the PR:

```
go run ./cmd/prufyx-maintainer rule validate --file contrib/rules/<your-file>.json
```

CI runs the same validator over every `*.json` file in this directory on
every pull request. A maintainer reviews and, if accepted, folds the rule
into the published pack; nothing in this directory is published
automatically.
