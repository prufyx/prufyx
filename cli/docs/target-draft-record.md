# Target draft record

`prufyx-maintainer target-draft record` records a replayable local half-A
target-draft run from a local Git checkout. It does not fetch, write output
files, publish data, approve a target, or establish upstream authority.

The caller supplies the exact expected half-A target and table row. Recording
continues only when the local replay reproduces both byte-for-byte.

```sh
prufyx-maintainer target-draft record \
  --dir /path/to/checkout \
  --slug example --name Example --repo github.com/example/example \
  --tags v1.0.0,v1.1.0 \
  --expected-target /private/input/target.json \
  --expected-row /private/input/table-row.json
```

`--dir`, `--slug`, `--name`, `--repo`, `--tags`, `--expected-target`, and
`--expected-row` are required. The optional recipe-v1 inputs are `--catalog`,
`--component`, `--fact-project`, `--rules`, `--strict-window`,
`--range-check-tags`, and `--collapse-directories`. An omitted catalog is
`cncf`. Expected target and row inputs are bounded regular files opened without
following links; symbolic links, directories, devices, FIFOs, files replaced
between inspection and opening, and oversized input files are refused.

On success stdout receives one canonical JSON envelope with schema
`prufyx.io/target-draft-record/v1`. Its `recipe`, `rules`, `factsBundle`,
`target`, `report`, `tableRow`, and `changelog` fields contain standard padded
base64 data. `rules` is an empty string only when no rules document applies.
The complete envelope is bounded. Diagnostics are written separately; a failed
run does not emit an envelope.

This recorder has no half-B selection. It rejects exclusions and recipe-v1
unsupported generator options, including duplicate derivation, multiple
prefixes, install-path inference or copy checks, and skipped patch fragments.
Unknown flags and positional arguments are refused. A recorded local replay is
not a publication, signature, admission, merge, or acceptance decision.
