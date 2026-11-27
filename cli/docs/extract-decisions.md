# Comparing extraction decisions

`prufyx-maintainer extract run --output-format v2` produces `decision-output.json` and `execution-receipt.json`. The default format remains `v1`. Chart extractors currently reject the v2 format.

The decision document preserves the complete run inventory and exact file bytes, replacing only these execution origins with JSON `null`:

- Extractor `version` and `codeDigest` in each candidate's `rule.evidence`, each attestation's `evidence`, each draft, and the manifest.
- The standard framework manifest's `codeFiles` array, after validating each record has exactly `path` and `sha256`, safe unique ordered relative paths and valid digests. Chart producer inputs are rejected.
- Each digest value in the manifest's `outputs` map. Output names remain in the decision document.

All other content remains, including extractor IDs, derivation/review/expiry times, source evidence, conditions, proof, withholding reasons, vectors, read inventories and unknown fields. Whitespace, object member order and array order outside origin slots remain significant. File modes must be `0644`; raw input is limited to 10,000 files and 64 MiB in total. Encoded decision/receipt pairs are limited to 128 MiB in total, enforced by both writer and reader. Symbolic links, duplicate JSON keys, unsupported schemas, unsafe paths, noncanonical extractor identities and incomplete file/hash inventories are rejected.

Each receipt retains the full original bytes, their hashes, and disjoint origin slots. Verification reconstructs every original from decision bytes plus those slots, checks the originals, then independently projects them again. It does not claim that full outputs with different build stamps are identical.

To bridge output from an unchanged older binary:

```sh
prufyx-maintainer extract decisions --from legacy-run --out decision-run
prufyx-maintainer extract decisions --verify decision-run
prufyx-maintainer extract decisions --compare decision-run --with another-decision-run
```

Each `extract decisions` invocation writes one JSON result to stdout, with schema `prufyx.io/extract-decision-check/v1`. Successful bridge/verification returns `VALID` and exit 0. Comparison returns `EQUAL` with exit 0 or `DIFFERENT` with exit 1. Invalid inputs return `INVALID` with exit 2 and diagnostics on stderr. Valid results bind `left.decisionSHA256` and `left.receiptSHA256`; comparisons also bind `right` with the same fields. Invalid results have neither digest object. A stdout write error also exits 2. Consumers must require the expected schema, result, exit code and pinned hashes together.

The v2 directory is deliberately unsupported by existing v1 `extract verify` and `extract apply`: it has no legacy `manifest.json`. Reconstruction is a proof, not an authorization to apply the recovered data. Equality in this format does not establish eligibility, current evidence qualification, source/build closure, signatures or admission. Callers must supply identical legitimate inputs and evaluation time and retain their existing checks. Versioned pack/report/client integration is separate work.
