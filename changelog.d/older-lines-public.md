### Added

- Floor derivation for CRD version targets: a pure function (`derivefloor.DeriveFloor`) returns `minFrom` (the lowest contiguous run of attested pairs up to the newest pair) and `derivedFrom` (the pairs below it that carry an attestation or a recorded stop) from per-pair outcomes. The QA oracle checks a claimed floor with the same function and refuses any difference, a pair in `[derivedFrom, minFrom)` with neither attestation nor stop included.
- `derivedFrom` as an optional target field (at most `minFrom`, defaults to it, never evidence). The knowledge gate refuses any lowering of `minFrom` or `derivedFrom` unless an owner approval for exactly that floor is in the change, for every author.
- The `hop-stop` record: the closed-code outcome of a hop derived without an attestation. Unknown codes, free text and the transient codes `release-pending` and `derive-failed` are refused.
- `hopstatus.Resolve`: per-hop status for a jump (BLOCKED with citation, PASS only from an attestation, L, G with the stop code, G `not-derived`); documented in `cli/docs/hopstatus.md`.
- Coverage report: an optional `olderHops` member counted apart from the cohort and never summed into it; the default report is byte-identical.
