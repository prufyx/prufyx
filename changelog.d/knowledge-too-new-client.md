### Changed

- `prufyx db update` and `prufyx db import` no longer record trust state for a validly signed knowledge package this build cannot read (unknown index format or a `minClientVersion` above the build). They exit `15` with reason `KNOWLEDGE_TOO_NEW_FOR_THIS_CLIENT`, keep the current store and the embedded knowledge usable, and a later readable package imports normally.
- The knowledge index accepts an optional `minClientVersion`, read before the rest of the index is parsed.
