### Changed
- Raise the per-file input limit of `scan` and `plan` from 2 MiB to 8 MiB so a whole rendered chart with its CRDs can be scanned as one file. The node, document, file-count and 32 MiB total limits are unchanged. The refusal message now names the limit and says to split the input into several files in a directory.
