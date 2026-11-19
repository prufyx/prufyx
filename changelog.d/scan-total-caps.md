### Changed

- Raise the total input limits of `scan` and `plan` so a large rendered apply set (100 or more charts) and a cluster export of about 30000 objects can be scanned in one run: 256 MiB in all (was 32 MiB), 65536 documents (was 8192), 16384 files (was 2048) and 6000000 YAML nodes (was 500000). The limits are still fixed, memory stays under 2 GiB at the node limit, and a refusal names the limit and says to split the input into several runs.
