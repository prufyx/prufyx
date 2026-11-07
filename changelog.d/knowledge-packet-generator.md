### Added

- `prufyx-maintainer knowledge-packet` assembles a daily signing packet from a local git repository and a pull request input file: the merged pull requests since the last published source commit, each classified as data, non-data or trust-path, with its exact-head gate line and data-review verdict (anything not in the strict form is listed as unverified), the rule, attestation and project deltas and the README number deltas, as a markdown summary and a JSON artifact with content and packet digests. It signs nothing, uses no network, and is not yet wired into any workflow.
