### Added

- Fact registry: caller-supplied set facts for command-line flags and configuration keys of falco, thanos, cortex and cilium (`component.<project>.cli_flags_set`, `component.<project>.config_keys_set`). They are inert until a reviewed release-note rule reads them; no rule is added by this change.
