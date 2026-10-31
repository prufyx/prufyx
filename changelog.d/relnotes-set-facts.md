### Added

- Fact registry: caller-supplied set facts for command-line flags (`component.<project>.cli_flags_set` for falco, thanos and cortex) and configuration keys (`component.falco.config_keys_set`). They are inert until a reviewed release-note rule reads them; no rule is added by this change.
