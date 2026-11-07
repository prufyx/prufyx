### Added

- Add an inert extractor for deprecation markers in the Envoy API protos: a text-only parser lists deprecated fields, messages, enums and enum values (with the deprecated-at-minor-version and disallowed-by-default annotations) as draft candidates, and states a field removal mechanically only when a later version reserves both its number and its name. Nothing in the registry, the knowledge data or the factory uses it yet.
