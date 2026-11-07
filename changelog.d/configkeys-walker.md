### Added

- Add the configuration key walker for Go sources: from a reviewed root type it lists the key paths of a yaml, json or mapstructure document, withholds the set when a type cannot be proven (custom unmarshaller, free-form map, ambiguous name, key collision, unresolvable type), and encodes keys through the shared member encoder.
