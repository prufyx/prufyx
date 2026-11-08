### Added

- Knowledge gate rules for provider lifecycle rows of a distribution record: a row is admitted only when the extractor compiled into the gate re-derives it byte for byte from committed excerpts that are already on the base, with the same freshness window as other mechanical records, and only while the oldest supported client can read provider facts. The first introduction of the section needs an owner approval; applicability statements stay refused. No extractor is compiled in yet, so the gate admits no provider row. No data, no new command option and no new data collection.
