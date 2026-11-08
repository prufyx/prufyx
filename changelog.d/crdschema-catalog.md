### Added

- Internal: the CRD schema extractor for Argo CD is now listed by the maintainer extract command. It reads only the tags of the target's own prefixes, starts at the target's first reviewed line, and records the items it withheld next to each pair. It attests nothing and publishes no rule or fact.
- Internal: the CRD schema ledger item charset no longer accepts "=", matching the shared extract framework ledger. No crd.schema ledger item is built with "="; an item that contains it (for example a file path) is recorded as a ledger fault instead of aborting the run.
