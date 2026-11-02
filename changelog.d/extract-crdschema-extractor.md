### Added

- `extract/crdschema` now implements the extractor interface for one project: a pair is decided for the whole release line (the result of the first releases is used only when every other release of both lines has the same fields and enum values), the pair proof is the result itself with its ledger at the top level, and a pair with any withheld item is recorded as not attested. It emits no rule and is not registered in any pack, so no scan result changes.
