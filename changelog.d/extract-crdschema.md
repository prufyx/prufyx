### Added

- Extractor library for removed CRD fields and enum values (`extract/crdschema`) and the shared set-member encoder it uses (`extract/membercode`). It compares the CRD files of two pinned commits and reports only removals it can prove; version-specific changes, possible renames, preserved-unknown subtrees, conversion webhooks, unprovable YAML and members that cannot be encoded exactly leave the result incomplete. Not wired into any pack, registry or rule yet, so no scan result changes.
