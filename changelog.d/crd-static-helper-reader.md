### Changed
- Read bounded, inert Helm helper definitions during CRD source scans when the complete pinned chart proves they emit only whitespace or fail. Unresolved output, dependencies and template effects remain unsupported.
