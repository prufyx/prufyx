### Changed

- A zero-padded twin of a release (v25.08.0 beside v25.8.0) at the same commit is now one release, kept under the canonical spelling, in both the crdversions extractor and the release completeness check of the knowledge gate (one shared rule, crdversions.FinalSet), instead of withholding the line. Twins at different commits, and a padded-only release beside any canonical-spelled release of the line, are still refused. Every crdversions code digest moves with this change, so the extractor digest re-derive of the knowledge data is a separate step.
