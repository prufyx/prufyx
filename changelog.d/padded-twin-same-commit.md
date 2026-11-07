### Changed

- The crdversions extractor reads a zero-padded twin of a release (v25.08.0 beside v25.8.0) at the same commit as one release, kept under the canonical spelling, instead of withholding the whole line. Twins at different commits, and a line mixing a padded-only release with a canonical-only one, are still withheld. Every crdversions code digest moves with this change, so the extractor digest re-derive of the knowledge data is a separate step.
