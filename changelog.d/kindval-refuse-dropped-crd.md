### Fixed

- The KIND-VAL CRD check no longer drops documents silently: an incomplete or repeated definition, an unlisted object, or a cited file without a definition now refuses the release instead of letting a missing definition read as a removed API version. Objects that are left out are counted per file in the run record (`skipped`).
