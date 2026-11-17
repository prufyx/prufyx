### Changed
- Target-draft: patch-fragment handling and escalation after any typed stop are now always on; the install-path inference rerun stays internal.

### Removed
- Target-draft flags `--skip-patch-fragments`, `--derive-duplicate-sources`, `--multi-prefix`, `--infer-install-paths` and `--check-install-path-copies` (the first is now the default, the others had no measured gain). The duplicate derivation is deleted; those trees keep the plain `duplicate-crd` stop.
