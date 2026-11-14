### Changed

- The Kueue CRD extractor target now lists six reviewed exclusions for files of its end-to-end test overlays (the cert-manager overlay and the MultiKueue Kubeflow overlay under `test/e2e/config`), each with per-tag evidence from the 57 release tags 0.15.0 to 0.20.4. In a dry run of the scanner these files no longer block a clean scan; the Helm chart template files still do, so no Kueue pair is attestable yet and line attestation stays off. The change touches no extractor code and no table row.
