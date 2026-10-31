### Changed

- The `crd.version-removal` extractor now attests release lines for `contour`. A reviewed exclusion covers `examples/optional-features/kustomization.yaml`, a user-run example that only deletes definitions from the rendered gateway manifest. The line 1.33 stays undecided: its rendered gateway manifests carry Contour's own definitions beside the experimental Gateway API ones.
