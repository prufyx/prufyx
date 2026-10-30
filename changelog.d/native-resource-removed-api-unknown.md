### Fixed

- `prufyx check cncf --project kubernetes --native-resource` no longer reports a scoped PASS for a resource at an API version the target release does not serve (a removed version such as `extensions/v1beta1` Ingress, an alpha version, or a version missing from the reviewed served-API list). It now exits 11 (UNKNOWN) with the reason, as `prufyx scan` does; `--format json` adds an `apiVersionGaps` list.
