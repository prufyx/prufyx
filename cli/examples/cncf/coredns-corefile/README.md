# CoreDNS direct federation directive

These synthetic Corefiles exercise the narrow native route for the existing
CoreDNS federation-removal rule. They do not represent a deployed
configuration.

The route accepts only `1.6.9` to `1.7.0`, or `1.9.4`, `1.10.1`, `1.11.4`,
`1.12.4`, or `1.13.2` to `1.14.7`. It requires the caller to declare a
complete selected Corefile and the official distribution. Those declarations
are not inferred from the file. Build `$PREVIEW_DIR/prufyx-community` as in
the repository [quickstart](../../../../../README.md#another-worked-example-a-metallb-migration-fact).

```sh
umask 077
cp cli/examples/cncf/coredns-corefile/blocked.Corefile "$PREVIEW_DIR/Corefile"
chmod 600 "$PREVIEW_DIR/Corefile"
"$PREVIEW_DIR/prufyx-community" check cncf --project coredns \
  --coredns-corefile "$PREVIEW_DIR/Corefile" --coredns-corefile-complete \
  --coredns-distribution official --from 1.13.2 --to 1.14.7 \
  --now 2026-09-13T00:00:00Z
```

`blocked.Corefile` has a direct `federation` directive and returns `BLOCKED`.
`fixed.Corefile` has a direct, safely admitted absence and returns a scoped
`PASS`. `unknown.Corefile` contains `import`, so it returns `UNKNOWN`; the
route does not read any referenced file. Balanced plugin bodies are
structurally admitted up to 32 levels but opaque: a `federation` token in an
argument or nested body is not a direct directive. Snippets, substitutions,
quoted or escaped text, malformed structure, and deeper nesting return
`UNKNOWN` instead of a negative-presence PASS.

The parser does not establish distribution identity, Corefile completeness,
plugin validity, DNS behavior, runtime state, or whole-upgrade safety.
