# containerd selected official runtime shim

These synthetic inputs exercise the exact containerd `1.7.28` to `2.0.0`
selected-runtime constraint. Copy an example to a private file before checking
it. Build `$PREVIEW_DIR/prufyx-community` as in the repository
[quickstart](../../../../../README.md#another-worked-example-a-metallb-migration-fact):

```sh
umask 077
cp cli/examples/cncf/containerd-runtime-shim/blocked-v2.toml "$PREVIEW_DIR/containerd.toml"
"$PREVIEW_DIR/prufyx-community" check cncf \
  --project containerd \
  --containerd-config "$PREVIEW_DIR/containerd.toml" \
  --runtime-handler runc \
  --from 1.7.28 --to 2.0.0 \
  --containerd-config-complete \
  --containerd-config-precedence-resolved \
  --containerd-official-upstream \
  --containerd-official-bundled-runtimes-only \
  --now 2026-09-12T12:30:00Z
```

`blocked-v2.toml` uses an admitted version-2 configuration. The upstream 2.0
migration preserves the selected `runtime_type`; the selected
`io.containerd.runc.v1` official bundled shim is the blocker. `fixed-v3.toml`
selects `io.containerd.runc.v2` and clears only that scoped constraint.
`unknown.toml` has an unresolved import, so a single-file check cannot determine
the selected effective runtime.

The bundled-runtimes-only flag declares that no separately installed custom
shim supplies the legacy runtime name. Omit it when that is unknown. The
adapter does not search the host, execute containerd or a shim, read imported
files, inspect a cluster, or claim startup or whole-upgrade compatibility.
