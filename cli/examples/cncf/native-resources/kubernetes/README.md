# Kubernetes v1.32 flow-control API removal

This example checks only a caller-selected, complete rendered target apply set
for `FlowSchema` and `PriorityLevelConfiguration` at the removed
`flowcontrol.apiserver.k8s.io/v1beta3` GVK. It requires an official-upstream
distribution and caller-declared target API apply intent.

Build `$PREVIEW_DIR/prufyx-community` as in the repository
[quickstart](../../../../../README.md#another-worked-example-a-metallb-migration-fact), then:

```sh
umask 077
work="$PREVIEW_DIR/kubernetes"
mkdir -m 700 "$work"
cp examples/cncf/native-resources/kubernetes/broken.json "$work/resource.json"
chmod 600 "$work/resource.json"
"$PREVIEW_DIR/prufyx-community" check cncf --project kubernetes \
  --native-resource "$work/resource.json" --from 1.31.0 --to 1.32.0 \
  --distribution official_upstream --target-api-apply-required \
  --resource-scope-complete --now 2026-09-12T10:00:00Z --format human
```

`broken.json` is a scoped blocker and `fixed.json` clears that exact GVK
predicate. `unknown.json` uses an unreviewed FlowSchema version and remains
UNKNOWN. The check does not validate manifest admission, CRDs, stored objects,
runtime clients, API-server configuration, or whole-upgrade safety.

Prepare batch-ready canonical input without hand-authoring facts:

```sh
"$PREVIEW_DIR/prufyx-community" prepare cncf --project kubernetes --input "$work/resource.json" \
  --from 1.31.0 --to 1.32.0 --distribution official_upstream \
  --target-api-apply-required --resource-scope-complete --format input >"$work/input.json"
digest="sha256:$(shasum -a 256 "$work/input.json" | awk '{print $1}')"
"$PREVIEW_DIR/prufyx-community" check cncf --project kubernetes --input "$work/input.json" \
  --input-digest "$digest" --now 2026-09-12T10:00:00Z
```

The minimizer accepts syntactically valid declared version pairs so a future
signed rule pack can reuse this fact without a parser release. Embedded metadata
currently reviews only `1.31.0 -> 1.32.0`; every other pair remains UNKNOWN.
