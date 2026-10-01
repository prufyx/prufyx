# Cilium cluster-name

The Cilium v1.17.18 check reads one private v1 ConfigMap and retains only whether
the whitespace-trimmed `data.cluster-name` violates the reviewed target syntax.

```sh
umask 077
work="$PREVIEW_DIR/cilium"
mkdir -m 700 "$work"
cp examples/cncf/native-resources/cilium/broken.yaml "$work/cilium.yaml"
"$PREVIEW_DIR/prufyx-community" check cncf --project cilium \
  --cilium-config-map "$work/cilium.yaml" --from 1.16.19 --to 1.17.18 \
  --cilium-distribution official_upstream --cilium-config-complete \
  --cilium-config-precedence-resolved --now 2026-09-12T10:00:00Z
```

The same flags work with `prepare cncf --format input`; redirect the canonical
declaration to a private file before supplying it to `check cncf` or `check batch`.
The result does not establish ClusterMesh, networking, name-collision, runtime,
or whole-upgrade safety.

```sh
"$PREVIEW_DIR/prufyx-community" prepare cncf --project cilium \
  --cilium-config-map "$work/cilium.yaml" --from 1.16.19 --to 1.17.18 \
  --cilium-distribution official_upstream --cilium-config-complete \
  --cilium-config-precedence-resolved --format input >"$work/input.json"
digest="sha256:$(shasum -a 256 "$work/input.json" | awk '{print $1}')"
"$PREVIEW_DIR/prufyx-community" check cncf --project cilium --input "$work/input.json" \
  --input-digest "$digest" --now 2026-09-12T10:00:00Z
```

The minimizer admits syntactically valid version pairs for later signed metadata,
but embedded metadata reviews only `1.16.19 -> 1.17.18`; another pair is UNKNOWN.
