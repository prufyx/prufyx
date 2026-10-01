# Native format preflights

These two source-reviewed checks classify one private local JSON file. They do
not contact a registry, pull an image, execute a CNI plugin, or observe a
runtime. Copy the public example to a new private regular file first:

```sh
umask 077
cp cli/examples/cncf/distribution-manifest/schema1-broken.json manifest.json
chmod 600 manifest.json
prufyx check cncf --project distribution --image-manifest manifest.json \
  --from 2.8.3 --to 3.0.0 \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format human
```

The schema1 example yields scoped `BLOCKED` while its source review is current.
Repeat with `schema2-fixed.json` for scoped `PASS`, or
`manifest-list-unknown.json` for `UNKNOWN`. The rule covers only removal
of Distribution's schema1 handler in the exact `2.8.3` to `3.0.0` source plan.
Distribution 2.8.3 could gate schema1 separately, and this check does not prove
that a source deployment accepted it. Signatures, descriptors, referenced
content, registry configuration, storage, pull, platform, and runtime behavior
remain outside the result.

For the CNI specification preflight, use the distinct specification component
and explicit operation:

```sh
umask 077
cp cli/examples/cncf/cni-spec/single-plugin-broken.json cni.json
chmod 600 cni.json
prufyx check cncf --project container-network-interface-cni \
  --cni-configuration cni.json --from 0.4.0 --to 1.0.0 \
  --operation configuration-spec-migration \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format human
```

The single-plugin example deliberately keeps the `1.0.0` label, proving that a
version-only edit remains scoped `BLOCKED`. Replace it with
`plugin-list-fixed.json` for scoped `PASS`, or `mixed-shape-unknown.json` for
`UNKNOWN`. Here `0.4.0` and `1.0.0` are CNI
**specification** versions under `pkg:generic/cni-configuration-spec`; they are
not versions of the containernetworking/cni Go library, a plugin, or a runtime.
The check ignores unrelated plugin-specific fields and retains only the bounded
shape, inspected spec version, and caller-declared migration intent. Plugin
support, chained execution, networking, and runtime compatibility remain
unresolved.

For both checks, unsupported or mixed relevant structure stays `UNKNOWN`, bad
JSON is invalid input, and the aggregate whole-migration assessment remains
`UNKNOWN` even when the scoped claim is `PASS`. The lower-level `prepare cncf`
route remains available when a caller needs to retain the minimized canonical
input separately; the direct commands prepare and evaluate only in memory.
They also accept the existing `--knowledge-db` selection in place of `--now`.
That selected store is authoritative and never falls back to embedded rules.
Historical replay additionally requires the matching raw input digest and all
three knowledge pins; a current selected-store check uses verifier-owned time.

## Argo CD 2.14.0 to 3.0.0 resource exclusions

`check cncf --project argo-cd --resource-exclusions-config-map FILE` evaluates
only a private, mode-0600 `v1` `argocd-cm` ConfigMap selected by the operator.
It requires complete and precedence-resolved declarations and an explicit true
v2-visibility-preservation intent. The parser accepts only an absent key, an
explicit empty YAML sequence, or the exact reviewed v3 source-default sequence;
all other shapes stay UNKNOWN. Runnable private-file examples are in
[`examples/cncf/native-resources/argocd-resource-exclusions`](../examples/cncf/native-resources/argocd-resource-exclusions/README.md).
