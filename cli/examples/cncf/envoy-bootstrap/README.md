# Envoy direct V2 transport blocker

These synthetic bootstrap fragments exercise the narrow Envoy native route for
the existing xDS-v2 rule. They are not deployed configurations and do not
prove a complete bootstrap, Envoy distribution, xDS discovery, protocol
success, server behavior, runtime state, or whole-upgrade safety.

The route supports only target `1.39.1` from `1.34.14`, `1.35.13`, `1.36.10`,
`1.37.6`, or `1.38.4`. The caller must declare that the local bytes are the
directly loaded bootstrap with `--envoy-bootstrap-selected`; that authority is
not inferred. Build `$PREVIEW_DIR/prufyx-community` as in the repository
[quickstart](../../../../../README.md#another-worked-example-a-metallb-migration-fact).

```sh
umask 077
cp cli/examples/cncf/envoy-bootstrap/direct-v2.json "$PREVIEW_DIR/bootstrap.json"
chmod 600 "$PREVIEW_DIR/bootstrap.json"
"$PREVIEW_DIR/prufyx-community" check cncf --project envoy \
  --envoy-bootstrap "$PREVIEW_DIR/bootstrap.json" --envoy-bootstrap-selected \
  --from 1.38.4 --to 1.39.1 --now 2026-09-13T00:00:00Z
```

`direct-v2.json` contains the direct ADS `transport_api_version: V2` witness
and returns `BLOCKED` for the existing predicate. `unknown-v3.json` returns
`UNKNOWN`: this blocker-only route never turns `V3`, `AUTO`, or field absence
into a native PASS.

Only direct snake-case `dynamic_resources.ads_config.transport_api_version`,
`dynamic_resources.lds_config.api_config_source.transport_api_version`, and
`dynamic_resources.cds_config.api_config_source.transport_api_version` are
inspected. YAML, `Any`/`typed_config`, other ConfigSource surfaces, dynamic
resources fetched after bootstrap, and runtime state are outside the route.
