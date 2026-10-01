# MariaDB Operator examples

These public synthetic resources contain no cluster names, credentials, or
private workload data. The route is deliberately narrow: it checks the
MariaDB Operator `26.3.0` to `26.6.0` prerequisite for one complete,
Galera-enabled `k8s.mariadb.com/v1alpha1` `MariaDB` resource before an
operator update. It does not inspect a cluster or prove runtime or data-plane
completion.

Build the local preview binary from the repository instructions, then copy the
selected resource into a private mode-0700 directory before checking it:

```sh
(
  set -eu
  umask 077
  PRIVATE_DIR="$(mktemp -d)"
  chmod 700 "$PRIVATE_DIR"
  trap 'rm -rf "$PRIVATE_DIR"' EXIT
  cp cli/examples/projects/mariadb-operator/broken.json "$PRIVATE_DIR/resource.json"
  set +e
  "$PREVIEW_DIR/prufyx-community" check project \
    --project mariadb-operator --mariadb-resource "$PRIVATE_DIR/resource.json" \
    --from 26.3.0 --to 26.6.0 \
    --resource-complete --pre-operator-update \
    --now 2026-09-13T09:00:00Z
  prufyx_example_exit=$?
  set -e
  test "$prufyx_example_exit" -eq 10
)
```

Use `fixed.json` in place of `broken.json` and change the final assertion to
`test "$prufyx_example_exit" -eq 0` for the scoped PASS, or use `unknown.json`
and assert exit 11 for UNKNOWN. `broken.json` is BLOCKED (exit 10), as shown.
The aggregate compatibility assessment remains UNKNOWN for all three results.
The `PREVIEW_DIR` binary path is the private path produced by the build step;
never put a private resource in the repository or pass a shared path.
