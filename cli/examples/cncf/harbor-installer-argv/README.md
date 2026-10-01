# Harbor installer argv check

These private JSON examples cover the reviewed Harbor `make/install.sh` pair
2.7.0 to 2.8.0 and `2.10.3`, `2.11.2`, `2.12.4`, `2.13.5`, or `2.14.4` to 2.15.2. The declaration describes one complete literal argv vector; it
does not execute the installer or inspect Harbor, Docker, ChartMuseum, a
database, or runtime state.

From the `cli` directory, save the input with mode `0600` and prepare it:

```sh
umask 077
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp examples/cncf/harbor-installer-argv/blocked.json "$work/blocked.json"
chmod 600 "$work/blocked.json"
./prufyx prepare cncf --project harbor \
  --input "$work/blocked.json" \
  --from 2.7.0 --to 2.8.0 --format input > "$work/harbor-prepared.json"
chmod 600 "$work/harbor-prepared.json"
```

Review the minimized input locally, then run the check with its exact digest:

```sh
./prufyx check cncf --project harbor --input "$work/harbor-prepared.json" \
  --input-digest "$(shasum -a 256 "$work/harbor-prepared.json" | awk '{print "sha256:" $1}')" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format human
```

The blocked example contains the removed `--with-chartmuseum` option. The fixed
example contains only other reviewed bare options and produces a scoped PASS. For
the `2.15.2` target pairs, only `--with-trivy` is a modeled non-removed option;
`--with-notary` and `--with-clair` are target-rejected and therefore remain UNKNOWN.
Help, wrappers, values, duplicates, unknown options, and unresolved input stay
UNKNOWN. To see the help boundary explicitly, prepare this private declaration
with the same pair, then check the minimized input; the check returns UNKNOWN
(exit `11`):

```sh
cat > "$work/help.json" <<'JSON'
{"apiVersion":"prufyx.io/harbor-installer-argv/v1alpha1","kind":"HarborInstallerArguments","effectiveArgvDeclared":true,"argv":["--help"]}
JSON
chmod 600 "$work/help.json"
./prufyx prepare cncf --project harbor --input "$work/help.json" \
  --from 2.7.0 --to 2.8.0 --format input > "$work/help-prepared.json"
chmod 600 "$work/help-prepared.json"
./prufyx check cncf --project harbor --input "$work/help-prepared.json" \
  --input-digest "$(shasum -a 256 "$work/help-prepared.json" | awk '{print "sha256:" $1}')" \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format human
```

Keep the temporary directory private and delete it after review.
