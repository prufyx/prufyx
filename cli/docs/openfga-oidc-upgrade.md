# OpenFGA 1.17.1 to 1.18.0 OIDC startup guard

OpenFGA 1.18.0 adds a startup validation guard: when `authn.method` is
`oidc`, the effective `authn.oidc.issuer` and `authn.oidc.audience` values must
both be nonempty. The check is scoped to this exact transition and those two
fields. It does not validate URLs, tokens, credentials, startup, or runtime.

The native input is a private JSON representation containing the nested
`authn.method`, `authn.oidc.issuer`, and `authn.oidc.audience` keys. Before
preparing it, resolve OpenFGA's config file, environment, and flag precedence
outside Prufyx. Pass `--effective-config-complete` only after that resolution;
the preparer never reads those other sources and never retains the values.

```sh
umask 077
input_digest=$(shasum -a 256 ./effective-config.json | awk '{print "sha256:" $1}')
prufyx prepare cncf --project openfga --input ./effective-config.json \
  --from 1.17.1 --to 1.18.0 --effective-config-complete --format input \
  --input-digest "$input_digest" > ./openfga-prepared.json
prepared_digest=$(shasum -a 256 ./openfga-prepared.json | awk '{print "sha256:" $1}')
prufyx check cncf --project openfga --input ./openfga-prepared.json \
  --input-digest "$prepared_digest" --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format human
```

With a complete effective OIDC configuration, an empty or missing issuer or
audience produces a scoped `BLOCKED` claim. Two nonempty strings produce a
scoped `PASS`. Missing completeness, non-OIDC or unknown mode, null or wrong
selected types, selected-key case ambiguity, and unresolved file/environment/
flag precedence remain `UNKNOWN`. The aggregate remains `UNKNOWN`.

This uses immutable source evidence from OpenFGA v1.18.0 `config.go:623-631`
and `CHANGELOG.md:11-15`. The target binds the native keys to command-line and
environment inputs, while its config loader also reads `config.yaml`; a file
omission alone therefore cannot establish the effective value.
