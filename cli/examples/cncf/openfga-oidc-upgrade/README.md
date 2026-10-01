# OpenFGA OIDC startup guard

This example uses a private, native-shaped JSON projection of the effective
OpenFGA configuration. Resolve `config.yaml`, environment, and command-line
precedence yourself, then pass `--effective-config-complete` only when that
resolution is complete. The preparer reads `authn.method` and the nested OIDC
`issuer` and `audience` strings; it does not parse YAML, start OpenFGA, or read
tokens and credentials.

```sh
umask 077
cp effective-config-missing.json ./openfga-effective.json
chmod 600 ./openfga-effective.json
prufyx check cncf --project openfga \
  --effective-config ./openfga-effective.json --effective-config-complete \
  --from 1.17.1 --to 1.18.0 --now 2026-09-11T18:00:00Z --format human
```

The missing issuer is a scoped blocker. Replace the value in the private
working copy with the target's nonempty effective issuer and repeat the same
command. A missing or false completeness declaration, non-OIDC method, null or
wrong selected type, selected-key case ambiguity, unresolved override, or
unsupported version pair remains `UNKNOWN`. Whitespace is nonempty, matching
the upstream target's strict empty-string guard.

Use `--effective-config-digest` to bind the supplied raw bytes. A selected
external knowledge replay also requires that digest, a replay report, and all
three knowledge pins; it never falls back to embedded rules.
