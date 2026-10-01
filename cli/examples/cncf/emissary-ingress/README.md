# Emissary-Ingress diagd argv

This synthetic direct argv demonstrates the reviewed Emissary-Ingress
3.10.0 → 4.0.1 removal of `diagd --metrics-endpoint`. It is a caller-owned
declaration; the command does not execute `diagd` or inspect wrappers,
environment, Helm values, deployment resources, or runtime behavior.

Create a private copy and check it directly with an already-built Community
binary:

```sh
umask 077
cp cli/examples/cncf/emissary-ingress/argv.json emissary-diagd-argv.json
chmod 600 emissary-diagd-argv.json
./prufyx check cncf --project emissary-ingress \
  --diagd-argv emissary-diagd-argv.json --from 3.10.0 --to 4.0.1 \
  --now 2026-09-11T18:00:00Z --format human
```

The direct check makes the scoped claim `BLOCKED` (exit `10`) because the
removed option is present. Edit the same private argv file to contain only
`["diagd"]`, run the identical command again, and the scoped claim is `PASS`
(exit `0`). The aggregate assessment remains `UNKNOWN`; unsupported argv
forms, wrappers and unrelated deployment settings remain unresolved.

Use `--diagd-argv-digest` to bind the supplied raw bytes. A selected external
knowledge replay also requires that digest, a replay report, and all three
knowledge pins; it never falls back to embedded rules.
