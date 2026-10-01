# Synthetic offline knowledge example

This example demonstrates the unreleased, operator-provisioned offline knowledge database with public synthetic inputs. It creates an ephemeral Ed25519 TUF root and two signed packages. Private keys remain process-local and are never serialized. The public root and packages live only in a uniquely named temporary directory that the runner removes.

Run it from a source checkout containing the vendored dependency tree:

```sh
prufyx community-preview example knowledge-cert-manager
```

The same binary imports revision 1, whose complete knowledge bundle has no cert-manager rule, and reports `UNKNOWN` with exit 11. Revision 2 adds the existing reviewed `1.20.3` to `1.21.1` removed-monitor-values rule and reports `BLOCKED` with exit 10 for the same synthetic values. The runner then replays the exact revision 1 report after revision 2 is current and requires a historical `MATCH` with exit 11.

The generator also accepts `--profile cloudevents-structured-json` when run
directly, producing empty revision 1 and active revisions 2 and 3 for the
isolated profile and historical-replay tests.

The signatures demonstrate transport, rollback, and selection mechanics only. Their freshness dates are generated for the synthetic run and do not record an upstream review. They are not an official Prufyx trust root, cert-manager or CloudEvents authority, or production signing workflow. The Go command performs no network or cluster operation and uses the vendored Go 1.26.8 source tree. The retained shell file is only a compatibility launcher.
