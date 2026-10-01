# Synthetic offline etcd examples

This walkthrough exercises the exact adjacent etcd `3.6.14` to `3.7.1`
source constraint through the native preparation and check commands. It uses
only complete, direct, caller-declared effective argument vectors.

Run the Go-owned walkthrough with an already-built Community executable:

```sh
/absolute/path/to/prufyx-community community-preview example cncf-etcd
```

The `run.sh` file is a thin compatibility shim for that native command. The Go
walkthrough runs the retained `3.5.17` to `3.6.0` regression and the latest
three cases. It creates private `0600` temporary inputs, binds source and
canonical input digests, removes its temporary tree, and uses no network,
cluster, or etcd process. The checked-in JSON files show the latest synthetic
inputs that correspond to its blocked, fixed, and unknown states.

- `blocked.json` contains the reviewed removed
  `--experimental-compact-hash-check-enabled=true` spelling. Preparation emits
  `component.etcd.experimental_flags_present=true`, and the scoped check is
  `BLOCKED` with exit `10`.
- `fixed.json` uses the documented
  `--feature-gates=CompactHashCheck=true` replacement. The complete finite target
  grammar emits the same fact as `false`, and the adjacent scoped check is
  `PASS` with exit `0`.
- `unknown.json` declares an indirect `--config-file` source. Preparation does
  not resolve it or emit a false fact, and the check remains `UNKNOWN` with
  exit `11`.

The same removed-flag predicate is available for exact current versions
`3.5.33`, `3.4.45`, `3.3.27`, and `3.2.32`, but replacing the flag cannot make
those direct proposals pass: a separate one-minor-at-a-time rule still blocks
each direct jump to `3.7.1`. Other current or target versions, unresolved
wrappers, templates, environment, separated values, duplicate names, unknown
flags, and config-file inputs remain `UNKNOWN`. In particular, the inferred
plain `--compact-hash-check-enabled=true` name is not registered by the pinned
3.7.1 target and remains `UNKNOWN`.

Raw arguments never appear in the minimized canonical input. These source-only
checks do not establish health, snapshot or v2-data safety, membership,
downgrade, startup, rolling-upgrade behavior, or whole-upgrade safety.
