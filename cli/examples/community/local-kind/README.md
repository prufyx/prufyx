# Local kind declaration proof

This optional, manual Go proof exercises the Kubernetes API collection path
without starting Prometheus. `current-prometheus-agent.yaml` declares a
Deployment with `replicas: 0`; its reports are declaration observations only.
They do not establish process startup, Agent mode, data or remote-write safety,
or whole-upgrade compatibility.

It requires kind v0.31.0 with a Docker-compatible provider, kubectl, an
already-built `prufyx` binary, and an already-built `prufyx-collector` binary.
It uses this pinned node image:

```text
kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f
```

Run it deliberately from the repository root. It never reads the ordinary
user kubeconfig and creates a disposable, randomly named kind cluster:

```sh
(cd cli && go run ./cmd/prufyx-maintainer local-kind \
  --prufyx /absolute/path/to/prufyx \
  --collector /absolute/path/to/prufyx-collector \
  --evidence /absolute/new/local-kind-evidence)
```

`run.sh` is a compatibility launcher for the same Go command:

```sh
sh cli/examples/community/local-kind/run.sh \
  /absolute/path/to/prufyx \
  /absolute/path/to/prufyx-collector \
  /absolute/new/local-kind-evidence
```

The command refuses proxy-configured environments before cluster creation. It
uses a task kubeconfig for every kind, kubectl, and collector call; checks its
loopback endpoint; and deletes only the run-owned cluster and task directory.
Do not use it against an existing cluster or kubeconfig.

The three proposed fixtures must yield these scoped results, while the
aggregate remains `UNKNOWN`:

| Proposed fixture | Scoped result | Process exit |
| --- | --- | --- |
| `proposed-preserve-agent.json` | `PASS` | `0` |
| `proposed-change-to-server.json` | `ATTENTION` | `11` |
| `proposed-ambiguous.json` | `UNKNOWN` | `11` |

The command stores mode-0600 reports, a path-free binary identity, a cleanup
receipt, and a SHA-256 manifest in the new evidence directory. It repeats the
preserve-agent input and requires byte-identical reports. The collector's
fixed GET/LIST footprint and any omissions remain documented in
[local-collection.md](../../../docs/local-collection.md).
