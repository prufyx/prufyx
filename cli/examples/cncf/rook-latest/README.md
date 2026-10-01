# Rook 1.20.7 exact-source examples

This offline walkthrough covers the exact Rook `1.15.9`, `1.16.9`, `1.17.9`,
`1.18.11`, and `1.19.11` origins proposed directly to `1.20.7`. For the
adjacent `1.19.11` origin it checks the source-stated Kubernetes minimum:
Kubernetes `1.30.9` is scoped `BLOCKED`, `1.31.0` is scoped `PASS`, and a
missing proposed Kubernetes component is `UNKNOWN`. Each of the four
non-adjacent origins is scoped `BLOCKED` for every declared Kubernetes
version, because a separate exact rule forbids that direct minor skip. The
aggregate whole-upgrade assessment remains `UNKNOWN` in every report. The
checked-in fixtures show the three Kubernetes-minimum states for the adjacent
`1.19.11` origin.

Run the Go-owned walkthrough with an already-built Community executable:

```sh
/absolute/path/to/prufyx-community community-preview example cncf-rook-latest
```

The `run.sh` file is a thin compatibility shim for that native command. The Go
walkthrough creates private `0600` temporary inputs, binds each exact digest,
uses the pinned review clock, removes its temporary tree, and uses no network
or cluster access. The checked-in JSON files show the corresponding synthetic
blocked, fixed, and unknown declarations.

Separate exact rules block direct `1.15.9`, `1.16.9`, `1.17.9`, and `1.18.11`
to `1.20.7` proposals because the target guide and the guide for the first
required hop document adjacent minor upgrades. The cited latest patch in each
first-hop line is evidence identity, not a mandatory exact intermediate. The
Kubernetes-minimum rules remain target-only constraints and do not by
themselves assert that any direct route is supported. Versions outside these
five exact current endpoints remain `UNKNOWN`.

These examples do not inspect Ceph state or health, CSI migration, CRDs, Helm
ordering, startup, rollout, rollback, or runtime behavior. A scoped `PASS`
establishes only the cited numerical Kubernetes minimum.
