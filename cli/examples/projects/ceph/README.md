# Ceph 20.2.4 selected OSD example

Ceph currently has no active rule. The rules for the `15.2.17`, `16.2.15`,
`17.2.9`, `18.2.8`, and `19.2.6` origins to `20.2.4`, and for `17.2.7` to
`18.2.0`, are withdrawn: the upstream upgrade notes require a cluster older than
Reef to be upgraded to Reef (18.2.z) or Squid (19.2.z) before Tentacle, and name
the latest minor release of the target series as the only supported and tested
path.

The Go-owned offline walkthrough evaluates one caller-selected current OSD
metadata object for each `20.2.4` origin and checks that every one of them
answers `UNKNOWN`:

```sh
/absolute/path/to/prufyx-community community-preview example project-ceph-latest
```

The checked-in JSON files show three synthetic metadata states (`filestore`,
`bluestore`, and an unsupported backend). The native walkthrough writes private
`0600` temporary files, binds their exact digests, removes the temporary
directory, and uses no network or cluster access.

Each withdrawn rule still cites its sources. The result says nothing about
selected or unselected OSDs, cluster inventory, a supported upgrade route,
migration, health, data safety, sequencing, startup, runtime behavior, or
whole-upgrade safety.
