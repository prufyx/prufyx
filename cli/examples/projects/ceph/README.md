# Ceph 20.2.4 selected OSD example

The Go-owned offline walkthrough evaluates one caller-selected current OSD
metadata object for each exact Ceph `15.2.17`, `16.2.15`, `17.2.9`,
`18.2.8`, and `19.2.6` origin proposed to `20.2.4`:

```sh
/absolute/path/to/prufyx-community community-preview example project-ceph-latest
```

For every origin, `osd_objectstore=filestore` produces a scoped `BLOCKED`,
`bluestore` produces a scoped `PASS`, and an unsupported backend remains
`UNKNOWN`. The checked-in JSON files show those three synthetic metadata
states. The native walkthrough writes private `0600` temporary files, binds
their exact digests, removes the temporary directory, and uses no network or
cluster access.

Each exact rule cites the origin source that emits the selected metadata shape
and the target source that rejects FileStore. The result says nothing about
unselected OSDs or cluster inventory. It does not claim that a direct upgrade
route is supported and does not evaluate migration, health, data safety,
sequencing, startup, runtime behavior, or whole-upgrade safety.
