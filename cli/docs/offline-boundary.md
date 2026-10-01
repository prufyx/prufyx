# Linux offline-boundary harness

`internal/offlineboundary` is an opt-in Go harness for an already-built
Community executable. Its Community journey test builds its binary and socket
positive control with Go, creates its private JSON fixtures with Go, and checks
the supported help, version, Karmada, Cilium, and signed-knowledge journeys in
Go. It does not collect a cluster or execute a supplied Kubernetes context.
Each traced command must have its declared exit result and must not make a
network syscall.

It is only meaningful on Linux with all of these prerequisites: `sudo -n`,
`unshare`, `setpriv`, `strace`, an explicit non-root UID/GID, and a separately
built Go positive-control binary. The positive control opens a loopback TCP
socket inside the same `unshare --net` isolation; if `strace` cannot observe
that socket, the harness fails rather than treating an empty trace as success.

Build the positive control from this checkout:

```sh
go build -o /private/path/prufyx-offline-boundary ./cmd/prufyx-offline-boundary
```

A release runner can opt into the Go-owned Community journey with:

```sh
PRUFYX_OFFLINE_BOUNDARY_ENABLE=1 \
go test ./internal/offlineboundary -run TestOfflineBoundaryLinuxCommunityJourneys
```

The generic `TestOfflineBoundaryLinuxIntegration` remains available for a
separately supplied private `0600` scenario file when a release runner needs
additional command coverage. The tests skip without explicit opt-in or off
Linux. A skipped test is not evidence that an executable is offline. Fixture
contents and command arguments are not emitted in product reports.
