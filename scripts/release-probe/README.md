# Release probe

Runs upstream release artifacts to see whether a command line item that one release line accepts is rejected, by name, by every final release of the next line. It only produces records; it changes no knowledge data and no check.

Upstream binaries run only on a GitHub-hosted runner (`.github/workflows/release-probe.yml`), after the self-tests have refused every injected fault. Each case gets a new container with no network, no mounts, a non-root user, no capabilities, resource and time limits, and no inherited environment.

- `spec.py` pairs, items, base invocations and the full case list.
- `releases.json` the pinned final tags and commits; a run refuses the pair when they differ from the coverage lines snapshot or from the upstream tag listing.
- `fetch.py` artifacts: a release asset matched against the upstream checksum file, otherwise the official image pinned by manifest digest.
- `engine.py`, `judge.py` the container run and the pass rules.
- `check.py` recomputes every result from the raw output and fails on any gap.

Unit checks, which run nothing upstream: `cd scripts/release-probe && python3 -B -m unittest test_probe`.

Not covered by a run: reading the upstream source on the parse path, and a rerun on a second machine. A pair that passes here is not proven by this alone.
