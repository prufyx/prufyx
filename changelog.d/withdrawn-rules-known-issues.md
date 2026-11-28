### Documentation

- The release notes list the known issues of v0.1.0-beta.0 for the withdrawn etcd, Harbor, Contour and Cilium rules. That release cannot read the current knowledge feed, so upgrade the client and do not rely on those answers.
- Lost blockers: inputs the withdrawn rules reported as `BLOCKED` are now `UNKNOWN`. In particular, `scan --fail-on blocked` on a CiliumNodeConfig v2alpha1 manifest for Cilium 1.19.0 to 1.20.0 now exits `0` with a note that this is not a PASS, although the removal is still real.
- The README multi-hop plan example describes the result after the withdrawals.
