### Added
- Kubernetes routes of several minor lines get a jump status in scan and plan output, composed from their hops by the same rules as other jumps (BLOCKED citing the blocked hop, ATTENTION citing notices, STEPWISE_PASS only when every hop is decided PASS on the same object content and install profile, otherwise UNKNOWN with the per-hop table). The verdict and exit code are unchanged.
