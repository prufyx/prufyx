### Fixed
- Reject incomplete oracle reads, missing object findings, and scoped family passes hidden by an aggregate unknown or blocker in batch QA.
- Bind batch QA summaries to their invocation and reject summaries written by failed or timed-out runners.
- Declare versioned Kubernetes QA scope before execution, preserving range checks and blocking required excluded targets.
