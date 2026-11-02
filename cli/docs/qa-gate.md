# Batch QA gate

`scripts/qa-auto/batch_gate.sh HEAD BASE` compares an exact data-only head with
its base. A green result requires a successful runner and a summary bound to
that invocation, head and base. A timeout or failed runner stays inconclusive
even if it wrote a zero-error summary first.

The CRD and Kubernetes oracles compare each removed group/version/kind with
its synthetic object's removal-rule finding in the same component. A scoped
family PASS is wrong when that family's input contains a removed object, including under an
aggregate UNKNOWN or BLOCKED. Unrelated findings cannot cover a missing object.
UNKNOWN without the expected finding is a mismatch, never evidence of safety.
Historical mismatch baselines cannot waive mismatches in a publication gate.

Failed Git reads, incomplete YAML, missing requested release lines and invalid
scan responses fail closed. A read document count is insufficient when any
document was omitted, templated or unparseable. The gate
intentionally omits kind probes; this omission does not validate live behavior.

Both removal oracles declare `prufyx.io/qa-scope/v2` before candidate scans.
The `kubernetes-api-removals-v2` and `crd-removals-v1` inventories record every
requested, executed, omitted and excluded target, required targets, and their
head, base and invocation identity. The summary and gate require both bound
inventories. Older Kubernetes-only receipts cannot validate this scope.

Kubernetes range scans retain alpha objects and aggregate checks. Unsupported
single-alpha probes have explicit exclusions. A swagger HTTP 404 is insufficient
to exclude a version: a bounded lookup of the fixed official Kubernetes Git
repository must succeed, report the requested release ref absent, and report
the preceding release ref present with a valid Git object ID. Only then may targets
depending on that unavailable version be excluded before execution. Requested
maximum versions remain in the inventory. Timeout, HTTP 503, malformed JSON,
existing refs or failed/ambiguous ref lookups remain errors. Consecutive future
versions without a published preceding ref conservatively remain errors.

CRD inventories retain selected projects, release-line pairs and exact tag
pairs. All source plans are read before scans. Failed source reads leave their
requests in the omitted inventory. A complete served-set read proving an empty
source produces an explicit exclusion and next bounded test. Every exclusion
identifies missing evidence and a next test; it supplies no PASS claim.

Required targets are derived from the exact base/head data diff before scans.
Unreadable or ambiguous data makes every single-object target required.
In batch mode every selected CRD project and pair is conservatively required;
an excluded empty-source pair therefore remains an error for publication.
`QA_REQUIRED_TARGETS` may name a JSON list of additional target identifiers;
`QA_REQUIRED_CRD_TARGETS` adds CRD requirements. Neither can remove inferred
requirements. A required excluded or unrequested target, incomplete inventory,
changed declaration or stale identity makes the gate inconclusive.

The entrypoint regression controls use synthetic upstream responses and scan
reports. The paired `run.sh` admission test stubs trusted build/oracle companions
while testing the actual data-only guard. These controls prove harness behavior;
they do not establish product compatibility or sandbox runtime fidelity.
