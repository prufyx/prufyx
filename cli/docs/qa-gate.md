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

Failed Git reads, incomplete YAML, missing requested release lines, unavailable
swagger data and invalid scan responses fail closed. A read document count
is insufficient when any document was omitted, templated or unparseable. Empty served source scope
is an explicit SKIP error and cannot supply a green case. The gate
intentionally omits kind probes; this omission does not validate live behavior.

The Kubernetes oracle declares `prufyx.io/qa-scope/v1` with the
`kubernetes-api-removals-v1` profile before any candidate scan. The inventory
records every requested, executed, omitted and excluded target, its required targets,
and its head, base and invocation identity. Only unsupported single-alpha
probes are excluded; each exclusion names its missing evidence and next test.
Range scans still include alpha objects and check aggregate verdicts. An
exclusion supplies no PASS claim.

Required targets are derived from the exact base/head data diff before scans.
Unreadable or ambiguous data makes every single-object target required.
`QA_REQUIRED_TARGETS` may name a JSON list of additional target identifiers;
it cannot remove inferred requirements. A required excluded or unrequested
target, incomplete inventory, changed declaration or stale identity makes the
gate inconclusive. Earlier results without this scope contract are invalid.
