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
swagger data and invalid scan responses fail closed. Empty served source scope
and omitted alpha-only single-object probes are explicit SKIP errors; they
cannot supply green cases. The gate
intentionally omits kind probes; this omission does not validate live behavior.
