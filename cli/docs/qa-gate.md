# Batch QA gate

`scripts/qa-auto/batch_gate.sh HEAD BASE` compares an exact data-only head with
its base. A green result requires a successful runner and a summary bound to
that invocation, head and base. A timeout or failed runner stays inconclusive
even if it wrote a zero-error summary first.

The CRD and Kubernetes oracles compare each removed group/version/kind with
its synthetic object's finding in the same component. A scoped family PASS is
wrong when that family's input contains a removed object, including under an
aggregate UNKNOWN or BLOCKED. Unrelated findings cannot cover a missing object.
UNKNOWN without the expected finding is a mismatch, never evidence of safety.

Failed Git reads, incomplete YAML, missing requested release lines, unavailable
swagger data and invalid scan responses fail closed. Empty served source scope
is reported as an explicit SKIP error; it cannot supply a green case. The gate
intentionally omits kind probes; this omission does not validate live behavior.
