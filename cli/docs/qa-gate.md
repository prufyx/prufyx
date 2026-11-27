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
Persistent review and rules allow-lists apply only to diagnostic runs. Batch mode
ignores them, so an actual failure remains in publication totals.

## Gate base

The base is not a free choice. For every form (explicit head with or without a
base, `--trust-operator`, `--poll`) the gate reads the tip of exactly
`refs/heads/main`, fetches the full history of main and the head into a new
repository, and runs only when the base is the single merge base of head and
tip, is that tip itself, and differs from the head. A head behind main must be
rebased first. A failed lookup, fetch or Git command, a main that moved between
lookup and fetch, a shallow source, no or several merge bases, or any other
base ends with exit 3: no run, no record, no fallback. The record stores the
tip read before the run. On the next poll a green record stays green only while
that tip is still the tip of main and equals its base; otherwise, or when the
tip cannot be read, it becomes `STALE`. A `run.sh` call with `QA_BASE` set
directly is a diagnostic and writes no gate record.

## Removed targets

Every CRD version target present at the base
(`cli/internal/extract/crdversions/target-*.json`) must be a regular file with
mode 100644 at the same path at the head. A deletion, rename, mode change,
symlink or directory in its place is refused, whether or not the changed list
names it; a signed batch or `QA_GATE_REPOS` does not admit it. There is
currently no route that admits removing a target through this gate. A changed
target that cannot be read at the head is refused, not treated as deleted.

## Installing the runtime

Install every script of `scripts/qa-auto/` together; `crd_inventory.py` is
required by `target_repos.py` and `qa_batch_scope.py`. Green records written by
an earlier runtime were made under a weaker base rule: when installing, remove
the green records in `$QA_STATE/gate/` or mark them `STALE`, then gate those
heads again.

## Verdicts and scope

Failed Git reads, incomplete YAML, missing requested release lines and invalid
scan responses fail closed. A read document count is insufficient when any
document was omitted, templated or unparseable. The gate
intentionally omits kind probes; this omission does not validate live behavior.

Both removal oracles declare `prufyx.io/qa-scope/v2` before candidate scans.
The `kubernetes-api-removals-v2` and `crd-removals-v1` inventories record every
requested, executed, omitted and excluded target, required targets, and their
head, base and invocation identity. The summary and gate require both bound
inventories. Older Kubernetes-only receipts cannot validate this scope.

Kubernetes plan checks use a companion scan of the same synthetic file and exact
range. Its complete intake and matching input digest are required. Each expected
removal must have an exact object/removal-rule finding in that scan at the same
hop, and that rule must appear in the plan stage. Each stage must have a known
verdict matching its expected removals and no gaps or unsupported findings.
An UNKNOWN stage, including one without expected removals, an empty stage list,
a missing finding or incomplete input stays erroneous and omitted from executed
plan scope. Release-line endpoints and explicit patch-zero endpoints identify
the same requested minor hop.

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
In batch mode `QA_PROJECTS` can only add CRD projects to the inferred scope; a
full selection stays full. Changed rule IDs determine rules scope independently
of that diagnostic filter.

The entrypoint regression controls use synthetic upstream responses and scan
reports. The paired `run.sh` admission test stubs trusted build/oracle companions
while testing the actual data-only guard. These controls prove harness behavior;
they do not establish product compatibility or sandbox runtime fidelity.
