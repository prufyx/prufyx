# ADR-0002: Add a declared one-rule review consistency gate

**Status:** Accepted after independent implementation and production-path review
**Date:** 2026-09-13
**Deciders:** Prufyx maintainer and independent implementation reviewer
**Technical Story:** [RFC-0001](../rfc/RFC-0001-public-project-knowledge-onboarding.md)

## Context

ADR-0001 separates source observations from reviewed executable rules. The
existing evidence-packet validator, retained-source verifier, target exporter,
and evaluator each prove a useful local property, but no machine-readable
artifact closes their identities around one maintainer decision. The Markdown
review template records process notes but is not machine-verifiable.

A verifier that only hashes supplied files would add no semantic evidence. A
verifier that calls a declared decision authenticated review would overstate
its authority. Parsing a target and evaluating one selected rule would also be
insufficient if unrelated target changes could travel under the same receipt.

## Decision

Add a closed v1 record and an offline verifier for one existing CNCF transition
rule. The verifier reuses the contribution and source-corpus validators, binds
all packet and corpus sources bidirectionally to the rule's evidence spans,
requires the complete target bytes to equal the compiled embedded export at the
bound revision, and executes the exact selected vector group.

The receipt separates consistency, declared process authorization, selected
engine compatibility, whole-target admission, baseline/candidate delta,
signing, and store selection. It never changes a packet's `CANDIDATE` /
`NOT_ADMITTED` state. Its accepted decision means only that the declared owner
wants this one consistent rule to proceed to a separate signing review.

## Consequences

The maintainer can reproduce a bounded intake-to-review gate offline and detect
changed packet receipts, retained source bytes, source role or endpoint
relabeling, vectors, rule evidence, engine capability, and unrelated target
mutations. PASS, BLOCKED, UNKNOWN, and wrong-pair cases are observed from the
evaluator rather than trusted as labels.

The verifier does not authenticate the maintainer, check the full target's
delta from a prior release, select a store, sign metadata, or authorize
publication. V1 cannot review neutral community-project rules because those
rules remain embedded in the batch path rather than the external CNCF target.
No universal feed is claimed until that separate architecture is designed.

## Alternatives considered

### Treat the existing Markdown record as the machine contract

Human-oriented paths and prose cannot be parsed as a closed stable identity,
and their presence does not prove that vectors ran. Keep the template as a
process note and add a separate JSON contract.

### Accept any target that passes the external parser

The external parser correctly validates compiled policy and engine shapes but
permits changed rule content. A receipt for one selected rule could then appear
to qualify unrelated additions. Require byte equality with the complete
embedded export at the explicit revision.

### Emit a signing-ready or admitted target state

Local consistency cannot establish authenticated human authorization, key
custody, baseline/candidate closure, or store policy. Preserve each as a
separate explicit state.

## Verification and rollback

Focused tests execute the existing Karmada PASS, BLOCKED, UNKNOWN, and wrong
pair vectors. Negative tests cover unrelated target mutation, source endpoint
and role mismatch, extra corpus sources, wrong packet declarations, unknown and
duplicate record fields, malformed vector input, and source-only proposals.
CLI tests cover local help, reordered options, missing/duplicate/unknown options,
and path/control-character redaction. A production-path acceptance run uses the
complete two-source set for the existing Crossplane composition-resources rule:
packet validation, retained-source verification, corpus verification, exact
target export, and `review-record verify` succeed, while the same command
rejects an unrelated parser-valid target mutation. The acceptance declaration
is explicitly a test fixture, not authenticated human review or new coverage.
An independent reviewer separately rebuilt the maintainer CLI and reproduced
the positive, help, reordered-option, and parser-valid target-mutation paths
before this decision was accepted.

Rollback removes the additive command, package, and docs. There is no schema or
data migration because the verifier writes no store and changes no existing
receipt or target.

## References

- [Declared review-record consistency gate](../declared-review-record.md)
- [ADR-0001](ADR-0001-source-observations-before-reviewed-rules.md)
- [Upstream review record template](../upstream-review-record-template.md)
