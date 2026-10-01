# ADR-0001: Keep source observations separate from reviewed executable rules

**Status:** Accepted
**Date:** 2026-09-12
**Deciders:** Prufyx maintainer and architecture reviewers
**Technical Story:** [RFC-0001](../rfc/RFC-0001-public-project-knowledge-onboarding.md)

## Context

Prufyx can verify retained public-source bytes and can package reviewed rules in
signed knowledge targets. A public GitHub release body may be edited after
publication, a tag reference may be moved, repository names may change, and a
correctly hashed changelog still says nothing by itself about license, component
identity, maintainer approval, compatibility, or runtime behavior.

Self-service onboarding must accept a public repository suggestion without
requiring repository control or manually calculated hashes. That makes the
initial data explicitly unreviewed and attacker controlled. Feeding it directly
into the existing rule target or support registry would let successful data
collection appear to authorize an executable result.

## Decision

We will store versioned source observations in an inspection-only local snapshot
model, require a separate maintainer review before any rule admission, and keep
all observation data out of existing executable knowledge targets and rule
selection paths.

Release bodies and commit-pinned files use different records. A release record
binds GitHub repository and release IDs, observation time, exact body digest,
and optional prior-observation metadata because its text can change. A file
record binds repository ID, exact tag reference observation, peeled 40-character
commit, conservative path, byte length, SHA-256, and raw-LF spans. A later sync
records release-body edits, rejects detected tag rebinding, and never overwrites
prior snapshots.

Integrity, license disposition, review, admission, and offline freshness,
continuity, and non-revocation status are reported separately. Future review,
revocation, rule-admission, and publication decisions require separate records.
No aggregate `PASS` is produced by onboarding. Submitter identity and an
optional declared relationship to a project are contribution metadata;
authenticated maintainer authority belongs to a separate review artifact.

## Consequences

### Positive

- Contributors get a complete repository-URL-to-proposal path without being
  treated as upstream maintainers or asked to compute hashes.
- Edited release text is recorded while detected tag movement rejects continuity.
- Existing executable rules, support counts, evaluator behavior, and signed
  package schemas do not change when a project is merely observed.
- The current `sourcecorpus` verifier and content-addressed object store can be
  reused for commit-pinned files.
- Untrusted repository data is never executed, built, rendered as active markup,
  or passed to a model.

### Negative

- A collected project cannot immediately produce compatibility results.
- Maintainers must create and retain a separate review decision before promoting
  any evidence into the existing rule workflow.
- Release bodies need their own observation schema and cannot use the simpler
  immutable-file corpus adapter.
- A future distributor must add an inspection-only package type instead of
  appending observations to the existing constraints target.

### Neutral

- CNCF membership, upstream ownership, repository identity, component identity,
  an open-source project, and a hosted SaaS product remain separate declarations.
- Signed observation metadata, if added later, will authenticate publisher bytes
  without converting `reference_only`, `license_unreviewed`, or `NOT_ADMITTED`
  records into reviewed rules.

## Alternatives Considered

### Add unreviewed observations to the current signed rule target

- **Pros:** Reuses the current update and packaging flow with one target.
- **Cons:** Consumers already treat that target as executable knowledge, so the
  distinction would depend on every evaluator path filtering perfectly.
- **Why rejected:** The failure mode is an unsupported result that appears
  reviewed; structural separation is easier to verify than pervasive filtering.

### Require an accepted evidence packet before collection

- **Pros:** Every retained source would already have a bounded claim and reviewer.
- **Cons:** It preserves the manual tag, commit, hash, and span work that the
  self-service workflow is intended to remove and excludes useful public tips.
- **Why rejected:** Public-source discovery is useful before rule design and does
  not require repository control.

### Treat release bodies as immutable files at their release tag

- **Pros:** One corpus schema and one verification model.
- **Cons:** GitHub release bodies are database records, can be edited separately
  from Git commits, and do not have a commit-pinned blob URL.
- **Why rejected:** A fabricated commit binding would hide the exact mutation the
  revision model must preserve.

### Clone repositories and derive evidence from a checkout

- **Pros:** Familiar Git semantics and broad file discovery.
- **Cons:** Adds Git configuration, hooks, submodules, LFS, checkout, disk, and
  repository parser surfaces beyond the bounded evidence need.
- **Why rejected:** Fixed GitHub metadata requests plus commit-pinned raw files
  provide the required identity and bytes with a smaller attack surface.

## References

- [RFC-0001: Local public-project knowledge onboarding](../rfc/RFC-0001-public-project-knowledge-onboarding.md)
- [Source corpus](../source-corpus.md)
- [Community product contract](../product-contract.md)
