# Upstream review record template

Copy this template beside a candidate packet and fill it with declared values
and hashes. Keep the packet and record as private review evidence until the
maintainer decides otherwise. Every digest covers the exact bytes named.

## Packet and catalogue binding

- Packet path: `PATH`
- Packet raw SHA-256 (exact file bytes, including any final LF): `sha256:...`
- Packet canonical JSON SHA-256 (validator canonical bytes, without a final LF): `sha256:...`
- Offline validator receipt path and SHA-256: `PATH`, `sha256:...`
- Validator receipt fields: `consistency: VALID`; `workflowState: CANDIDATE` (exit `0`)
- Pinned Landscape revision: `40-hex revision` for `existing_project_transition`;
  `NOT_APPLICABLE` for `new_catalogue_identity_proposal`
- Landscape file SHA-256: `sha256:...` for `existing_project_transition`;
  `NOT_APPLICABLE` for `new_catalogue_identity_proposal` (the validator does not
  read Landscape for that kind and its receipt has `landscapeDigest: null`)
- Optional retained source-corpus receipt path and SHA-256: `PATH`, `sha256:...` / `NONE`
- Optional collection receipt path and SHA-256: `PATH`, `sha256:...` / `NONE`

These fields bind files for review. They do not authenticate a contributor or
reviewer, promote a candidate, or authorize signing, publication, or training.

## Identity and exact transition

- Project slug and display name: `...`
- Canonical catalogue repository: `https://github.com/OWNER/REPO`
- Submission kind (copy the packet value): `...`
- Local catalogue consistency: `matched pinned local identity` / `not applicable for new proposal`.
  This checks local slug/repository consistency only; catalogue status and
  contributor identity remain unverified.
- For `existing_project_transition`, current endpoint: version `...`, tag `...`, annotated tag object `...` or `DIRECT_COMMIT`, peeled commit `40-hex`
- For `existing_project_transition`, proposed endpoint: version `...`, tag `...`, annotated tag object `...` or `DIRECT_COMMIT`, peeled commit `40-hex`
- Transition direction and exact scope: `...` for `existing_project_transition`;
  `NOT_APPLICABLE` for `new_catalogue_identity_proposal` (its packet must have
  `transition: null` and an empty `tagBindings` array)

Record a tag-to-commit check only after independently retrieving the official
tag reference and peeling it to the commit used by each immutable source URL.
If a source is context rather than an endpoint, label its version
`reference_only` and explain why.

## Independent source checks

Add one row per source file. Add intermediate or dry-run material as a separate
row with `role: intermediate_attachment`; it must never be relabelled as the
current or proposed endpoint source.

| Role | Version | Source kind | Immutable blob URL | Peeled commit | Full-file SHA-256 / bytes | Raw-LF spans (`start-end`, digest) | Retrieved UTC | Result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `current_endpoint` / `proposed_endpoint` / `intermediate_attachment` | `...` | `...` | `https://github.com/.../blob/<40-hex>/...` | `...` | `sha256:...` / `...` | `...` | `YYYY-MM-DDThh:mm:ssZ` | `PASS / FAIL / UNKNOWN` |

Source review notes:

- Primary official source and repository relationship: `...`
- Exact parser, schema, migration, or call-path lines supporting the claim:
  `...`
- Raw-LF span rule used: selected lines joined with LF, with no separator after
  the final selected line.
- Historical or context material deliberately excluded from the endpoint
  claim: `...` / `NONE`
- Source limitations and unresolved identity/tag questions: `...`

The source row proves only what the reviewer checked in the retained bytes. It
does not by itself prove compatibility, runtime behavior, licence terms, or
maintainer authority.

## Scoped claim and vectors

Complete this section only when proposing a scoped rule for an existing project
transition. For a new catalogue identity proposal, record `NOT_APPLICABLE`;
identity intake adds no rule or transition coverage.

- Rule ID, if a rule is proposed: `...` / `NO RULE`
- Proposed constraint and existing compiled operator: `rule ID / closed operator / exact predicate`
- Exact subject and current/proposed version endpoints: `...`
- Registered facts, type, and compiled owner: `fact.id = value`
- Input authority and fact state: the complete input authority is
  `OPERATOR_DECLARED_MINIMIZED`; each fact state is exactly `declared`,
  `missing`, `unsupported`, or `conflict`. Rule source evidence identifies
  reviewed source references; it is not fact authority.
- Proposed intent and deployment/configuration surface: `...`
- What a scoped `PASS` proves: `...`
- What a scoped `BLOCKED` proves: `...`
- Missing, unsupported, ambiguous, custom or outside-scope valid input:
  scoped `UNKNOWN` with the bounded reason `...`
- Malformed input: parser rejection with its error and CLI exit `2` recorded
  separately; it produces no scoped claim.
- Explicit non-claims (runtime, stored-object migration, full workload validity,
  image provenance, or other omitted surface): `...`

List distinct canonical input cases. Do not count labels or notes as distinct
inputs, and do not make a missing fact mean `false`.

| Case | Input digest | Current/proposed side | Declared facts | Expected scoped result or separate parser rejection | Bounded reason or next action |
| --- | --- | --- | --- | --- | --- |
| `positive / blocked / missing / unsupported / outside` | `sha256:...` | `...` | `...` | `PASS / BLOCKED / UNKNOWN` | `...` |
| `malformed input` | `sha256:...` | `...` | `...` | No claim; record parser error and CLI exit `2` | `...` |

## Review roles and technical acceptance

Each role is a separate review step. An identity and timestamp are declarations
until the surrounding process authenticates them.

| Role | Identity | UTC time | Evidence path and SHA-256 | Decision / limits |
| --- | --- | --- | --- | --- |
| Independent source reviewer | `...` | `...` | `...` | `PASS / CHANGES / REJECT`; source limits |
| Builder or vector reviewer | `...` | `...` | `...` | `PASS / CHANGES / REJECT`; case limits |
| Implementation reviewer | `...` | `...` | `...` | `PASS / CHANGES / REJECT`; code scope |
| Maintainer technical acceptance | `...` | `...` | `...` | `ACCEPTED / PENDING / REJECTED`; exact scope |

## Reproduction and remaining gates

- Source retrieval/check commands and working directory: `...`
- Actual source revision or binary path and SHA-256: `...`
- Test commands, exit codes, and output/log SHA-256: `...`
- Test UTC and whether the result was local, offline, or networked: `...`
- Runtime, cluster, customer-data, credential, network, and model surfaces not
  exercised: `...`
- Remaining gates before any data change: `...`
- Separate signing/publication decision and owner: `PENDING / ...`
- Next falsifiable test and stopping condition: `...`

The record is review evidence only. It does not change the packet validator,
create a knowledge rule, authenticate upstream sources, authorize a model,
sign data, publish a feed, or grant permission to retain customer data.
