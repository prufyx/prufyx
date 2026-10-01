# Declared review-record consistency gate

`prufyx-maintainer review-record verify` is an offline, read-only gate for one
CNCF rule. It proves that a closed declared decision is consistent with the
existing contribution, retained-source, embedded-target, and evaluator
contracts. It does not authenticate the named maintainer or perform promotion.

The v1 command is deliberately narrow:

```text
prufyx-maintainer review-record verify \
  --record RECORD.json \
  --packet PACKET.json \
  --landscape LANDSCAPE.json \
  --source-manifest CORPUS.json \
  --source-root OBJECTS \
  --vectors REVIEWED-VECTORS.json \
  --target CONSTRAINTS.json
```

The named options may appear in any order. Each is required exactly once;
unknown options and positional arguments are rejected. Run
`prufyx-maintainer review-record verify --help` for local usage. Parse and
verification failures emit only a fixed rejection message, never supplied
paths or record values.

Inputs are local regular files. The command uses no network, keys, client
configuration, store, or subprocess. It recomputes the existing candidate
packet receipt, packet-source receipt, and source-corpus receipt. Every corpus
record must point in both directions to the same packet and selected rule, with
the exact source kind, endpoint version, commit, URL, full-file digest, and
span digest. A rule source's existing `contentDigest` must recompute as either
that exact full file or that exact raw-LF span; its URL, revision, and line
range must also match. Every selected rule source must match exactly one packet
span and vice versa.

The supplied target must byte-for-byte equal
`cncfcheck.ExportEmbeddedExternalBundle` at the record's positive revision.
Parsing some other structurally valid target is insufficient. The record binds
both the complete vector file bytes and the canonical selected vector group.
The verifier executes every selected case at the declared evaluation clock and
requires observed PASS, BLOCKED, and UNKNOWN cases plus wrong-current and
wrong-target UNKNOWN cases. Malformed input remains parser rejection and cannot
be counted as UNKNOWN. V1 reports malformed-input coverage as a separate
`NOT_CHECKED` parser gate; its focused negative test proves that malformed input
cannot satisfy the selected vector group.

Receipt digest fields bind the canonical receipt JSON without a trailing LF,
independent of how a CLI redirected it. The record is a closed JSON object:

```json
{
  "schema": "prufyx.io/declared-knowledge-review-record/v1",
  "decision": {
    "authority": "DECLARED_MAINTAINER_DECISION_NOT_AUTHENTICATED",
    "state": "ACCEPTED_FOR_SIGNING_REVIEW",
    "maintainer": "PUBLIC REVIEW FIXTURE",
    "decidedAt": "2026-09-13T08:00:00Z",
    "scope": "ONE_RULE_CONSISTENCY_ONLY"
  },
  "subject": {
    "project": "PROJECT",
    "ruleId": "RULE_ID",
    "knowledgeRevision": "73",
    "evaluationAt": "2026-09-13T08:00:00Z"
  },
  "bindings": {
    "packetDigest": "sha256:...",
    "packetReceiptDigest": "sha256:...",
    "sourceReceiptDigest": "sha256:...",
    "sourceCorpusManifestDigest": "sha256:...",
    "sourceCorpusReceiptDigest": "sha256:...",
    "vectorFileDigest": "sha256:...",
    "selectedVectorGroupDigest": "sha256:...",
    "targetDigest": "sha256:...",
    "engineCapabilityDigest": "sha256:...",
    "ruleDigest": "sha256:...",
    "ruleEvidenceDigest": "sha256:..."
  }
}
```

`maintainer` is a declared public display name, not an authenticated identity.
It must be valid printable Unicode, 1-128 UTF-8 bytes, with no leading or
trailing whitespace, path separators, control characters, formatting
characters, or line separators. Rejecting those values prevents a local path
or terminal-control value from being copied into the path-free receipt.

On success the canonical receipt says `consistency: VALID`, preserves the
declared `ACCEPTED_FOR_SIGNING_REVIEW` decision, and reports
`processAuthorization: DECLARED_NOT_AUTHENTICATED`. Readiness is scoped to the
one rule. The receipt states `baselineCandidateDelta: NOT_CHECKED`,
`fullTargetAdmission: NOT_DETERMINED`, `signing: NOT_PERFORMED`, and
`storeSelection: NOT_PERFORMED`.

These states are separate:

- **Consistency** means the supplied bytes, digests, identities, source roles,
  rule, and executed cases agree.
- **Process authorization** is still a declaration until an external process
  authenticates the maintainer and decision.
- **Engine compatibility** covers only the selected rule and cases under the
  compiled engine capability.
- **Signing** needs separately chosen key custody, recovery, and signing steps.
- **Store selection** remains a local client decision under an independently
  bootstrapped trust root.

Source-only proposals remain `NOT_REVIEWED` and `NOT_ADMITTED`; the verifier
rejects them as review packets. A PASS case is evidence for one predicate, not
identity admission or whole-upgrade approval. Existing Markdown review records
remain valid process notes, and existing candidate receipts keep their current
vocabulary. This additive schema does not rewrite them.

V1 covers the exported CNCF constraints target only. Neutral community-project
rules still live in the embedded batch path and cannot use this contract. That
architecture gap must be resolved before claiming one universal signed feed.

The implementation acceptance run exercised the public production command end
to end for the existing Crossplane composition-resources transition, using its
complete two-source set from previously retained immutable bytes. It also
rejected an unrelated parser-valid target mutation through that same command.
This proves usability of the gate and adds no project, rule, transition, or
adoption coverage. Karmada remains a focused existing-behavior vector fixture;
its incomplete candidate source set is correctly rejected by the full gate.

Rollback is removal of this command, package, and documentation. The gate does
not mutate another schema, client configuration, source corpus, rule pack,
knowledge store, or signed metadata, so rollback has no data migration.
