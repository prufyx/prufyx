# Line attestations

A **line attestation** is a statement about the knowledge pack, not about an
upstream project: for one component, one minor release line and one fact
family, the rules it lists are *all* the rules the pack holds. An empty list
means the pack holds none, because nothing in that family changes on that
line.

Without it, Prufyx cannot tell "nothing in scope was removed in 1.28" from
"nobody looked at 1.28". With it, a line that has been looked at, and found
quiet, can be told apart from a line that is simply missing.

Attestations never take part in a rule's verdict. The engine sees the same
rule document with or without them, and no command in this release reads
them to change an answer. The published knowledge pack carries none.

## The record

```json
{
  "component": "pkg:github/kubernetes/kubernetes",
  "line": "1.31",
  "factFamily": "kubernetes.removed_served_gvk",
  "completeness": "COMPLETE_REVIEWED_RULES_FOR_LINE",
  "ruleIds": [],
  "evidence": {
    "basis": "mechanical",
    "extractor": {"id": "k8s.served-api-removal", "version": "1.1.0", "codeDigest": "sha256:..."},
    "derivedAt": "2026-10-03T00:00:00Z",
    "reviewedAt": "2026-10-03T00:00:00Z",
    "validUntil": "2027-01-01T00:00:00Z",
    "sources": [
      {"id": "openapi-1-30-0", "url": "https://github.com/kubernetes/kubernetes/blob/<commit>/api/openapi-spec/swagger.json",
       "revision": "<commit>", "contentDigest": "sha256:...", "startLine": 1, "endLine": 123456},
      {"id": "openapi-1-31-0", "url": "...", "revision": "<commit>", "contentDigest": "sha256:...", "startLine": 1, "endLine": 123999}
    ]
  }
}
```

| Field | Rule |
| --- | --- |
| `component` | Must be the component of the fact family. |
| `line` | A minor line, `major.minor` (`1.31`), no leading zeros. |
| `factFamily` | One of the families listed below. Any other value is rejected. |
| `completeness` | Always `COMPLETE_REVIEWED_RULES_FOR_LINE`. |
| `ruleIds` | Rule ids in strictly ascending order, no repeats, at most 256. Required, and `[]` for a quiet line (never `null`). |
| `evidence.basis` | Required: `reviewed` (a maintainer read the sources) or `mechanical` (a versioned extractor derived it from pinned source). |
| `evidence.extractor`, `evidence.derivedAt` | Required for `mechanical`, forbidden for `reviewed`. A mechanical attestation's `reviewedAt` equals its `derivedAt`. |
| `evidence.reviewedAt`, `evidence.validUntil` | UTC, `YYYY-MM-DDTHH:MM:SSZ`. `validUntil` is after `reviewedAt` and at most 90 days later, the same window as a rule. |
| `evidence.sources` | One to eight sources, exactly as a rule's: ascending ids, a pinned 40-hex commit, an immutable GitHub URL at that commit, the whole file's `sha256`, and a line span. |

Parsing is exact: every required member must be present, member names are
case-sensitive (no case or Unicode folding), a member may not repeat, no
value may be `null`, and unknown members are rejected.

A document is a non-empty array in canonical order (component, then fact
family, then line in numeric order, so `1.9` comes before `1.10`), with at
most one attestation per component, line and family.

## Fact families

The list is compiled into Prufyx. Adding a family is a code change.

| Family | Component | Covers rules that read a fact matching |
| --- | --- | --- |
| `kubernetes.removed_served_gvk` | `pkg:github/kubernetes/kubernetes` | `component.kubernetes.*_removed_gvk_present` |

`kubernetes.removed_served_gvk` covers beta and stable API versions that a
Kubernetes minor release stops serving. It says nothing about alpha
versions, aggregated or custom API servers, or CRDs.

A rule **belongs** to a family when its subject is the family's component
and it reads at least one of the family's facts, as its condition, set
condition or an applicability condition. A rule that reads one family fact
and another unrelated fact still belongs, so it must be listed.

A rule **belongs** to a line through the minor line of its `subject.to`.
A rule from `1.24.0` to `1.25.0` (with or without a range) belongs to `1.25`.

## The exact-set rule

For each attestation, `ruleIds` must equal, as a set, the pack's rules that
belong to its component, line and family:

- a rule the pack holds for that scope and the attestation leaves out fails
  (`attestation-missing-rule`): the attestation would hide it;
- a listed id the pack does not hold for that scope (unknown, on another
  line, or in another family) fails (`attestation-extra-rule`).

A withdrawn rule is still in the pack and must still be listed.

## Every listed rule covers the whole line

Equal sets are not enough: a listed rule must also match **every** upgrade
into the line, or an upgrade it does not match would find no rule while the
line is attested. For `kubernetes.removed_served_gvk` an upgrade into line
`M.m` starts on the previous minor line (Kubernetes upgrades one minor line
at a time), so a listed rule must carry a version range with

```
range.from.gte <= M.(m-1).0   and   M.m.0     <= range.from.lt
range.to.gte   <= M.m.0       and   M.(m+1).0 <= range.to.lt
```

Range bounds are half-open (`gte <= version < lt`), exactly as rule matching
uses them, so this range matches every release of the previous line going to
every release of the line. A rule without a range matches only its own
anchor pair (for example `1.31.0` to `1.32.0`, not `1.31.4` to `1.32.1`) and
is not line-wide. A listed rule that is not line-wide fails
(`attestation-rule-not-line-wide`). A line on which the pack holds such a
rule cannot be attested at all: listing the rule fails this check and
leaving it out fails the exact set. A line `M.0` has no previous minor line
in its major and cannot be attested.

A planner that uses an attestation must still evaluate each listed rule for
the upgrade's actual versions: a listed rule that does not match the
upgrade, or does not reach a verdict, makes that upgrade a gap, never
covered.

The check runs when a pack is loaded (one mismatch rejects the whole pack),
inside every extractor run that emits attestations, and through
`rulecheck.ValidateLineAttestations` / `ValidatePackAttestations` for
maintainer tooling. Those functions can also report an attestation that is
not current at a given time (`attestation-not-current`).

## Freshness

An attestation is evaluated like a rule's evidence:

| At time `now` | Freshness |
| --- | --- |
| before `reviewedAt` | `clock_before_review` |
| from `reviewedAt` up to, not including, `validUntil` | `current` |
| at or after `validUntil` | `stale` |

Only a `current` attestation may be relied on. A stale attestation is
treated as if it were absent: the line is a gap again, never a pass.

## In a knowledge pack

Attestations go in an optional `lineAttestations` member of the CNCF rule
pack. A pack that carries it must use the schema
`prufyx.io/cncf-source-rule-pack/v1alpha4` (which also allows ranged and
set-valued rules), or the schema of a newer feature it also carries (see
[upgrade-paths.md](upgrade-paths.md#in-a-knowledge-pack)); that schema is
refused without attestations, and attestations are refused under any other
schema. Binaries built before
attestations existed reject such a pack, both for the unknown member and the
unknown schema, so an attested pack can never be read as an unattested one.
A pack without the member is byte-for-byte what it was before.

The pack's own top-level member names are matched exactly before the pack is
decoded, by the same function in the pack loader and in
`rulecheck.ValidatePackAttestations`: any name that is not exactly one of
`schema`, `revision`, `policyId`, `policyDigest`, `landscapeFileDigest`,
`registryDigest`, `entries`, `lineAttestations`, `pathPolicies` or
`distributions` (for example
`LineAttestations`, or a spelling that only matches under Unicode case
folding), and any name that repeats, rejects the pack. So every reader sees
the same attestation section, or none.

The pack digest covers the attestations, as it covers every other byte of
the pack. The external knowledge target format does not carry attestations
yet: an external pack with `lineAttestations` is refused, and so is a pack
with attestations given to `knowledge-targets build`.

Library callers look attestations up with
`cncfcheck.AttestationsFor(component, line, family, now)`, which returns the
attestation (at most one) with its freshness, or nothing when the line is not
attested.

## Mechanical attestations from `k8s.served-api-removal`

The [`k8s.served-api-removal`](extractors/k8s.served-api-removal.md)
extractor (version 1.1.0 and later) attests every line it derives, for the
family `kubernetes.removed_served_gvk`:

- `ruleIds` are exactly the rules the run derived for that line (empty for a
  quiet line);
- the sources are the whole OpenAPI specification at both release tags: the
  extractor has already checked that every beta or stable kind that leaves
  the specification is a declared removal;
- the attestation carries the same provenance and lease as the run's rules.

It does **not** attest a line when the pair is withheld, or when a removal
on that line has no adapter fact (and therefore no rule): attesting it
would claim the rules are complete while one removal has none. The manifest
records, for every pair, `"attestation": {"status": "attested" | "not-attested",
"line", "families", "reason"}`. The attestations are written to
`attestations.json`, whose digest is in the manifest; `extract verify`
re-derives the run and reports the file if a single byte differs. A run that
attests no line (for example, every pair withheld) writes no
`attestations.json`, since an attestation document is never empty; `extract
verify` then reports a stray `attestations.json` as not produced by the
re-derivation.

Every rule the extractor emits has a range over the whole previous minor
line and the whole target line, so its attestations pass the line-wide
check.

An extractor's attestation is complete relative to that extractor's rules.
Placed in a pack that also holds other rules for the same line and family
(for example, reviewed rules for the same removals), it fails the exact-set
check until the two are reconciled: either the attestation lists every rule,
or the duplicates are removed.

## Renewal

Attestations expire like rules, and must be renewed the same way.

- **Mechanical**: renewed by re-derivation. Run the same extractor build
  again against the same pinned tags with a new `--derived-at`; the
  attestation comes back with later `derivedAt`, `reviewedAt` and
  `validUntil` and nothing else changed. A new extractor version or build also changes
  `evidence.extractor`, which is a loosening change but not a plain renewal. `extract verify` proves it is reproducible from the pinned bytes.
  A person does not renew a mechanical attestation.
- **Reviewed**: renewed by an automated `evidence reattest` statement, when
  `evidence repin` finds every cited source unchanged on its release line, at
  most twice in a row (see
  [evidence-reattestation.md](evidence-reattestation.md#line-attestations-and-path-policies)).
  Only `evidence.reviewedAt` and `evidence.validUntil` change, and the
  attestation must still list exactly the pack's rules for its scope. Any
  other change is a new review.

Every change between two attestation sets is classified by
`lineattest.Classify`. Each set may hold at most one attestation per
component, line and family; a set with two is an error.

| Change | Class |
| --- | --- |
| an attestation removed | tightening |
| `validUntil` earlier, or `reviewedAt` later, and nothing else changed | tightening |
| an attestation added | loosening |
| `reviewedAt` later, `derivedAt` later (when present) and `validUntil` later, nothing else changed (a renewal; `Renewal` is set) | loosening |
| `validUntil` later without a later `reviewedAt`/`derivedAt`, or either moved earlier (backdating) | loosening, not a renewal |
| any change to `ruleIds`, sources, basis or extractor | loosening |

A tightening change can only turn a covered line back into a gap. A
loosening change can make an answer rely on an attestation; for a mechanical
attestation it is acceptable only with a reproducible derivation behind it,
and for a reviewed one only after a person's review.

## What an attestation never claims

- That an upgrade is safe, or anything about runtime behaviour.
- Anything about other fact families, other components, or patch releases.
- Completeness after `validUntil`.
