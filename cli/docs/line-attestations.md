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
rule document with or without them. `scan` reads them to decide whether a
Kubernetes hop is covered for removed APIs, and whether a project's
custom-resource versions are decided on a hop (see
[custom-resources.md](custom-resources.md#line-reviews-of-custom-resource-versions));
no `check` route reads them. The published knowledge pack carries mechanical
attestations for every Kubernetes line from 1.20 to 1.37. Nine of them are
empty-list attestations (1.20, 1.21, 1.23, 1.24, 1.28, 1.30, 1.31, 1.35 and
1.36): minors in which no served API was removed. The other nine (1.22, 1.25,
1.26, 1.27, 1.29, 1.32, 1.33, 1.34 and 1.37) list the served-API removal rules
derived for that line. It carries none for other components.

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
| `releases` | Required for a release-scoped family (`crd.custom_resource_versions`), forbidden for any other. `from` and `to` each name 1 to 64 final releases, `{"version": "X.Y.Z", "commit": "<40 hex>"}`, of the previous minor line and of the line, in strictly ascending version order: every release the derivation read. |
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

The list is compiled into Prufyx. Adding a family is a code change. A family
has one or more components, and for each component the facts whose rules it
covers.

| Family | Components | Covers rules that read a fact matching | Releases |
| --- | --- | --- | --- |
| `kubernetes.removed_served_gvk` | `pkg:github/kubernetes/kubernetes` | `component.kubernetes.*_removed_gvk_present` | no |
| `crd.custom_resource_versions` | each project of the custom-resource table ([custom-resources.md](custom-resources.md#projects)) | exactly that project's `component.<project>.custom_resource_versions_set` | required |

`kubernetes.removed_served_gvk` covers beta and stable API versions that a
Kubernetes minor release stops serving. It says nothing about alpha
versions, aggregated or custom API servers, or CRDs.

`crd.custom_resource_versions` covers, per project, the custom-resource
versions (`group/version/Kind`) its own CustomResourceDefinitions serve. It
says nothing about schemas, conversion, stored versions, other projects'
CustomResourceDefinitions, or anything else about the project. A project
joins the family only through the reviewed custom-resource table (the same
change that registers its set fact). Its attestations are release-scoped:
they name the releases the derivation read, and cover a hop only between two
of them, so a release published later is a gap until the attestation is
renewed.

A community-catalog project of the table is a member of the family like a CNCF
one: membership follows the table row, not the catalog. A row whose component
the table lists twice, or that is not a valid component, admits nothing.
The attestations of a community project are stored in the CNCF rule pack,
next to its rules (the community-corpus pack and its record sections are not
used for them), and are admitted by the same proofs. The per-change cap
(200) and the daily limit (50) count every loosening record of every pack
together. An attestation also names the code digest of the extractor that
derived it, so after an extractor change a record with the old digest no
longer feeds the `complete` predicate of the ALL window until it is derived
again. Only that predicate reads the code digest; the A/B status does not.

A rule **belongs** to a family when its subject is one of the family's
components and it reads at least one of that component's facts in the
family, as its condition, set condition or an applicability condition. A rule that reads one family fact
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

The previous line comes from one function, `lineattest.PreviousLine`
(component, line). For an ordinary component it is `M.(m-1)`. A component
whose releases are named for the calendar month (a closed set in code; see
the release scheme `calver-edge` in
[extractors/crd.version-removal.md](extractors/crd.version-removal.md)) has
lines `YY.M`, and the line before `YY.1` is `(YY-1).12`. Every place that
checks a hop, the releases of an attestation, the release completeness of an
empty list, the coverage report and the scan, asks it. A calendar component
has no line-wide rules: the range arithmetic above is about minor lines of
one major, so such a component's family has no rule that covers a line and an
attestation of it lists no rule.

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
the pack. The external knowledge target format carries attestations in a
records envelope (`prufyx.io/operator-cncf-knowledge/v1alpha2`):
`knowledge-targets build` puts each attestation in the target of the
project whose component it names, and a client admits it with the same
exact-rule-set check (see
[Records in project targets](cncf-knowledge-per-project.md#records-in-project-targets)).
A `v1alpha1` envelope with `lineAttestations` is refused.

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

## Mechanical attestations from `crd.version-removal`

The [`crd.version-removal`](extractors/crd.version-removal.md) extractor
(version 2.1.0 and later) attests, for `crd.custom_resource_versions`, the
later line of every pair it derives completely (every release of both lines,
a clean scan of the whole repository at each, rules over both whole lines, no
removed definition), when the later line is the next minor line of the same
major and the project is in the custom-resource table. The attestation lists
the pair's rules and names every release read. As for Kubernetes, the
manifest records the attestation status of every pair, `attestations.json`
holds the attestations, and `extract verify` covers them.

## Empty-list attestations: admission

A mechanical attestation that lists no rule says that nothing was removed
between the two lines. The gate admits a new or changed one only when the
extractor it names re-derives that exact record from pinned upstream bytes
(as for any mechanical record) and all of these hold. A refused change carries
a detail that starts `empty-list/<code>:`, and the report has an extra check
named `empty-list` while a change holds such a record.

1. The target attests: the extractor, as compiled into the gate, declares the
   fact family and attests this component. A target that does not attest, or an
   unknown extractor, is refused.
2. The record names the extractor identity (id, version, code digest) that
   this gate ships.
3. Every cited source is an immutable blob URL of the extractor's repository at
   a full 40-hex revision, with a clean file path, no query or fragment, and a
   line span of at least one line; every release commit is a full 40-hex commit.
   The whole-file digests and spans are read from upstream by the citations
   check, and a finding there is attached to the record.
4. The record was derived inside the usual 24-hour window and stays valid for
   more than 14 days after the gate's clock.
5. The releases are complete, and the newest line of the change is empty (see
   below).

| Code | Refused because |
| --- | --- |
| `target-not-attesting` | the extractor is unknown, does not declare the family, or attests another component |
| `extractor-digest` | the extractor identity in the record is not the one the gate ships |
| `citation` | a source or release commit has a malformed URL, revision or span, or the citations check has a finding for the record |
| `freshness` | `derivedAt` is outside the window, or `validUntil` is not more than 14 days ahead |
| `releases-incomplete` | the tags the gate reads do not show exactly the releases or anchors the record names |
| `newest-pair-not-empty` | the newest empty-list line of a component and family in the change was not derived empty by the gate's own run |

Conditions 2 and 4, the form part of condition 3 and the target check run
before re-derivation, so a record they refuse is never re-derived; the
upstream part of condition 3 (digest and line span) is the citations check, and
an empty list is refused when that check did not run or did not pass. For the custom-resource family, the gate lists the final
release tags (`<prefix>X.Y.Z` for a prefix of the target, no pre-release or
suffix) of the previous minor line and of the line itself, and requires the
record's `releases.from` and `releases.to` to be exactly those, by version and
commit, in ascending order, one to 64 per side. A version tagged at two
commits, a matching tag without a full commit, or no release of a line
refuses the record. The Kubernetes family names no releases. The gate requires
final tags `v1.(L-1).0` and `v1.L.0` with full commits, requires the record's
`openapi-1-(L-1)-0` and `openapi-1-L-0` sources to cite exactly those commits,
requires `L-1` to be at least the extractor's first source minor, and refuses
the record when any final tag `v1.(L-1).*` or `v1.L.*` has no full commit. It
does not require the patch releases: it relies on Kubernetes removing served
API versions only at the `.0` release of a minor line.

If the change holds several empty-list records of one component and family,
the newest of them must be one the gate's own run derived empty. When it is
not, every empty-list record of the change is refused with
`newest-pair-not-empty`.

An empty Kubernetes list means that no beta or stable served API version was
removed between `v1.(L-1).0` and `v1.L.0`, as declared by the lifecycle files
and the OpenAPI specification of the two releases. A removal for which the
extractor has no adapter fact is not claimed absent: the line stays
unattested.

A reviewed (not mechanical) empty-list attestation is not affected: it still
needs a reattestation statement or an owner approval. The scheduled
`--rederive-all` run re-derives unchanged records and does not apply these
checks, since an unchanged record is not a loosening. Empty-list records count
as loosening changes toward the per-change cap and the daily limit like any
other record.

## Retracting an attestation

Retract a wrong attestation by withdrawing it (`evidence.state` `active` to
`withdrawn`): that is a tightening change the knowledge gate admits without a
proof, and the record stays in the pack. Do not delete it. Deleting a line
attestation is also a tightening, but when it is the last record that needs the
pack's current schema level, the pack's required schema level drops, and the gate
refuses a schema downgrade. Deleting the last record needs the owner path (an
owner-authored change, merged by the owner).

## Renewal

Attestations expire like rules, and must be renewed the same way.

- **Mechanical**: renewed by re-derivation. Run the same extractor build
  again against the same pinned tags with a new `--derived-at`; the
  attestation comes back with later `derivedAt`, `reviewedAt` and
  `validUntil` and nothing else changed. A new extractor version or build also changes
  `evidence.extractor`, which is a loosening change but not a plain renewal. `extract verify` proves it is reproducible from the pinned bytes.
  A person does not renew a mechanical attestation.
- **Mechanical, at a new extractor build**: when the extractor's code digest
  or version has moved, re-derive and apply with
  `extract apply --renew-attestations`. The run's attestation then replaces
  the stored one of the same component, line and family, in place, if and only
  if both are mechanical, the extractor id is the same, the code digest or
  version differs, the run's `derivedAt` is later, and component, line, fact
  family, completeness and `ruleIds` are identical. `releases` may only grow
  (every stored version and commit stays, in order; new patch releases are
  appended); `sources` and the lease may change. Anything else stays a
  collision, as without the flag; an identical re-run changes nothing. The
  flag also renews rules (next item) and does not combine with `--withdraw`,
  `--rules-only` or `--quiet-lines-only`. The gate sees one loosening change
  per record and admits it only under the conditions of a new mechanical
  attestation (re-derived byte for byte by the gate's own extractor build, its
  digest, `derivedAt` within 24 hours, `validUntil` more than 14 days away,
  complete releases). Each record counts toward the 200-per-change and
  50-per-day loosening caps and toward the weekly stagger cap, so set
  `--lease-days` per target to spread `validUntil` over ISO weeks.
- **Mechanical rules, at a new extractor build**: the same flag renews the
  run's rules. A rule whose id is already in the pack is replaced in place
  (the entry keeps its position) if and only if both entries are active,
  mechanical rules of the same extractor id derived at different builds
  (version or code digest); the entries are byte-identical once
  `rule.evidence.extractor`, `derivedAt`, `reviewedAt`, `validUntil` and
  `sources` are removed; the stored and the run's sources have the same set of
  source ids (URLs, revisions, digests and cited spans may change); the run's
  entry has a `derivedAt` strictly later than the stored entry's, `reviewedAt`
  equal to its `derivedAt`, and a `validUntil` after it. A withdrawn or
  reviewed stored rule, a changed body, another extractor and unreadable
  timestamps are a collision, as without the flag. `extract run` does not
  refuse such ids as taken when the packs hold them as active mechanical rules
  of the same extractor; every other check still applies, and `extract apply`
  re-validates the renewed entries with `rule validate`, with only that id
  check lifted for them. `extract apply` lists them as `renewed N rule(s)`,
  and a run that only renews still writes the pack. If the source ids differ
  there is no producer path: the owner edits the entry by hand, and the gate
  admits any mechanical change that its own build re-derives byte for byte
  within 24 hours. The gate sees a rule with an identical body and changed
  evidence as a loosening change (renew, re-pin or basis change), proven by
  re-deriving it at the gate's own build within 24 hours of `extract run`, with
  no approval. Each renewed rule counts toward the 200-per-change,
  50-per-day (automation-authored commits only) and weekly stagger caps.
  Scheduled `--rederive-all` runs fail for a rule left at an old extractor
  digest, which is why such rules must be renewed after an extractor change.
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
