# Upgrade paths

An upgrade from one version to another is not always one step. The
Kubernetes control plane, for example, must not skip a minor version: an
upgrade from 1.24.17 to 1.30.4 passes through 1.25, 1.26, 1.27, 1.28 and
1.29. Each of those steps is a **hop**, and a rule can only speak about the
hops it covers.

An **upgrade-path policy** is a reviewed knowledge record that says how a
component's upgrades are formed. Prufyx uses it to split an upgrade into
hops. The policy itself never decides that a hop is safe; rules do that, one
hop at a time.

No command reads path policies to change an answer in this release, and the
published knowledge pack carries none. This page describes the record, the
planner and the checks a pack must pass, for contributors and maintainers.

## Policies

The vocabulary is closed. Any other value is rejected.

| Policy | Path from the actual version to the target | Example |
| --- | --- | --- |
| `sequential_minor` | one hop per minor line, within one major version | Kubernetes control plane |
| `direct` | one hop; the lines in between are not visited | a project whose upgrade guide allows skipping |
| `sequential_major` | one hop per major line, one hop within a major | a project that requires stepping through each major |

**Silence is never `direct`.** A component without a policy record gets one
hop from its actual version to the target, and that hop is not taken to be
enough on its own: if no rule decides it, the upgrade has a gap. Recording
`direct` takes a reviewer and a cited source that says skipping is allowed,
exactly like any other policy.

## Hops

The ends of a path are the exact versions you gave. Every end in between is a
whole **line**, never a made-up version, because you may stop at any release
of it:

```
1.24.17 -> 1.25      (hop 1)
1.25    -> 1.26      (hop 2)
1.26    -> 1.27      (hop 3)
1.27    -> 1.28      (hop 4)
1.28    -> 1.29      (hop 5)
1.29    -> 1.30.4    (hop 6)
```

Under `sequential_major` an intermediate end is a major line such as `2`.

Some upgrades cannot be planned, and are reported as a gap instead of hops:

| Gap | When |
| --- | --- |
| `DOWNGRADE_NOT_REVIEWED` | the target is below the actual version |
| `PATH_NOT_PLANNABLE` | either version is not `major.minor.patch`, both are equal, the policy is unknown or belongs to another component, a `sequential_minor` path crosses a major version (the last minor line of the old major is not known), or the path would need more than 64 hops |

A patch upgrade within one line is always one hop.

## When a rule decides a hop

A rule decides a hop only if it matches every upgrade the hop stands for:

- Between two exact versions, the rule must match that pair, by its reviewed
  pair or by its reviewed range.
- At a line end, the rule needs a reviewed range whose side contains the whole
  line: `gte` at or below `M.m.0` and `lt` at or above `M.(m+1).0`. The
  published Kubernetes ranges (`from [1.24.0, 1.25.0)`, `to [1.25.0, 1.26.0)`)
  cover whole lines. A rule without a range covers one exact pair and never
  decides a hop with a line end.
- A major-line end is never covered, because a reviewed range spans at most
  one minor line per side.

A rule **overlaps** a hop when it applies to at least one upgrade the hop
stands for: for example, a rule reviewed for exactly `1.25.7 -> 1.26.0`
overlaps the hop `1.25 -> 1.26`, because an operator who stopped at 1.25.7
takes that upgrade. A hop is decided only when every current rule of the
component that overlaps it also covers it. A rule that overlaps a hop
without covering it leaves the hop undecided, and a hop no rule decides stays
a gap; neither is ever reported as passing.

A rule reviewed for a whole multi-line upgrade (from the actual version
straight to the target) matches no single hop of a sequential plan; it still
applies to the upgrade as a whole and must not be lost when the upgrade is
split into hops.

## The record

```json
{
  "component": "pkg:github/kubernetes/kubernetes",
  "policy": "sequential_minor",
  "evidence": {
    "state": "active",
    "reviewedAt": "2026-10-04T00:00:00Z",
    "validUntil": "2027-01-02T00:00:00Z",
    "sources": [
      {
        "id": "kubernetes-website-version-skew-upgrade-order",
        "url": "https://github.com/kubernetes/website/blob/<commit>/content/en/releases/version-skew-policy.md",
        "revision": "<commit>",
        "contentDigest": "sha256:<whole-file digest>",
        "startLine": 189,
        "endLine": 193
      }
    ]
  }
}
```

- `component` is a package URL, and it must be the subject component of a
  project in the catalog: the same identity that project's rules use.
- `policy` is one of the three policies above.
- `evidence` has exactly the members and checks of a rule's evidence:
  `state` is `active` or `withdrawn`; `basis` is optional (`reviewed`, the
  default, or `mechanical` with `extractor` and `derivedAt`); `reviewedAt`
  and `validUntil` are UTC times, `validUntil` after `reviewedAt` and at most
  90 days later; `sources` cites one to eight pinned files, each with a
  40-character commit, an immutable GitHub URL at that commit, the whole
  file's sha256 and the line span that supports the policy.

A document of records is a non-empty JSON array with at most 256 records, at
most one per component, sorted by `component`. Parsing is exact: an unknown
or misspelled member (including a case variant such as `Policy`), a member
that repeats, a missing required member or a `null` value rejects the whole
document.

## Freshness

A record is evaluated at an explicit time, exactly as a rule's evidence is:

| Freshness | When |
| --- | --- |
| `withdrawn` | `evidence.state` is `withdrawn` |
| `clock_before_review` | the time is before `reviewedAt` |
| `stale` | the time is at or after `validUntil` |
| `current` | otherwise |

Only a `current` record is used to plan. A record that exists but is not
current is a gap of its own: the knowledge says how the component must be
upgraded and only its review has lapsed, so the upgrade is never planned as
one direct hop instead, and never passes.

## In a knowledge pack

Records go in an optional `pathPolicies` member of the CNCF rule pack. A
pack carries exactly the schema of the newest feature it uses:

| Feature | Pack schema |
| --- | --- |
| none of the below | `prufyx.io/cncf-source-rule-pack/v1alpha1` |
| a reviewed version range | `prufyx.io/cncf-source-rule-pack/v1alpha2` |
| a set-valued rule | `prufyx.io/cncf-source-rule-pack/v1alpha3` |
| line attestations | `prufyx.io/cncf-source-rule-pack/v1alpha4` |
| upgrade-path policies | `prufyx.io/cncf-source-rule-pack/v1alpha5` |
| a one-way notice rule | `prufyx.io/cncf-source-rule-pack/v1alpha6` |
| a consensus or lead rule | `prufyx.io/cncf-source-rule-pack/v1alpha7` |
| a support-range rule (`severity`) | `prufyx.io/cncf-source-rule-pack/v1alpha8` |
| distribution records ([kubernetes-distribution-versions.md](kubernetes-distribution-versions.md#distribution-records-and-applicability)) | `prufyx.io/cncf-source-rule-pack/v1alpha9` |
| served-API lists ([scan.md](scan.md#served-api-lists)) | `prufyx.io/cncf-source-rule-pack/v1alpha10` |

So a pack with path policies and no notice rule, with or without line
attestations, uses `v1alpha5`, and `v1alpha5` without path policies is refused. Binaries built
before path policies existed reject such a pack twice, for the unknown member
and the unknown schema. A pack without the member is byte-for-byte what it
was before.

The pack's top-level member names are matched exactly before decoding (see
[line-attestations.md](line-attestations.md#in-a-knowledge-pack)), and
`pathPolicies` is one of them. Any defect in the section, or a component that
is not a catalog subject component, rejects the whole pack. The pack digest
covers the section.

The external knowledge target format carries path policies in a records
envelope: `knowledge-targets build` puts each policy in the target of the
project whose component it names (see
[Records in project targets](cncf-knowledge-per-project.md#records-in-project-targets)).
A `v1alpha1` envelope with `pathPolicies` is refused. A reviewed record is renewed by
an automated `evidence reattest` statement, at most twice in a row, when its
citations are unchanged on their release lines (see
[evidence-reattestation.md](evidence-reattestation.md#line-attestations-and-path-policies));
`evidence repin` monitors its citations. A record that is not renewed
expires, and its paths become gaps again.

## For library callers

- `upgradepath.PlanPath(component, from, to, policy)` returns the plan: the
  hops, or a gap. Pass `nil` when the component has no current record.
- `cncfcheck.PathPolicyFor(component, now)` returns the embedded pack's
  record for a component with its freshness. Its `Policy()` is `nil` unless
  the record is current; pass that straight to `PlanPath`. `Found` is false
  when there is no record (plan one direct hop), and `RecordNotCurrent()` is
  true when a record exists but is not current (a gap: do not plan).
- `Hop.Overlaps(rule)` reports whether a rule matches at least one upgrade a
  hop stands for, and `Hop.CoveredBy(rule)` whether it matches every one.
  Select the rules of a hop with `Overlaps`, not by matching at `M.m.0`: a
  rule for another release of the line does not match there. The hop is
  decided only if every current overlapping rule also satisfies `CoveredBy`.
  `Endpoint.EngineVersion()` gives the concrete version that stands for a
  line end (`M.m.0`) in an engine input.
- `rulecheck.ValidatePathPolicies(document, options)` and
  `rulecheck.ValidatePackPathPolicies(pack, options)` report every problem
  the pack loader would reject, and, given a time, every record that is not
  current.
