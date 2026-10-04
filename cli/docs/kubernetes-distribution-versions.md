# Kubernetes distribution versions

Prufyx can turn a distribution's version string into the upstream Kubernetes
version it is built on. Only the formats below are accepted. Anything else is
rejected; Prufyx does not guess.

| Distribution | Accepted format | Example | Needs a declared distribution? |
| --- | --- | --- | --- |
| `official_upstream` | `v1.N.P` or `1.N.P` | `v1.29.3` | no (default for a bare version) |
| `kubeadm` | same as upstream | `v1.29.3` | yes |
| `talos` | same as upstream | `v1.29.3` | yes |
| `aks` | `1.N.P` or `v1.N.P` | `1.29.4` | yes |
| `eks` | `v1.N.P-eks-<7 lowercase hex>` | `v1.29.3-eks-adc7111` | no |
| `gke` | `1.N.P-gke.<build>` (optional `v`, as the API server reports it) | `1.29.3-gke.1093000` | no |
| `k3s` | `v1.N.P+k3s<n>` | `v1.29.4+k3s1` | no |
| `rke2` | `v1.N.P+rke2r<n>` | `v1.29.4+rke2r1` | no |
| `openshift` | `4.M` or `4.M.P` | `4.16.3` | yes |

Rules:

- Numbers are plain decimals without leading zeros (`v1.029.3` is rejected)
  and at most six digits; build and release numbers (`<build>`, `<n>`) must be
  at least 1 and at most nine digits.
- Pre-release or build suffixes that are not in the table (`-rc.1`, `+meta`)
  are rejected, as are incomplete markers such as `v1.29.3-eks`, `+k3s` or
  `+rke2r`.
- If a distribution is declared and the string clearly belongs to another one
  (for example `v1.29.4+k3s1` declared as `rke2`), the result is an error.
  A bare version declared as `eks`, `gke`, `k3s` or `rke2` is also an error,
  because those distributions are recognised by their suffix.
- OpenShift versions are mapped to a Kubernetes minor through a built-in
  table. If the OpenShift minor is not in the table the result is "unknown",
  and the patch version of Kubernetes is never reported for OpenShift.

Each successful result reports the distribution, the raw string, the upstream
version and how it was derived: `exact` (the string identifies itself),
`declared` (the distribution came from your declaration) or `mapped`
(OpenShift table).

## Distribution records and applicability

Knowing which distribution a cluster runs does not tell Prufyx that the
distribution behaves like upstream Kubernetes. That needs reviewed knowledge,
kept in an optional `distributions` section of the CNCF rule pack. The
published pack carries no such section yet, so the lookups below report only
`official_upstream` and `kubeadm` as upstream; for every other distribution,
no rule family is treated as checked the upstream way.

The section holds two lists:

```json
{
  "records": [
    { "distribution": "openshift", "controlPlane": "self_managed",
      "kubernetesMapping": [ { "line": "4.16", "kubernetes": "1.29" } ],
      "evidence": { "state": "active", "reviewedAt": "…", "validUntil": "…", "sources": [ … ] } }
  ],
  "applicability": [
    { "distribution": "eks", "family": "kubernetes.removed_served_gvk", "status": "applies",
      "evidence": { … } }
  ]
}
```

(The values above only show the shape; they are not shipped statements.)

- A **record** states one distribution's identity: its id from the table
  above, its control plane (`managed` or `self_managed`; `eks`, `gke` and
  `aks` are always `managed`, `k3s`, `rke2` and `talos` always
  `self_managed`), and for `openshift` only, an optional mapping of
  OpenShift minor lines (`4.N`) to Kubernetes minor lines (`1.M`), strictly
  increasing in both. A mapping never gives a patch version.
  `official_upstream` and `kubeadm` take no record.
- An **applicability statement** says that one rule family `applies` or is
  `not_applicable` to one distribution, with an optional `reason` of at most
  256 bytes. It needs a record for the same distribution in the section.
  The families are `kubernetes.removed_served_gvk`,
  `kubernetes.flow_control_api`, `kubernetes.component_flags`,
  `kubernetes.feature_gates`, `kubernetes.component_config` and
  `kubernetes.node`.

Absence is never a pass:

- A distribution without a current record, or a family without a current
  `applies` statement for it, is not checked the upstream way: it is a gap.
- `not_applicable` is also a gap, with its reason. It never removes a family
  from a check and never contributes to a PASS.
- A record or statement that has expired, was withdrawn, or is dated after
  the time of the check is treated as absent. Freshness is computed as for a
  rule: `withdrawn`, then `clock_before_review`, then `stale` from
  `validUntil` on.
- An OpenShift mapping is used only while the OpenShift record is current;
  otherwise an OpenShift version stays "unknown".

Every record and statement carries the evidence block of a rule: `state`,
optional `basis`, `reviewedAt`, `validUntil` (at most 90 days later) and one
to eight sources pinned to a Git commit with a whole-file digest. Provider
documentation that is not in a Git repository cannot be cited yet, so such a
distribution stays a gap until a pinned statement exists.

The section is read strictly: unknown, misspelt, repeated or `null` members,
an unknown distribution, family, status or control plane, records or
statements out of order or repeated, more than 64 records, more than 512
statements, a bad time or a source that is not pinned to a Git commit
reject the whole pack. A pack with the section uses the schema
`prufyx.io/cncf-source-rule-pack/v1alpha9` (see the table in
[upgrade-paths.md](upgrade-paths.md#in-a-knowledge-pack)); a pack without it
is byte-for-byte what it was before, and the pack digest covers the section.

For now the section is fenced off everywhere it cannot yet be handled: the
external knowledge target format and `knowledge-targets build` refuse a pack
with it, `evidence reattest` and `evidence repin` refuse it (its records are
not renewed and expire), the support inventory refuses it, and the knowledge
gate treats any change to it as a change to a top-level pack member, which it
never admits. Maintainers can validate a section with
`rulecheck.ValidateDistributions`, or the section of a whole pack with
`rulecheck.ValidatePackDistributions`; with fetching enabled, every source
gets the same online check a rule source gets.

For library callers, `distribution.Index.ApplicabilityFor(distribution,
family, now)` answers one question, and only a result whose `Applies()` is
true may be checked as upstream. `Index.OpenShiftTable(now)` gives the
current OpenShift mapping for `k8sversion.ParseWith(raw, declared, table)`,
which behaves exactly as `k8sversion.Parse` when the table is nil.
