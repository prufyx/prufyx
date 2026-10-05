# NO BLOCKERS FOUND IN COVERED CHECKS: 7 areas were not checked

## NOT CHECKED (7)

| Area | What | Next step |
| --- | --- | --- |
| etcd | etcd is not evaluated by scan yet | run prufyx check cncf --project etcd, or verify its upgrade notes by hand |
| kubernetes | 1 manifest(s) use API versions that the review of Kubernetes 1.30 does not list as served | check those API versions against the Kubernetes 1.30 API reference by hand |
| kubernetes | it is not declared that these manifests are applied to the target kubernetes API | if they are, add targetApplyRequired: true to prufyx.yaml or pass --target-api-apply-required |
| kubernetes | the kubernetes distribution is not declared | for upstream builds, add distribution: official\_upstream to prufyx.yaml or pass --distribution official\_upstream |
| kubernetes | the kubernetes manifests are not declared to be the complete set you apply | if they are, add resourceScopeComplete: true to prufyx.yaml or pass --resource-scope-complete |
| kubernetes | 1 document(s) contain unrendered templates | render them (for example with helm template) and scan the output |
| kubernetes 1.27 -> 1.28 | kubernetes 1.28 has not been reviewed for removed APIs | check the kubernetes 1.28 release notes for removed APIs by hand, or request coverage |

## ONE-WAY CHANGES (1)

| Area | Rule | What |
| --- | --- | --- |
| kubernetes 1.25 -> 1.26 | `kubernetes.synthetic-notice.1-25-0-to-1-26-0` | This is a one-way change that cannot be rolled back. Before you upgrade: Back up etcd before you start; the stored objects are rewritten. |

## SOURCES

| Rules | Source | Lines | Revision |
| --- | --- | --- | --- |
| `kubernetes.synthetic-notice.1-25-0-to-1-26-0` | <https://github.com/kubernetes/website/blob/9f1af2971c32124bff0a1f42255ba5a2f3c8a16f/content/en/releases/version-skew-policy.md> | 189-193 | `9f1af2971c32` |

Checked 6 hops, 2 documents, 2 components (1 covered).

Scope limits: node and kubelet version skew not evaluated; Kubernetes: only API versions in the supplied manifests are evaluated; live cluster objects, CRDs, stored versions, admission and component configuration are not.

note: 1 input file is readable by other users; use --input-permissions strict to refuse them

Evidence: every finding cites pinned upstream source (--verbose). No network used.

<details>
<summary>Evidence and provenance</summary>

```
evaluated at: 2026-10-04T00:00:00Z
input: sha256:e82ec12fddc5793f21b09d3c46f07b142b8bd96ab4ea1c1e338133948dd8a07d
knowledge: embedded cncf-2026-09-13.4 sha256:4d2718043fbc41bb0f99ce8a69ea9ef253c52249bb88254b969d1ebdab46e5c5
engine contract: sha256:2cc7bb0052068bd2668d1c4419782bacd6fcbf34e73f9bf9cf08206cd1363fa6
build: development
network used: no
```

</details>
