# BLOCKED: 1 problem must be fixed; 2 areas were not checked

## PROBLEMS TO FIX (1)

### kubernetes 1.24.17 -> 1.30.4: 6 hops (path policy sequential\_minor)

| Hop | Problem | Where | Fix |
| --- | --- | --- | --- |
| 1.24.17 -> 1.25 | Kubernetes 1.25 stops serving CronJob through batch/v1beta1 | `applyset.yaml:1` `CronJob default/nightly-report` | Migrate the named CronJob manifest to batch/v1, then reassess the complete target apply set. Validate admission, CRDs, stored objects, runtime clients, and API-server configuration separately. |

## NOT CHECKED (2)

| Area | What | Next step |
| --- | --- | --- |
| kubernetes | 1 manifest(s) use API versions that the review of Kubernetes 1.30 does not list as served | check those API versions against the Kubernetes 1.30 API reference by hand |
| kubernetes | 2 document(s) contain unrendered templates | render them (for example with helm template) and scan the output |

## SOURCES

| Rules | Source | Lines | Revision |
| --- | --- | --- | --- |
| `kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0` | <https://github.com/kubernetes/website/blob/9f1af2971c32124bff0a1f42255ba5a2f3c8a16f/content/en/docs/reference/using-api/deprecation-guide.md> | 87-93 | `9f1af2971c32` |
| `kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0` | <https://github.com/kubernetes/website/blob/9f1af2971c32124bff0a1f42255ba5a2f3c8a16f/content/en/releases/version-skew-policy.md> | 189-193 | `9f1af2971c32` |

Read 2 documents over 6 hops; 1 of 1 component has rules (partially evaluated).

Scope limits: node and kubelet version skew not evaluated; Kubernetes: only API versions in the supplied manifests are evaluated; live cluster objects, CRDs, stored versions, admission and component configuration are not.

Evidence: every finding cites pinned upstream source (--verbose). No network used.

<details>
<summary>Evidence and provenance</summary>

```
evaluated at: 2026-11-20T00:00:00Z
input: sha256:b98fcd349edbc6da86b0c9d4b792af158ac5c7558db0015339077cc23daec186
knowledge: embedded cncf-2026-09-13.5 sha256:8c4d7dadfe538923310663c8c261bdf70ba5568956e6c2f096eeaaca9c13173e
engine contract: sha256:0d46478e7a818c192fa57367bf17bf5a066ec7e414d0b745e0f900fd319fd463
build: development
network used: no
```

</details>
