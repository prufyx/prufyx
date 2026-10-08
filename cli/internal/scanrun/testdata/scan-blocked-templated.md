# BLOCKED: 1 problem must be fixed before this upgrade

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

Checked 6 hops, 2 documents, 1 component (1 covered).

Scope limits: node and kubelet version skew not evaluated; Kubernetes: only API versions in the supplied manifests are evaluated; live cluster objects, CRDs, stored versions, admission and component configuration are not.

Evidence: every finding cites pinned upstream source (--verbose). No network used.

<details>
<summary>Evidence and provenance</summary>

```
evaluated at: 2026-10-04T00:00:00Z
input: sha256:b98fcd349edbc6da86b0c9d4b792af158ac5c7558db0015339077cc23daec186
knowledge: embedded cncf-2026-09-13.4 sha256:b8bca5facdc3081165459bc726fe269e1321abb4690dbe0be090bc313850d548
engine contract: sha256:2cc7bb0052068bd2668d1c4419782bacd6fcbf34e73f9bf9cf08206cd1363fa6
build: development
network used: no
```

</details>
