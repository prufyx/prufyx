# BLOCKED: 1 problem must be fixed; 2 areas were not checked

## PROBLEMS TO FIX (1)

### kubernetes 1.24.17 -> 1.30.4: 6 hops (path policy sequential\_minor)

| Hop | Problem | Where | Fix |
| --- | --- | --- | --- |
| 1.24.17 -> 1.25 | Kubernetes 1.25 stops serving CronJob through batch/v1beta1 | `applyset.yaml:1` `CronJob default/nightly-report` | Migrate the named CronJob manifests to batch/v1. Reassess the complete target apply set. Validate admission, CRDs, stored objects, runtime clients, and API-server configuration separately. |

## NOT CHECKED (2)

| Area | What | Next step |
| --- | --- | --- |
| kubernetes | 1 manifest(s) use API versions that the review of Kubernetes 1.30 does not list as served | check those API versions against the Kubernetes 1.30 API reference by hand |
| kubernetes | 2 document(s) contain unrendered templates | render them (for example with helm template) and scan the output |

## SOURCES

| Rules | Source | Lines | Revision |
| --- | --- | --- | --- |
| `kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0` | <https://github.com/kubernetes/kubernetes/blob/4ce5a8954017644c5420bae81d72b09b735c21f0/staging/src/k8s.io/api/batch/v1beta1/zz_generated.prerelease-lifecycle.go> | 48-74 | `4ce5a8954017` |
| `kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0` | <https://github.com/kubernetes/kubernetes/blob/4ce5a8954017644c5420bae81d72b09b735c21f0/api/openapi-spec/swagger.json> | 1-90087 | `4ce5a8954017` |
| `kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0` | <https://github.com/kubernetes/kubernetes/blob/a866cbe2e5bbaa01cfd5e969aa3e033f3282a8a2/api/openapi-spec/swagger.json> | 1-81603 | `a866cbe2e5bb` |

Read 2 documents over 6 hops; 1 of 1 component has rules (partially evaluated).

Scope limits: node and kubelet version skew not evaluated; Kubernetes: only API versions in the supplied manifests are evaluated; live cluster objects, CRDs, stored versions, admission and component configuration are not.

Evidence: every finding cites pinned upstream source (--verbose). No network used.

<details>
<summary>Evidence and provenance</summary>

```
evaluated at: 2026-11-15T00:00:00Z
input: sha256:b98fcd349edbc6da86b0c9d4b792af158ac5c7558db0015339077cc23daec186
knowledge: embedded cncf-0000-00-00.0 sha256:0000000000000000000000000000000000000000000000000000000000000000
engine contract: sha256:0d46478e7a818c192fa57367bf17bf5a066ec7e414d0b745e0f900fd319fd463
build: development
network used: no
```

</details>
