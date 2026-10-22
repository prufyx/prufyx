# BLOCKED: 1 problem must be fixed; 1 area was not checked

## PROBLEMS TO FIX (1)

### kubernetes 1.24.17 -> 1.25.3: 1 hop (no reviewed path policy)

| Hop | Problem | Where | Fix |
| --- | --- | --- | --- |
| 1.24.17 -> 1.25.3 | Kubernetes 1.25 stops serving CronJob through batch/v1beta1 | `applyset.yaml:1` `CronJob default/nightly-report` | Migrate the named CronJob manifests to batch/v1. Reassess the complete target apply set. Validate admission, CRDs, stored objects, runtime clients, and API-server configuration separately. |

## HOPS

### kubernetes 1.24.17 -> 1.25.3: 1 hop (no reviewed path policy)

| Hop | Status |
| --- | --- |
| 1.24.17 -> 1.25.3 | BLOCKED |

## NOT CHECKED (1)

| Area | What | Next step |
| --- | --- | --- |
| kubernetes | 1 manifest(s) use API versions not in the Kubernetes 1.25 served list, stable (GA) versions only | check those API versions against the Kubernetes 1.25 API reference by hand |

## PASSED (6)

- kubernetes 1.24.17 -> 1.25.3 `kubernetes.served-api-removal.autoscaling-v2beta1.1-24-0-to-1-25-0`
- kubernetes 1.24.17 -> 1.25.3 `kubernetes.served-api-removal.discovery-k8s-io-v1beta1.1-24-0-to-1-25-0`
- kubernetes 1.24.17 -> 1.25.3 `kubernetes.served-api-removal.events-k8s-io-v1beta1.1-24-0-to-1-25-0`
- kubernetes 1.24.17 -> 1.25.3 `kubernetes.served-api-removal.node-k8s-io-v1beta1.1-24-0-to-1-25-0`
- kubernetes 1.24.17 -> 1.25.3 `kubernetes.served-api-removal.policy-v1beta1-pdb.1-24-0-to-1-25-0`
- kubernetes 1.24.17 -> 1.25.3 `kubernetes.served-api-removal.policy-v1beta1-psp.1-24-0-to-1-25-0`

## SOURCES

| Rules | Source | Lines | Revision |
| --- | --- | --- | --- |
| `kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0` | <https://github.com/kubernetes/kubernetes/blob/4ce5a8954017644c5420bae81d72b09b735c21f0/staging/src/k8s.io/api/batch/v1beta1/zz_generated.prerelease-lifecycle.go> | 48-74 | `4ce5a8954017` |
| `kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0` | <https://github.com/kubernetes/kubernetes/blob/4ce5a8954017644c5420bae81d72b09b735c21f0/api/openapi-spec/swagger.json> | 1-90087 | `4ce5a8954017` |
| `kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0` | <https://github.com/kubernetes/kubernetes/blob/a866cbe2e5bbaa01cfd5e969aa3e033f3282a8a2/api/openapi-spec/swagger.json> | 1-81603 | `a866cbe2e5bb` |

Read 2 documents over 1 hop; 1 of 1 component has rules (partially evaluated). 6 checks passed (--show-passes).

Scope limits: node and kubelet version skew not evaluated; Kubernetes: only API versions in the supplied manifests are evaluated; live cluster objects, CRDs, stored versions, admission and component configuration are not.

Evidence: every finding cites pinned upstream source (--verbose). No network used.

<details>
<summary>Evidence and provenance</summary>

```
evaluated at: 2026-12-05T00:00:00Z
input: sha256:706abd92d4968558d52e272d3f490af7280ce84a6011ae824a9fa9ae7b4c47f7
knowledge: embedded cncf-0000-00-00.0 sha256:0000000000000000000000000000000000000000000000000000000000000000
engine contract: sha256:0d46478e7a818c192fa57367bf17bf5a066ec7e414d0b745e0f900fd319fd463
build: development
network used: no
```

</details>
