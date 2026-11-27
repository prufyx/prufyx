# BLOCKED: 1 problem must be fixed; 1 area was not checked

## PROBLEMS TO FIX (1)

### kubernetes 1.24.17 -> 1.30.4: 6 hops (path policy sequential\_minor)

| Hop | Problem | Where | Fix |
| --- | --- | --- | --- |
| 1.24.17 -> 1.25 | Kubernetes 1.25 stops serving CronJob through batch/v1beta1 | `applyset.yaml:1` `CronJob default/nightly-report` | Migrate the named CronJob manifests to batch/v1. Reassess the complete target apply set. Validate admission, CRDs, stored objects, runtime clients, and API-server configuration separately. |

## Jump kubernetes

- kubernetes 1.24.17 -> 1.30.4: BLOCKED on the stepwise path (hop 1 decides); a direct skip was not evaluated
- hop 1 1.24.17 -> 1.25: BLOCKED kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0
- hop 2 1.25 -> 1.26: UNDECIDED (API\_VERSION\_NOT\_REVIEWED)
- hop 3 1.26 -> 1.27: UNDECIDED (API\_VERSION\_NOT\_REVIEWED)
- hop 4 1.27 -> 1.28: UNDECIDED (API\_VERSION\_NOT\_REVIEWED)
- hop 5 1.28 -> 1.29: UNDECIDED (API\_VERSION\_NOT\_REVIEWED)
- hop 6 1.29 -> 1.30.4: UNDECIDED (API\_VERSION\_NOT\_REVIEWED)
- decided by hop 1
- missing for hop 2: API\_VERSION\_NOT\_REVIEWED; next: check those API versions against the Kubernetes 1.30 API reference by hand
- missing for hop 3: API\_VERSION\_NOT\_REVIEWED; next: check those API versions against the Kubernetes 1.30 API reference by hand
- missing for hop 4: API\_VERSION\_NOT\_REVIEWED; next: check those API versions against the Kubernetes 1.30 API reference by hand
- missing for hop 5: API\_VERSION\_NOT\_REVIEWED; next: check those API versions against the Kubernetes 1.30 API reference by hand
- missing for hop 6: API\_VERSION\_NOT\_REVIEWED; next: check those API versions against the Kubernetes 1.30 API reference by hand
- scope: composed from the hops of the planned path through the named releases, from the reviewed removed-API rules, line reviews and one-way notices that apply to each hop, for the objects of the manifests as they are today; a direct skip of a release line, other patch releases of an intermediate line, behaviour changes without a removed API, and gaps the report lists outside any hop are not part of a pass; kubelet skew not checked: no kubelet version is declared (--kubelet-version-min, --kubelet-version-max)

## NOT CHECKED (1)

| Area | What | Next step |
| --- | --- | --- |
| kubernetes | 1 manifest(s) use API versions that the review of Kubernetes 1.30 does not list as served | check those API versions against the Kubernetes 1.30 API reference by hand |

## SOURCES

| Rules | Source | Lines | Revision |
| --- | --- | --- | --- |
| `kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0` | <https://github.com/kubernetes/kubernetes/blob/4ce5a8954017644c5420bae81d72b09b735c21f0/staging/src/k8s.io/api/batch/v1beta1/zz_generated.prerelease-lifecycle.go> | 48-74 | `4ce5a8954017` |
| `kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0` | <https://github.com/kubernetes/kubernetes/blob/4ce5a8954017644c5420bae81d72b09b735c21f0/api/openapi-spec/swagger.json> | 1-90087 | `4ce5a8954017` |
| `kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0` | <https://github.com/kubernetes/kubernetes/blob/a866cbe2e5bbaa01cfd5e969aa3e033f3282a8a2/api/openapi-spec/swagger.json> | 1-81603 | `a866cbe2e5bb` |

Read 2 documents over 6 hops; 1 of 1 component has rules (partially evaluated). 10 checks passed (--show-passes).

Scope limits: node and kubelet version skew not evaluated; Kubernetes: only API versions in the supplied manifests are evaluated; live cluster objects, CRDs, stored versions, admission and component configuration are not.

Evidence: every finding cites pinned upstream source (--verbose). No network used.

<details>
<summary>Evidence and provenance</summary>

```
evaluated at: 2001-01-01T00:00:00Z
input: sha256:706abd92d4968558d52e272d3f490af7280ce84a6011ae824a9fa9ae7b4c47f7
knowledge: embedded cncf-0000-00-00.0 sha256:0000000000000000000000000000000000000000000000000000000000000000
engine contract: sha256:ddae9a60600415a2a294a3ac9a4a5d6d2348625bbb245e46d435d4d04a9c5fb4
build: development
network used: no
```

</details>
