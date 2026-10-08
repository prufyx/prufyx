# BLOCKED: 1 problem must be fixed before this upgrade

## PROBLEMS TO FIX (1)

### kubernetes 1.24.17 -> 1.25.3: 1 hop (no reviewed path policy)

| Hop | Problem | Where | Fix |
| --- | --- | --- | --- |
| 1.24.17 -> 1.25.3 | Kubernetes 1.25 stops serving CronJob through batch/v1beta1 | `applyset.yaml:1` `CronJob default/nightly-report` | Migrate the named CronJob manifest to batch/v1, then reassess the complete target apply set. Validate admission, CRDs, stored objects, runtime clients, and API-server configuration separately. |

## HOPS

### kubernetes 1.24.17 -> 1.25.3: 1 hop (no reviewed path policy)

| Hop | Status |
| --- | --- |
| 1.24.17 -> 1.25.3 | BLOCKED (LINE\_NOT\_ATTESTED) |

## NOT CHECKED (2)

| Area | What | Next step |
| --- | --- | --- |
| kubernetes | no reviewed list of the API versions Kubernetes 1.25 serves; 2 manifest(s) cannot be checked | check them against the Kubernetes 1.25 API reference by hand, or request coverage |
| kubernetes 1.24.17 -> 1.25.3 | kubernetes 1.25 has not been reviewed for removed APIs | check the kubernetes 1.25 release notes for removed APIs by hand, or request coverage |

## PASSED (6)

- kubernetes 1.24.17 -> 1.25.3 `kubernetes.endpointslice-v1beta1-removed.1-24-0-to-1-25-0`
- kubernetes 1.24.17 -> 1.25.3 `kubernetes.event-v1beta1-removed.1-24-0-to-1-25-0`
- kubernetes 1.24.17 -> 1.25.3 `kubernetes.hpa-v2beta1-removed.1-24-0-to-1-25-0`
- kubernetes 1.24.17 -> 1.25.3 `kubernetes.pdb-v1beta1-removed.1-24-0-to-1-25-0`
- kubernetes 1.24.17 -> 1.25.3 `kubernetes.psp-v1beta1-removed.1-24-0-to-1-25-0`
- kubernetes 1.24.17 -> 1.25.3 `kubernetes.runtimeclass-v1beta1-removed.1-24-0-to-1-25-0`

## SOURCES

| Rules | Source | Lines | Revision |
| --- | --- | --- | --- |
| `kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0` | <https://github.com/kubernetes/website/blob/9f1af2971c32124bff0a1f42255ba5a2f3c8a16f/content/en/docs/reference/using-api/deprecation-guide.md> | 87-93 | `9f1af2971c32` |
| `kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0` | <https://github.com/kubernetes/website/blob/9f1af2971c32124bff0a1f42255ba5a2f3c8a16f/content/en/releases/version-skew-policy.md> | 189-193 | `9f1af2971c32` |

Checked 1 hop, 2 documents, 1 component (1 covered). 6 checks passed (--show-passes).

Scope limits: node and kubelet version skew not evaluated; Kubernetes: only API versions in the supplied manifests are evaluated; live cluster objects, CRDs, stored versions, admission and component configuration are not.

Evidence: every finding cites pinned upstream source (--verbose). No network used.

<details>
<summary>Evidence and provenance</summary>

```
evaluated at: 2026-11-20T00:00:00Z
input: sha256:706abd92d4968558d52e272d3f490af7280ce84a6011ae824a9fa9ae7b4c47f7
knowledge: embedded cncf-2026-09-13.4 sha256:49d715bf400ab7030216bae7973abc63a44b6c5f0eaf0a1fb1a7ed54695d080d
engine contract: sha256:2cc7bb0052068bd2668d1c4419782bacd6fcbf34e73f9bf9cf08206cd1363fa6
build: development
network used: no
```

</details>
