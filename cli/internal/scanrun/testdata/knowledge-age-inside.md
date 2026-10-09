# BLOCKED: 1 problem must be fixed; 2 areas were not checked

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
| kubernetes | no reviewed list of the API versions Kubernetes 1.25 serves; 2 manifest(s) cannot be checked | check them against the API reference of that Kubernetes release by hand, or request coverage: https://github.com/prufyx/prufyx/issues/new?template=project-knowledge.yml |
| kubernetes 1.24.17 -> 1.25.3 | no review confirms that the removed-API rules for kubernetes 1.25 name every API that line removes | check the kubernetes 1.25 release notes for other removed APIs by hand, or request a line review |

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

Read 2 documents over 1 hop; 1 of 1 component has rules (partially evaluated). 6 checks passed (--show-passes).

Scope limits: node and kubelet version skew not evaluated; Kubernetes: only API versions in the supplied manifests are evaluated; live cluster objects, CRDs, stored versions, admission and component configuration are not.

Evidence: every finding cites pinned upstream source (--verbose). No network used.

<details>
<summary>Evidence and provenance</summary>

```
evaluated at: 2026-11-20T00:00:00Z
input: sha256:706abd92d4968558d52e272d3f490af7280ce84a6011ae824a9fa9ae7b4c47f7
knowledge: embedded cncf-2026-09-13.7 sha256:75c9a31b1f9611cfe70afe378415759e41e4e41dfefd7ce31389c584570b2d2b
engine contract: sha256:0d46478e7a818c192fa57367bf17bf5a066ec7e414d0b745e0f900fd319fd463
build: development
network used: no
```

</details>
