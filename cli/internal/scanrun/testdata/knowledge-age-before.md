# NO BLOCKERS FOUND IN COVERED CHECKS: 9 areas were not checked

## HOPS

### kubernetes 1.24.17 -> 1.25.3: 1 hop (no reviewed path policy)

| Hop | Status |
| --- | --- |
| 1.24.17 -> 1.25.3 | PARTIAL (EVIDENCE\_EXPIRED, LINE\_NOT\_ATTESTED) |

## NOT CHECKED (9)

| Area | What | Next step |
| --- | --- | --- |
| kubernetes | no reviewed list of the API versions Kubernetes 1.25 serves; 2 manifest(s) cannot be checked | check them against the Kubernetes 1.25 API reference by hand, or request coverage |
| kubernetes 1.24.17 -> 1.25.3 | the review of rule kubernetes.served-api-removal.autoscaling-v2beta1.1-24-0-to-1-25-0 is not current (clock\_before\_review) | use a Prufyx release with current knowledge, or check this change by hand |
| kubernetes 1.24.17 -> 1.25.3 | the review of rule kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0 is not current (clock\_before\_review) | use a Prufyx release with current knowledge, or check this change by hand |
| kubernetes 1.24.17 -> 1.25.3 | the review of rule kubernetes.served-api-removal.discovery-k8s-io-v1beta1.1-24-0-to-1-25-0 is not current (clock\_before\_review) | use a Prufyx release with current knowledge, or check this change by hand |
| kubernetes 1.24.17 -> 1.25.3 | the review of rule kubernetes.served-api-removal.events-k8s-io-v1beta1.1-24-0-to-1-25-0 is not current (clock\_before\_review) | use a Prufyx release with current knowledge, or check this change by hand |
| kubernetes 1.24.17 -> 1.25.3 | the review of rule kubernetes.served-api-removal.node-k8s-io-v1beta1.1-24-0-to-1-25-0 is not current (clock\_before\_review) | use a Prufyx release with current knowledge, or check this change by hand |
| kubernetes 1.24.17 -> 1.25.3 | the review of rule kubernetes.served-api-removal.policy-v1beta1-pdb.1-24-0-to-1-25-0 is not current (clock\_before\_review) | use a Prufyx release with current knowledge, or check this change by hand |
| kubernetes 1.24.17 -> 1.25.3 | the review of rule kubernetes.served-api-removal.policy-v1beta1-psp.1-24-0-to-1-25-0 is not current (clock\_before\_review) | use a Prufyx release with current knowledge, or check this change by hand |
| kubernetes 1.24.17 -> 1.25.3 | kubernetes 1.25 has not been reviewed for removed APIs | check the kubernetes 1.25 release notes for removed APIs by hand, or request coverage |

Checked 1 hop, 2 documents, 1 component (1 covered).

Scope limits: node and kubelet version skew not evaluated; Kubernetes: only API versions in the supplied manifests are evaluated; live cluster objects, CRDs, stored versions, admission and component configuration are not.

Evidence: every finding cites pinned upstream source (--verbose). No network used.

<details>
<summary>Evidence and provenance</summary>

```
evaluated at: 2026-11-06T00:00:00Z
input: sha256:706abd92d4968558d52e272d3f490af7280ce84a6011ae824a9fa9ae7b4c47f7
knowledge: embedded cncf-2026-09-13.4 sha256:54c40b58a69b6f99126b0dab01c99d2bf6be00a0f53adc57922a81640da17684
engine contract: sha256:2cc7bb0052068bd2668d1c4419782bacd6fcbf34e73f9bf9cf08206cd1363fa6
build: development
network used: no
```

</details>
