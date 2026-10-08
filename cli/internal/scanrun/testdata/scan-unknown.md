# NO BLOCKERS FOUND IN COVERED CHECKS: 2 areas were not checked

## NOT CHECKED (2)

| Area | What | Next step |
| --- | --- | --- |
| kubernetes 1.27 -> 1.28 | kubernetes 1.28 has not been reviewed for removed APIs | check the kubernetes 1.28 release notes for removed APIs by hand, or request coverage |
| kubernetes 1.29 -> 1.30.4 | kubernetes 1.30 has not been reviewed for removed APIs | check the kubernetes 1.30 release notes for removed APIs by hand, or request coverage |

Checked 6 hops, 2 documents, 1 component (1 covered). 11 checks passed (--show-passes).

Scope limits: node and kubelet version skew not evaluated; Kubernetes: only API versions in the supplied manifests are evaluated; live cluster objects, CRDs, stored versions, admission and component configuration are not.

Evidence: every finding cites pinned upstream source (--verbose). No network used.

<details>
<summary>Evidence and provenance</summary>

```
evaluated at: 2026-10-04T00:00:00Z
input: sha256:f97b2da482d3ad4454ea833ec04bdf3e2b1b8e8a7daecc26b9ea26c8142261c1
knowledge: embedded cncf-2026-09-13.4 sha256:4d2718043fbc41bb0f99ce8a69ea9ef253c52249bb88254b969d1ebdab46e5c5
engine contract: sha256:0d46478e7a818c192fa57367bf17bf5a066ec7e414d0b745e0f900fd319fd463
build: development
network used: no
```

</details>
