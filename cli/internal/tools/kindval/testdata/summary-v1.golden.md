# KIND-VAL results

Generated 1970-01-01T00:00:00Z; prufyx abc.

| Line | Server | Served APIs | Served-API claims | Removal (verdict) claims | CRD claims |
|---|---|---|---|---|---|
| 1.31 | v1.31.14 | 4 | 1 ok / 0 bad | - | - |
| 1.32 | v1.32.11 | 2 | 1 ok / 1 bad | 1 ok / 1 bad | 5 ok / 0 bad |

Claims: 8 confirmed, 2 refuted, 2 undetermined, 0 error. Findings: 1 HIGH, 2 MEDIUM, 0 INFO.

## Served-API changes between consecutive lines

- 1.31 -> 1.32: 2 removed, 0 added, 1 removed without a claim
  - removed: flowcontrol.apiserver.k8s.io/v1beta3 FlowSchema
  - removed: h.example/v1beta1 K

## Findings

- HIGH removal.passed: 1.31.14 -> 1.32.11: the scan PASSES h.example/v1beta1 K, which 1.31 serves and 1.32 rejects
- MEDIUM diff.1.32.h-example_v1beta1_K: line 1.32 no longer serves h.example/v1beta1 K (served by 1.31); no claim names it
- MEDIUM k8s.1.32.apps_v1_Deployment.not_served: line 1.32 (v1.32.11): the claim says apps/v1 Deployment is not_served, the API server says served
