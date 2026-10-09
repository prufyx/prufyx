# BLOCKED: 3 problems must be fixed; 3 areas were not checked

> trust policy: evidence basis reviewed, mechanical only; 2 rule(s) that apply were left out, so the result cannot pass
>
> trust policy: 1 unverified lead(s) not shown; add lead to --require-basis to list them
>
> 1 finding(s) rely on model consensus

## PROBLEMS TO FIX (3)

### kubernetes 1.24.17 -> 1.30.4: 2 hops (path policy sequential\_minor)

| Hop | Problem | Where | Fix |
| --- | --- | --- | --- |
| 1.24.17 -> 1.25 | Kubernetes 1.25 stops serving CronJob through batch/v1beta1 | `deploy/app 0.yaml:1` `CronJob prod/job-0`<br>`deploy/app 1.yaml:2` `CronJob prod/job-1`<br>`deploy/app 2.yaml:3` `CronJob prod/job-2`<br>`deploy/app 3.yaml:4` `CronJob prod/job-3`<br>`deploy/app 4.yaml:5` `CronJob prod/job-4`<br>... and 2 more | Migrate the manifest to batch/v1. |
| 1.24.17 -> 1.25 | PodSecurityPolicy \| is removed | `psp.yaml#0/2` `PodSecurityPolicy restricted` | Use Pod Security Admission. |
| whole upgrade 1.24.17 -> 1.30.4 | Whole upgrade rule | `w.yaml:3` `Thing (no name)` | Do the thing. |

## NOT CHECKED (3)

| Area | What | Next step |
| --- | --- | --- |
| etcd | etcd is not evaluated by scan yet | run prufyx check cncf --project etcd, or verify its upgrade notes by hand |
| kubernetes | the kubernetes manifests are not declared to be the complete set you apply | if they are, add resourceScopeComplete: true to prufyx.yaml or pass --resource-scope-complete |
| kubernetes 1.25 -> 1.26 | rule kubernetes.x could not be decided (STALE) | run the hop with prufyx check cncf to see the rule's next action, or check by hand |

## ONE-WAY CHANGES (2)

| Area | Rule | What |
| --- | --- | --- |
| kubernetes 1.25 -> 1.26 | `kubernetes.notice-a` | This is a one-way change that cannot be rolled back. Before you upgrade: Back up etcd first. |
| kubernetes 1.25 -> 1.26 | `kubernetes.notice-b` | A one-way change was not established (NO\_DATA). Next action: Run the check by hand. |

## UNSUPPORTED COMBINATIONS (1)

| Area | Rule | What |
| --- | --- | --- |
| kubernetes 1.25 -> 1.26 | `kubernetes.support-a` | Outside a documented support range: node skew over 3 minor versions. Fix: Upgrade nodes first. |

## UNVERIFIED LEADS (1)

| Area | Rule | What |
| --- | --- | --- |
| kubernetes 1.24.17 -> 1.25 | `kubernetes.lead-a` | Unverified lead; it does not block. Worth checking: Look at the ingress class. |

## SOURCES

| Rules | Source | Lines | Revision |
| --- | --- | --- | --- |
| `kubernetes.cronjob-removed` | <https://example.test/blob/0123456789abcdef0123456789abcdef01234567/doc.md> | 87-90 | `0123456789ab` |
| `kubernetes.cronjob-removed`<br>`kubernetes.psp-removed` | <https://example.test/blob/0123456789abcdef0123456789abcdef01234567/doc.md> | 189-192 | `0123456789ab` |
| `kubernetes.whole` | <https://example.test/blob/0123456789abcdef0123456789abcdef01234567/doc.md> | 5-8 | `0123456789ab` |
| `kubernetes.support-a` | <https://example.test/blob/0123456789abcdef0123456789abcdef01234567/doc.md> | 40-43 | `0123456789ab` |
| `kubernetes.notice-a` | <https://example.test/blob/0123456789abcdef0123456789abcdef01234567/doc.md> | 9-12 | `0123456789ab` |
| `kubernetes.lead-a` | <https://example.test/blob/0123456789abcdef0123456789abcdef01234567/doc.md> | 1-4 | `0123456789ab` |

Read 9 documents over 2 hops; 1 of 1 component has rules (partially evaluated). 1 check passed (--show-passes).

Scope limits: node and kubelet version skew not evaluated.

note: 1 input file is readable by other users; use --input-permissions strict to refuse them

Evidence: every finding cites pinned upstream source (--verbose). No network used.

<details>
<summary>Evidence and provenance</summary>

```
evaluated at: 2026-10-04T00:00:00Z
input: sha256:1111111111111111111111111111111111111111111111111111111111111111
config: sha256:2222222222222222222222222222222222222222222222222222222222222222
knowledge: embedded rev-1 sha256:3333333333333333333333333333333333333333333333333333333333333333
engine contract: sha256:4444444444444444444444444444444444444444444444444444444444444444
build: 1.2.3
network used: no
```

</details>
