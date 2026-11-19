# UNKNOWN: no blocker in the checks that ran; 2 areas were not checked (see NOT CHECKED)

## Jump kubernetes

- kubernetes 1.24.17 -> 1.30.4: UNKNOWN, at least one hop of the stepwise path is not decided; every hop is listed
- hop 1 1.24.17 -> 1.25: PASS
- hop 2 1.25 -> 1.26: PASS
- hop 3 1.26 -> 1.27: PASS
- hop 4 1.27 -> 1.28: UNDECIDED (LINE\_NOT\_ATTESTED)
- hop 5 1.28 -> 1.29: PASS
- hop 6 1.29 -> 1.30.4: UNDECIDED (LINE\_NOT\_ATTESTED)
- missing for hop 4: LINE\_NOT\_ATTESTED; next: check the kubernetes 1.28 release notes for other removed APIs by hand, or request a line review
- missing for hop 6: LINE\_NOT\_ATTESTED; next: check the kubernetes 1.30 release notes for other removed APIs by hand, or request a line review
- scope: composed from the hops of the planned path through the named releases, from the reviewed removed-API rules, line reviews and one-way notices that apply to each hop, for the objects of the manifests as they are today; a direct skip of a release line, other patch releases of an intermediate line, behaviour changes without a removed API, and gaps the report lists outside any hop are not part of a pass; kubelet skew not checked: no kubelet version is declared (--kubelet-version-min, --kubelet-version-max)

## NOT CHECKED (2)

| Area | What | Next step |
| --- | --- | --- |
| kubernetes 1.27 -> 1.28 | no review confirms that the removed-API rules for kubernetes 1.28 name every API that line removes | check the kubernetes 1.28 release notes for other removed APIs by hand, or request a line review |
| kubernetes 1.29 -> 1.30.4 | no review confirms that the removed-API rules for kubernetes 1.30 name every API that line removes | check the kubernetes 1.30 release notes for other removed APIs by hand, or request a line review |

Read 2 documents over 6 hops; 1 of 1 component has rules (partially evaluated). 11 checks passed (--show-passes).

Scope limits: node and kubelet version skew not evaluated; Kubernetes: only API versions in the supplied manifests are evaluated; live cluster objects, CRDs, stored versions, admission and component configuration are not.

Evidence: every finding cites pinned upstream source (--verbose). No network used.

<details>
<summary>Evidence and provenance</summary>

```
evaluated at: 2001-01-01T00:00:00Z
input: sha256:f97b2da482d3ad4454ea833ec04bdf3e2b1b8e8a7daecc26b9ea26c8142261c1
knowledge: embedded cncf-0000-00-00.0 sha256:0000000000000000000000000000000000000000000000000000000000000000
engine contract: sha256:0d46478e7a818c192fa57367bf17bf5a066ec7e414d0b745e0f900fd319fd463
build: development
network used: no
```

</details>
