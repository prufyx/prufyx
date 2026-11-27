# PASS FOR THE DECLARED SCOPE (Kubernetes API versions in the supplied manifests only; not a whole-upgrade pass)

## Jump kubernetes

- kubernetes 1.24.17 -> 1.30.4: STEPWISE\_PASS, every hop of the stepwise path is decided; not a statement about a direct jump
- hop 1 1.24.17 -> 1.25: PASS
- hop 2 1.25 -> 1.26: PASS
- hop 3 1.26 -> 1.27: PASS
- hop 4 1.27 -> 1.28: PASS
- hop 5 1.28 -> 1.29: PASS
- hop 6 1.29 -> 1.30.4: PASS
- decided by hop 1, 2, 3, 4, 5, 6
- scope: composed from the hops of the planned path through the named releases, from the reviewed removed-API rules, line reviews and one-way notices that apply to each hop, for the objects of the manifests as they are today; a direct skip of a release line, other patch releases of an intermediate line, behaviour changes without a removed API, and gaps the report lists outside any hop are not part of a pass; kubelet skew not checked: no kubelet version is declared (--kubelet-version-min, --kubelet-version-max)

Read 2 documents over 6 hops; 1 of 1 component has rules. 11 checks passed (--show-passes).

Scope limits: node and kubelet version skew not evaluated; Kubernetes: only API versions in the supplied manifests are evaluated; live cluster objects, CRDs, stored versions, admission and component configuration are not.

Evidence: every finding cites pinned upstream source (--verbose). No network used.

<details>
<summary>Evidence and provenance</summary>

```
evaluated at: 2001-01-01T00:00:00Z
input: sha256:f97b2da482d3ad4454ea833ec04bdf3e2b1b8e8a7daecc26b9ea26c8142261c1
knowledge: embedded cncf-0000-00-00.0 sha256:0000000000000000000000000000000000000000000000000000000000000000
engine contract: sha256:ddae9a60600415a2a294a3ac9a4a5d6d2348625bbb245e46d435d4d04a9c5fb4
build: development
network used: no
```

</details>
