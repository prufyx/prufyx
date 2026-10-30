# Prufyx Community v0.1.0-beta.0

**Public beta pre-release.** This is a build for testers. Expect gaps, and
read "Known limitations" before relying on a result. A result is a scoped
finding about the rules that were checked, not a statement that a whole upgrade
is safe. The [beta tester guide](https://github.com/prufyx/prufyx/blob/main/cli/docs/beta-tester-guide.md) walks through install,
the main commands and how to report a wrong answer.

Prufyx checks a planned upgrade of Kubernetes or a CNCF project against
reviewed, source-cited rules and answers `PASS`, `BLOCKED` or `UNKNOWN`. It
runs locally and offline, and a deterministic engine computes every verdict.
When the evidence does not decide the question the answer is `UNKNOWN`.

## What this build is

- **Candidate build.** `prufyx version` reports `"candidateOnly": true` and the
  profile `community-<os>-<arch>`. The release workflow builds from the tag and
  attests the archives; it does not apply maintainer signing. A report from
  this build is not signed Prufyx compatibility evidence.
- **Unpinned trust root.** `prufyx version` reports `"trustRootDigest":
  "UNPINNED"` unless the release notes of a later build say otherwise. The
  build identity binds no release trust root.
- **Official knowledge feed.** The knowledge trust root is pinned in the build
  (separate from the unpinned build identity above). `prufyx db update` with no
  flags fetches the official signed feed and refuses anything not signed from
  the pinned root. Feed metadata is refreshed by a weekly publish run and expires after
  at most 14 days, sooner if reviewed evidence expires earlier. If runs fail,
  the feed stops verifying once its timestamp expires. Without a
  store, or if you do not run `db update`, the knowledge embedded in the binary
  is used. See
  [knowledge updates](https://github.com/prufyx/prufyx/blob/main/cli/docs/knowledge-updates.md).
- **Embedded rules expire.** Every rule in the CNCF and community-project
  packs is time-limited and stops being valid on its expiry date unless its
  review is renewed. A build without newer knowledge answers `UNKNOWN` for an
  expired rule. Check the dates of the knowledge store you use with
  `prufyx db status` before you rely on a result.

## What works

- `prufyx scan`: rendered Kubernetes manifests and a target version; reports
  API versions that a release on the way to the target stops serving. Human,
  Markdown, JSON, SARIF and CSV output. Kubernetes only. See the
  [scan guide](https://github.com/prufyx/prufyx/blob/main/cli/docs/scan.md).
- `prufyx plan`: the hops of a multi-hop upgrade as ordered stages, built from
  one `scan`. No stage is `PASS` yet (hop actions and node rolls are not
  checked). See the [plan guide](https://github.com/prufyx/prufyx/blob/main/cli/docs/plan.md).
- `prufyx check cncf`, `check project`, `check batch` and the named checks
  (listed in the [support inventory](https://github.com/prufyx/prufyx/blob/main/cli/docs/community-support-inventory.md)),
  including `--strict-exit`, which makes a scoped `PASS` exit `14` so CI cannot
  read it as a complete pass. See [exit codes](https://github.com/prufyx/prufyx/blob/main/cli/docs/exit-codes.md).
- `prufyx prepare cncf` and `prepare project`: build a check input from a
  project's own configuration file.
- `prufyx catalog cncf` and `catalog checks`: list the projects, the embedded
  rules and the exact command and input each rule reads.
- `prufyx assess` (opt-in, the only command that reads a cluster, read-only
  through kubectl with an explicit kubeconfig and context).
- `prufyx db verify`, `db import`, `db update` and `db status` for signed
  knowledge packages, with an explicit bootstrap root (see above).

The [quickstart](https://github.com/prufyx/prufyx/blob/main/cli/docs/quickstart.md) takes a clean clone to a real `BLOCKED`
verdict on a Kubernetes API removal, with its upstream citation.

## Coverage

The figures for this release (projects, rules, line attestations, Kubernetes
minors and the A+B / S / G split of the last five minor upgrades) are in the
generated block at the end of this file. They are computed from the data files
of the two revisions; nobody types them. The method is in the
[coverage report guide](https://github.com/prufyx/prufyx/blob/main/cli/docs/coverage-report.md). Most upgrades are still not decided as a
whole: a gap (G) is `UNKNOWN`, never a pass, and a catalogued project is not
tested coverage. These figures are not a statement that any upgrade is safe.

## Install and verify

Archives are built for linux and darwin on amd64 and arm64:
`prufyx_<tag>_<os>_<arch>.tar.gz` (the `prufyx` CLI) and
`prufyx-collector_<tag>_<os>_<arch>.tar.gz`. For linux on amd64 and arm64 the
`prufyx` CLI is also published as `prufyx_<tag>_linux_<arch>.deb` and `.rpm`.
`SHA256SUMS` lists every archive and package, and each of them has a GitHub
build provenance attestation. Verify before you
run anything from an archive:

```sh
TAG=v0.1.0-beta.0
ARCHIVE="prufyx_${TAG}_linux_amd64.tar.gz"
BASE="https://github.com/prufyx/prufyx/releases/download/$TAG"
curl -fsSLO "$BASE/SHA256SUMS" && curl -fsSLO "$BASE/$ARCHIVE"

# 1. The archive matches the published checksum (detects changed bytes only).
grep " $ARCHIVE\$" SHA256SUMS | sha256sum -c -

# 2. The archive was built by this repository's release workflow from this tag.
gh attestation verify "$ARCHIVE" \
  --repo prufyx/prufyx \
  --signer-workflow prufyx/prufyx/.github/workflows/release.yml \
  --source-ref "refs/tags/$TAG" \
  --deny-self-hosted-runners

# 3. Unpack and compare the self-reported build identity.
tar -xzf "$ARCHIVE"
"./prufyx_${TAG}_linux_amd64/prufyx" version
```

To install a package instead, run steps 1 and 2 with the package file name
(`prufyx_${TAG}_linux_amd64.deb`, or `.rpm`, or an `arm64` one), then
`sudo dpkg -i` the `.deb` or `sudo rpm -U` the `.rpm`. The package holds the
binary of the attested archive, the licence files and no install scripts.

The checksum alone says nothing about who built the archive; the attestation
is the origin check (it needs the `gh` CLI and network access). `prufyx
version` is self-reported by the binary, so use it only as a consistency check
after steps 1 and 2. Details are in
[releasing](https://github.com/prufyx/prufyx/blob/main/cli/docs/releasing.md). On macOS, `sha256sum` may be missing: use
`shasum -a 256 -c -` instead.

You can also build from source; see the [README](https://github.com/prufyx/prufyx/blob/main/README.md).

## Known limitations

- Most checks need operator-declared inputs (an effective config, a
  kubeconfig-derived snapshot, or similar); Prufyx does not infer them.
- `scan` does not look at a live cluster, custom resources, stored versions,
  admission or component configuration, or node version skew. A patch-only
  upgrade within one line is not evaluated for removals; check the patch
  release notes by hand.
- A multi-minor jump is evaluated line by line. Where no reviewed rule decides
  a crossed line the answer is `UNKNOWN`.
- Most projects have rules for exact version pairs only. Check coverage for
  your versions with `prufyx catalog checks --project SLUG --from X --to Y`
  before reading an `UNKNOWN` as "nothing found".
- The collector (`prufyx-collector`) observes only a few components; most
  component facts have to be declared by the operator.
- Input files for `check` must be regular, owner-only files (for example mode
  `0600`) and not symlinks. A symlinked path is refused rather than followed.
- No Windows archive is published, and file or directory input to `prufyx scan`
  is not supported on Windows. Windows support is planned for beta.1.
- Planned, not in place: maintainer-signed releases.
- Single maintainer: the main branch has one maintainer, so changes get no
  second-person review. A CODEOWNERS file and a required reviewer are planned
  for beta.1.
- Embedded knowledge expires: its earliest rule ends on 2026-12-07. After that
  date, a run with a pinned `--now` answers `UNKNOWN` for the affected rules
  until the knowledge is renewed. Run `prufyx db update` to fetch newer
  knowledge from the official signed feed; the embedded knowledge stays as the
  offline fallback.
- mariadb-operator is not covered in this build. It is planned for beta.1.
- Some upgrade pairs stay `UNKNOWN`: four Kyverno pairs (gap G11) and the
  kubeswift 0.1 to 0.3 upgrade have no decided rule.
- A knowledge package that this build cannot read makes `prufyx db update`
  exit `15` (`KNOWLEDGE_TOO_NEW_FOR_THIS_CLIENT`). The current store and the
  embedded knowledge are kept. Upgrade prufyx.
- `scan` and `check` use the newer of the local database and the embedded
  knowledge, compared by the latest evidence review date per project. A
  removal-only correction without a new review date cannot be told from an
  older database (see [knowledge updates](https://github.com/prufyx/prufyx/blob/main/cli/docs/knowledge-updates.md)).
- The generated block lists no added projects ("Projects added to the support
  inventory (0)"): no project was newly catalogued since `v0.0.1-alpha.1`. The
  gain is more reviewed rules and line attestations for catalogued projects.

## Reporting issues

Use the repository's issue templates at
https://github.com/prufyx/prufyx/issues, and see the
[beta tester guide](https://github.com/prufyx/prufyx/blob/main/cli/docs/beta-tester-guide.md#report-a-wrong-answer). Report security issues
privately as described in [SECURITY.md](https://github.com/prufyx/prufyx/blob/main/SECURITY.md). Never include customer
configuration, cluster snapshots or credentials.

## What changed in this release

<!-- release-notes:begin -->

Changes from `v0.0.1-alpha.1` (a96744cd69a6) to `v0.1.0-beta.0` (b55e9425f44b), computed by `prufyx-maintainer release-notes` from the data files of the two trees. No figure or list below is typed by hand.

### Summary

| Measure | v0.0.1-alpha.1 | v0.1.0-beta.0 | Change |
| --- | --- | --- | --- |
| Projects catalogued with retained public sources | 58 | 58 | 0 |
|   of them source-only, no check | 11 | 11 | 0 |
| Projects with at least one executable check | 65 | 65 | 0 |
| CNCF source rules, active | 190 | 245 | +55 |
| CNCF projects with a rule | 53 | 53 | 0 |
| Rules for non-CNCF projects | 34 | 34 | 0 |
| Non-CNCF projects with a rule | 8 | 8 | 0 |
| Line attestations | 0 | 97 | +97 |
| Kubernetes minors with a line attestation | 0 | 18 | +18 |
| Projects with a release-line snapshot (README coverage block) | 55 | 78 | +23 |
| Upgrades between consecutive release lines | 275 | 390 | +115 |
| Decided for the whole release-line pair (A+B) | 0 | 40 | +40 |
| Rule for one exact version pair only (S) | 44 | 40 | -4 |
| Gap, no valid rule (G) | 231 | 310 | +79 |

The release-line figures are the README coverage block, generated on 2026-10-08 (v0.0.1-alpha.1) and 2026-10-30 (v0.1.0-beta.0) by `scripts/readme-coverage.sh`; the block comes from `prufyx-maintainer coverage report`.

### Projects added to the support inventory (0)

No project was added.

### Catalogued projects that gained their first executable check (0)

None.

### Onboarding batches (7 approved, 40 project entries)

- batch `ob-20261016-2`, decision `approve`:
  - `dex` (cncf, new): proof pair v2.45.0 to v2.46.0
  - `k8gb` (cncf, new): proof pair v0.20.0 to v1.0.0
  - `k8up` (cncf, new): proof pair v2.15.0 to v2.16.0
  - `openyurt` (cncf, new): proof pair v1.6.0 to v1.7.0
  - `submariner` (cncf, new): proof pair v0.23.1 to v0.24.0
- batch `ob-20261016-3`, decision `approve`:
  - `logging-operator-kube-logging` (cncf, new): proof pair 6.8.0 to 6.9.0
  - `schemahero` (cncf, new): proof pair v0.25.0 to v0.26.0
- batch `ob-20261022-1`, decision `approve`:
  - `chaos-mesh` (cncf, new): proof pair v2.7.0 to v2.8.0
  - `eraser` (cncf, new): proof pair v1.3.0 to v1.4.0
  - `kanister` (cncf, new): proof pair 0.118.0 to 0.119.0
  - `kcp` (cncf, new): proof pair v0.32.0 to v0.33.0
  - `kubevela` (cncf, new): proof pair v1.10.0 to v1.11.0
  - `wasmcloud` (cncf, new): proof pair v2.10.0 to v2.11.0
- batch `ob-20261023-1`, decision `approve`:
  - `grafana-operator` (community, new): proof pair v5.24.0 to v5.25.0
  - `kubernetes-ingress` (community, new): proof pair v5.6.0 to v5.7.0
  - `opentelemetry-operator` (community, new): proof pair v0.161.0 to v0.162.0
  - `trivy-operator` (community, new): proof pair v0.35.0 to v0.36.0
- batch `ob-20261026-1`, decision `approve`:
  - `akri` (cncf, new): proof pair v0.13.8 to v0.14.0
  - `awx-operator` (community, new): proof pair 2.18.0 to 2.19.0
  - `cyclops` (community, new): proof pair v0.20.0 to v0.21.0
  - `fluent-operator` (community, new): proof pair v3.9.0 to v3.10.0
  - `kube-green` (community, new): proof pair v0.6.0 to v0.7.0
  - `kubestellar` (cncf, new): proof pair v0.29.0 to v0.30.0
  - `kubeswift` (community, new): proof pair v0.19.0 to v0.20.0
  - `operator-lifecycle-manager` (community, new): proof pair v0.45.0 to v0.46.0
  - `radius` (cncf, new): proof pair v0.60.0 to v0.61.0
  - `redis-operator` (community, new): proof pair v0.26.0 to v0.27.0
  - `sealed-secrets` (community, new): proof pair v0.40.0 to v0.41.0
- batch `ob-20261027-2`, decision `approve`:
  - `kuberhealthy` (cncf, new): proof pair v2.7.0 to v3.0.0
  - `mariadb-operator` (community, new): proof pair 26.6.0 to 26.10.0
  - `openchoreo` (cncf, new): proof pair v1.2.0 to v1.3.0
- batch `ob-20261028-5`, decision `approve`:
  - `burrito` (community, new): proof pair v0.14.0 to v0.15.0
  - `furiko` (community, new): proof pair v0.2.0 to v0.3.0
  - `k6-operator` (community, new): proof pair v1.6.0 to v1.7.0
  - `k8s-cleaner` (community, new): proof pair v0.23.0 to v0.24.0
  - `kmesh` (cncf, new): proof pair v1.1.0 to v1.2.0
  - `kubean` (cncf, new): proof pair v0.38.0 to v0.39.0
  - `metal3-io` (cncf, new): proof pair v0.13.0 to v0.14.0
  - `onepassword-operator` (community, new): proof pair v1.11.0 to v1.12.0
  - `vault-secrets-operator` (community, new): proof pair v1.27.0 to v1.28.0

Only approved batches are counted. A project entry names the project and the proof pair of versions the batch rests on; it does not by itself add a project to the catalogue (see the support inventory list above).

### Projects with custom-resource version checks (73)

The from-release has no table file; all 73 projects are listed.

- `akri` (cncf): 1 CRD group
- `antrea` (cncf): 2 CRD groups
- `argo-cd` (cncf): 1 CRD group
- `awx-operator` (community): 1 CRD group
- `burrito` (community): 1 CRD group
- `cert-manager` (cncf): 2 CRD groups
- `chaos-mesh` (cncf): 1 CRD group
- `cilium` (cncf): 1 CRD group
- `cloudnativepg` (cncf): 1 CRD group
- `cluster-api` (community): 3 CRD groups
- `contour` (cncf): 1 CRD group
- `crossplane` (cncf): 5 CRD groups
- `cyclops` (community): 1 CRD group
- `dapr` (cncf): 1 CRD group
- `dex` (cncf): 1 CRD group
- `eck-operator` (community): 12 CRD groups
- `eraser` (cncf): 1 CRD group
- `external-secrets` (cncf): 2 CRD groups
- `fluent-operator` (community): 2 CRD groups
- `furiko` (community): 1 CRD group
- `gateway-api` (community): 1 CRD group
- `grafana-operator` (community): 1 CRD group
- `istio` (cncf): 4 CRD groups
- `k6-operator` (community): 1 CRD group
- `k8gb` (cncf): 2 CRD groups
- `k8s-cleaner` (community): 1 CRD group
- `k8up` (cncf): 1 CRD group
- `kanister` (cncf): 1 CRD group
- `karmada` (cncf): 8 CRD groups
- `kcp` (cncf): 6 CRD groups
- `keda` (cncf): 2 CRD groups
- `kmesh` (cncf): 1 CRD group
- `kong-ingress-controller` (community): 1 CRD group
- `koordinator` (cncf): 5 CRD groups
- `kube-green` (community): 1 CRD group
- `kubean` (cncf): 1 CRD group
- `kuberhealthy` (cncf): 1 CRD group
- `kubernetes-ingress` (community): 4 CRD groups
- `kubestellar` (cncf): 1 CRD group
- `kubeswift` (community): 10 CRD groups
- `kubevela` (cncf): 2 CRD groups
- `kueue` (community): 1 CRD group
- `kuma` (cncf): 1 CRD group
- `kyverno` (cncf): 4 CRD groups
- `logging-operator-kube-logging` (cncf): 2 CRD groups
- `longhorn` (cncf): 1 CRD group
- `mariadb-operator` (community): 1 CRD group
- `metal3-io` (cncf): 1 CRD group
- `metallb` (cncf): 1 CRD group
- `mongodb-kubernetes` (community): 3 CRD groups
- `node-feature-discovery` (community): 1 CRD group
- `onepassword-operator` (community): 1 CRD group
- `openchoreo` (cncf): 1 CRD group
- `openkruise` (cncf): 2 CRD groups
- `opentelemetry-operator` (community): 1 CRD group
- `openyurt` (cncf): 4 CRD groups
- `operator-lifecycle-manager` (community): 1 CRD group
- `percona-postgresql-operator` (community): 2 CRD groups
- `prometheus-operator` (community): 1 CRD group
- `radius` (cncf): 2 CRD groups
- `rancher` (community): 9 CRD groups
- `redis-operator` (community): 1 CRD group
- `rook` (cncf): 2 CRD groups
- `schemahero` (cncf): 2 CRD groups
- `sealed-secrets` (community): 1 CRD group
- `strimzi` (cncf): 2 CRD groups
- `submariner` (cncf): 1 CRD group
- `tekton` (cncf): 2 CRD groups
- `trivy-operator` (community): 1 CRD group
- `vault-secrets-operator` (community): 1 CRD group
- `velero` (cncf): 1 CRD group
- `volcano` (cncf): 8 CRD groups
- `wasmcloud` (cncf): 1 CRD group

### Rules by project (80 added, 25 removed)

| Catalogue | Project | Added | Removed | Rules now |
| --- | --- | --- | --- | --- |
| CNCF | `cilium` | 1 | 0 | 4 |
| CNCF | `crossplane` | 2 | 0 | 3 |
| CNCF | `kubernetes` | 62 | 25 | 63 |
| CNCF | `kyverno` | 1 | 0 | 7 |
| CNCF | `openfga` | 1 | 0 | 2 |
| CNCF | `spire` | 1 | 0 | 2 |
| CNCF | `strimzi` | 10 | 0 | 11 |
| CNCF | `vitess` | 2 | 0 | 3 |

Counts include rules that are withdrawn; withdrawn rules are not used and are listed below.

### Rules newly withdrawn (0)

None.

### Line attestations by project (16)

- `ansible/awx-operator`: 5 now; new lines 2.15, 2.16, 2.17, 2.18, 2.19
- `aquasecurity/trivy-operator`: 5 now; new lines 0.32, 0.33, 0.34, 0.35, 0.36
- `cert-manager/cert-manager`: 2 now; new lines 1.20, 1.21
- `cilium/cilium`: 2 now; new lines 1.16, 1.17
- `cyclops-ui/cyclops`: 2 now; new lines 0.20, 0.21
- `dapr/dapr`: 6 now; new lines 1.14, 1.15, 1.16, 1.17, 1.18, 1.19
- `fluent/fluent-operator`: 2 now; new lines 3.10, 3.11
- `kedacore/keda`: 5 now; new lines 2.17, 2.18, 2.19, 2.20, 2.21
- `kubernetes/kubernetes`: 18 now; new lines 1.20, 1.21, 1.22, 1.23, 1.24, 1.25, 1.26, 1.27, 1.28, 1.29, 1.30, 1.31, 1.32, 1.33, 1.34, 1.35, 1.36, 1.37
- `kubeswift-io/kubeswift`: 18 now; new lines 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.10, 0.11, 0.12, 0.13, 0.14, 0.15, 0.16, 0.17, 0.18, 0.19, 0.20, 0.21
- `kumahq/kuma`: 5 now; new lines 2.10, 2.11, 2.12, 2.13, 2.14
- `mongodb/mongodb-kubernetes`: 6 now; new lines 1.9, 1.10, 1.11, 1.12, 1.13, 1.14
- `nginx/kubernetes-ingress`: 5 now; new lines 5.3, 5.4, 5.5, 5.6, 5.7
- `strimzi/strimzi-kafka-operator`: 5 now; new lines 0.50, 0.51, 1.1, 1.2, 1.3
- `tektoncd/pipeline`: 6 now; new lines 1.13, 1.14, 1.15, 1.16, 1.17, 1.18
- `velero-io/velero`: 5 now; new lines 1.14, 1.15, 1.16, 1.17, 1.18

### Kubernetes minors

Lines with a line attestation (18): 1.20, 1.21, 1.22, 1.23, 1.24, 1.25, 1.26, 1.27, 1.28, 1.29, 1.30, 1.31, 1.32, 1.33, 1.34, 1.35, 1.36, 1.37. New since `v0.0.1-alpha.1`: 1.20, 1.21, 1.22, 1.23, 1.24, 1.25, 1.26, 1.27, 1.28, 1.29, 1.30, 1.31, 1.32, 1.33, 1.34, 1.35, 1.36, 1.37.

### Merged pull requests (204)

- #71 crd.version-removal 2.0.0: release lines, full-tree scan, line-wide ranges, targets as data
- #74 Line attestations per component: crd.custom_resource_versions (scoped results in scan)
- #40 scan: --format csv
- #79 Knowledge targets carry records: line attestations, path policies, served-API lists per project
- #54 CLI help: short grouped overview, per-command help, optional colour
- #49 README: Support Prufyx (hardware sponsorship)
- #44 scan: --fail-on and --only-blocked
- #67 Batch approvals: one owner signature for up to 50 reviewed entries (BATCH-APPR)
- #85 REGISTRY-WAVE-1: register CRD facts for wave-1 projects
- #89 registry: Kubernetes feature-gate facts for k8s.feature-gate-removal
- #91 KIND-VAL: validate Prufyx knowledge against real API servers (kind)
- #93 kindval: decide version claims of releases without a pair claim
- #86 CRD-GEN wave 2: 11 add-on operators
- #87 CRD-GEN: read kubebuilder patch fragments and v1beta1 copies
- #88 COMMUNITY-CRD: community catalog for CRD targets + 10 add-on operators
- #90 COMMUNITY-KNOW: community knowledge paths (inert) + CRD parser/target fixes
- #96 engine: a non-comparable dependency version is UNKNOWN, never BLOCKED
- #100 extract: reviewed custom-resource table and extractor targets as embedded data files
- #101 extract: per-extractor code digests
- #97 crd.version-removal: templated chart CRDs read as checked copies, Go-defined CRDs named (2.4.0)
- #99 crd.version-removal: reviewed pre-patch bundles, inline patches, group-rename successors, knative-v tags (2.5.0)
- #94 engine: chart subjects and set-membership rules (inert)
- #95 extract: helm.values 1.0.0
- #98 extract: helm.values 1.1.0, values keys with dots become set members
- #102 scan: Helm chart values as a declared chart hop
- #103 Verdict-neutral notices over a Helm values-path set
- #104 Ranged chart rules over consecutive chart lines
- #105 kindval: verdicts, reason codes and canary controls (results v2)
- #119 knowledge: pin the owner approval key and the reattestation trust root
- #111 gate: additive fact-registry change admitted with an owner approval
- #114 knowledge gate: onboarding batches (owner-signed, data-only project onboarding)
- #122 gate: onboarding hardening and more scan finding classes in a batch proof
- #113 coverage: --window ALL and the complete predicate
- #121 CRD-GEN wave 3, batch 1: five CNCF projects (onboarding batch)
- #107 tests: state the shipped CNCF pack with and without the custom-resource version-removal batch
- #106 kindval: crd-field claims decided by strict server-side field validation
- #117 gate: empty-list line attestations for quiet lines, five admission conditions
- #125 coverage: lines snapshot 2026-10-17 with every release line
- #123 gate: raise the onboarding dry run's per-project budget to 250 REST requests and 3000 reads
- #126 knowledge: CRD version-removal rules for crossplane, kyverno, strimzi (re-derived)
- #118 knowledge: empty-list line attestations for nine quiet Kubernetes minors
- #120 knowledge: Kubernetes removals from the extractor, all lines 1.20 to 1.37 attested
- #131 extract: attest custom-resource versions for the keda, velero, cert-manager and cilium CRD targets
- #138 knowledge: quiet-line attestations for the keda and cert-manager CRD targets
- #139 knowledge: quiet-line attestations for the velero CRD target
- #134 cncfcheck: memoize the bundle per generation under the synthetic tag
- #135 knowledgegate: run tests in parallel
- #136 scanrun, cncfcheck: run independent tests in parallel
- #141 cli: clear usage errors for assess and check arguments
- #142 docs: quickstart leads with scan; verdicts and declarations pages
- #137 cncfcheck: memoize parsed rule documents and per-rule derivations
- #132 ci: shard build/test behind the Build, vet, test fan-in
- #133 ci: race detector per-package matrix, affected packages only on PRs
- #143 check: shared human report (verdict first, grouped findings, citations behind -v)
- #127 onecommand: scan tests for registry-matched images (grafana, velero, etcd)
- #144 check: object locations (file:line Kind ns/name) and --redact
- #145 cli: short help for check and prepare, generated per-project docs
- #116 check: citation and removal guard for CRD targets and the custom-resources table
- #146 docs: one-command-flow Run it shows the current assess usage errors
- #148 knowledge: attest the dapr, kuma and tekton CRD targets
- #150 kind-val.sh: --name-prefix for the cluster names
- #151 Onboarding unblock A: quiet custom-resource lines of any project, lowercase subject components
- #129 onecommand: do not show the tag of a digest-pinned image as an observed version
- #128 imageidentity: image identities for coredns, fluent-bit, keda, kibana, kyverno, loki
- #64 knowledge: correct the evidence of seven CNCF rules
- #149 registry: values-path set facts for the reviewed chart sources
- #154 knowledge: quiet-line attestations for the dapr and tekton CRD targets
- #152 crdversions: exclude the SPIRE quickstart sample from the istio scan
- #109 release: provenance and the draft release wait for the owner's approval
- #112 docs: generate the CNCF preview counts from the coverage sources; correct the Kubernetes removal list
- #124 CRD-GEN wave 3, batch 2: two CNCF projects (onboarding batch)
- #161 docs: kind-judge aggregate report 2026-10-22
- #167 knowledge: register the kubelet version-skew fact and the kubelet version declarations
- #66 Kubernetes 1.32–1.36: version-skew rules and fact registry
- #173 knowledge: register the openfga, spire and vitess facts
- #157 knowledge: reviewed rules for openfga, spire and vitess (no CRD target)
- #174 coverage: name the cert-manager component in the lines snapshot
- #153 knowledge: attest the longhorn CRD target
- #147 customresources: attribute by (api group, kind)
- #177 intake: accept Kubernetes manifests nested up to 64 levels (public CRDs such as cert-manager)
- #178 evidence repin and reattest: read and monitor served-API lists as records
- #156 knowledge: attest CloudNativePG CRD versions
- #169 ci: exempt prufyx-bot from the CLA check
- #181 ci: shard the slow test jobs
- #182 knowledge gate: admit mechanical served-API lists by re-derivation
- #184 maintainer: served-lists build, and tools accept the servedAPIs member
- #165 release-notes: generate what a release adds (CHANGELOG + release notes)
- #172 knowledge: Kubernetes 1.37 kubelet version-skew rule
- #166 extract apply: renew a mechanical attestation at a new extractor build
- #168 extract apply: --renew-attestations also renews mechanical rules
- #186 knowledge: served-API lists for Kubernetes 1.19 to 1.37
- #164 Admit community projects to line attestation and to onboarding batches
- #171 scan: a planned hop through the intermediate line satisfies require_intermediate_version in the whole-upgrade check
- #158 crdversions: ignore definitions of groups another project owns
- #189 knowledgegate: admit a new reviewed path policy with an owner approval (subject pathPolicy)
- #187 knowledge: reviewed upgrade-path policy sequential_minor for Kubernetes (draft)
- #190 extract: mongodb-kubernetes target attests its CRD version lines (WI-8b step 1)
- #193 tests: weekly batch simulation asserts the renewal gap, not a capped-rule count
- #191 knowledge: re-derive the cert-manager and dapr CRD line attestations (WI-8b shard 1)
- #197 coverage: lines snapshot 2026-10-23
- #162 test(kindval): true removal controls for the 1.36 to 1.37 hop
- #163 scan: Kubernetes pre-release versions (engine and parser, never a PASS)
- #159 Onboarding bundle intake by pull request
- #202 Publish the CNCF knowledge as per-project targets; judge size per target
- #200 knowledgegate: O4 compares the landscape repository with ASCII case folded
- #179 knowledge: onboarding batch ob-20261022-1 (6 CNCF CRD projects)
- #196 knowledge: Kubernetes control-plane no-minor-skip rules 1.29 to 1.37
- #203 extract: renew a held attestation when only its releases extend
- #194 scan: declared kubelet versions feed the kubelet skew rule
- #195 scan: evaluate fact-less mandatory-intermediate rules
- #201 onboard-bundle: scan object keys, fix private-IP false positive on versions with a dotted prefix
- #92 kubernetes: scan tests and docs for patch-level removals 1.32 to 1.37
- #185 docs: how to supply kubelet version evidence for the skew rule
- #206 kind-val: reason install-rejected for deterministic apiserver rejects of a CRD apply
- #207 kindval: diagnostic ladder for unknown-field install rejections
- #208 crdbatchids: accept the factory's mechanical custom-resource rules beside the batch
- #210 knowledgegate: retry an unclassified 403 once without the token
- #198 knowledge: onboarding batch ob-20261023-1 (4 community CRD projects)
- #209 knowledgegate: onboarding-bot key tier (code only)
- #213 supportinventory: leave notice rules out of the generic inventory
- #214 rulecheck: retry an unclassified 403 once without the token
- #211 crd.version-removal: calver-edge release scheme (edge-YY.M.N and YY.M.N-edge)
- #212 crd.version-removal: read a templated CRD whose spec is included from a chart file
- #216 knowledgegate: test the pre-tier key file from a fixed copy
- #215 knowledge: register the onboarding bot signing key
- #217 lineattest: make the community-member test fit a calendar component
- #220 onboarding: batch ob-20261026-1
- #222 docs: README coverage after onboarding batch ob-20261026-1
- #221 test: use reserved .invalid group for unknown-group fixtures
- #224 gate: admit generated README coverage block
- #226 gate: admit generated CNCF source preview counts
- #227 Add maintainer intake form and 'For project maintainers' page
- #228 knowledge: kubeswift line attestation flag
- #230 knowledgegate: let a human change land a generated-block renderer change
- #229 coverage: split the CRD version row into reviewed targets and published data
- #231 extract: five community custom resource targets attest their version lines
- #233 cncfcheck, communityapp: community tests no longer assume awx-operator ships no data
- #234 tests: no remaining test assumes a community project ships no data
- #235 knowledgegate: diagnose GitHub 403s and back off on secondary rate limits
- #237 knowledgegate: read repos of IP allow-listed orgs over anonymous git
- #238 tests: a custom-resource target may also be a community source-rule project
- #232 knowledge: factory batch ffb7abb53c7c (5 gate passes)
- #239 onboarding: batch ob-20261027-2
- #240 coveragereport: attribute attestations via the reviewed CRD target
- #242 ci(knowledge-gate): read-only GitHub App token for re-derivation
- #241 knowledge: factory batch 340c4fea3b16 (3 gate passes)
- #243 test(knowledge-gate): stricter secret checks in the workflow shape test
- #244 scan: detect current versions from manifest labels
- #250 onboarding: batch ob-20261028-5
- #247 knowledgegate: bot-tier onboarding 14 batches / 210 projects per 7 days (15 per batch unchanged)
- #252 plan: prufyx plan, staged multi-hop upgrade plan
- #258 knowledge-sign init: separate root passphrase
- #255 db update: no-flag update from the official feed, embedded-root plumbing
- #257 extract: renew a mechanical line attestation at the same build
- #253 codeowners: own cli/internal/knowledgepin
- #254 plan: --to kubernetes=newest-covered
- #260 knowledgegate: fix flaky supersede test race
- #265 fix(cncf): harbor --with-clair is rejected at 2.8.0, not PASS
- #263 scan: removed API no longer hidden by an alpha or unserved neighbour
- #262 Add the knowledge publish workflow and the root pin release check
- #268 cncfprepare: KubeVirt slirp/passt/macvtap and unknown interface keys are UNKNOWN, not PASS
- #267 Add evidence reattest keygen for the automation signing key
- #270 scan: multi-hop planning for custom-resource and Helm chart runs (UP-6a)
- #275 scan: do not claim nothing was evaluated when a hop produced a result
- #272 docs: beta tester guide, release notes skeleton, README beta banner
- #273 cncfprepare: etcd native argv with rejected or ignored flag values is UNKNOWN, not PASS
- #278 release: fail a tag build when the embedded knowledge expires within 30 days
- #251 knowledge: factory batch 0b525cca4cb3 (2 gate passes)
- #277 kubernetes component check: no REMOVED_SETTING_ABSENT when no removed-setting predicate ran
- #279 docs: mention newest-covered in the beta tester guide
- #276 knowledge: renew the cert-manager and dapr CRD line attestations (expire 2026-11-25)
- #280 Changelog fragments: stop CHANGELOG.md merge conflicts
- #282 kubernetes component check: KUBERNETES_COMPONENT_SKEW_ONLY when only the skew predicate ran
- #281 constraintengine: raise compiled registry fact cap from 256 to 2048
- #283 knowledge-publish: key files get a final newline; publisher doc fixes
- #284 knowledge: a per-project index may list up to 1024 project targets
- #285 Bound onboarding dry-run listings apart from file reads
- #288 cncfprepare: reword SETS_COMPLETE comment, make skew-only test assert the proposed facts
- #286 crd.version-removal: accept chart tag prefixes
- #291 crd.version-removal: read zero-padded minor in calendar release tags
- #292 coveragereport baseline: bot knowledge PRs no longer move it
- #293 knowledge: pin the official cncf-projects root
- #294 docs: README explains offline and online knowledge
- #295 extract: attest kyverno and mariadb-operator lines, read kubeswift from 0.1
- #299 release-notes: list projects of the custom-resource version table
- #298 db status: use the default store when --db-root is omitted
- #301 assess: exit with the declared-scope aggregate; upgradeplan: report UNKNOWN lowers plan
- #300 Release: publish .deb and .rpm assets for linux amd64/arm64
- #304 check cncf kubernetes native-resource: unserved API version is UNKNOWN, not PASS
- #308 knowledge: factory batch 5244d77c13e8 (3 gate passes)
- #314 coverage: lines snapshot 2026-10-30
- #305 scan: report skipped hidden directories and non-manifest files (no false PASS)
- #307 Go 1.26.10 toolchain, govulncheck CI job, tidy go.mod, drop knowledge-release workflow
- #303 Newer knowledge wins; expired local store falls back to embedded
- #302 Knowledge publish: oldest-supported-client gate
- #310 release: attest SHA256SUMS
- #312 docs: the official knowledge feed is live and the root is pinned
- #313 constraintengine: the stale-rule next action points to db update
- #315 docs: use hello@prufyx.com as the sponsorship contact
- #309 scan: chart route turns unread entries into gaps
- #317 Pinned --now must not hide real-time knowledge expiry
- #306 knowledge: too-new signed packages are rejected without recording trust (exit 15)
- #318 action: fail-on defaults to blocked,unknown
- #321 fix(db update): human header says already up to date when nothing imported

### How to read these figures

A catalogued project is not tested coverage: a catalogue entry says Prufyx holds retained public sources for the project, and only an executable check can block an upgrade. Decided means a valid rule or attestation covers every version of both release lines, so the answer is BLOCKED or UNKNOWN, never a whole-upgrade PASS; decided is not safe. An exact-pair rule decides only the versions it names. A line attestation says which rules were derived for a release line, not that an upgrade into it is safe. The metrics are defined in `cli/docs/coverage-report.md`.

<!-- release-notes:end -->
