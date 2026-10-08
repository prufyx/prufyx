# Third-party material and attribution

The first-party Prufyx source and documentation are licensed by Spas Atanasov
under the [GNU Affero General Public License v3.0 only](LICENSE). First-party
knowledge data is licensed under [CC BY-SA 4.0](DATA-LICENSE.md). These grants
do not relicense third-party material or grant rights to third-party
trademarks.

| Material | Distribution treatment |
| --- | --- |
| Go runtime and standard library | Compiled into release binaries using Go 1.26.8 with CGO disabled. The Go Authors' BSD license is included at [LICENSES/Go-BSD-3-Clause.txt](LICENSES/Go-BSD-3-Clause.txt). |
| External Go modules | The offline knowledge-database implementation uses the exact vendored module profile below. Release builds use `-mod=vendor` with network access disabled. |
| Official upstream release and source references | Public URLs, identities, digests, short factual summaries, and narrowly scoped predicates. The TiKV target-preflight contribution example also retains three complete upstream files for local digest and span verification under the source licenses listed below. Upstream names identify the subject of a check; they imply no endorsement. |
| Synthetic fixtures and checkpoint source | Prufyx-authored examples and recorded first-party source checkpoints, except the modified upstream test fixtures listed under [Modified upstream test fixtures](#modified-upstream-test-fixtures). Recorded source paths describe checkpoint provenance, not independent origin attestations. |

The focused Community package contains only the files selected by its
[source policy](cli/release/community-shipping-policy-v2.json). Its upstream
source receipts identify the exact source of each check. GitHub artifact
attestations authenticate release build provenance; they do not certify the
truth or completeness of a compatibility claim.

For each release, the build records its Go toolchain, module metadata, exact
source identity and artifact checksums. Report an attribution concern privately
to [hello@prufyx.com](mailto:hello@prufyx.com).

## Vendored Go module notices

The Community v2 source policy binds the complete vendored tree, every module
version and checksum, every distributed notice copy, and the one binary embed
resource. The binary resource is protobuf's reviewed
`editions_defaults.binpb`; its exact digest is recorded in the source policy.

| Module | Version | Declared license and included notices |
| --- | --- | --- |
| `github.com/BurntSushi/toml` | `v1.6.0` | MIT; [license](LICENSES/Module-BurntSushi-toml-MIT.txt) |
| `github.com/cenkalti/backoff/v5` | `v5.0.3` | MIT; [license](LICENSES/Module-cenkalti-backoff-MIT.txt) |
| `github.com/google/go-containerregistry` | `v0.20.7` | Apache-2.0; [license](LICENSES/Module-google-go-containerregistry-Apache-2.0.txt) |
| `github.com/opencontainers/go-digest` | `v1.0.0` | Apache-2.0; [code license](LICENSES/Module-opencontainers-go-digest-Apache-2.0.txt) and [documentation license](LICENSES/Module-opencontainers-go-digest-docs-CC-BY-SA-4.0.txt) |
| `github.com/secure-systems-lab/go-securesystemslib` | `v0.11.0` | MIT; [license](LICENSES/Module-go-securesystemslib-MIT.txt) |
| `github.com/sigstore/protobuf-specs` | `v0.5.0` | Apache-2.0; [license](LICENSES/Module-sigstore-protobuf-specs-Apache-2.0.txt) |
| `github.com/sigstore/sigstore` | `v1.10.6` | Apache-2.0; [license](LICENSES/Module-sigstore-Apache-2.0.txt) |
| `github.com/theupdateframework/go-tuf/v2` | `v2.4.2` | Apache-2.0; [license](LICENSES/Module-go-tuf-Apache-2.0.txt) and [notice](LICENSES/Module-go-tuf-NOTICE.txt) |
| `golang.org/x/crypto` | `v0.56.0` | BSD-3-Clause; [license](LICENSES/Module-golang-x-crypto-BSD-3-Clause.txt) and [patent grant](LICENSES/Module-golang-x-crypto-PATENTS.txt) |
| `golang.org/x/sys` | `v0.47.0` | BSD-3-Clause; [license](LICENSES/Module-golang-x-sys-BSD-3-Clause.txt) and [patent grant](LICENSES/Module-golang-x-sys-PATENTS.txt) |
| `golang.org/x/term` | `v0.45.0` | BSD-3-Clause; [license](LICENSES/Module-golang-x-term-BSD-3-Clause.txt) and [patent grant](LICENSES/Module-golang-x-term-PATENTS.txt) |
| `google.golang.org/genproto/googleapis/api` | `v0.0.0-20250825161204-c5933d9347a5` | Apache-2.0; [license](LICENSES/Module-google-genproto-Apache-2.0.txt) |
| `google.golang.org/protobuf` | `v1.36.11` | BSD-3-Clause; [license](LICENSES/Module-google-protobuf-BSD-3-Clause.txt) and [patent grant](LICENSES/Module-google-protobuf-PATENTS.txt) |
| `gopkg.in/yaml.v3` | `v3.0.1` | MIT and Apache-2.0 across the module's files; [license](LICENSES/Module-go-yaml-v3-MIT-Apache-2.0.txt) and [notice](LICENSES/Module-go-yaml-v3-NOTICE.txt) |

## Retained upstream source files

The TiKV target-preflight contribution example includes unchanged complete
copies of two TiKV source files and one PingCAP documentation file at the exact
commits named in its candidate packet. The TiKV files retain their copyright
and license headers. The PingCAP document has no file-level author declaration,
so it is attributed to PingCAP and contributors to the named docs repository.
These copies support local full-file digest and line-span verification only;
including them does not authenticate their origin, approve the candidate, or
establish runtime behavior.

| Retained material and attribution | Immutable source identity | Upstream terms included with the Community source |
| --- | --- | --- |
| TiKV server configuration, TiKV Project Authors (copyright 2017) | [`src/config/mod.rs` at `3f446cfa9eb1d5c653031d261e185911495d0359`](https://github.com/tikv/tikv/blob/3f446cfa9eb1d5c653031d261e185911495d0359/src/config/mod.rs), SHA-256 `aca62aff55a59927e5e6ff1f0d6aebda9aa00e559a110e6fc05f73b42aff2ca3` | Apache-2.0; [license](LICENSES/Source-TiKV-Apache-2.0.txt) |
| TiKV backup endpoint, TiKV Project Authors (copyright 2019) | [`components/backup/src/endpoint.rs` at `3f446cfa9eb1d5c653031d261e185911495d0359`](https://github.com/tikv/tikv/blob/3f446cfa9eb1d5c653031d261e185911495d0359/components/backup/src/endpoint.rs), SHA-256 `c111331404f6e8af7fc9b80426d1f989473741c93009f2202488113897f3db46` | Apache-2.0; [license](LICENSES/Source-TiKV-Apache-2.0.txt) |
| *TiKV Configuration File*, PingCAP and contributors to the PingCAP docs repository; no file-level author is stated | [`tikv-configuration-file.md` at `8d85871d64efa8bcad2d3c3c4c7edc2f4f3045be`](https://github.com/pingcap/docs/blob/8d85871d64efa8bcad2d3c3c4c7edc2f4f3045be/tikv-configuration-file.md), SHA-256 `9b3e8421658de1e93f6d2fa8833688c0bdbd3a02545262e221c9794ca0cca021` | CC BY-SA 3.0 Unported; [license](LICENSES/Source-PingCAP-docs-CC-BY-SA-3.0.txt) |

The AGPL-3.0-only grant for first-party Prufyx source and the CC BY-SA 4.0
grant for first-party knowledge data, both stated at the top of this file, are
separate from these upstream works and do not relicense them, including the
PingCAP document.

## Modified upstream test fixtures

The `crd.version-removal` extractor's tests include modified copies of the
Strimzi CustomResourceDefinition manifests at two release commits, and of the
Cilium, Kyverno and Longhorn CustomResourceDefinition manifests at every final
release of two consecutive release lines each. The body of every version's
`schema:` key was replaced by a minimal object schema (and, in Longhorn's
`deploy/longhorn.yaml`, every document that is not a CustomResourceDefinition was
removed); every other line is unchanged, so names, groups, version order and the
`served` and `storage` flags are the upstream ones. The copies serve only as test
input and do not establish runtime behavior. `PROVENANCE.txt` in each fixture
directory lists every release tag, commit and file with the digest of the
unmodified upstream file.

| Retained material and attribution | Immutable source identity | Upstream terms included with the Community source |
| --- | --- | --- |
| Strimzi CustomResourceDefinition manifests (`040-Crd-kafka.yaml` to `049-Crd-kafkarebalance.yaml`, ten files per commit), Strimzi authors; modified (schema bodies replaced) | [`install/cluster-operator` at `54081abf97d0e5e524de773b88343756934db1a8`](https://github.com/strimzi/strimzi-kafka-operator/tree/54081abf97d0e5e524de773b88343756934db1a8/install/cluster-operator) (0.51.0) and [at `4836c7dd74ce973f06d97936916ed7f20c1a2ff0`](https://github.com/strimzi/strimzi-kafka-operator/tree/4836c7dd74ce973f06d97936916ed7f20c1a2ff0/install/cluster-operator) (1.0.0), in `cli/internal/extract/crdversions/testdata/strimzi` | Apache-2.0; [license](LICENSES/Source-Strimzi-Apache-2.0.txt) |
| Cilium CustomResourceDefinition manifests (`pkg/k8s/apis/cilium.io/client/crds/v2` and `v2alpha1`), Authors of Cilium; modified (schema bodies replaced) | [github.com/cilium/cilium](https://github.com/cilium/cilium) at the commits of `v1.19.0` to `v1.19.8` and `v1.20.0` to `v1.20.2` listed in `cli/internal/extract/crdversions/testdata/oracle/PROVENANCE.txt` | Apache-2.0; [license](LICENSES/Source-Cilium-Apache-2.0.txt) |
| Kyverno CustomResourceDefinition manifests (`config/crds`), The Kyverno Authors; modified (schema bodies replaced) | [github.com/kyverno/kyverno](https://github.com/kyverno/kyverno) at the commits of `v1.15.0` to `v1.15.20` and `v1.16.0` to `v1.16.4` listed in `cli/internal/extract/crdversions/testdata/oracle/PROVENANCE.txt` | Apache-2.0; [license](LICENSES/Source-Kyverno-Apache-2.0.txt) |
| Longhorn CustomResourceDefinition manifests (`deploy/longhorn.yaml`), The Longhorn Authors; modified (schema bodies replaced, other documents removed) | [github.com/longhorn/longhorn](https://github.com/longhorn/longhorn) at the commits of `v1.8.0` to `v1.8.2` and `v1.9.0` to `v1.9.2` listed in `cli/internal/extract/crdversions/testdata/oracle/PROVENANCE.txt` | Apache-2.0; [license](LICENSES/Source-Longhorn-Apache-2.0.txt) |

The `k8s.served-api-removal` and `k8s.feature-gate-removal` extractors' tests
include trimmed copies of Kubernetes source files at synthetic fixture commit
identifiers. Each Go file keeps its upstream license header ("Copyright The
Kubernetes Authors", with the upstream year). The fixture directories'
`PROVENANCE.txt` files list, for every file, the upstream release tag, the
upstream commit and the SHA-256 of the whole upstream file. Files marked
"verbatim" there are unchanged; every other file was cut down (see the
modifications column) and is therefore a modified copy. The copies serve only
as test input and do not establish runtime behavior.

| Retained material and attribution | Immutable source identity | Upstream terms included with the Community source |
| --- | --- | --- |
| Kubernetes API registration and lifecycle files (`zz_generated.prerelease-lifecycle.go` verbatim; each `register.go` trimmed to its license header, package clause and `GroupName` constant) and `api/openapi-spec/swagger.json` reduced to the `x-kubernetes-group-version-kind` entries of the autoscaling, batch, policy, flowcontrol, authentication, apiextensions and apiregistration groups, The Kubernetes Authors; modified (trimmed), in `cli/internal/extract/k8sservedapis/testdata/fixture/github.com/kubernetes/kubernetes` | [`kubernetes/kubernetes`](https://github.com/kubernetes/kubernetes) at v1.24.0 `4ce5a8954017644c5420bae81d72b09b735c21f0`, v1.25.0 `a866cbe2e5bbaa01cfd5e969aa3e033f3282a8a2`, v1.30.0 `7c48c2bd72b9bf5c44d21d7338cc7bea77d0ad2a`, v1.31.0 `9edcffcde5595e8a5b1a35f88c421764e575afce`, v1.32.0 `70d3cc986aa8221cd1dfb1121852688902d3bf53`, v1.33.0 `60a317eadfcb839692a68eab88b2096f4d708f4f`; per-file upstream SHA-256 values in `cli/internal/extract/k8sservedapis/testdata/fixture/PROVENANCE.txt` | Apache-2.0; [license](LICENSES/Source-Kubernetes-Apache-2.0.txt) |
| Kubernetes feature-gate definitions (`kube_features.go`, `feature_gate.go`, `known_features.go` and the feature-list YAML files), The Kubernetes Authors; modified (each cut down to a few feature gates and formatted with gofmt) unless `PROVENANCE.txt` marks the file verbatim, in `cli/internal/extract/k8sfeaturegates/testdata/fixture/github.com/kubernetes/kubernetes` | [`kubernetes/kubernetes`](https://github.com/kubernetes/kubernetes) at v1.22.0 `c2b5237ccd9c0f1d600d3072634ca66cefdf272f`, v1.23.0 `ab69524f795c42094a6630298ff53f3c3ebab7f4`, v1.31.0 `9edcffcde5595e8a5b1a35f88c421764e575afce`, v1.32.0 `70d3cc986aa8221cd1dfb1121852688902d3bf53`, v1.36.0 `ecf6decece6a6de25a57aad9ba90b6ce580f6f78`, v1.37.0 `f54c212e3a2f75d674b717a9b29052b20b60aefc`; per-file upstream SHA-256 values in `cli/internal/extract/k8sfeaturegates/testdata/fixture/PROVENANCE.txt` | Apache-2.0; [license](LICENSES/Source-Kubernetes-Apache-2.0.txt) |

## Go 1.26.8 notices included with binaries

The complete `LICENSES/` directory accompanies each Linux binary archive.
These notices come from the exact Go 1.26.8 distribution used to enumerate
the CLI's Linux amd64 and arm64 dependencies with `CGO_ENABLED=0` and no
Go experiments. Upstream comment prefixes are preserved in extracted notice
blocks; their copyright, permission, and disclaimer text is unchanged.

| Included material | Preserved notices |
| --- | --- |
| Go runtime and standard library | [Go BSD license](LICENSES/Go-BSD-3-Clause.txt) and [Go patent grant](LICENSES/Go-PATENTS.txt). |
| Standard-library vendored Go subrepositories | [x/crypto license](LICENSES/Go-x-crypto-BSD-3-Clause.txt), [patents](LICENSES/Go-x-crypto-PATENTS.txt); [x/net license](LICENSES/Go-x-net-BSD-3-Clause.txt), [patents](LICENSES/Go-x-net-PATENTS.txt); [x/sys license](LICENSES/Go-x-sys-BSD-3-Clause.txt), [patents](LICENSES/Go-x-sys-PATENTS.txt); [x/text license](LICENSES/Go-x-text-BSD-3-Clause.txt), [patents](LICENSES/Go-x-text-PATENTS.txt). The x/sys CPU package is selected for amd64. |
| amd64 runtime memory copying derived from Inferno | [Lucent, Vita Nuova, and Go copyright and MIT terms](LICENSES/Go-runtime-Inferno-MIT.txt), from `src/runtime/memmove_amd64.s`. |
| Edwards25519 scalar arithmetic generated by fiat-crypto | [fiat-crypto copyright and BSD terms](LICENSES/Go-fiat-crypto-BSD-1-Clause.txt), from `src/crypto/internal/fips140/edwards25519/scalar.go`. |
| Math implementations derived from upstream numerical code | [SunPro 1993 notice](LICENSES/Go-math-SunPro-1993.txt), [SunPro 2004 notice](LICENSES/Go-math-SunPro-2004.txt), and [Stephen L. Moshier attribution](LICENSES/Go-math-Moshier.txt). The Go BSD license also accompanies these Go implementations. |

This is a conservative union of the two platform source dependency sets;
linker elimination can remove unused functions. Compiler-only dependencies,
the race runtime, and BoringSSL library objects are not included in these
release binaries. The ordinary Go `notboring` implementation remains covered
by the Go notices. Changed toolchains, build experiments, CGO settings, targets,
or imported dependencies require a fresh notice inventory.
