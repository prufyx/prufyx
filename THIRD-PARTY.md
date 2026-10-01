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
| Synthetic fixtures and checkpoint source | Prufyx-authored examples and recorded first-party source checkpoints. Recorded source paths describe checkpoint provenance, not independent origin attestations. |

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

The Apache-2.0 grant for first-party Prufyx material at the top of this file is
separate from these upstream works and does not relicense the PingCAP document.

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
