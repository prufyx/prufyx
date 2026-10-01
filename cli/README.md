# Prufyx Community CLI

Build the Community binary from this module with Go 1.26.8:

```sh
GOTOOLCHAIN=local GOWORK=off GOFLAGS='-mod=vendor -buildvcs=false' GOPROXY=off GOSUMDB=off \
  go build -trimpath -buildvcs=false -o ../prufyx ./cmd/prufyx-community
../prufyx --help
```

The Community entrypoint exposes focused cert-manager values and Prometheus mode
checks, plus an unreleased [CNCF source-constraint preview](docs/CNCF-SOURCE-PREVIEW.md)
over minimized operator declarations. Optional `prepare cncf` derives only its
documented exact-pair facts from one private local JSON input. The
[generated support inventory](docs/generated/community-support-inventory.md)
is the complete current list of preparer-capable projects and their limits. It
retains no raw workload data and performs no live observation or upgrade check.
The exact external Go module closure is included under `vendor/` and
bound by the Community v2 source policy, so builds do not fetch modules. It has
no hosted account requirement or model invocation. See the [quickstart](../README.md),
[command guide](docs/community-checks.md),
[cert-manager knowledge database](docs/knowledge-database.md),
[CNCF knowledge database](docs/cncf-knowledge-database.md),
[Buildpacks Lifecycle Platform API plan walkthrough](examples/cncf/README.md#review-a-buildpacks-lifecycle-platform-api-plan),
[in-toto-run key argument walkthrough](examples/cncf/README.md#review-an-in-toto-run-key-argument-plan),
[TUF Updater source-call walkthrough](examples/cncf/README.md#review-a-tuf-updater-source-call),
[KFP Python SDK component-authoring walkthrough](examples/cncf/README.md#review-a-kfp-python-sdk-component-authoring-change),
[CubeFS MetaNode planned-upgrade walkthrough](examples/cncf/README.md#review-a-cubefs-metanode-planned-upgrade-guard),
[CRI-O ArtifactStore named-reference walkthrough](examples/cncf/README.md#review-a-cri-o-artifactstore-named-reference-plan),
[OPA and Kyverno latest-target walkthroughs](examples/cncf/README.md#review-opa-and-kyverno-latest-target-constraints),
[SPIFFE X.509-SVID public-leaf URI-SAN subset](docs/spiffe-x509-svid.md),
[CloudEvents structured JSON core-envelope subset](docs/cloudevents-structured-json.md),
[TiKV 8.5.8 GCS WIF full-backup planned-operation preflight](docs/tikv-gcp-v2-wif-backup.md),
[Distribution and CNI native format preflights](docs/native-format-preflights.md),
[community-project native configuration and workload checks](docs/community-project-checks.md). The native CNCF routes include exact Kubernetes flow-control, Cilium ConfigMap, and containerd selected-runtime predicates; each retains unsupported facts as `UNKNOWN`. For Fluent Bit, use `check project --project fluent-bit --effective-config FILE --from 3.2.0 --to 4.0.0 --effective-config-complete --current-default-was-used --preserve-http2-enabled --now RFC3339` for the reviewed default-preservation route, or one listed origin to `5.1.2` with `--require-http2` for the separate target-only requirement. See the
[local batch check guide](docs/batch-checks.md),
[product contract](docs/product-contract.md) and
[data handling](docs/data-handling.md).

Run all tests in this staged Community module with `go test -mod=vendor ./...`, and
run `go vet -mod=vendor ./...`. Native release and collector checks are specified by the
[source gate](release/COMMUNITY-SOURCE-GATE.md).
