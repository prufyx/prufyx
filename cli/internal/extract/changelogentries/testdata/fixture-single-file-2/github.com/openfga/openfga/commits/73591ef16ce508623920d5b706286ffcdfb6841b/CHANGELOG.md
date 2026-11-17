# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Try to keep listed changes to a concise bulleted list of simple explanations of changes. Aim for the amount of information needed so that readers can understand where they would look in the codebase to investigate the changes' implementation, or where they would look in the documentation to understand how to make use of the change in practice - better yet, link directly to the docs and provide detailed information there. Only elaborate if doing so is required to avoid breaking changes or experimental features from ruining someone's day.

## [Unreleased]

## [1.20.0] - 2026-09-08
### Added
- Added `WithServiceName` server option to allow embedders to override the `serviceName` field used for the `grpc_service` label on OpenFGA's package-level Prometheus metrics and `telemetry.RPCInfo.Service`. This enables multiple `Server` instances in the same process to emit separate metric series. Note it does not rename the standard gRPC server metrics (e.g. `grpc_server_handled_total`), whose labels are derived from the registered gRPC service. Use stable, low-cardinality names, as the value becomes a metric label. Defaults to `openfgav1.OpenFGAService_ServiceDesc.ServiceName` when omitted (backward compatible). [#3265](https://github.com/openfga/openfga/pull/3265)

### Fixed
- Fixed a deadlock in ListUsers that caused a timeout with partial results when the number of union/intersection operands exceeded `OPENFGA_RESOLVE_NODE_BREADTH_LIMIT` and the operands each resolved to more than one user. Thank you to [@fabianluque](https://github.com/fabianluque) for the discovery and detailed report! [#3284](https://github.com/openfga/openfga/pull/3284)

### Security
- Upgraded go toolchain and images to use go1.26.8 to fix [CVE-2026-39821](https://pkg.go.dev/vuln/GO-2026-5026). [#3287](https://github.com/openfga/openfga/pull/3287)
- Rebuilt the embedded `grpc-health-probe` (bumped to `v0.4.57`, built with Go 1.26.8) to match the server toolchain and pick up `google.golang.org/grpc` v1.83.2, which fixes [GHSA-vp52-pcj8-j9qc](https://github.com/advisories/GHSA-vp52-pcj8-j9qc). [#3289](https://github.com/openfga/openfga/pull/3289)

## [1.19.0] - 2026-08-24
### Added
- Adds configurable pipeline optimization for weight-one difference subtract edges with high cardinality on wildcard leaves. For now, this configuration is internal only. [#3267](https://github.com/openfga/openfga/pull/3267)

### Fixed
- Fixed validation-ordering defect where malformed `RelationReference` (relation_or_wildcard oneof set but yielding neither wildcard nor non-empty relation) panicked `WriteAuthorizationModel`. `NewAndValidate` now runs all validation before graph construction. Also closed gap in `validateTypeRestrictions` that silently accepted a positional variant, causing model-wide nil weighted graph and performance degradation. **Breaking:** Already-persisted malformed models fail to resolve on cache miss with `ErrInvalidModel` rather than silently running degraded. See `pkg/typesystem/typesystem.go`. [#3262](https://github.com/openfga/openfga/pull/3262)
- Scope context-cancelation stripping to query execution only. No longer can deadlock on saturated connection pool. [#3255](https://github.com/openfga/openfga/pull/3255)
- Updated v2 resolution diagnostic logging in `Check` and `ListUsers` to gate on InfoLevel log level. Removed diagnostic logging from `Expand` whose resolution will not change. [#3254](https://github.com/openfga/openfga/pull/3254)

### Security
- Fixed [GHSA-5278-rrxc-mgf7](https://github.com/openfga/openfga/security/advisories/GHSA-5278-rrxc-mgf7), where StreamedListObjects could return a result that should have been excluded during an error. Thank you to [@yxshwanth](https://github.com/yxshwanth) for the detailed report and fix.
