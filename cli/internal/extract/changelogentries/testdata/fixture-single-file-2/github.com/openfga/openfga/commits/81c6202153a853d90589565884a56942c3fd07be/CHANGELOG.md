# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Try to keep listed changes to a concise bulleted list of simple explanations of changes. Aim for the amount of information needed so that readers can understand where they would look in the codebase to investigate the changes' implementation, or where they would look in the documentation to understand how to make use of the change in practice - better yet, link directly to the docs and provide detailed information there. Only elaborate if doing so is required to avoid breaking changes or experimental features from ruining someone's day.

## [Unreleased]

## [1.18.3] - 2026-08-05
### Fixed
- Fixed experimental `weighted_graph_check` intermittently returning `false` when evaluating relations that cross two or more distinct recursive TTUs which share the same tupleset relation. [#3244](https://github.com/openfga/openfga/pull/3244)

## [1.18.2] - 2026-08-03
### Added
- Extended experimental `weighted_graph_check` diagnostic logging to cover the `wildcard_with_exclusion` and `userset_with_exclusion` shapes: the log now fires when v2 Check rejects one of these shapes and Check falls back to v1, and when v2 Check is skipped entirely because the weighted graph fails to build. These logs surface authorization models that may be affected by a future v1 deprecation, and no operator action is required. [#3204](https://github.com/openfga/openfga/pull/3204)

### Changed
- Matched experimental `weighted_graph_check` cache metrics with original Check cache metrics: iterator cache metrics renamed to `tuples_cache_total_count`, `tuples_cache_hit_count`, `tuples_cache_discard_count`, `tuples_cache_size`; query cache metrics added as `check_cache_total_count`, `check_cache_hit_count`, `check_cache_invalid_hit_count`. [#3184](https://github.com/openfga/openfga/pull/3184)

### Fixed
- Fixed experimental `weighted_graph_check` incorrectly returning `false` for models with two or more independently-recursive relations where satisfying the outer recursive relation requires resolving through an unrelated, nested recursive relation (e.g. `descendant_principal: member or descendant_principal from child_group` where `member` transitively reaches a separately-recursive `admin: direct_admin or admin from parent_group`). `FlattenNode` now only excludes edges belonging to the specific recursive relation currently being unwound, instead of excluding every recursive edge in the graph. Thanks to [@yxshwanth](https://github.com/yxshwanth) for the contribution! [#3195](https://github.com/openfga/openfga/issues/3195)
- Tuple condition validation now checks that a condition is bound to the specific type-restriction facet (concrete user, typed wildcard, or userset) that matches the tuple's user, not just the user type and condition name. Previously a relation such as `define viewer: [user, user:* with cond]` would accept a tuple like `document:1#viewer@user:alice` carrying `cond`, even though `cond` is only defined on the `user:*` facet. Because this validation also runs when reading tuples during query resolution, such tuples are now consistently rejected across Check and ListObjects. See `internal/validation/validation.go`. [#3218](https://github.com/openfga/openfga/pull/3218)
- Converted the FlattenNode function of the internal/modelgraph package from a recursive algorithm to an iterative one. This more robustly handles deep relationship nesting. [#3224](https://github.com/openfga/openfga/pull/3224)
- Fixed experimental `weighted_graph_check` returning incorrect results for multi-branch recursion on the same relation; e.g., `member: [user] or member from parent or member from child`. [#3239](https://github.com/openfga/openfga/pull/3239)

### Security
- Update toolchain Go version to 1.26.5 and rebuild the embedded `grpc-health-probe` (bumped to `v0.4.53`, built with Go 1.26.5) so released images no longer ship the Go standard library vulnerabilities documented in the [Go 1.26.5 release notes](https://go.dev/doc/devel/release#go1.26.5), including CVE-2026-39822. [#3219](https://github.com/openfga/openfga/pull/3219)
