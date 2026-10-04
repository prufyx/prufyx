# Changelog

All notable user-visible changes to Prufyx are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Maintainer tooling: the `crd.version-removal` extractor (registered as
  `crd.version-removal.<project>` for Argo CD, Istio and Strimzi) derives
  rules for custom-resource versions a release no longer serves, from the
  CustomResourceDefinition manifests in the project's repository at two
  release tags, and records every CRD's served and storage versions in the
  run manifest. No rules are shipped: the custom-resource version set they
  read is not declared by any adapter yet. See
  `cli/docs/extractors/crd.version-removal.md`.
- `prufyx scan`: one command that reads rendered manifests (files,
  directories or standard input) and an upgrade target, and answers with one
  headline: `BLOCKED` (exit 10) with the file, object and fix for every
  blocker, `NO BLOCKERS FOUND IN COVERED CHECKS` (exit 11) with every area that
  was not checked and what to do about it, or `PASS FOR THE DECLARED SCOPE`
  (exit 0) only when nothing is missing. It evaluates Kubernetes API versions
  that a release on the way stops serving, plans the upgrade one release line
  at a time when a reviewed upgrade-path policy exists, reads `prufyx.yaml`,
  accepts files other users can read with a note (`--input-permissions
  strict` refuses them), prints digests instead of paths and names with
  `--redact`, lists one-way changes and unverified leads separately without letting them
  change the answer, lists combinations outside a documented support range
  (never a pass, never a blocker), accepts `--require-basis` like `check cncf`, and writes JSON with schema `prufyx.io/scan-report/v1alpha1`
  (`cli/docs/generated/schemas/scan-report-v1alpha1.json`). See
  `cli/docs/scan.md`.
- Maintainer tooling: the knowledge gate gains circuit breakers (a change that
  withdraws more than 5 percent of a pack's active rules, or more than 20 rules
  of one project, fails with an alarm), a per-day limit on loosening changes
  counted from the history of `main` (`gate daily-count`, fails closed), a shadow
  mode in which no change is ever eligible for automatic merging, and per-run
  `gate-metrics.json` and `gate-alarms.json` files with an optional alarm issue
  in a separate repository. See `cli/docs/knowledge-gate.md`.
- `prufyx-maintainer evidence reattest` renews reviewed line attestations and
  reviewed upgrade-path policies in automated mode, so a pack carrying them
  is no longer refused; human batches leave them out, and a review record for
  one is refused. Only each renewed record's `evidence.reviewedAt` and
  `evidence.validUntil` change; a new check (V10) refuses any other change to
  either section, and every attestation must still list exactly the pack's
  rules for its scope. Mechanical records are never renewed by it. `evidence
  repin` now also classifies the citations of attestations and path policies,
  and the support inventory reads every CNCF pack schema level: it accepts
  packs with set rules, attestations or path policies, and refuses notice,
  consensus, lead and support-range rules until each has its own section.
  See `cli/docs/evidence-reattestation.md`.
- The CNCF knowledge database can be published as one signed TUF target per
  project (`knowledge/cncf/projects/<project>.v1.json`) plus an index target
  (`knowledge/cncf/index.v1.json`), each capped at 1 MiB, through the new
  `cncf-projects` profile of `db verify`, `db import`, `db update` and
  `db status`. The index and every project target are verified against the
  signed targets role; missing, extra, mismatched and oversize targets are
  rejected, and the index and each project keep their own rollback floor.
  `check cncf` and `check batch` detect the layout from the store and read
  only the projects being checked. Per-project packages may be up to 8 MiB.
  See `cli/docs/cncf-knowledge-per-project.md`.
- `prufyx-maintainer knowledge-targets build` writes the per-project targets
  from the embedded pack deterministically, and `knowledge-targets
  check-size` fails when any target reaches 80% of the 1 MiB per-target cap,
  naming the target and its size. CI runs the size check.

### Changed

- A rule pack (embedded or external) in which any object holds a repeated
  member, or two members whose names differ only in letter case, is now
  refused, because different JSON readers would read it differently. The
  shipped packs are unchanged.
- Input files that must be private are now accepted with any owner-only mode
  (`0600`, `0400`, `0700`, ...); only a group or other permission bit is refused.
  This applies to every `check cncf` route that reads a private input file.
- With the single-target `cncf` profile, a per-project package or store is
  now rejected before the store changes with exit code `2`, a message that
  names the `cncf-projects` profile, and `db update` reason
  `KNOWLEDGE_LAYOUT_MISMATCH`. Existing single-target stores keep working.
- Human output of `check cncf` on the Kubernetes native-resource route and
  the other native-resource routes, and of the generic `--input` preview, is
  shorter and answers first. `PASS` claims are counted instead of listed
  (`--show-passes` lists them), the aggregate follows the claims, each
  distinct pinned source is printed once at the end, and a transition no rule
  reviews prints one `UNKNOWN` line naming the reviewed pairs instead of one
  block per rule. JSON output, verdicts and exit codes are unchanged.
- The Kubernetes native-resource route (`check cncf --project kubernetes
  --native-resource`) now reads single and multi-document YAML as well as JSON,
  flattens `v1` `List` and typed `*List` documents, and treats template syntax
  per document instead of anywhere in the file. JSON input produces the same
  prepared input digest and verdicts as before; JSON `null` values (as printed
  by `kubectl get -o json`) are now accepted. Input size and file-permission
  rules are unchanged.
- Prufyx is now published at `github.com/prufyx/prufyx`. The Go module path is
  `github.com/prufyx/prufyx/cli`.
- Source code is licensed under the GNU Affero General Public License v3.0 only
  (`AGPL-3.0-only`), replacing Apache-2.0. Reviewed knowledge data is licensed
  under CC BY-SA 4.0; see `DATA-LICENSE.md`.
- Contributions require a signed Contributor License Agreement (`CLA.md`)
  instead of a DCO sign-off.

### Added

- Rule data can now carry one-way upgrade notices: a reviewed rule that says a
  transition cannot be rolled back, with the reviewed steps to take before
  upgrading. A notice shows up as its own `NOTICE` claim and its own lines in
  human output (`cannot be rolled back: ...`, `before you upgrade: ...`); it
  never changes a verdict, an aggregate or the exit status. No notice rules
  are shipped yet.
- Evidence bases `empirical`, `consensus` and `lead` for rules, and
  `check cncf --require-basis LIST` on every route, embedded and external
  knowledge. A consensus rule (two independent model readings, citations
  verified) may block but never passes: where it finds nothing its claim is
  `NO_KNOWN_ISSUE` (exit 11) and a scope assessment stays UNKNOWN
  (`CONSENSUS_ONLY_SCOPE`). A lead (one unverified model reading) never blocks
  or passes and is evaluated only when `lead` is listed. The default admits
  `reviewed,mechanical,empirical,consensus`; a check that left out rules says
  how many (`trustPolicy` in JSON, a `trust policy:` line in human output),
  and one that left out a verdict rule (any basis other than lead) never exits
  0. `check batch` has no `--require-basis` and always uses the default. Every finding prints its evidence basis, and human output
  states how many findings rely on model consensus. Documents with a consensus
  or lead rule use rules schema
  `prufyx.io/deterministic-constraint-rules/v1alpha5` and pack schema
  `prufyx.io/cncf-source-rule-pack/v1alpha7`. No such rules are shipped yet.
- Support-range rules: a `require_component_version` rule may carry
  `"severity": "unsupported"`. When the declared combination is outside the
  documented support range the claim is `UNSUPPORTED` (the rule's own reason
  code and next action), not `BLOCKED`: it is never a pass, the exit status is
  11 unless another claim blocks, and a scope assessment stays UNKNOWN
  (`UNSUPPORTED_COMBINATION`). Human output adds a headline line naming how
  many component combinations are outside their documented support range.
  Documents with such a rule use rules schema
  `prufyx.io/deterministic-constraint-rules/v1alpha6` and pack schema
  `prufyx.io/cncf-source-rule-pack/v1alpha8`. No such rules are shipped yet.
- A scope-completeness report is now refused unless every PASS, BLOCKED or
  `NO_KNOWN_ISSUE` claim is listed under its component. Before, a hand-edited
  report could move a blocking claim into `outOfScopeRules` and still pass the
  report's self-consistency check as a scope-complete pass (replay already
  caught it). Reports produced by Prufyx are unchanged.
- Upgrade-path policies: a knowledge pack may carry an optional
  `pathPolicies` section saying how a component's upgrades are split into
  hops (`sequential_minor`, `direct` or `sequential_major`), each record with
  the same cited, time-limited evidence as a rule. A pack with the section
  uses schema `prufyx.io/cncf-source-rule-pack/v1alpha5`, which earlier
  binaries reject, and is rejected as a whole if any record is malformed or
  names a component that is not a catalog project's. A component without a
  current policy is never assumed to allow skipping lines. A pack now always
  carries the schema of the newest feature it uses. No verdict or exit code
  changes, and the published pack carries no policies. See
  `cli/docs/upgrade-paths.md`.
- Line attestations: a knowledge pack may carry an optional
  `lineAttestations` section stating that, for one component, minor line and
  fact family, the listed rules are all the rules (none for a quiet line). A
  pack with the section uses schema
  `prufyx.io/cncf-source-rule-pack/v1alpha4`, which earlier binaries reject,
  and is rejected unless every attestation lists exactly the pack's rules for
  its line and family and each listed rule matches every upgrade into the
  line. The pack's top-level member names must be spelled exactly. The
  `k8s.served-api-removal` extractor (1.1.0) writes mechanical attestations to
  `attestations.json` when a run attests at least one line. Attestations do not change
  any verdict or exit code, and the published pack carries none. See
  `cli/docs/line-attestations.md`.
- `prufyx-maintainer gate export|classify|limits|verify` and the `Knowledge
  gate` workflow check every change to the shipped knowledge. Each changed
  rule is classified from the pack diff, as the engine reads it, as tightening
  (withdraw, earlier `validUntil`) or loosening (anything else, including any
  change to a top-level pack member); a loosening change is admitted only when
  the gate re-derives a mechanical rule byte for byte from upstream bytes it
  fetches itself, verifies a signed reattestation statement against its own
  evidence check, or verifies a pinned owner approval bound to the base and
  proposed entry. Trust material can change only through a person's change
  matching a pinned digest. The gate checks the exact git blobs of both
  commits, checks every pack, caps loosening changes per change, honours a
  `factory/PAUSE` kill switch and reports, without acting on it, whether a
  change is eligible for automatic merging and for which head commit. See
  `cli/docs/knowledge-gate.md`.
- Rules may declare how their evidence was produced: `evidence.basis`
  (`reviewed` or `mechanical`; absent means reviewed), `evidence.extractor`
  and `evidence.derivedAt`. The fields are parsed strictly, never affect a
  verdict, and are shown with every finding in human output (`evidence basis:
  ...`) and, for mechanical rules, in JSON (`evidenceBasis`,
  `evidenceExtractor`, `evidenceDerivedAt`). Existing rule packs and reports
  are unchanged. `evidence reattest` refuses to renew a mechanical rule.
- A local, machine-verifiable declared-review consistency record that binds one
  selected rule to exact packet, source-corpus, target, and executed-vector
  evidence. It does not authenticate the declared reviewer, admit a full target,
  sign metadata, or select a client store.
- An additive unsigned knowledge release plan for binding publisher assertions
  to client import, including compatible v1 receipt reuse and v2 assertion
  verification. The workflow has no official signing root, feed, or publication.
- Bounded 4 MiB release-list intake, preserving the existing closed schema and
  rejecting oversized, malformed, or inconsistent input before use.
- Native CoreDNS Corefile and Envoy JSON-bootstrap routes, a Prometheus
  `remote_write` HTTP/2-default route, and a MariaDB Operator Galera
  `autoUpdateDataPlane` prerequisite check. Each remains limited to its exact
  reviewed versions, input authority, and documented `UNKNOWN` boundary.
- An OpenTelemetry Collector native internal-metrics check for the exact
  0.110.0 to 0.111.0 localhost-default change, requiring complete resolved
  configuration and explicit feature-gate and non-loopback scrape declarations.
- Release-audit corrections for bounded support-inventory source reads,
  canonical JSON error propagation, Go 1.26.8 enforcement, DCO range checking,
  shipping allowlists, complete entrypoint verification, staged receipt bounds,
  and release-workflow state checks.
- Local batch checks for up to 64 prepared canonical inputs, with descriptor-relative
  file admission, deterministic scoped reports, embedded or explicitly selected
  signed local CNCF knowledge, and no cluster, network, subprocess, or database
  update operation.
- Exact native CNCF predicates for Kubernetes `1.31.0` to `1.32.0` flow-control
  v1beta3 resources, Cilium `1.16.19` to `1.17.18` effective ConfigMap cluster
  names, and containerd `1.7.28` to `2.0.0` selected official runtime shims.
- A scoped MariaDB `10.11.8` to `11.4.2` native option-file predicate for an
  explicitly required removed InnoDB defragmentation behavior.

- An explicit adopter-managed CNCF metadata refresh workflow. The existing
  Community CLI import, update, and check path can consume a compatible signed
  rule revision without changing that binary. A Community CLI built from this
  source reports TUF and source-evidence freshness separately and exposes the
  fixed target contract. The maintainer binary exports a complete compatible
  replacement target, prepares deterministic sequential TUF role payloads,
  signs public role metadata with encrypted local role keys, and verifies the
  final package through the existing consumer path. These source tools do not
  configure an official root or feed, publish bytes, or enable automatic
  startup refresh.
- A development-preview latest-target matrix, checked on 2026-09-12, covering
  115 selected exact project/version pairs across 23 projects. Each project
  contributes five selected earlier stable releases to one exact target. The
  matrix distinguishes native input from operator declarations, names each
  scoped predicate and `UNKNOWN` boundary, preserves an additional historical
  Jaeger route, and records Notation as a qualification gap. It does not claim
  universal minor-line coverage, runtime proof, or whole-upgrade safety.
- Two additional canonical Prometheus `2.55.1` to `3.14.0` constraints over
  existing operator-declared facts. They cover the selected Alertmanager
  `api_version` and classic-histogram key only, remain outside the
  23-project/115-selected-pair matrix, and preserve `UNKNOWN` for missing,
  custom, unresolved, runtime, and whole-upgrade state.
- A bounded offline collection verifier for multiple private source-corpus shards.
  It verifies retained bytes, rejects conflicting metadata and duplicate records,
  counts shared objects once, and binds per-shard receipts. Source interpretation,
  rule acceptance and publication remain separate.
- A contributor review record template binding exact endpoints, source spans,
  scoped claims, distinct test cases and independent review decisions.
- An explicit maintainer-only capture tool for bounded immutable public GitHub
  source requests. It checks declared file and line-span hashes, writes private
  candidate evidence, and requires separate offline verification and source
  review. The product CLI does not invoke it or send customer configuration.
- An offline public-source corpus verifier with bounded manifests, retained
  file and exact line-span hashes, repeatable receipts, and a synthetic example.
  This maintainer tool verifies local bytes and declared metadata only; it does
  not download sources, establish release provenance, or publish rules.
- An offline upstream evidence contribution validator, versioned candidate packet,
  examples, and an issue template. Validation checks local consistency only;
  it cannot authenticate a maintainer, verify upstream bytes, publish a rule,
  or authorize model training. Public submissions remain closed during private review.
- An embedded CNCF catalogue with 255 pinned identities and an initial
  maintainer-selected portfolio of 30 projects, separate from rule coverage.
- An optional local source-constraint preview: 35 exact rules across 31
  projects and 65 registered facts, with 290 rule-scoped cases, bounded
  UNKNOWN remediation, source hashes and review expiry. Existing named checks
  remain separate.
  Added exact Fluentd minimum-Ruby and Crossplane Composition-mode constraints;
  these require declared proposed facts and do not test application startup.
- Added separate exact Falco 0.40.0 to 0.41.0 and 0.40.0 to 0.42.0
  constraints, plus Kuma 2.8.0 to 2.9.0 source
  constraints. Their proposed command-surface facts are operator declarations;
  missing, custom, ambiguous, and other-surface inputs remain UNKNOWN, with no
  argv-parser or runtime claim.
- Added an exact Linkerd 2.13.7 to 2.14.0 MeshTLSAuthentication target-schema
  constraint. Its selector and validation-scope facts are operator declarations;
  CRD parsing, API admission, stored-object migration, and runtime behavior remain
  outside the preview.
- Added an exact SPIRE 1.10.4 to 1.11.0 source constraint for legacy `-ttl`
  and `--ttl` options in the declared proposed direct `spire-server entry create`
  surface. Official-distribution and command-surface guards are required;
  argv parsing, replacement validation and server runtime remain unverified.
- Added two exact Dragonfly 2.2.3 to 2.2.4 constraints for declared debug-log
  retention intent in the manager and scheduler configuration surfaces. Each
  requires the matching surface, official distribution and explicit current
  and proposed intent; configuration parsing, default inference and runtime
  behavior remain unverified.
- Added an exact Cortex 1.17.2 to 1.21.1 constraint for the declared removed
  `querier.at-modifier-enabled` command option, with official-distribution and
  command-surface guards. This establishes no query or runtime behavior.
- Added an exact Strimzi 0.51.0 to 1.0.0 Kafka custom-resource API constraint.
  Declared `v1beta2` presence is scoped BLOCKED only with explicit official
  target-CRD admission intent and the matching resource surface. Installed CRDs,
  API admission execution and stored-resource migration remain unverified.
- An exact Karmada 1.18.3 to 1.19.0 application-failover `purgeMode` constraint
  for declared PropagationPolicy or ClusterPropagationPolicy input. Removed
  `Immediately` or `Graciously` values are scoped BLOCKED only with official
  target-CRD admission intent and the matching surface. The check does not parse
  policy resources; its optional one-resource preparer can only witness a legacy
  value. CRD/API admission execution, migration, complete-set absence and
  failover runtime remain unverified.
- Optional local Karmada preparation for the exact 1.18.3 to 1.19.0 transition
  reads one private policy and witnesses only a legacy value. Missing or replacement
  values remain UNKNOWN; it never proves aggregate absence or PASS.
- A fixed compiled registry capacity of 256 fact definitions for reviewed CLI
  capabilities. Generic registry construction and per-component input and enum
  limits remain 64; downloaded metadata cannot add fact definitions.
- Optional local Linkerd preparation from one private MeshTLSAuthentication
  JSON resource. It derives selector emptiness and records explicit distribution
  and schema-validation intent, while disclosing that it does not validate a CRD.
- Private-file CLI admission, exact report replay and a synthetic Helm example
  for the preview. No generic transition has runtime reproduction evidence.
- Optional `prepare cncf` for the Kyverno 1.12.5 to 1.13.0 constraint. It derives
  minimized facts from a private proposed Pod or Deployment JSON, with explicit
  distribution and the bare `reports-controller` scope. Wrappers and unresolved
  invocations remain UNKNOWN. Preparation performs no
  upgrade check or live observation and retains no raw workload data.
- An explicit offline cert-manager knowledge database using operator-provisioned
  TUF roots and signed local packages, with current status, exact selection
  assertions and separately labeled historical replay.
- A public synthetic empty-to-active knowledge example whose ephemeral signing
  keys are never persisted.
- A separate signed CNCF knowledge profile for data-only rule updates over the
  compiled registry and operators. Local import, current checks and exact
  historical replay work with the same binary; a synthetic Kyverno example
  demonstrates empty-to-active coverage. No public feed is configured.
- Explicit `db update` downloads a bounded complete package from a chosen HTTPS
  URL, retains it privately for recovery, and reuses local TUF verification.
  Download requests receive no evaluation inputs. An offline maintainer helper
  assembles already signed metadata without changing signed bytes or review dates.

### Fixed

- Immutable upstream file paths may start a segment with an underscore, allowing
  paths such as Karmada's `_crds`. Owner, repository, revision, network and path
  traversal restrictions remain enforced.
- Bound the etcd and containerd constraints to direct final-release source
  registrations and removal statements. This replaces the etcd release-candidate
  changelog reference and strengthens containerd provenance while preserving the
  existing predicates and review-expiry dates.
- Corrected the Kyverno constraint and preparer to require the reports-controller
  execution surface and an explicit upstream-distribution declaration. The
  previous generic Kyverno command scope was unsupported by the retained source.
  Old boolean-only declarations now remain UNKNOWN. The preparer recognizes only
  literal `reportsChunkSize` integer options within deterministic signed 32-bit
  bounds; unrelated or ambiguous arguments remain UNKNOWN.
- Release-gate fixtures now restore the caller's file-creation mask, retain
  private evidence outside their synthetic public source tree, and use bounded
  subprocess waits for FIFO admission checks.

### Security

- Candidate artifact metadata now accurately describes separate attestations
  as requiring independent verification; local or ordinary CI metadata does
  not itself prove that an OIDC attestation exists.
- Generic rules cannot add collection fields, fetch references, execute code or
  upload inputs. The preview accepts compiled boolean/enum facts only and keeps
  whole-upgrade assessment UNKNOWN. CNCF and cert-manager signed knowledge use
  separate stores and fixed target profiles. CNCF review validity is bounded
  to 90 days, independently of TUF metadata freshness.
- External selection is complete and fail closed: missing, stale, withdrawn or
  invalid data never falls back to embedded knowledge or mixes
  rules across revisions.
- Release source builds use an exact vendored module profile with module sums,
  a canonical whole-tree digest, binary-resource pins and byte-bound notices.

## [0.1.0-alpha.4] - 2026-09-07

### Added

- A focused `check cert-manager-values` command for three removed monitoring
  settings in the reviewed 1.20.3 → 1.21.1 transition. Reports include source
  identity, remediation, explicit schema-validation assumptions and local replay.
- Named `check prometheus-mode` output with human and JSON formats. Its scoped
  PASS exits 0; the legacy command retains aggregate exit 11.
- A single content-addressed source policy with complete selected tests,
  native Linux package gates and required vulnerability and secret scanning.

### Security

- Optional collection retains typed public component facts instead of private
  image references, and uses context pseudonyms that change between runs.
- Credential helper environment forwarding is explicit and bounded; ambient
  proxy settings require an explicit operator choice.
- Local values checks reject unsafe file types, permissive modes, oversized
  inputs, duplicate JSON keys and digest/replay mismatches.

### Scope

- The focused public entrypoint includes the two documented checks. Broad
  research commands are excluded from the selected source package.
- Both checks keep whole-upgrade aggregate UNKNOWN. Runtime upgrade testing,
  independently downloaded knowledge and broader transition coverage are planned.

## [0.1.0-alpha.3] - 2026-09-07

### Added

- A deterministic local assessment for one source-reviewed question: whether
  a declared Prometheus Agent/Server mode is preserved from `2.55.1` to
  `3.1.0` on the reviewed Linux `arm64/v8` image manifests.
- Scoped `PASS`, `ATTENTION`, and `UNKNOWN` results with source receipts,
  minimized input bindings, explicit omissions, and bounded next actions.
- A no-cluster synthetic example covering each scoped outcome while keeping
  synthetic evidence visibly non-authoritative.
- An opt-in, read-only kubeconfig collection path for a real current
  observation, with producer-bound mode and platform-image predicates.
- Community contribution, DCO 1.1, and private vulnerability-reporting
  guidance.

### Security

- Proposed workload files require an exact SHA-256 pin and private file mode.
- Synthetic current evidence is rejected by the real-observation authority
  path.
- Completed mode assessments always retain aggregate `UNKNOWN` and exit `11`.

### Known limitations

- Only Prometheus `2.55.1` to `3.1.0` and the exact reviewed Linux `arm64/v8`
  platform-manifest digests are supported.
- The result covers declared mode preservation only. Process startup, applied
  runtime state, data safety, remote write, rollback, and whole-upgrade
  compatibility are not evaluated.
- Release assets and artifact signatures are not claimed until the maintainer
  publishes them.

[Unreleased]: https://github.com/prufyx/prufyx-cli/compare/v0.1.0-alpha.4...HEAD
[0.1.0-alpha.4]: https://github.com/prufyx/prufyx-cli/releases/tag/v0.1.0-alpha.4
[0.1.0-alpha.3]: https://github.com/prufyx/prufyx-cli/releases/tag/v0.1.0-alpha.3
