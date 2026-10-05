# Changelog

All notable user-visible changes to Prufyx are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- One exit-code table for `scan` and `check` ([exit-codes.md](cli/docs/exit-codes.md)),
  and an opt-in `--strict-exit` flag on every `check` route: a scoped `PASS`
  exits `14` instead of `0`, so CI cannot read one passed rule as a complete
  pass (`scan` exit `0` means a complete scope). Without the flag, exit codes,
  output and replay reports are unchanged. A line on standard error notes the
  scoped pass when the flag is used.
- Per-repository owner baseline choice for repositories whose latest release the
  shared rule refuses to choose (`PENDING_AMBIGUOUS_LATEST`). The owner records
  the chosen tag and the exact commit it must resolve to in
  `cli/knowledge/repin-baselines.json` (strict schema). `evidence repin
  --baselines FILE` compares the repository's otherwise pending citations with
  that tag, only while the tag exists and resolves to exactly the recorded commit;
  they record `baseline: owner_choice` and the entry digest. A human statement can
  renew on it (`evidence reattest prepare|verify --baselines`; new `verify` check
  V12 and V9 comparison; automation never does). The knowledge gate admits a
  change to the file only with an owner approval per entry (approval v2,
  `subject: repinBaseline`, single-use and forward-only like records; check
  `repin-baselines`), and re-runs the evidence check with the base file.
  `approval sign|verify --subject repinBaseline` signs and checks it.
  The ambiguity rule itself is unchanged.

### Fixed

- `evidence reattest verify --rerun-worklist` (V9) now also compares the signing
  job's worklist with the independent one on `resolution` and every other
  baseline-selecting field (stale flag, baseline mode, baseline, line, pinned and
  compared tag, owner entry digest), in both directions. A forged worklist that
  drops `resolution: tag_fallback` from a latest-baseline citation is refused.

### Changed

- `extract apply --withdraw` now requires the rule to cite both commits of the run's pair (from and to), not just a subset of them; otherwise it refuses with exit 3.
- `evidence reattest`: a pending citation now excludes only the rules that cite
  it (`CITATION_PENDING`) instead of every rule of the pack. The statement
  records the pending citations and `verify` re-derives them. `prepare` and
  `evidence repin` name the pending repositories with the number of rules they
  affect. `prepare --now` overrides the clock for rehearsals only; such a
  statement is marked and is refused by `sign` and `verify`.
- `factory mirror` reads release metadata in pages of 20 (it was 100), so
  repositories with long release notes no longer exceed the 8 MiB page bound
  and are no longer left with unknown releases; `--release-pages` now counts
  pages of 20 (default 100). `evidence repin` chooses the latest release or
  tag with one rule shared by the HTTP and mirror sources (highest strict
  version among non-draft, non-pre-release releases; strict-version tags only
  for the tags fallback; other or mixed tag prefixes, or a non-strict newest
  release, leave the repository pending instead of choosing), documented in `cli/docs/evidence-repin.md`.
- `check cncf --native-resource` and `check cncf --custom-resources` print
  `scoped result: BLOCKED`, `UNKNOWN` or `PASS` before the `aggregate:` line.
  It is the result of the checked rules and matches the exit code; the
  aggregate line stays the whole-upgrade compatibility, which these modes
  never decide.
- `prufyx-maintainer evidence repin` compares citations in repositories
  without GitHub Releases (for example `golang/go`) with the newest release
  tag on their pinned tag's own line (`baseline: tag_line`), derived from the
  repository's git tags, instead of one repository-wide tag. Anything it
  cannot order keeps the previous baseline with the reason. Releases named
  as pre-releases (`-rc1`, `-RC.1`, `-beta.0`) no longer make a release line
  ambiguous when GitHub does not flag them. `evidence reattest` accepts
  tag-line citations in human statements only.
- The knowledge gate's default daily loosening limit is 50 (was 400). The
  repository variable `KNOWLEDGE_MAX_DAILY_LOOSENING` still raises it.
- The CLA workflow no longer prints commit author e-mail addresses in its
  comment; it names the commits instead.

### Documentation

- README and the `scan` and quickstart guides now state how rules are
  established, which input permissions `check` and `scan` accept, what `scan`
  covers today and why it cannot yet answer PASS, and the date the rule counts
  were taken.
- THIRD-PARTY.md lists the Kubernetes-derived test fixtures with their
  upstream commits, and `LICENSES/` includes the Kubernetes Apache-2.0 text.

### Added

- `prufyx-maintainer extract apply --rules-only` merges only the run's rules,
  without attestations and without changing the pack schema. The new
  `prufyx-maintainer extract supersede --out RUN --pack FILE` removes the
  reviewed rules that rules of the run cover (same constraint key, a region
  containing the reviewed rule's), adds the run's rules and prints the old to
  new map as JSON; partial coverage, a run that matches no reviewed rule and
  any other change are refused with exit 3 and nothing is written.
  Documented in `cli/docs/extractors/tooling.md`.
- `prufyx-maintainer approval sign` writes an owner approval for one reviewed
  rule of a change, checked with the knowledge gate's own verifier before it is
  written; `approval verify` checks one approval file offline. The key comes
  from a file only its owner can read (mode `0600` or `0400`, no link) or from
  a pipe on standard input. `approval public-key` and `approval keys-digest`
  print the values needed to pin the key.

- Custom-resource versions: Prufyx records which custom-resource versions
  (`group/version/Kind`) your rendered manifests use for Argo CD, Istio and
  Strimzi, the projects whose CRDs the `crd.version-removal` extractor reads.
  An object is assigned to a project only through a reviewed, compiled table
  of the API groups each project's CRDs define; an unknown or shared group is
  never assigned, and keeps every set incomplete. Rules over the set block on
  a listed version and pass only when you declare the manifests complete.
  New `check cncf` mode `--custom-resources FILE`
  (`--custom-resources-complete`, `--custom-resources-digest`), which can
  block (exit 10) but never exits 0, and `scan` now checks these projects'
  custom-resource versions instead of reporting them as not evaluated (they
  are never reported as covered). No rules are shipped yet. See
  `cli/docs/custom-resources.md`.
- Knowledge compatibility: the fact registry gains the three custom-resource
  version sets, so its digest changes, and the embedded CNCF pack moves to
  revision `cncf-2026-09-13.3` (same rules; only the registry digest and the
  revision differ). External CNCF packs and knowledge databases built against
  the previous registry, including revision `cncf-2026-09-13.2`, are refused
  by this release until they are rebuilt.
- Knowledge compatibility: the fact registry gains the four Kubernetes
  removed-API facts of the 1.33 (`authentication.k8s.io/v1beta1`
  SelfSubjectReview), 1.34 (`admissionregistration.k8s.io/v1beta1`
  ValidatingAdmissionPolicy and ValidatingAdmissionPolicyBinding) and 1.37
  (`networking.k8s.io/v1beta1` IPAddress and ServiceCIDR,
  `storage.k8s.io/v1beta1` VolumeAttributesClass) lines, which the
  `k8s.served-api-removal` extractor derives rules over. The embedded CNCF
  pack moves to revision `cncf-2026-09-13.4` (same rules; only the registry
  digest and the revision differ). External CNCF packs and knowledge
  databases built against the previous registry, including revision
  `cncf-2026-09-13.3`, are refused by this release until they are rebuilt.
  No rule reads the four facts yet. A `check cncf` or `check batch` input
  that declares one of them is now evaluated instead of refused (exit 2):
  `check cncf --project kubernetes` (`--native-resource` or `--input`) and
  `check batch` on a transition into 1.33, 1.34 or 1.37 report UNKNOWN
  (exit 11, no reviewed transition), and an input for another transition
  that also declares one of these facts is decided by that transition's own
  rules, as for any other fact the rules do not read. `scan` still reports a
  hop into 1.33, 1.34 or 1.37 as having no reviewed rule.
- Maintainer tooling: `review-record new` writes the review record for a rule
  that an `evidence reattest` human statement sampled for full review. It
  checks the prepared statement against the rule pack, the worklist and the
  engine, refuses a rule the statement did not sample and a line attestation
  or path-policy record, and computes every binding (prior pack, worklist,
  engine, the rule's exact version and its compared citations) from the
  checked statement. `evidence reattest prepare` and `verify` check every
  binding again and refuse a record for a rule the statement does not sample.
  `review-record new --individual` writes an individual review of a rule the
  statement renews or holds back only by the consecutive-cycle cap. A declared
  review record no longer satisfies a sampled rule. See
  `cli/docs/evidence-reattestation.md`.
- Maintainer tooling: `prufyx-maintainer` refuses a repeated option also when
  it is spelled with one dash (`-name`).
- `prufyx scan`, `prufyx check cncf` and `prufyx check batch` print one line on
  standard error when the knowledge they used has an active rule that ends
  within 30 days of the evaluation instant, or has already ended, and point to
  `prufyx db update` and `--knowledge-db`. Standard output, the JSON, SARIF and
  Markdown formats and the exit status are unchanged. See the scan and
  community-checks guides.
- A composite GitHub Action (`action.yml`) that runs `prufyx scan`: it installs
  a checksum-verified release binary or builds from source, writes the
  Markdown report to the job summary, and exposes the report file for SARIF
  upload. See `cli/docs/github-action.md`.
- Maintainer tooling: `prufyx-maintainer consensus normalise` and
  `consensus verify` check a removal claim read from upstream release notes
  against pinned bytes, offline and without a model. Only the release's
  "Urgent Upgrade Notes" and "Changes by Kind" subsections are read, and every
  line must fit a strict line grammar (plain text, headings, `-`/`*` list
  items nested exactly, code spans matched on their line, and links without
  a title to the project's GitHub organisations, contributors and
  documentation hosts); a heading section with anything else (raw HTML,
  comments, images, code blocks, tables, link definitions and more) is never
  cited, a claim whose name appears in one stays a lead, and raw HTML anywhere
  in the release section before a cited item makes it a lead. The release
  notes must be read at the release's tag commit or later on its release
  branch. A name must be cited by exactly one visible list item with a
  removal cue that is not negated, future or undone, and named nowhere else
  in the read subsections; it must exist in the earlier release's mechanical
  inventory and be absent from the later one's; and the item's pull request
  links must appear in the release range's commit subjects. Exit codes 0, 2,
  3 and 4. The knowledge gate re-runs the verifier on a consensus rule's
  claims bundle (at most 20 bundles and ten minutes per run) and reports the
  verdict; consensus rules are still not admitted. See
  `cli/docs/consensus-verify.md`.

- Knowledge format: CNCF rule packs can carry an optional `distributions`
  section (pack schema `prufyx.io/cncf-source-rule-pack/v1alpha9`) with
  reviewed Kubernetes distribution records (control-plane model, and for
  OpenShift a minor-line mapping to Kubernetes) and per-distribution
  statements of which rule families apply. A distribution or family without a
  current statement is a gap, and `not_applicable` never contributes to a
  PASS. No records are shipped. The external target format, the per-project
  split, `evidence reattest`, `evidence repin` and the support inventory
  refuse a pack with the section for now. See
  `cli/docs/kubernetes-distribution-versions.md`.

- `prufyx scan --knowledge-db DIR` reads the rules from a verified local CNCF
  knowledge database (`cncf` or `cncf-projects` layout, filled by `db update`
  or `db import`) instead of the knowledge built into the binary, so renewed
  or withdrawn rules reach `scan` without a new binary. The database is
  verified exactly as for `check cncf --knowledge-db` and the scan is evaluated
  at that verification time (`--now` is refused with it). Any verification
  failure exits 3 and never falls back to the built-in knowledge. A targeted
  project the per-project index does not list is reported with the new gap
  `PROJECT_NOT_IN_KNOWLEDGE`. The report's provenance names the database
  (`knowledgeStore`: path, layout, target, trust receipt and each project
  target) in every output format; `--redact` replaces the path with its
  digest. `scan` never writes to the directory: a path that is not an existing
  private (0700) knowledge database is refused before it is opened. Without
  the flag the output is unchanged.

- Maintainer tooling for automated runs of the extractors: `extract apply`
  merges a run's rules and line attestations into a rule pack (sorted, refusing
  an id that exists with different content and any change to a rule the run did
  not produce, and admitted by the rule checks and the engine loader), or with
  `--withdraw` marks the rules the extractor no longer produces as withdrawn;
  `extract inventory` prints the complete feature-gate, served-kind or
  custom-resource inventory parsed at one commit, or exits 3 without a list;
  `extract run --wants-out` lists the files the offline mirror lacks (exit 3)
  instead of withholding silently; and `factory mirror --test-releases-api-base`
  (tests only, refused without `--test-allow-file-remote`) reads release
  metadata from a local server. See `cli/docs/extractors/tooling.md`.
- Maintainer tooling: the `crd.version-removal` extractor (registered as
  `crd.version-removal.<project>` for Argo CD, Istio and Strimzi) derives
  rules for custom-resource versions a release no longer serves, from the
  CustomResourceDefinition manifests in the project's repository at two
  release tags, and records every CRD's served and storage versions in the
  run manifest. No rules are shipped. See
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
- `prufyx scan --format sarif` (SARIF 2.1.0 for GitHub code scanning: one error
  result per finding and location, not-checked areas, one-way changes and leads
  as tool notifications, verdict and provenance as run properties) and
  `--format markdown` (tables for pull request comments and change tickets).
  The exit code does not depend on the format; `--redact` applies to both.
- Maintainer tooling: the knowledge gate compares the CNCF pack's line
  attestations and upgrade-path policies record by record instead of refusing
  every change to them. Removing a line attestation, withdrawing a path policy
  or moving a record's `validUntil` earlier is tightening. A reviewed record
  renews only through one verified automated reattestation statement that
  renews it and changes nothing but its `reviewedAt` and `validUntil`, exactly
  as the statement gives them; a mechanical line attestation only when the
  extractor in the gate re-derives it byte for byte; a reviewed line
  attestation otherwise only with an owner approval for exactly that record
  plus a cross-check against the extractor's own derivation of the line.
  Record changes count toward the loosening limits and the kill switch, a new
  breaker limits how many records one change may switch off, and review
  records for records are refused. A CNCF pack holding records still fails
  the per-project target check until that split supports them. See
  `cli/docs/knowledge-gate.md`.
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

- Rules over a custom-resource version set can no longer make a check exit 0
  outside the `--custom-resources` mode. The generic
  `check cncf --project P --input FILE` route (embedded or `--knowledge-db`
  knowledge, and its replay) exits 11 at best whenever an evaluated rule reads
  `component.<project>.custom_resource_versions_set`, and its human output
  says why; a `check batch` CNCF item with such a rule is never `PASS`. This
  holds until a per-release-pair record shows that the published rules name
  every version a release stops serving. `assess --scope-input` cannot
  evaluate such rules. No such rule is shipped yet.
- An object of a kind other than `List` with a top-level `items` array is no
  longer read as a resolved part of the apply set (`check cncf --project
  kubernetes --native-resource`, `check cncf --custom-resources` and `scan`):
  only `List` kinds are flattened, so the objects in its `items` were never
  read, and a removed API version inside them could pass. Such an object is
  now left out like any document that cannot be placed: the set is
  unresolved, `scan` names the gap `DOCUMENTS_NOT_EVALUATED` (also on lines
  without removed APIs), and the object is never a witness. A removed version
  in the other documents still blocks (exit 10).
- A blocker is no longer hidden by unrelated input that cannot be read. Before,
  one templated, unparseable or non-Kubernetes document next to a
  `batch/v1beta1` CronJob turned `scan` from `BLOCKED` with one finding into
  exit 11 with no finding. A removed API version used by a document that was
  read is now reported as `BLOCKED` (exit 10) when that document is applied
  as written whatever the unread documents hold. A document that may not be
  rendered at all is not used: one in a file where an unread document opens
  or closes a template action (`if`, `range`, `with`, `define`, `block`,
  `else`, `end`) that it does not close within one value, a test template or
  a document of a conditional or unlisted subchart of a raw Helm chart, and a
  Helm test hook. The unreadable documents are still listed as omitted and named as a
  gap, so the answer is never a pass, and absence is never concluded from
  them: every other removed-API fact, and any rule that depends on what they
  contain, stays undecided. The same applies to
  `check cncf --project kubernetes --native-resource` and to custom-resource
  versions (`scan` and `check cncf --custom-resources`), where the versions
  read are recorded as an incomplete set.
- `scan` could answer `PASS FOR THE DECLARED SCOPE` with a document that was
  read but could not be placed as a Kubernetes object (an `apiVersion` or
  `kind` that is not valid, or a list with invalid metadata) when every hop
  entered a release line without removed APIs. Such a document is now always
  the gap `DOCUMENTS_NOT_EVALUATED`, whatever the declarations, and also
  for projects checked for custom-resource versions when a rule blocks.
- The rule parser rejects a `forbid_predicate_value` rule whose `appliesWhen`
  requires its own condition fact to hold a different value. Such a rule could
  never block, yet it passed and could make a component scope-complete.
  `prufyx-maintainer rule validate` reports it as `vacuous-condition`. No
  published rule is affected.
- `--redact` output now orders finding locations and omitted documents by
  their redacted values, so the order no longer reveals how the hidden paths
  sort.
- The knowledge gate's full re-derivation no longer re-derives a changed
  mechanical rule that the change itself already re-derived: each failure is
  reported once, and the count excludes changed rules that were already
  re-derived. A tightening edit to a mechanical rule (an earlier expiry) is
  still re-derived and counted.
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
