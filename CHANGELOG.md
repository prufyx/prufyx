# Changelog

All notable user-visible changes to Prufyx are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `scripts/kind-val.sh --name-prefix P` names the clusters `P-<line>` (default `prufyx-kind`, unchanged), so several runs (each with its own prefix and `--out`) can share one Docker host; their cluster creations take turns where `flock` exists (`--create-lock`).
- CNCF knowledge: 13 custom-resource version-removal rules (`crd.version-removal`)
  for Crossplane (2), Kyverno (1) and Strimzi (10), each forbidding a
  custom-resource version the target release no longer serves, and Strimzi
  line attestations for the lines 0.50, 0.51, 1.1, 1.2 and 1.3. Pack revision
  `cncf-2026-09-13.8` is unchanged; `check cncf` and `scan` can now block such
  an upgrade where the declared custom resources still use a removed version.
- Knowledge gate: a change that adds fact definitions to the CNCF fact registry
  (and so moves the pack's `registryDigest`) is admitted with an owner approval
  of the new subject `registryDigest`, signed and checked with
  `prufyx-maintainer approval sign|verify --subject registryDigest`. The gate
  reads the definitions from the base and head source without running the
  change's code and refuses any removed, retyped or moved definition, a digest
  that does not match, and any other top-level pack change in the same change.
  Existing gate decisions are unchanged.
- The embedded knowledge pack carries mechanical line attestations for every
  Kubernetes line from 1.20 to 1.37, which `scan` reads for those lines. Nine
  lines in which no served API was removed (1.20, 1.21, 1.23, 1.24, 1.28,
  1.30, 1.31, 1.35, 1.36) carry an empty rule list; the other nine (1.22,
  1.25, 1.26, 1.27, 1.29, 1.32, 1.33, 1.34, 1.37) list the served-API removal
  rules derived for them. A hop into an attested line no longer reports
  `LINE_NOT_ATTESTED` for removed APIs. The pack moves to schema `v1alpha4`;
  earlier builds refuse such a pack, so upgrade the CLI first. External
  knowledge keeps its format: only a records envelope carries attestations.
- Maintainer command `prufyx-maintainer docs-tables` (with `--check`): writes
  the tables of the reviewed custom-resource projects and of the
  `crd.version-removal` targets to `cli/docs/generated/` from the data compiled
  into Prufyx; the hand-written pages link to them. No check output changes.
- `prufyx scan` can check a Helm chart upgrade: `--chart PROJECT=NAME[@SOURCE]`
  (or `declarations.helm` in `prufyx.yaml`) declares that the project's
  `--from`/`--to` versions are chart versions, resolved through exactly one
  current row of the reviewed chart-source table, and `--helm-values FILE`,
  `--helm-set KEY=VALUE` and `--helm-values-complete` supply the values the
  release uses. Such a hop is checked only against the chart's rules about
  required and no longer accepted values keys and the Kubernetes version the
  chart needs (`--to kubernetes=` is then needed); application rules are
  never applied to it, application hops are unchanged, and the rest of the
  chart and application upgrade is always reported as not checked. Values
  files must be strict YAML; a key left `null` after the merge or values not
  declared complete keep required keys undecided. Values are never printed;
  the report identifies them by digest. The built-in knowledge carries no
  chart rule yet, so a chart hop is reported as not evaluated. The
  `scan-report-v1alpha1` JSON schema gained the optional members
  `inventory[].chart`, `paths[].chart`, `chart` in hop references,
  `findings[].keys` and `provenance.helmValues`; integrators who vendor the
  schema should refresh it.
- `prufyx check cncf` fact-family checks of an input that declares a
  component's `chart` are now served by that chart's rules only: a chart rule
  about another chart is never selected, and an application rule over the same
  facts is reported undetermined (`RULE_APP_VERSION_NOT_DECLARED`). Inputs
  without a declared chart are selected exactly as before.
- Knowledge paths for community-catalog projects (inert until a rule of one is
  published): the rule pack has its own schema level for entries of a
  community project (only `forbid_set_member` rules over the project's own
  custom-resource version set), the knowledge database carries a per-project
  target for it under `knowledge/community/projects/` (the shared index is
  then `v3`), and `check cncf --custom-resources`, `scan`, `catalog checks`,
  the support inventory and the scan report accept it, labelled as the
  community catalog in every output (a note in each scan format, `catalog` in
  the JSON report, the inventory and the rule listing). A community project is
  never in the CNCF catalogue, its counts or the corpus attestation, and it
  cannot carry a line review yet. Without a community rule in the knowledge
  nothing changes, except that a scan configuration file may now name a
  community project (the scan then refuses it, as `--to` does, instead of
  calling it unknown). The `scan-report-v1alpha1` JSON schema gained the
  optional member `inventory[].catalog` (`"community"`); integrators who vendor
  the schema should refresh it.
- Maintainer extractor `crd.version-removal` 2.3.0: a `{{` inside a CRD schema
  `description` is read as documentation (Cluster API's ClusterClass) while any
  other `{{` still makes the file a template; a target can switch to another
  repository from one release line on (Kong Ingress Controller reads
  `Kong/kubernetes-configuration` from 3.4, citations at full commits of that
  repository); a project with several install channels declares the one the
  rules are about and reads the others (Gateway API's standard and
  experimental channels), and a version another channel still serves is never
  forbidden.

- Community catalog for custom-resource versions: the reviewed
  custom-resource table now also lists projects outside the embedded CNCF
  landscape catalog, each labelled `community` (no CNCF status is asserted)
  and carrying its upstream repository and licence, cited from the licence
  file at a full commit. Ten community projects join it: Cluster API,
  Elastic Cloud on Kubernetes, Gateway API, Kong Ingress Controller, Kueue,
  MongoDB Controllers for Kubernetes, Node Feature Discovery, the Percona
  Operator for PostgreSQL, the Prometheus Operator and Rancher. Their
  custom-resource version sets are registered and their API groups are
  attributed to them, so their objects no longer keep other projects' sets
  incomplete; nothing about them is checked yet (`check cncf` and `scan`
  refuse a community project with a message saying so, and no rule or line
  review of one can be published). The maintainer extractor
  `crd.version-removal` gains the ten targets (`"catalog": "community"` in
  its target table; a community target never attests).
  The fact registry changes with the ten sets, so the embedded CNCF pack moves
  to revision `cncf-2026-09-13.8` (same rules; only the registry digest and the
  revision differ); external CNCF packs and knowledge databases built against
  the previous registry, including revision `cncf-2026-09-13.7`, are refused by
  this release until they are rebuilt.
- API groups in the namespaces Kubernetes reserves (`*.k8s.io`, `*.x-k8s.io`,
  `*.kubernetes.io`) are listed in the custom-resource table only through a
  reviewed ownership record (group, defining repository, owning project),
  never by suffix; overlaps are refused. `gateway.networking.k8s.io`
  (Gateway API) is such a group: it is now a custom-resource group of Gateway
  API, and `scan` no longer checks Gateway API objects against the list of
  APIs Kubernetes serves (nor counts them as alpha Kubernetes APIs), unless
  that list names the group.
- Maintainer extractor `helm.values` 1.0.0, registered once per reviewed chart
  as `helm.values.<project>.<chart>` (cert-manager, External Secrets Operator,
  the Istio gateway chart, KEDA, MetalLB and the OpenTelemetry Collector). It
  compares a chart's source at the first release of two consecutive release
  lines and derives anchor-only chart rules only where Helm itself refuses the
  upgrade: a raised `kubeVersion` lower bound (`require_component_version` on
  Kubernetes), keys the values schema newly requires with no default
  (`require_set_member`), and keys a closed schema object no longer admits
  (`forbid_set_member`). Removed or changed defaults and values the templates
  no longer reference are recorded in the proof, never as rules. Charts whose
  `Chart.yaml` carries a placeholder version at the release tag (cert-manager,
  Istio) are withheld. `extract inventory` prints a `helm-values` inventory for
  these ids. The chart-source table now holds a reviewed, cited row for each
  of these charts; only `rulecheck` reads it. It runs through
  `cli/internal/extract/chartrun`; its code digest covers the extractor
  framework, `chartrun` and its own package. No other extractor's code digest
  or output changes. See `cli/docs/extractors/helm.values.md`.

- Chart rules (not used by any shipped rule yet): a rule subject may name a
  Helm chart (`subject.chart`, a normalised repository URL and a chart name),
  and the new `require_set_member` operator passes only when a complete
  declared set holds every listed member, blocks when a complete set lacks one
  (the claim lists `missingMembers`), and is UNKNOWN otherwise. A chart rule
  applies only to a component declared through that same chart; an
  application rule never applies to a chart hop, which is UNDETERMINED
  (`RULE_APP_VERSION_NOT_DECLARED`). Documents with such a rule use rules
  schema `prufyx.io/deterministic-constraint-rules/v1alpha8` and pack schema
  `prufyx.io/cncf-source-rule-pack/v1alpha13`; documents without one are
  byte-identical and evaluate exactly as before. `rulecheck` admits a chart
  rule only from a mechanical extractor and only for a chart listed in the
  reviewed chart-source table. See `cli/docs/contributing-rules.md`.
- Extractor framework, chart extractors (not used by any extractor yet): a new
  package, `cli/internal/extract/chartrun`, runs extractors whose candidates
  name a chart in the rule subject and may carry a `require_component_version`
  dependency. It stamps, checks and writes runs exactly as the extractor
  framework does (same manifest schema, files and reads logs) and generates
  and engine-checks the vectors of chart `forbid_set_member`,
  `require_set_member` and a proposed-side `gte` dependency bound (the blocked
  vector's missing members are compared too). The framework's own files do
  not change and no other extractor imports the package, so the code digests
  of `k8s.feature-gate-removal`, `k8s.served-api-removal` and every
  `crd.version-removal.*` id do not move. A chart extractor's code digest
  covers the framework, `chartrun` and its own package.

- Set notices (no shipped rule uses them yet): two verdict-neutral operators
  over a declared set fact on a chart hop. `notice_set_member_present` is a
  NOTICE when a listed member is present (complete set or not; the claim
  lists `matchedMembers`); `notice_set_member_absent` is a NOTICE only when a
  complete set lacks a listed member (the claim lists `missingMembers`).
  Otherwise each is UNKNOWN, with the new reason `RULE_NOTICE_NOT_APPLICABLE`
  when a complete set gives it nothing to say; that claim prints nothing. Set
  notices are counted in `noticeRules`, never decide or change an aggregate,
  carry their own reason code and no verdict wording, and their members are
  never printed as forbidden or required members. Documents with one use rules
  schema `prufyx.io/deterministic-constraint-rules/v1alpha9` (scope contract
  `scope-completeness-contract-v8`) and pack schema
  `prufyx.io/cncf-source-rule-pack/v1alpha14`; documents without one keep
  their schema, digests and replay bytes. `rulecheck` admits a set notice
  only from a mechanical extractor, on a values-path set fact, with reason
  `HELM_VALUES_KEY_NOT_REFERENCED` (present) or `HELM_VALUES_DEFAULT_CHANGED`
  (absent), and a set notice carries no `appliesWhen`. See
  `cli/docs/contributing-rules.md`.

- Ranged chart rules (no shipped rule uses them yet): a chart rule may carry a
  `range` that widens it from its anchor pair to every release of two chart
  release lines, in one of two shapes only. Between consecutive lines of one
  major the range pins the later line's first release as a boundary
  (`PREVIOUS_MINOR_LINE`, `CHANGED_IN_RELEASE` or `REMOVED_IN_RELEASE`,
  `TARGET_SERIES`), so a hop that crosses it from outside the range is
  UNKNOWN with `RULE_RELEASE_BOUNDARY_NOT_REVIEWED`, never not applicable;
  between any other two lines each side is one whole line
  (`UPGRADE_FROM_SERIES`, `TARGET_SERIES`). Any other basis, a range on an
  operator other than `require_component_version`, `require_set_member` or
  `forbid_set_member`, a crossing and a severity are refused on a chart rule;
  set notices stay anchor-only. A hop matched through the range discloses it
  in `subjectMatch` and never makes the declared scope complete; a report
  seals that disclosure on a chart-rule claim only under the new contract. Documents
  with such a rule use rules schema
  `prufyx.io/deterministic-constraint-rules/v1alpha10` (scope contract
  `scope-completeness-contract-v9`) and pack schema
  `prufyx.io/cncf-source-rule-pack/v1alpha15`; a chart rule with a range under
  `v1alpha8` or `v1alpha9` is refused, and documents without one keep their
  schema, digests and replay bytes. `rulecheck` admits a ranged chart rule
  only from a mechanical extractor, in one of the two shapes, with each anchor
  the first release of its line. See `cli/docs/contributing-rules.md`.
- Maintainer extractor `helm.values` 1.3.0 ranges a Kubernetes minimum, newly
  required values or keys the schema no longer admits rule over both release
  lines of its pair when the same derivation, run on every final release of
  the earlier line against every final release of the later one, gives the
  same rule as the anchors, every release reads, each line has more than one
  final release, each anchor is the first release of its line and no tag
  outside the tag scheme (another prefix, a part over four digits, a tag
  without a commit) names a version of either line. Otherwise the rule stays
  anchor-only, as do all notices. The range covers every version of both
  lines, including releases without a matching tag and later patches; the
  proof covers only the tagged final releases it lists. The proof records the
  pair's range outcome and, per rule kind, the outcome, the number of release
  pairs checked and the first pair whose rule differs. A ranged rule's next
  action names the later line (`2.16.x`). The chart extractor runner
  (`internal/extract/chartrun`) carries a chart rule's range into the entry
  (`rule.range`) and leaves the decision to `rulecheck` and the engine: a
  range outside the chart-range shapes, or whose anchors are not the first
  releases of both lines, refuses the run. Only `helm.values` and `chartrun`
  source changed, so the code digest of every `helm.values.*` extractor
  changes and its earlier outputs must be derived again; no other
  extractor's code digest changes. See `cli/docs/extractors/helm.values.md`.

- KIND-VAL (maintainer tool, `cli/internal/tools/kindval` and
  `cli/scripts/kind-val.sh`): checks the Kubernetes knowledge against real
  API servers in kind clusters, one per release line: the served APIs
  against the removal table, scan verdicts for a corpus of removed-API
  manifests against server dry runs, and upstream CRD release pairs against
  supplied custom-resource claims. Writes machine-readable results (every
  claim confirmed, refuted or unevaluated) and a summary. Not part of the
  test suite. See [kind-val.md](cli/docs/kind-val.md).
  `kindval crd` also installs, on its own, a release that `crd-version`
  claims name and no pair covers, so those claims are decided instead of
  `undetermined`; a release that cannot be installed from the claim's
  evidence stays `undetermined` with the reason, a failed fetch or install is `error`.
  Results v2 (additive): a `prufyx.io/kind-val-claims/v2` claims file gives
  `prufyx.io/kind-val-results/v2`, where every claim also has a `verdict`
  (`confirmed-by-execution`, `refuted`, `undetermined`, `error`) and, unless
  confirmed, a `reason` from a closed list of codes. The run also decides
  reviewed control claims (known true and known false, embedded from
  `controls.json`, each value cited to an upstream file at a commit) for
  every kind it has; they are reported apart in `controls`, and when a
  control of a kind does not come out as expected on a line, every claim of
  that kind on that line is an `error` with reason `canary-failed` and a
  `HIGH` finding names the control. `kind-val.sh` still writes v1 claims and
  results by default; `--v2` opts in. A v1 claims file gives exactly the v1
  results as before.
  New claim kind `crd-field` (claims v1 and v2): a field-level change between
  two releases of a project's CRDs (`field-removed`, `field-required-added`,
  `field-type-changed`, `enum-value-removed`, `validation-tightened`) is
  decided by the API server's strict field validation. Within the run of the
  release pair, `kindval crd` reads the installed From schema from the
  cluster, builds a minimal object that sets only the claimed path, requires
  a server dry run (`--validate=strict`) to accept it at From, sends it again
  after To is applied in place and after a fresh install of To (which
  decides), and matches To's answer against a closed set of
  message patterns on the exact path. A refusal for another reason or on
  another path, a permissive schema, a path absent at From, a missing value
  or an object that cannot be built is `undetermined` with a reason code
  (`schema-permissive`, `path-not-in-from`, `value-missing`,
  `object-not-buildable`, `from-rejected`, `other-rejection`); `refuted`
  means only that To's CRD schema accepts the object (webhooks and
  controllers are not installed). The crd run file gains `fields` (additive);
  Schema-validation paths match in both array spellings (`[N]` and `.N`) and
  bracketed map keys; an accept while the path is absent from To's schema is
  `undetermined`; an in-place dry run with no answer leaves the fresh install
  to decide (no cross-check).
  reviewed `crd-field` controls join the controls file.

- Knowledge gate: the first attested update of a pack that holds an older schema
  is admissible. A change of the pack's top-level `schema` member is admitted
  only when it raises the schema to exactly the lowest level the pack's content
  requires, with nothing else changing at the top level, every rule and record
  change admitted by its own rules, and no trust material or registry change
  in the same pull request; every other pack-member change is still refused.
  Such a change is never eligible for automatic merging (the owner merges the
  first attested update of a pack). To retract a wrong attestation, withdraw it
  rather than deleting it; deleting the last record needs the owner path.

- Knowledge targets carry records: per-project CNCF targets (and the single
  target) now carry line attestations, upgrade-path policies and served-API
  lists, each record in the target of the project whose component it names.
  A target with records uses the envelope
  `prufyx.io/operator-cncf-knowledge/v1alpha2` and its index
  `prufyx.io/cncf-knowledge-index/v2` (entries flag `records: true`); a pack
  without records produces the same v1 bytes as before. Clients admit each
  record with the checks of the embedded pack and refuse a record in another
  project's target; binaries without this support refuse such a database
  rather than read it without its records. `scan --knowledge-db` reads
  served-API lists from the database. The knowledge gate's `targets/cncf`
  check now passes for a pack with records, and a new `records-trust` check
  refuses a change that changes records and trust material together.
  Distribution records still have no target and are refused.
- Line attestations per component: the fact family
  `crd.custom_resource_versions` covers, for each project of the
  custom-resource table, the rules over its own custom-resource version set.
  Its attestations carry a new `releases` member naming every release of both
  lines the derivation read, and cover a hop only between two of them. The
  maintainer extractor `crd.version-removal` 2.1.0 attests every line it
  derives completely (all releases, clean full-tree scan, line-wide rules, no
  removed definition) for the next minor line of the same major; the
  knowledge gate admits such an attestation only by re-deriving it, and
  cross-checks a reviewed one against the extractor of its own component.
  `scan` then reports, per hop, a family result (`PASS` or `BLOCKED` within
  `crd.custom_resource_versions` only, with the family's scope); the project
  is still never covered and the answer never `PASS` because of it. `check`
  routes keep the exit cap and now say they read no line review. The coverage
  report counts these attestations as A for the family. No attestation is
  shipped. Compatibility: once a pack carries such an attestation, every
  earlier build, including v0.0.1-alpha.1, refuses the whole pack (unknown
  family), fail-closed; upgrade the CLI first. A patch upgrade within a
  reviewed line has its own gap. See `cli/docs/line-attestations.md` and
  `cli/docs/custom-resources.md`.

### Changed

- CLI help: `prufyx check -h`, `prepare -h`, `check cncf -h`, `prepare cncf -h` and the
  `project` routes are now a purpose, three examples and a flags table (under 40
  lines). `--project SLUG --help` on a route prints that project's usage. The former
  long usage moved to generated pages in `cli/docs/projects/`. `prufyx help --all`
  lists hidden commands and flags; `community-preview` no longer shows in the overview.

- The 25 reviewed Kubernetes served-API removal rules of the embedded pack are
  replaced by the rules the `k8s.served-api-removal` extractor derives from the
  pinned upstream source (rule ids `kubernetes.served-api-removal.*`, evidence
  basis `mechanical`), plus four new ones (Kubernetes 1.33
  `authentication.k8s.io/v1beta1`, 1.34 `admissionregistration.k8s.io/v1beta1`
  and two for 1.37). The conditions are unchanged and the version ranges equal
  or wider, so the same manifests are `BLOCKED`; the reason code is now
  `KUBERNETES_SERVED_API_REMOVED`, and the rule ids, next-action text and cited
  sources differ. A mechanical rule is current only from its derivation
  instant: an evaluation time (`--now`) before `2026-10-17T06:54:28Z` answers
  `UNKNOWN`.
- Maintainer extractor `helm.values` 1.1.0: a values key holding a `.` or any
  other character outside `[A-Za-z0-9_/-]` (an annotation name such as
  `nginx.ingress.kubernetes.io/proxy-body-size`), or a first key that does not
  start with a letter or digit, is now listed in a rule instead of being
  recorded only. Such a path is written as an escaped member,
  `k..<key>..<key>`, where every byte of a key other than a letter, digit, `/`
  or `-` becomes `_` and two upper-case hex digits; every other path keeps the
  plain dotted member it had in 1.0.0. The class `unexpressible` now means only
  a member longer than 128 bytes or a schema key holding a NUL byte. The values-path set fact description states
  the encoding, and `rulecheck` refuses a member of a values-path set fact that
  is not the canonical member of its path. A values file whose key holds a NUL
  byte is outside the strict YAML subset. No engine contract, schema or
  registry digest changes. See `cli/docs/extractors/helm.values.md`.
- Maintainer extractor `helm.values` 1.2.0 derives two set notices, which
  never pass, block or change completeness. `HELM_VALUES_KEY_NOT_REFERENCED`
  (`notice_set_member_present`, rule id `...unread-values`) lists values keys
  the earlier chart's templates name and the later chart's templates provably
  no longer read: the later chart has a `templates/` directory, every template
  parses, no entry there is a symbolic link, submodule or other non-file, no
  template uses `index`, `tpl`, the whole values, the root context outside
  `include`, `template`, `if` or `with`, or any other route the scan does not
  resolve, the chart has no dependency and no `charts/` directory, no later
  template names the key, a key above it or a key below it, and the later
  values schema does not require or declare it.
  `HELM_VALUES_DEFAULT_CHANGED` (`notice_set_member_absent`, rule id
  `...changed-defaults`) lists keys whose scalar default changed as Helm reads
  it, holds only over a complete values set, and compares only booleans,
  plain decimals and strings that every YAML reader reads the same way, under
  no subchart or global key, where neither values schema refuses the key or
  leaves it unread. The template scan now counts every unresolved route, and
  the proof classifies each key either notice considered (`unread`,
  `changed`). Chart extractor runner (`internal/extract/chartrun`): set notices
  have their own test vectors (`notice`, `no-notice-complete`,
  `unknown-incomplete`), and a vector kind of the other family is refused.
  Only the `helm.values.*` code digests move; the extractor framework files
  are unchanged, so the digests of `k8s.feature-gate-removal`,
  `k8s.served-api-removal` and `crd.version-removal.*` do not move. See
  `cli/docs/extractors/helm.values.md`.
- Chart extractor runner (`internal/extract/chartrun`): a chart extractor may
  name shared packages whose source is part of its code, and `helm.values`
  names the values reader and member encoding it shares
  (`internal/helmvaluespath`), so a change there changes its code digest. Only
  the `helm.values.*` code digests move; the extractor framework files are
  unchanged, so the digests of `k8s.feature-gate-removal`,
  `k8s.served-api-removal` and `crd.version-removal.*` do not move.
- Maintainer extractor `crd.version-removal` 2.9.0: a target file can list
  `devOnlyMakeTargets`, Makefile targets a reviewer states exist for
  development only (a local lab cluster), each with its Makefile, target name,
  reason and evidence. At a release where the files show the target is reached
  from nowhere else (its name occurs only in its own rule and in special rules
  such as `.PHONY`, nothing runs make with a name it cannot read, includes and
  the default goal are literal, no `.RECIPEPREFIX`, no prerequisite that can
  expand to the name when its variables are over-approximated from the
  Makefiles' assignments), the install-surface guard
  does not count the recipe lines of that target as an install of an excluded
  path; at any other release the entry is not applied and the exclusion is void
  as before. The scan record lists each entry (`devOnlyMake`: applied, why not,
  the references left out, the documents that name the target). The loader
  refuses a name that says install, deploy, setup, apply, bootstrap,
  provision, release or up, a pattern or variable, and a duplicate. Adding an
  entry is a narrowing for the target guard and may not be part of an
  onboarding batch. A `define`, `endef`, `include` or `.RECIPEPREFIX` line now
  ends the Makefile rule above it for the guard, so a recipe line after one is
  no longer skipped as the recipe of a test target. No target uses the member:
  rules, records and attestations are unchanged except for the extractor
  version and every `crd.version-removal.*` code digest.
- Maintainer extractor `crd.version-removal` 2.6.0: a reviewed exclusion of
  YAML or JSON files (one file or a pattern, never a directory) can declare
  `"defines": "none"`, and the scan checks that claim at every release: a file
  that is strictly decodable, holds no template syntax, no definition, no
  `apiextensions.k8s.io` document, no mapping that names the kind and has a
  `spec`, no manifest inside a string, and is no kustomization or chart is
  class `no-definition`, which does not block attestation. A file that fails a
  check keeps its class (or is `unread`) and blocks, but never withholds a
  pair. The install-surface guard still voids such an entry for every
  referrer but `//go:embed` (embedding a data file that defines nothing
  installs nothing). The loader refuses the value with `copies` or
  `prePatch`, on a directory, on any name other than `.json`, `.yaml` or
  `.yml`, and on a kustomization, `Chart.yaml`, `requirements.yaml` or
  `values.yaml` name or a pattern that matches one. No target uses it yet:
  rules, records and attestations are unchanged except for the extractor
  version and every `crd.version-removal.*` code digest. Turning an entry
  into a `defines: none` entry is a changed exclusion for the target guard.
- Maintainer extractor `crd.version-removal` 2.5.0: a reviewed exclusion can
  name the kustomization that renders its files into a listed bundle
  (`prePatch`), and the scan checks that rendering at every release. It is
  accepted only in one exact shape: a kustomization with nothing but its one
  resource (the excluded directory) and patches of literally named
  definitions, whose operations either only touch version schemas, conversion
  settings and metadata labels and annotations or add a version that is
  neither served nor stored; the patched definitions must be the listed ones.
  Then the files are class `pre-patch-copy` and the kustomization class
  `pre-patch`, neither blocking attestation; any other shape leaves every file
  as it was. Elastic Cloud on Kubernetes' `config/crds/v1/resources/` is
  reviewed this way, so its pairs, withheld by conflicting copies until now,
  are derived (none attestable yet). A kustomization patch given inline as a
  string is read like a patch file. A definition the later line no longer
  defines records the one definition of the same kind and plural under
  another API group as its `successor` (recorded only, never a rule); the
  Percona Operator for PostgreSQL 2.9 to 3.0 pair stays withheld, by a patch
  that writes a scratch path. The release tag prefix `knative-v` is accepted.
  Other output changes only in the extractor version and code digest.
- Maintainer extractor `crd.version-removal` 2.4.0 reads templated YAML files
  (Helm chart templates of the listed definitions) in every location, where
  earlier versions read them only under a reviewed exclusion that declares copies. A
  template is read only when its literal lines fix the versions it renders:
  directives only as a condition around the whole file or inside `metadata`,
  expressions only in `metadata` and `spec.conversion`, each rendering a
  release or chart name, a quoted value or an indented block, so none can add
  a line at column 0. Such a template that is a copy of the listed definitions
  is class `templated-copy` and does not block attestation; one that is not a
  copy is `unread`, never a `conflict` or `extra`. Any other templated form is
  `unread`, including declared copies the earlier reader accepted (an inline
  `include` or `.Values` reference among them) and a template whose top-level
  `apiVersion` or `kind` is an expression, which was not a finding before.
  Go code that builds a definition is now class `go-defined`, with the
  effects `unsupported` had.
  Rules and vectors of a scan without such files are unchanged.
- Maintainer extractor `crd.version-removal`: each
  `crd.version-removal.<project>` id has its own code digest. The target table
  is one file per target (`target-<project>.json`, schema
  `prufyx.io/crd-version-target/v1`), and an id's digest covers the
  extractor's code and its own target file only, so adding or changing one
  target no longer moves the digest of every other id. The version does not change
  and outputs are unchanged apart from the code digest, which differs once for
  every id; the Kubernetes extractors' digests do not move. A rule or line
  attestation of a `crd.version-removal` id that is added or changed from now
  on must be derived with this build (the gate refuses one that names the old
  shared digest); published records are unaffected until they change.
- Maintainer extractor `crd.version-removal` 2.2.0 reads the kubebuilder
  scaffolding beside a project's generated definitions and its legacy copies,
  which kept every pair of such a project from being attestable: strategic
  merge patch fragments (conversion webhook, CA injection) and kustomize
  transformer configurations below a directory whose kustomization lists the
  definitions (classes `crd-patch`, `kustomize-config`), and
  `apiextensions.k8s.io/v1beta1` copies that agree with the listed definitions
  (`legacy-copy`). Each shape is checked strictly: a fragment that touches
  versions, the group or anything but conversion settings and metadata, a
  configuration whose field specs reach other paths, a v1beta1 copy that serves
  other versions, or any file that does not match exactly still blocks
  attestation (or withholds the pair). Rules and vectors are unchanged.
  A kustomize field spec with an empty `kind`, `group` or `version` (a wildcard
  in kustomize) and a `patches`, `patchesJson6902` or `replacements` entry
  whose target does not literally name a kind other than
  `CustomResourceDefinition` (selected by name, group, a kind pattern, a label
  selector, or no kind) now block attestation, as such an entry could change a
  definition without naming the kind.
  Every transformer configuration that a kustomization below a declared
  definition directory names (`configurations`) is read even when it never
  contains the kind name, as a field spec without a kind applies to every
  kind; one that is unparseable or reaches other paths than conversion settings
  and metadata blocks attestation.
- Maintainer extractor `crd.version-removal`, CRD-GEN wave 2: eleven more
  projects are read (Antrea, CloudNativePG, Contour, Dapr, External Secrets
  Operator, Karmada, Koordinator, MetalLB, OpenKruise, Tekton Pipelines and
  Volcano; 23 in total), each over its latest six release lines (four for MetalLB, whose window starts
  at 0.13). Their custom-resource version sets are registered in the fact registry and their
  API groups listed in the reviewed table, like the twelve of the first wave.
  The line attestation (`attest`) stays off for all eleven. API groups that
  end in `.k8s.io` or that several projects ship (`multicluster.x-k8s.io`)
  are not listed for any project. The embedded CNCF pack moves to revision
  `cncf-2026-09-13.7` (same rules; only the registry digest and the revision
  differ); external CNCF packs and knowledge databases built against the
  previous registry are refused by this release until they are rebuilt. No
  rule over the new sets ships yet.
- Knowledge compatibility: the fact registry gains the custom-resource
  version set (`component.<project>.custom_resource_versions_set`) of nine more
  projects, and the reviewed custom-resource table lists their API groups:
  cert-manager, Cilium, Crossplane, KEDA, Kuma, Kyverno, Longhorn, Rook and
  Velero join Argo CD, Istio and Strimzi (the 12 targets of the
  `crd.version-removal` extractor). The knowledge gate now admits rules
  re-derived for these projects; objects of the new groups are attributed to
  their project in `check cncf --custom-resources` and `scan`, and a group of
  a project that is not in the table is still never attributed. The embedded
  CNCF pack moves to revision `cncf-2026-09-13.5` (same rules; only the
  registry digest and the revision differ). External CNCF packs and knowledge
  databases built against the previous registry, including revision
  `cncf-2026-09-13.4`, are refused by this release until they are rebuilt. No
  rule over the new sets ships yet.
- Maintainer extractor `crd.version-removal` 2.0.0: pairs are consecutive
  release lines and every final release of both lines is read; a removal that
  holds for both whole lines gives a rule with a cited range over them,
  otherwise the rule holds for the pair of first releases only (as in 1.0.0).
  The whole repository tree is scanned at each release for definitions outside
  the listed paths, including test, example and vendored directories (a file
  there blocks attestation; Rook installs from `deploy/examples`), Helm chart
  dependencies and remote kustomize resources from other repositories,
  template, jsonnet and cue sources and Go code that builds a definition; a
  conflicting copy withholds the pair, an unread CRD source at a later-line
  release withholds or narrows its rules, chart templates declared as copies
  are checked, and a definition that left the listed paths (at the later
  line's first release or a later one) is recorded as removed (never a rule)
  instead of withholding the pair. The proof records the hop shape (only the
  previous minor line is attestable), the storage-version history (a removed
  former storage version gets a next action that migrates stored objects
  first) and versions served outside the listed paths that the later line no
  longer serves. The reviewed project table is now a
  data file covered by the code digest (the code digest of every extractor
  now also covers embedded JSON data files, so every extractor's digest
  changes), with nine more projects (cert-manager, Cilium, Crossplane, KEDA,
  Kuma, Kyverno, Longhorn, Rook, Velero) whose custom-resource sets are not
  registered yet, so the knowledge gate refuses their rules. CRD manifests are
  read with bounds sized for generated schemas (Argo CD's pairs are no longer
  withheld). Reviewed exclusions of the scan now carry evidence, may not lie
  under install locations (a wildcard only in the last path element), and are
  void at a release where a kustomization, Helm chart, Makefile install
  target, document or shell-script install command, container build (Dockerfile,
  Containerfile, Earthfile), nix file, ko `kodata` directory or embedding Go
  package (in a directory above or inside the excluded path) refers to a path
  under it.
  Gzip-compressed definitions in Go sources (Velero's install CRDs) are read
  and compared like YAML files. No rule is shipped. See
  `cli/docs/extractors/crd.version-removal.md`.

### Fixed

- A `require_component_version` rule whose declared dependency version the
  engine cannot compare now gives UNKNOWN
  (`RULE_DEPENDENCY_VERSION_NOT_COMPARABLE`) instead of BLOCKED, or
  UNSUPPORTED for a support-range rule: such a version proves neither side of
  the bound. The input parser already refuses these versions, so no current
  report changes; the evaluator no longer relies on it.

### Security

- Build identity: a release identity now accepts only `trustRootDigest:
  UNPINNED`. A linker flag could set any `sha256:` digest (or a lowercase
  `unpinned`) and `prufyx version` and every report repeated it as a trust root
  claim that nothing in the binary checks. A development identity is now
  reported only when the embedded identity marker is also at its development
  default.
- Release workflow: the tag build no longer restores the `actions/setup-go`
  cache (a cache written by another run on the default branch could reach an
  attested binary), checkout does not keep the job token, a tag that is not a
  v-prefixed semantic version stops the run before any build, each binary must
  carry the build identity the workflow computed (the native target also runs
  `prufyx version`), and the archives are byte-reproducible (sorted members,
  the tagged commit's time, numeric root owner, normalized modes, `gzip -n`).
- `prufyx-maintainer evidence reattest prepare` writes its three files into a
  new `--output-dir` only: an existing path or symbolic link there is refused,
  and a failed write leaves no directory. `evidence reattest sign` creates
  `--output` as a new file and never replaces or writes through an existing
  file or symbolic link.
- The knowledge gate now checks the cited sources of every added or changed
  rule, path policy and line attestation against upstream: the revision must be
  a commit object (not an annotated tag object) that is the commit of a tag of
  the cited repository or in its default branch history (a commit that exists
  only in a fork is refused), the whole-file sha256 at it must equal `contentDigest`, and the
  cited lines must be inside the file. A citation that cannot be checked fails
  the gate, within an overall deadline (`--citations-timeout`). In the offline
  `--source fixture:` mode a change that cites a source fails this check (it
  is never verified, so it is never eligible for automatic merge); a change
  that cites nothing has nothing to verify. `rule verify-citations` covers path policies, line
  attestations and distribution records too, and a new nightly workflow runs
  it over every pack. The code the gate's checks rest on (`rulecheck`,
  `constraintengine`, `upgradepath`, `distribution`, `evidencerepin`,
  `repinbaselines`) is now CODEOWNED.
- Offline-boundary probes now write each strace capture into a fresh private
  directory and read only regular files from it, so stale, planted or
  prefix-colliding files in the work directory can no longer be mistaken for
  trace evidence; a symlinked work directory is rejected. The local collector
  opens its output root without following a symlink and changes its mode through
  that descriptor, and the collector output root and the offline-boundary work
  directory must be owned by the current user (checked on Unix).
- GitHub Action: `verify-attestation: false` is now accepted only together with
  `archive-sha256` (a release's own checksum does not show who built the
  archive); without the pin the install stops before any download. Existing
  workflows that turned the attestation off without a pin must add the pin.
- GitHub Action: `GH_TOKEN` is passed only to `gh attestation verify` (not to
  curl, tar or the source build); the action's work directory under
  `RUNNER_TEMP` is refused if it is a symbolic link or not owned by the runner
  user, a `RUNNER_TEMP` with a newline is refused, and report files are created
  private (mode 600 in a 700 directory) whatever the runner's umask.
- Synthetic scenario corpus validator: refuses symbolic links in the corpus
  tree and index paths that are absolute, contain `..` or pass through a link;
  `tests/run-conformance.sh` now runs the v4 corpus it lives in (it pointed at
  v3).

### Added

- `prufyx scan --format csv`: a header row, a summary row (the verdict and the headline), then one row per blocking finding location (verdict, rule id, project, file, line, kind, namespace, name, title, fix), then one row per gap and, with passes shown, one per pass. Cells use the same escaping as the other formats and cells that could start a spreadsheet formula get a leading quote.
- Optional colour in help output only (bold headings, highlighted command
  names), on only when stdout is a terminal. `NO_COLOR`, `PRUFYX_COLOR=never`
  and `TERM=dumb` turn it off; `PRUFYX_COLOR=always` forces it on. Report
  output is never coloured.
- `prufyx scan --fail-on blocked|unknown|none` (default `unknown`, exit codes
  unchanged): `blocked` exits 0 for an undecided scan but still 10 for BLOCKED,
  `none` exits 0 for both. A suppressed exit 0 is not a PASS: `scan` prints a
  note on standard error whenever the flag changes a non-zero code. Usage (2)
  and integrity (3) errors are never suppressed, and neither is a scan whose
  manifests use an API version the target does not serve; the report is
  unchanged.
- `prufyx scan --only-blocked`: human and Markdown output list only BLOCKED
  findings and print one line counting the hidden items, but keep the gap for API
  versions the target does not serve; JSON and SARIF stay complete.
- `prufyx-maintainer corpus-attestation generate|check --tree DIR` attests the
  pack files of a checked-out tree (its root or its `cli/` directory) instead of
  the pack embedded in the binary, so a mechanical candidate can be re-attested
  locally. The output names its binding (`binding=tree:...` or `binding=embedded`).
  The command no longer needs a CLI root from the working directory when `--tree`
  is given. See `docs/knowledge-gate.md`.
- `prufyx-maintainer knowledge-targets check-size --tree DIR` checks the CNCF
  pack files of a checkout with the knowledge gate's measurement.
- `prufyx-maintainer evidence repin --fail-on-missing` (with `--source mirror`)
  exits 3, after writing the worklist and wants file, when files are missing from
  the mirror. The default exit code stays 0. With `--source http` the flag is
  refused.
- Community-project pack: support-range rules (`require_component_version`
  with `severity: "unsupported"`) and one-way notices (`notice_one_way`) are
  now accepted, with the same meaning as in the CNCF pack. New pack schema
  levels `prufyx.io/community-project-source-rule-pack/v1alpha3` (notices) and
  `v1alpha4` (support ranges, which admit notices); a pack with neither keeps
  `v1alpha1`/`v1alpha2` and loads as before. An `UNSUPPORTED` claim is never
  `PASS` and never `BLOCKED` and exits 11; notices are informational and left
  out of the exit code; `check project` prints a note for combinations outside
  a documented support range ("not verified, not shown to be broken"), prints
  applicable notices with their scope, and never words anything as safe. The
  native `check project` routes cannot declare a support range's dependency,
  so they list such a rule as not evaluated on this route (use `check batch`
  with the dependency declared, or check the cited source by hand) instead of
  turning a scoped PASS into an unresolvable UNKNOWN. In `check batch`, a
  community item treats `UNSUPPORTED` as unknown and ignores notices for its
  outcome, and the human output prints an item's applicable notices (with one
  scope line) and the support-range note, for both packs. The notice scope line
  and the evidence basis line are the same in both packs. `catalog checks`
  shows a rule's kind (one-way notice, support range). Admission is stricter: a
  notice or support range lists only the facts its `appliesWhen` reads, and a
  support range never depends on the project's own component. The generated
  support inventory counts support-range rules and notices separately from
  verdict rules, lists support ranges as their own `check batch` capability,
  and lists a project holding only notices or support ranges under its own
  state without counting it as executable. The shipped community pack holds
  neither kind yet.
- Image-based component detection (DETECT-1, phase 1): a reviewed registry
  (`cli/internal/imageidentity/data/image-sources.json`) maps container image
  repositories to projects and reads a version only from a tag that follows the
  entry's declared scheme. `assess` now classifies the projects it covers
  instead of reporting them as not observable. Unlisted, digest-only,
  operator-implied, distribution-built and mis-tagged images yield no version,
  and a component seen with an unknown version is indeterminate rather than a
  version mismatch. A component with any unversioned image (digest-only,
  `latest`, a pre-release or off-scheme tag) is unknown as a whole and never
  takes an exact version from a sibling image. A project that only the image
  registry identifies is never reported ABSENT, because a mirrored or rebuilt
  image is invisible to it; it is indeterminate when no image is seen. The
  collection metadata records the digest and schema of the image registry
  (`imageSourcesDigest`, `imageSourcesSchema`) and a bundle without this
  binary's digest is not used for registry-identified projects. Records outside
  the catalog produce no rows. `prufyx-maintainer rule verify-citations
  --image-sources <file>` re-verifies every citation of the registry (commit,
  whole-file digest and line span), and a CI workflow runs it on changes and
  weekly.
  A digest-pinned image (`name:vX.Y.Z@sha256:...`) at a version different from
  the other images of a component also makes that component a conflict (this
  covers the adapter projects too). A version is exact only over the images the
  registry can see: mirrored or rebuilt images are invisible (see
  `cli/docs/one-command-flow.md`).
- Served-API lists (internal; the shipped knowledge carries none yet): the rule
  pack may hold a top-level `servedAPIs` member, one list per Kubernetes release
  line of the `apiVersion kind` pairs the line serves, and a pack that holds it
  uses the schema `prufyx.io/cncf-source-rule-pack/v1alpha10`. Scan reads it to
  tell an object the target line still serves from one nobody reviewed
  (`API_VERSION_NOT_REVIEWED`). The loader refuses the whole pack when a list
  for line L names an API that the removal table marks as removed at a line at
  or below L. A `SCOPE_COMPLETE_PASS` report names the list it relied on in
  `paths[].servedList` (line, basis, freshness, `validUntil` and a digest of the
  sorted pairs); the member is absent from every other report. The external
  knowledge target format, `knowledge-targets build`, `evidence repin`,
  `evidence reattest` and the support inventory refuse a pack with the member,
  and the knowledge gate never admits a change to it. See
  [scan.md](cli/docs/scan.md#served-api-lists) and
  [upgrade-paths.md](cli/docs/upgrade-paths.md#in-a-knowledge-pack).
- `prufyx-maintainer coverage report` classifies the last N release lines of
  each project into attested, bounded, spot and gap pairs and reports the
  coverage totals as JSON and Markdown, from a pack and an offline lines
  snapshot; `coverage lines-from-tags` builds that snapshot from captured tag
  lists. Reporting only; no verdict changes. See `cli/docs/coverage-report.md`.
- Batch approvals for the knowledge gate: one owner signature
  (`prufyx.io/knowledge-approval-batch/v1`, the web-approval key) admits up to
  50 reviewed rules and line attestations of one change. The gate recomputes
  everything the batch binds (every entry's base and candidate digest, both
  pack files, its own classification of the change, the entries' cited sources,
  the sample of entries the owner read in full and the review summary), verifies
  the entries' citations upstream itself (offline mode is refused), runs the
  extractor cross-check on line attestations, and refuses a batch that is
  older than 72 hours, already in the base, behind a later decision, mixed with
  any file outside the pack files and their generated outputs, or that lists a
  tightening change as approved. `approval sign --batch` shows the summary and
  signs only after the owner types the batch id; `approval verify --batch`
  checks a batch offline. A batch is never eligible for automatic merging.
  A spent batch file stays in the tree until 14 days after it expired, because
  it still refuses older per-entry approvals; forward-only holds for rules and
  records in both directions, across packs for records. The signer shows the
  signer, key id and validity before it asks for the batch id, and applies the
  gate's changed-path rule. See
  [knowledge-gate.md](cli/docs/knowledge-gate.md#batch-approvals).
- Kubernetes knowledge for the minor lines 1.33 to 1.36: four reviewed kubelet
  version-skew rules (kubelet at most three minor versions older than the
  target control plane, never newer) over the new declaration
  `declarations.minimumKubeletVersion` (and, for a mixed fleet, the optional
  `declarations.maximumKubeletVersion`) of the component-configuration
  selection. BLOCKED means unsupported by the upstream version-skew policy, not
  a broken cluster. See [kubernetes-component-config.md](cli/docs/kubernetes-component-config.md).
- `prufyx-maintainer knowledge-publish release`: one offline, deterministic step
  that builds a signed knowledge-database release (TUF targets, snapshot and
  timestamp, package and release plan) from the reviewed embedded knowledge,
  with expiry taken from the knowledge's evidence validity and signing keys
  supplied by path. A disabled draft workflow
  (`.github/workflows/knowledge-release.yml`) documents the secrets a hosted
  release needs. See [knowledge-publisher.md](cli/docs/knowledge-publisher.md).
- `check cncf` (without `--now` or `--knowledge-db`) and `scan` (without `--knowledge-db`
  or `--now`) use the verified knowledge database that `prufyx db update` installed in
  the default store location, so knowledge refreshes need no new build. With no store
  they use the embedded knowledge. A store that is present but invalid, expired or
  rooted in another trust root is refused (exit 3), never replaced silently;
  `--knowledge=embedded` forces the embedded knowledge. `--now` and `--knowledge-db`
  behave as before and replay reports are unchanged. `db update` for `cncf-projects`
  may omit `--db-root`. See [knowledge-updates.md](cli/docs/knowledge-updates.md).
- Product-pinned knowledge root: a profile can embed the SHA-256 of its initial TUF
  root, and `db update` then trusts only that root (rotation follows the signed root
  chain). The `cncf-projects` entry ships empty, so behaviour is unchanged until a pin
  is set; see [knowledge-updates.md](cli/docs/knowledge-updates.md).
- `extract run --lease-days N` (1-365, default 90) sets the validity window of the
  derived rules.
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

- `prufyx-maintainer approval sign --subject lineAttestation` refuses what the
  gate refuses: a record that is mechanical in the base and a change that only
  shortens `validUntil`. `approval verify` for a line attestation or a repin
  baseline now needs `--base-root DIR` (the base checkout) and refuses an
  approval the base already holds or has superseded, before it prints OK.
  `approval` refuses the baseline flags (`--repository`, `--base-baselines`,
  `--head-baselines`) for the `rule` and `lineAttestation` subjects.
  `approval verify --base-root` must be a base checkout: it needs the layout's
  pack file and refuses a pack that differs from `--base-pack` or
  `--base-baselines`. The pack loader also refuses a served list that names a
  1.16 removal (`apps/v1beta1`, `apps/v1beta2`, `extensions/v1beta1`).
- A ranged rule whose range pins a REMOVED_IN_RELEASE or CHANGED_IN_RELEASE
  boundary is no longer excluded for a hop that crosses that boundary outside
  the range. The engine reports it UNDETERMINED
  (`RULE_RELEASE_BOUNDARY_NOT_REVIEWED`), so such a hop can no longer reach
  SCOPE_COMPLETE_PASS; `assess` reports an origin below the range as
  `APPLICABLE_NEEDS_DECLARATION` (no `--to`) or
  `INDETERMINATE_HOP_OUTSIDE_REVIEWED_RANGE` (target at or above the boundary)
  instead of not applicable; route discovery lists these rules with
  `matchMode: boundary-unreviewed`. The ranged, set, notice, basis, severity and
  crossing contract digests change; exact-only documents are unaffected.
  A downgrade across the boundary of a CHANGED_IN_RELEASE range is unreviewed
  too (reverting a change is not proven harmless); a downgrade across a
  REMOVED_IN_RELEASE boundary keeps its exclusion, because the removed API
  exists again on the lower line. The CNCF rule selection no longer drops such
  a rule before evaluation (a wide anchor rule could otherwise exit 0),
  `catalog checks` prints the `boundary-unreviewed` and `crossing` match modes
  and no anchor route for them, and quiet output names the crossed boundaries.
- `prufyx scan`: an upgrade that skips release lines (for example
  `1.24.17 -> 1.30.4` without a reviewed path policy) no longer answers
  `NO BLOCKERS FOUND IN COVERED CHECKS` (exit 11) for a manifest at an API
  version a line it enters removed. For each line with known removals, the step
  of the hop that enters it is evaluated; a reviewed rule that covers the whole
  step and blocks it makes the answer `BLOCKED` (exit 10), and the finding names
  the step (`crossedLine` in JSON and SARIF). The gap text "removed before the
  evaluated hops" was false and is gone.
- `prufyx scan`: a manifest at an API version the target does not serve that no
  reviewed rule decided is always named (gap `API_VERSION_NOT_SERVED`), also on
  a line a hop enters when the rule could not decide, and the headline then
  reads `UNKNOWN: manifests use API versions the target does not serve; migrate
  them before upgrading (...)` instead of "no blockers". This covers every
  removal Prufyx has reviewed, also those before 1.22 (for example an
  `extensions/v1beta1` Deployment, removed in 1.16), not only the scan rule
  table. When the step that enters a line decided nothing, `RULE_NOT_DECIDED`
  gaps say why (no rule, a rule left out by `--require-basis`, a rule that
  covers only part of the step).
- The `scan-report-v1alpha1` JSON schema gained the optional member
  `finding.crossedLine` (with `line`, `from`, `to`, `inputDigest`,
  `engineContractDigest`); integrators who vendor the schema must refresh it,
  because a validator pinned to the previous schema rejects reports that carry
  it. On such a finding `match` describes the step, not the hop.
- `prufyx scan`: the `LINE_NOT_ATTESTED` gap no longer says a line "has not been
  reviewed for removed APIs" next to a blocker from a reviewed rule of that line;
  it says no review confirms the line's rules name every API it removes. The
  `DOWNGRADE_NOT_REVIEWED` gap names a next action instead of "none", and no
  longer points at nonexistent rollback notes: it says to check the component's
  documentation on downgrades (the Kubernetes control plane has none).
- Knowledge: evidence corrections from the model-assisted review of the
  embedded CNCF pack (pack revision unchanged; the rules keep their ids,
  ranges and verdict logic). Three vendored-file `contentDigest` values of
  `cri-o.artifact-short-name-rejected.1-35` (still withdrawn) now equal the
  whole-file sha256 at the cited commit; `emissary-ingress.metrics-endpoint-removed.3-10-to-4-0`
  cites the v3.10.0 commit instead of the annotated tag object;
  `cilium.cluster-name-invalid.1-16-19-to-1-17-18` also cites the 32-byte limit
  (`types.go` lines 30-31); `prometheus.remote-write-http2-default.2-55-1-to-3-14-0`
  cites the remote-write defaults (lines 221-233) instead of the scrape
  defaults; the descriptions of `falco.deprecated-cli-flags-removed.0-40-to-0-42`
  (the 0.42.0 tag commit has no 0.42 changelog section; removal landed in 0.41.0),
  `metallb.legacy-configmap-removed.0-12-1-to-0-13-2` (removed in 0.13.0, still
  unsupported in 0.13.2) and `cloudnativepg.cluster-reference-immutable.1-29-to-1-30`
  (also backported, shipping from 1.29.2, which two added sources cite) now
  state only what the cited sources show; two Rook `nextAction` typos
  (`1.15x`, `1.16x`) are fixed. The corpus attestation digests follow.
  `prufyx-maintainer rule verify-citations` reports no findings over both packs.
- `prufyx assess --format json`: the collector progress lines ("Context …", "Created local API observation directory …", "Verify context files with …") now go to stderr, so stdout carries only the JSON report and parses as JSON.
- `extract` file writes are never made through a symlink and no longer depend on
  the umask. `extract run` builds the output in a staging directory beside `--out`
  and renames it into place after an fsync, without replacing anything that
  appears at `--out` meanwhile (no partial output on failure; a symlink or
  non-empty `--out` present at the check is refused; directories 0755, files
  0644). An existing empty `--out` is replaced by the staged directory, which
  keeps its permission bits (never looser than 0755) but not its owner, ACLs or
  xattrs; `--out .` fills the current directory in place. `--wants` files and
  pack writes (`extract apply`, supersede) refuse a symlink or non-regular target
  present at the check, never write through one that appears later, and fsync
  before the rename. Directory fsync errors other than EINVAL/ENOTSUP are now
  reported. Extractor outputs and code digests are unchanged.
- `scan` human and Markdown output, and its usage and input error messages, no
  longer print text taken from the scanned input or from knowledge as itself when
  it holds terminal escape sequences, carriage returns, line breaks, other control
  or format characters, or bidirectional controls. Each is shown as a visible
  `\xNN` or `\uXXXX` escape (bytes that are not UTF-8 as `\xNN`), so a name or
  path cannot clear the screen, retitle the terminal or forge a report line.
  JSON and SARIF now write the same characters as `\u` escapes; the decoded
  values are unchanged. Ordinary printable text is byte for byte as before.
- Maintainer rule check and knowledge gate HTTP clients now apply a total request
  timeout, ignore proxy environment variables, fetch only over https (plain http
  only to a loopback address), and follow redirects only within the original host
  and scheme (at most three), so a redirect can no longer reach another host or
  downgrade to http. Oversized or stalled responses fail the run with an error.

- `prufyx scan` no longer reports a removed API from a Helm subchart that may not be
  rendered: a subchart listed twice in `Chart.yaml` with a condition on any entry,
  a subchart matched by its own `Chart.yaml` name rather than its directory, a
  `file://` sibling chart that another chart lists with a condition, tags or an
  alias, and a `helm.sh/hook` annotation given as a list that includes `test`
  now leave the answer UNKNOWN instead of BLOCKED.
- `evidence reattest verify --rerun-worklist` (V9) now also compares the signing
  job's worklist with the independent one on `resolution` and every other
  baseline-selecting field (stale flag, baseline mode, baseline, line, pinned and
  compared tag, owner entry digest), in both directions. A forged worklist that
  drops `resolution: tag_fallback` from a latest-baseline citation is refused.
- `evidence reattest prepare|verify` (V5) no longer rejects a pack whose
  mechanical rules were re-derived after the chain head's `attestedAt`; like
  mechanical records they are renewed by re-derivation, not the human chain.
  Reviewed rules still need chain coverage.

### Changed

- `prufyx` and `prufyx help` now print a short overview (about 20 lines) with
  the commands grouped by purpose, instead of every usage line. Exit status
  is unchanged (0). The full usage moved to per-command help:
  `prufyx <command> help`, `--help`, `-h` and `prufyx help <command>`.
- Help text no longer uses MariaDB or MariaDB Operator in examples; the
  MariaDB rules and knowledge are unchanged.
- Knowledge compatibility: the fact registry gains the five Kubernetes
  component feature-gate set facts
  `component.kubernetes.<component>_feature_gates_set` (`kube_apiserver`,
  `kube_controller_manager`, `kube_scheduler`, `kubelet`, `kube_proxy`), the
  facts the `k8s.feature-gate-removal` extractor derives `forbid_set_member`
  rules over. The embedded CNCF pack moves to revision `cncf-2026-09-13.6`
  (same rules; only the registry digest and the revision differ). External
  CNCF packs and knowledge databases built against the previous registry,
  including revisions `cncf-2026-09-13.4` and `cncf-2026-09-13.5`, are
  refused by this release until they are rebuilt. No published rule reads the facts yet, and only
  `check cncf --kubernetes-component-config` supplies them, from the
  configuration the caller selects and the scopes the caller declares
  complete. `scan` and `check cncf --native-resource` do not supply them, so
  a feature-gate rule is never evaluated there and can never produce a PASS.
  A `--kubernetes-component-config` check on a one-minor-line transition now
  prepares the five sets (incomplete unless the scope is declared complete).
  On a transition without a published predicate (lines before 1.23 and after
  1.30) the sets decide the preparation reason, which can read
  `KUBERNETES_COMPONENT_EVIDENCE_INCOMPLETE` instead of
  `KUBERNETES_COMPONENT_NO_REVIEWED_PREDICATE_FOR_TRANSITION` (the check still
  reports UNKNOWN, no reviewed rule). On lines 1.23 to 1.30 the preparation
  state and reason come from the predicate facts only, as before; an
  incomplete set does not change them.
- `knowledge-targets check-size` prints first what it checked (the embedded pack,
  a `--dir` directory or a `--tree` checkout) and the single-target line names its
  target.
- `corpus-attestation` reads and writes the attestation asset and the rule pack
  without following a symbolic link below the directory it works in: it writes a
  temporary file, flushes it and renames it into place, and refuses a symbolic
  link, FIFO or other non-regular file at the asset or any link among its parent
  directories (previously a link was followed and its target overwritten).
- `scan` treats the reason code `KUBERNETES_SERVED_API_REMOVED` (carried by the mechanical
  Kubernetes API-removal rules) as a decided claim, like `REVIEWED_SOURCE_CONSTRAINT`, and the
  check-route catalog describes the native routes of both generations of the Kubernetes
  API-removal rules (the reviewed ones now shipped and the mechanical ones that will replace
  them), so the catalog stays exact on either side of that replacement. No shipped rule
  changes.
- Extractor code digest: the digest now also covers the reviewed `*.json` data
  files a source set embeds next to its Go code (a table an extractor reads is
  part of its code). The framework file changed, so the code digest of every
  extractor changes once (`k8s.feature-gate-removal`, `k8s.served-api-removal`,
  `crd.version-removal.*`, the chart-versions derivation). No published rule
  carries a code digest yet, so nothing shipped needs re-deriving; rules
  derived with an earlier binary no longer re-derive and must be derived again.
- Extractor framework: a line attestation candidate may carry the releases of
  both lines its derivation read, an extractor may name the one component it
  attests, and the line attestation type has an optional `releases` member. No
  extractor uses any of it yet, so extractor output does not change, but the
  framework files changed, so the code digest of every extractor changes once
  more (same consequence as the entry above).
- User-facing messages now say what is true. An undecided `scan` headline
  starts with `UNKNOWN:` (it no longer opens with "NO BLOCKERS FOUND"), a
  blocked one says how many areas were not checked, and the summary line reads
  "Read N documents over N hops; X of Y components have rules (partially
  evaluated)". The JSON summary gains `componentsWithRules`; `componentsCovered`
  is kept for one release as its old name.
- `scan --format sarif` reports every not-checked area as a `warning` result
  (`prufyx/gap/<REASON>`), so code scanning no longer shows "no alerts" for an
  undecided scan. The GitHub Action prints `UNKNOWN` for exit 11 and its
  documentation no longer calls a green UNKNOWN a sensible default; use
  `fail-on: unknown` to stop on it. A scan with the gap `API_VERSION_NOT_SERVED`
  (a manifest on an API version the target does not serve) fails the Action
  step under every `fail-on` except `none`.
- UNKNOWN next actions are plain words. The Kubernetes apply-set check names
  the missing declaration and its flag (`--resource-scope-complete`,
  `--target-api-apply-required`, `--distribution official_upstream`); other
  routes say which fact is missing from the input and exactly where to declare
  it (the `facts` list of the `current` or `proposed` component, with
  `"state": "declared"` and a `boolValue`, `enumValue` or `setValue`); a rule
  whose declared fact does not match says it does not apply. The Kubernetes
  route names every missing declaration in one line.
- Replay: the wording of the next actions in a `check` report changed, and
  replay compares exact bytes. A report saved by an earlier build that holds an
  UNKNOWN claim no longer replays; `--replay-report` now says "the report is
  from an older engine contract" and exits 2 (it used to exit 3 with a generic
  failure), because only the wording differs and no decision does. Generate a
  new report with this build. A report whose decisions differ is still an
  integrity failure (exit 3).
- The GitHub Action fails closed when it cannot confirm the gaps: with
  `format: json` it reads the report it already has; with another format the
  confirming JSON scan must exit 11 with output, else the step fails. The
  gap is read with `jq` (or a whitespace tolerant check where `jq` is absent).
  SARIF gap results keep their identity when only the counts in the message
  change, sit at the `--config` file when only standard input was read, and
  the help of `prufyx/gap/API_VERSION_NOT_SERVED` says to migrate. An
  unknown component name only gets "closest" suggestions that are near it. A
  scan that evaluated nothing says "UNKNOWN: nothing could be evaluated".
  `--strict-exit` followed by `--strict-exit=false` prints the exit 0 note, as
  the last form decides.
- The knowledge age note no longer recommends `prufyx db update`, which needs a
  source and a trust root that no official feed provides yet. It names a newer
  source build or a signed package imported with `prufyx db import`, and says
  that expired rules answer UNKNOWN. Stale and withdrawn rules say the same.
- A `check` that exits 0 prints one note on standard error that the whole
  upgrade is still UNKNOWN and that CI should use `--strict-exit`. Exit codes
  and standard output are unchanged. The documentation uses `--strict-exit` in
  every CI example and describes exit 0 as "the checked rules passed".
- `catalog cncf` and `catalog checks` count only active rules: a withdrawn rule
  is listed apart (`0 active generic source rules (1 withdrawn)`, rule coverage
  `WITHDRAWN_ONLY`), so the generic preview is 53 projects, not 54. An unknown
  project is an error (exit 2) with the closest slugs; a catalogued project
  without rules says so and links the request form.
- `check cncf` on a generic route prints `scoped result:` like the native
  route; a PASS shows its remediation as "if this changes:"; `1 rule PASS`
  and `1 rule for another transition` use the singular; an unknown `--project`
  names the slug and the closest ones; the multi-minor hint says each minor
  step must be checked.
- `prufyx version --format human`; `--help` lists `version`, the `scan` output
  formats, the `assess` flags, the exit status of `scan`, `check cncf` and
  `check project`, and splits the Harbor usage lines. The cert-manager human
  report prints every cited source with its lines and digest.
- Documentation: the draft release notes say they are a draft, the Windows
  statement matches the build, the CHANGELOG no longer links release tags that
  do not exist, the inventory refresh example uses the committed index digest,
  and the quickstart counts the reviewed Kubernetes pairs correctly.

- `k8s.served-api-removal` 1.3.0: every reviewed migration hint now cites the
  passage of the upstream deprecation guide (kubernetes/website at a pinned
  revision, with start and end line) that supports it, and a test checks each
  citation against a pinned copy of the guide. The six kinds removed after that
  guide keep the generic text and carry no citation. Rule ids, constraints and
  ranges do not change; the guide's v1beta3 alternative for flow control v1beta1
  is cited as a second passage. See
  [the extractor](cli/docs/extractors/k8s.served-api-removal.md).
- Post-merge review fixes for the renewal path. `evidence reattest prepare` (automated) now names the pending
  repositories of a rule excluded as `REVIEWED_OUTSIDE_STATEMENT_CHAIN`, so its own statement verifies (V11).
  `verify` against the independent worklist (V11) now checks only that no renewed rule cites a citation pending
  there, instead of requiring the whole pack's pending set to match. A rule with a pending citation and a drifted
  one is reported with the drift reason plus its pending repositories (it was `CITATION_PENDING`), and V11 names a
  pending rule missing from the statement. Automated statements now list a mechanical rule dated after the chain
  head as `MECHANICAL_RULE_EXCLUDED` (it was `REVIEWED_OUTSIDE_STATEMENT_CHAIN`); re-prepare any in-flight automated
  statement, which otherwise fails V3.
- `extract supersede` now uses the knowledge gate's pairing function (new `internal/supersedepred`): it refuses
  (exit 3) a reviewed rule whose replacement has another predicate or project, a rule that is not `reviewed`, a run
  rule that would replace several reviewed rules, and a replacement that is not new, active and mechanical.
- Windows: `prufyx-community` refuses file input with "not supported on Windows" and the Unix-only tests of
  `currentbundle` and `knowledgeauto` carry `!windows` build constraints, so `GOOS=windows go vet` passes.
- `constraintengine.ConstraintKey` is now the one exported constraint-key function; `extract supersede` and the gate call it instead of keeping their own copies.
- `k8s.served-api-removal` 1.2.0: the next action of each derived API-removal rule
  names the removed kinds and the exact version to migrate to (for example
  CronJob to `batch/v1`, Ingress to `networking.k8s.io/v1`), says to validate
  admission, CRDs, stored objects, runtime clients and API-server configuration
  separately, and for PodSecurityPolicy says to remove it and migrate to Pod
  Security Admission or an admission webhook. The text comes from a reviewed
  table; it is offline and deterministic. Rule ids, constraints and ranges do
  not change. See [the extractor](cli/docs/extractors/k8s.served-api-removal.md).
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

- README: a Coverage section whose numbers are generated by `scripts/readme-coverage.sh` (from `coverage report` and the support inventory; `--check` detects a stale block), the Kubernetes and CNCF rule scope stated precisely with implemented, internal and planned work separated, the `assess` cluster read disclosed, and CI advised to use `check --strict-exit`.
- README and the `scan` and quickstart guides now state how rules are
  established, which input permissions `check` and `scan` accept, what `scan`
  covers today and why it cannot yet answer PASS, and the date the rule counts
  were taken.
- THIRD-PARTY.md lists the Kubernetes-derived test fixtures with their
  upstream commits, and `LICENSES/` includes the Kubernetes Apache-2.0 text.

### Added

- Knowledge gate: a **supersede** class. A reviewed rule may be removed when the
  same change adds an active mechanical rule that re-derives from the pinned
  upstream bytes, has an equal constraint key and an otherwise identical
  predicate, and covers its region (and, for a set rule, its members). Only
  the owner's own change is admitted (`--owner-login`, default `airstand`, for
  both author and sender); it is never eligible for automatic merging, counts
  as one loosening, is not a withdrawal for the circuit breakers, and the
  report lists each `R -> M` pair under `supersedes`.
- `prufyx` builds for Windows (amd64 and arm64). File and directory input,
  the knowledge store and the `check prometheus-mode` real-observation path are
  Unix-only and refuse on Windows (the observation route exits 2 with "real
  observation is not supported on this platform"); standard input still works.
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
  written; `--subject lineAttestation --record ID` does the same for one
  reviewed line attestation (mechanical attestations and path policies cannot
  be approved; the gate uses a record approval once and only forward);
  `approval verify` checks one approval file offline. The key comes
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

## 0.1.0-alpha.4 - 2026-09-07 (not published as a release)

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

## 0.1.0-alpha.3 - 2026-09-07 (not published as a release)

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

[Unreleased]: https://github.com/prufyx/prufyx/commits/main

No release has been published yet. The two alpha version headings above name
development milestones, not release tags.
