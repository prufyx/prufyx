# Upstream evidence contributions

Use an upstream evidence packet to propose either a new catalogue identity or an
exact transition for a project already in the pinned CNCF Landscape catalogue.
The packet is public-source metadata only. Do not include customer bundles,
Kubernetes configuration, paths, credentials, Secrets, logs, source archives,
or private excerpts.

The transition and new-identity packet schema is closed and versioned as
`prufyx.io/upstream-evidence-packet/v1`. A separate closed v2 shape exists only
for the TiKV 8.5.8 GCS WIF full-backup target preflight described below. The
existing tool can create a source-free incomplete skeleton and validate a
completed packet locally:

```sh
cd cli
go run ./cmd/prufyx-maintainer contribution validate \
  --packet examples/contributions/synthetic-new-identity-packet.json
```

For a new packet, scaffold the closed object shape from the identifiers and
versions you already reviewed:

```sh
go run ./cmd/prufyx-maintainer contribution scaffold \
  --kind existing_project_transition --project-slug PROJECT \
  --display-name 'PROJECT' --repository https://github.com/OWNER/REPOSITORY \
  --current-version X.Y.Z --proposed-version A.B.C \
  --output PRIVATE-packet.json
```

The scaffold is deliberately incomplete and contains no tags, source URLs,
digests, excerpts, or compatibility claim. Complete those fields from public
sources, then run the unchanged `validate` command. The command creates a new
0600 file and refuses to overwrite an existing path or follow a symlink in the
output path; choose a real directory for its parent.

The sole target-only scaffold is fixed to the reviewed TiKV component, target
and operation:

```sh
go run ./cmd/prufyx-maintainer contribution scaffold \
  --kind existing_project_target_preflight \
  --project-slug tikv --display-name TiKV \
  --repository https://github.com/tikv/tikv \
  --target-version 8.5.8 --operation gcs-full-backup-wif \
  --output PRIVATE-tikv-packet.json
```

Target-only flags are rejected for v1 kinds, and transition endpoint flags are
rejected for this v2 kind. The v2 skeleton remains incomplete and private until
its exact tag, three source roles, declarations and review metadata are supplied.

The output is a canonical `prufyx.io/upstream-evidence-receipt/v1` receipt.
It always says `workflowState: CANDIDATE`. It proves only that the packet is
well formed and locally consistent. In particular, validation does **not**
fetch an upstream source, authenticate a submitter or reviewer, verify tag to
commit bindings, verify source bytes/hash/span, establish license terms, admit
a catalogue identity, prove CNCF membership, prove compatibility, authorize a
rule, or publish signed data.

An optional maintainer or contributor check can bind a packet's declared public
source digests and complete line excerpts to already-supplied local public
bytes. It does not download anything and uses digest-addressed regular files
under `SOURCE_ROOT/sha256/<declared-file-digest>`:

```sh
cd cli
go run ./cmd/prufyx-maintainer contribution verify-sources \
  --packet PRIVATE-packet.json --source-root SOURCE_ROOT
```

It checks exact raw-LF inclusive spans and excerpt text without whitespace,
Unicode, tab, or carriage-return normalization. A literal horizontal TAB is
allowed only inside an excerpt and must match the supplied bytes exactly; older
v1 validators reject tab-bearing packets, so this additive acceptance is not a
migration promise. It emits no source text, IDs, URLs, or local paths. A
matching receipt remains `CANDIDATE` and
`NOT_ADMITTED`: it does not authenticate upstream retrieval or tags, decide the
claim or license, admit support, or authorize a rule, signing, or publication.

## Self-service project intake

Open the [**Propose a project or transition** issue form](https://github.com/prufyx/prufyx/issues/new?template=new-project.yml)
before preparing a packet. In GitHub, use **Issues → New issue → Propose a
project or transition**. It collects the stable project identity, canonical
repository, exact endpoint versions, immutable source references, requested
support kind, a bounded claim and its `UNKNOWN` boundary, sanitized test
expectations, and the declared license/attribution disposition. The form is an
intake checklist; it does not modify the Landscape, executable inventory, or
rule pack.

Then create the corresponding packet using the existing schema and examples,
or use the source-free `scaffold` command above to prepare its closed shape.
Run the offline validator from `cli/` and attach its receipt to the issue or
review record:

```sh
go run ./cmd/prufyx-maintainer contribution validate \
  --packet examples/contributions/karmada-1.18.3-to-1.19.0-candidate.json
```

Keep the packet state `NOT_REVIEWED`/`CANDIDATE` until an independent reviewer
fetches the pinned upstream commits and tags, recomputes source bytes, full-file
digests and spans, checks the license/attribution disposition, and evaluates
the bounded claim. A submitted packet never executes contributor code, enters
the executable support inventory automatically, or publishes a rule. Never
include customer configuration, cluster data, credentials, Secrets, logs,
source archives, or private excerpts in an issue or packet.

The repository CODEOWNERS file names the sole maintainer, `@airstand`; it does
not by itself prove enforced branch protection or a second human/GitHub
approval. Independent automated-agent review supplies technical evidence for
the maintainer's acceptance decision.

The source gate discovers every positive candidate JSON file directly under
`examples/contributions/` and validates it with the same offline validator.
Run that check locally with:

```sh
cd cli
go run ./cmd/prufyx-maintainer contribution-candidates
```

Candidate names are deterministic, regular non-symlink JSON files. The gate
accepts at most 64 files, each no larger than the validator's 256 KiB bound;
unsafe or unexpected entries fail the gate instead of being skipped. Files in
`examples/contributions/negative/` remain dedicated rejection fixtures for the
validator tests. The check performs no network access, source fetch, submitted
command execution, or credential use, and prints only a path-free count and
packet digests. A successful receipt remains `CANDIDATE` and
`NOT_ADMITTED`: automatic validation never adds a rule, source record, or
executable support entry.

After validation, use the concise [upstream review record
template](upstream-review-record-template.md) to keep the packet, source
checks, scoped claim, tests, and acceptance gates together. The template is a
human review aid, not a second packet schema or an approval mechanism.

By default, existing-project validation uses this checkout's pinned Landscape
file. An explicit `--landscape FILE` override uses those caller-selected local
bytes instead; the receipt binds them as `landscapeDigest`. Compare that digest
with the expected catalogue revision before relying on identity consistency.
Neither choice authenticates the catalogue or proves CNCF membership.

## Packet contents

A v1 packet has exactly these top-level fields:

- `submission.kind`: `new_catalogue_identity_proposal` or
  `existing_project_transition`.
- `project`: public slug, display name, and canonical GitHub repository URL.
  Existing transitions must exactly match the pinned Landscape identity.
  A new proposal is only a proposal and changes neither the catalogue nor CNCF
  membership. The one closed Buildpacks exception permits slug `buildpacks`
  to select `https://github.com/buildpacks/lifecycle` for a Lifecycle component
  transition while the Landscape identity remains `https://github.com/buildpacks/pack`.
  It does not permit another Buildpacks sibling repository or change the
  runtime component identity `pkg:oci/buildpacksio/lifecycle`.
  The separate closed Kubeflow exception permits slug `kubeflow` to select
  `https://github.com/kubeflow/pipelines` for the KFP SDK component while the
  Landscape identity remains the Kubeflow repository. It permits no other
  Kubeflow sibling repository as the selected component.
- `transition`: exact current and proposed versions for an existing project;
  it is `null` for a new identity proposal.
- `tagBindings`: the two endpoint `version`, `tag`, and 40-character `commit`
  declarations for a transition. Tags are unique, slash-separated conservative
  components: no empty component, `..`, trailing dot or slash, or `.lock`
  suffix. Their assertion is always `DECLARED_UNVERIFIED` until independently
  fetched and reviewed.
- `sources`: bounded official-source candidates. Every one has a finite
  `sourceKind`, a declared version, a 40-character commit, a GitHub immutable
  `blob/<commit>/<path>` URL for the declared repository, a full-file SHA-256,
  and one or more line-anchored excerpts. For a transition, the source commit
  must equal the declared tag binding for that source version. The excerpt
  must contain exactly the declared span's line count; it helps reviewers locate
  a claim but does not prove the full-file digest or source authenticity.
  Only the closed Kubeflow Pipelines transition may include one supplementary
  `migration_guide` from the exact approved Kubeflow website path and commit.
  That packet must also contain ordinary Pipelines source evidence at both
  endpoint versions. The guide version declares proposed-SDK applicability; it
  is not a website release tag or evidence that the guide existed at release time.
- `declaration`, `limitations`, and `attribution`: a bounded candidate claim,
  explicit limits, and declared license/attribution status. They are
  declarations, not proof or a legal conclusion.
- `review`: `NOT_REVIEWED` plus a claimed reviewer kind (`agent` or `human`)
  and identity. This is not authentication, independent review, maintainer
  approval, or publication authority.

The sole v2 packet has schema `prufyx.io/upstream-evidence-packet/v2` and
`submission.kind: existing_project_target_preflight`. It is fixed to project
`tikv`, canonical repository `https://github.com/tikv/tikv`, target `8.5.8`,
operation `gcs-full-backup-wif`, one `v8.5.8` tag declaration, and three source
records with explicit `evidenceRole` values:

- `target_setting_declaration` at `tikv/tikv` `src/config/mod.rs`;
- `target_full_backup_caller` at `tikv/tikv`
  `components/backup/src/endpoint.rs`; and
- `operator_action_guidance` at `pingcap/docs`
  `tikv-configuration-file.md`.

The two TiKV source records must use the fixed target commit. The separately
pinned documentation commit is allowed only for the exact guidance role and
path. Guide-only packets, mixed TiKV endpoint commits, other projects,
operations, repositories, roles, paths or tag declarations are rejected. Its
validation receipt alone includes `submissionKind`; the source-verification
receipt retains the existing source-receipt fields and binds the v2 packet by
`packetDigest`. Neither receipt admits the target profile or verifies upstream
tags. The complete candidate is
[`tikv-8.5.8-gcp-v2-wif-backup-candidate.json`](../examples/contributions/tikv-8.5.8-gcp-v2-wif-backup-candidate.json).

The synthetic packet and negative examples are intentionally non-authoritative.
They must never be copied as source evidence. The separate
`crossplane-1.20.0-to-2.0.0-candidate.json` dogfoods an existing catalogue
identity with retained public-source pins. It remains `NOT_REVIEWED` and
`CANDIDATE`; its declarations do not add Crossplane coverage or a rule.

`karmada-1.18.3-to-1.19.0-candidate.json` is a bounded real-source example
for the existing Karmada policy transition. It keeps two immutable GitHub blob
references and short line excerpts for the `purgeMode` enum change; it does not
add or promote a rule. Validate it from `cli/` with:

```sh
go run ./cmd/prufyx-maintainer contribution validate \
  --packet examples/contributions/karmada-1.18.3-to-1.19.0-candidate.json
```

The receipt must report `consistency: VALID`, `workflowState: CANDIDATE`, and
exit `0`. The paired
`examples/contributions/negative/karmada-source-commit-mismatch.json` deliberately
changes the current source commit while retaining its current version; the same
validator must reject it with exit `2`. These checks cover packet consistency
only. An independent reviewer still retrieves the pinned commits and tags,
recomputes the full-file digests and raw-LF spans, and separately decides whether
the existing scoped rule remains justified.

`cri-o-artifact-named-reference-1.34.0-to-1.35.0-candidate.json` is the bounded
CRI-O ArtifactStore named-reference example. Its ordinary transition packet
keeps both endpoint tag declarations and eight immutable CRI-O source files;
the source verification receipt covers every retained raw-LF span. It remains
`NOT_REVIEWED`/`CANDIDATE`: validation and source-byte matching do not establish
tag authenticity, approve the scoped rule, or prove registry, store, request,
ordinary-image or runtime behavior. Validate it from `cli/` with:

```sh
go run ./cmd/prufyx-maintainer contribution validate \
  --packet examples/contributions/cri-o-artifact-named-reference-1.34.0-to-1.35.0-candidate.json
```

## Workflow and authority

1. A contributor creates a packet with the selected submission kind and runs the
   offline validator. The packet remains `review.state: NOT_REVIEWED`; a
   successful local receipt reports `workflowState: CANDIDATE`.
2. An independent reviewer uses the [review record
   template](upstream-review-record-template.md), fetches primary sources
   separately, verifies the declared release/tag-to-commit bindings, source
   bytes/digest/spans, attribution, and the exact claimed limitation, and tests
   an appropriate bounded rule candidate where one is justified.
3. A maintainer records technical acceptance for the reviewed candidate in the
   same record, with the implementation and test evidence identified there.
4. Metadata-only rules can reuse existing canonical facts and admitted raw input
   formats after review; follow the [knowledge-update handoff](knowledge-updates.md#assemble-an-already-signed-package).
   New fact types or engine behavior require a CLI release, while extending
   native-input preparation can also require a CLI update. Any rule/data change still passes
   compiled-registry admission, vectors, source-expiry checks, and a future
   maintainer signing/publication gate. The current assembler/import-update path
   is not a production publisher.

Each step is separate. A packet, receipt, reviewer assertion, synthetic test,
or model output cannot skip a later step. The validator has no network, model,
subprocess, signing, CI-artifact execution, evaluator, or publication
capability.

Standards-conformance profiles have no version transition and therefore do not
fit the v1 transition packet. The embedded
[`cloudeventsstructuredjson/data/profile.json`](../internal/cloudeventsstructuredjson/data/profile.json)
is the concrete closed-profile example: it binds the profile/rule/capability
identities and two immutable source records with bounded spans. A proposed
profile update follows the same independent source and semantic review, then
the existing [already-signed package handoff](knowledge-updates.md#assemble-an-already-signed-package).
Copying or assembling the JSON does not approve, sign, or publish it.

If a transition also needs evidence from an intermediate removal version or a
dry-run, attach that evidence to the review record as an explicitly labelled
intermediate source check. Keep endpoint packet sources bound to their declared
current or proposed version; never relabel intermediate evidence as an endpoint
source. For example, a Cortex dry-run may use a separate intermediate-version
attachment to explain the review path, but it does not change the endpoint
packet or prove a runtime result.

No model training follows from a contribution. A future training experiment
would need an explicit public-data, source-license, retention, evaluation, and
publication decision; customer data stays ineligible by default.

## Planned optional model workflow

Model assistance is planned research, not a current Community feature. It may
be considered only for separately authorized public-source dataset revisions:
a packet or its declared license assertion never authorizes retention or
training, and customer configurations remain ineligible. The local client has
no cloud or model dependency, and ordinary metadata updates do not require
training.

1. A maintainer approves a public-source corpus revision and its lineage for a
   bounded research purpose.
2. The experiment records the dataset hash, source-policy decision, model
   recipe, and project-and-release-separated evaluation split.
3. The model emits candidate declarations only; each candidate enters the same
   offline packet validator used by a human or agent contributor.
4. Independent source review and bounded rule tests check each candidate.
5. Maintainer technical acceptance precedes any separate signed-pack decision.

The experiment must improve false-blocker precision, preserve `UNKNOWN` for
missing or unsupported evidence, and keep unsupported-claim rate within the
approved threshold against a deterministic baseline. Failing any gate blocks
use of the model output as contribution evidence or published data.
