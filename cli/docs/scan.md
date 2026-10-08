# `prufyx scan`

`prufyx scan` reads your rendered manifests and a target version and gives one
answer: can this upgrade go ahead, what must be fixed first (with the file and
object), and what was not checked. It never contacts a cluster or the network.

Today `scan` evaluates **Kubernetes**: API versions in your manifests that a
Kubernetes release on the way to the target stops serving. For Argo CD, Istio
and Strimzi it checks the custom-resource versions in your manifests against
published rules about versions the target release no longer serves (see
[custom-resources.md](custom-resources.md)); those projects are never reported
as covered. Other projects are reported as not covered, with the
`prufyx check cncf` command that covers them.

## Example

```sh
cat > applyset.yaml <<'YAML'
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: nightly-report
  namespace: default
spec:
  schedule: "0 2 * * *"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: report-settings
  namespace: default
data:
  mode: nightly
YAML
chmod 600 applyset.yaml
prufyx scan applyset.yaml --from kubernetes=1.24.17 --to kubernetes=1.25.3 \
  --distribution official_upstream --resource-scope-complete --target-api-apply-required \
  --now 2026-10-04T00:00:00Z
```

```
BLOCKED: 1 problem must be fixed before this upgrade

kubernetes 1.24.17 -> 1.25.3: 1 hop (no reviewed path policy)
  1.24.17 -> 1.25.3   Kubernetes 1.25 stops serving CronJob through batch/v1beta1
                      applyset.yaml:1  CronJob default/nightly-report
                      fix: Migrate the named CronJob manifest to batch/v1, then reassess the complete target apply set. Validate admission, CRDs, stored objects, runtime clients, and API-server configuration separately.

NOT CHECKED (2)
  kubernetes   no reviewed list of the API versions Kubernetes 1.25 serves; 2 manifest(s) cannot be checked - check them against the Kubernetes 1.25 API reference by hand, or request coverage
  kubernetes 1.24.17 -> 1.25.3   kubernetes 1.25 has not been reviewed for removed APIs - check the kubernetes 1.25 release notes for removed APIs by hand, or request coverage

Checked 1 hop, 2 documents, 1 component (1 covered). 6 checks passed (--show-passes).
Scope limits: node and kubelet version skew not evaluated; Kubernetes: only API versions in the supplied manifests are evaluated; live cluster objects, CRDs, stored versions, admission and component configuration are not.
Evidence: every finding cites pinned upstream source (--verbose). No network used.
evaluated at 2026-10-04T00:00:00Z; input sha256:706abd92d4968558d52e272d3f490af7280ce84a6011ae824a9fa9ae7b4c47f7; knowledge embedded cncf-2026-09-13.4 sha256:b8bca5facdc3081165459bc726fe269e1321abb4690dbe0be090bc313850d548
```

The exit code is `10`. The built-in knowledge does not yet carry reviews of
whole release lines or reviewed lists of served API versions, so the answer
also names `LINE_NOT_ATTESTED` and `API_VERSION_NOT_REVIEWED`: it can be
`BLOCKED` or "not every area checked", but not yet a pass. `applyset.yaml:1` is the line of the CronJob's
`apiVersion`; for a document without a known line the location is
`file#document` (and `/item` for an object inside a `List`).

## Command

```text
prufyx scan [PATH ...] [-] --to COMPONENT=VERSION [--from COMPONENT=VERSION ...]
    [--config FILE]
    [--distribution official_upstream|custom_build]
    [--resource-scope-complete[=true|false]] [--target-api-apply-required[=true|false]]
    [--format human|json|sarif|markdown] [--show-passes] [--verbose] [--redact]
    [--input-permissions strict|refuse-writable] [--require-basis LIST]
    [--knowledge-db DIR | --now RFC3339]
```

| Flag | Meaning |
| --- | --- |
| `PATH` | Files or directories of rendered manifests. A directory is read recursively (`*.yaml`, `*.yml`, `*.json`; hidden directories skipped; symlinks never followed). `-` reads standard input. Without a path, the `inputs` of `prufyx.yaml` are used, else the current directory. |
| `--to C=V` | Target version of component `C`, a project name from `prufyx catalog cncf`. Repeatable; at least one target is required (here or in `prufyx.yaml`). |
| `--from C=V` | Version of `C` in use now. Repeatable. `scan` never reads the Kubernetes version from manifests: without it the answer names the gap. |
| `--config FILE` | The [`prufyx.yaml`](scan-config.md) to read. Default: `prufyx.yaml` next to the first `PATH`. Flags override the file key by key. |
| `--distribution` | `official_upstream` or `custom_build`. Only `official_upstream` is evaluated. |
| `--resource-scope-complete` | Declares that the inputs are every manifest you apply. |
| `--target-api-apply-required` | Declares that the inputs are applied to the target Kubernetes API. |
| `--format` | `human` (default), `json`, `sarif` or `markdown`. The format changes only what is printed: the verdict and the exit code are the same. |
| `--show-passes` | Lists every passed check (human and Markdown output). |
| `--verbose` | Shows the status of every hop and the pinned sources of each finding (human and Markdown output). |
| `--redact` | Prints `sha256:` digests instead of file paths, object names and namespaces. Human and Markdown output show the first 12 hex characters; SARIF uses a name under `redacted/`. |
| `--input-permissions` | `refuse-writable` (default) or `strict`. See below. |
| `--require-basis` | The evidence bases whose rules are evaluated, a comma-separated subset of `reviewed`, `mechanical`, `empirical`, `consensus`, `lead`. Default: `reviewed,mechanical,empirical,consensus`, the same as `prufyx check cncf`. A rule left out that applies to a hop keeps the hop undecided (`RULE_NOT_DECIDED`) and the report says how many were left out. |
| `--knowledge-db` | Read the knowledge from this verified local knowledge database instead of the knowledge built into the binary. See "Knowledge database" below. |
| `--now` | The evaluation instant, canonical UTC with whole seconds (`2026-10-04T00:00:00Z`). Default: the current time, truncated to the second. It is printed in every report; pass it to replay a scan exactly. Not accepted with `--knowledge-db`. |

A component version is `X.Y.Z` with no prefix, suffix or leading zeros. An
unknown component name is refused and the three closest names are listed.

## Knowledge database

Without `--knowledge-db`, `scan` uses the knowledge built into the binary, and
its rules expire with that binary's reviews. With `--knowledge-db DIR`, `scan`
reads the rules from a local CNCF knowledge database that
`prufyx db update` or `prufyx db import` filled, in either layout: `cncf` (one
target) or `cncf-projects` (one target per project). A renewed or withdrawn
rule therefore reaches `scan` without a new binary. See
[Explicit knowledge downloads](knowledge-updates.md) and
[Per-project CNCF knowledge targets](cncf-knowledge-per-project.md).

The database is verified exactly as for `prufyx check cncf --knowledge-db`:
the TUF metadata is checked again at the current time, rollback and clock
floors apply, the selection's trust receipt must match, and in the
per-project layout the index and the target of every targeted project are
checked against the signed metadata. Every project named with `--to` must
verify, including one `scan` does not evaluate yet: a damaged target for any
of them stops the scan. The scan is evaluated at that same instant, so
`--now` is refused; the instant is printed in the report.

`scan` never writes to the directory. Before the database is opened, the path
must be an existing directory, not a symbolic link, with mode `0700` (as
`db update` and `db import` create it), holding the database's profile or
selection file. Otherwise the scan stops with exit `3` and names the reason:
no directory at that path; the directory must be private to its owner (mode
0700) and not a symbolic link; or the directory is not a knowledge database.

- Any verification failure (a changed target, a missing project target, a
  rolled-back selection or clock, a layout that does not match the store, a
  database with nothing selected, or a path that fails the checks above) stops
  the scan with exit
  `3` and `KNOWLEDGE INTEGRITY FAILURE`, and nothing is printed on standard
  output. The built-in knowledge is never used instead.
- A targeted project that the selected per-project index has no target for is
  not checked: it is reported with the gap `PROJECT_NOT_IN_KNOWLEDGE` and the
  answer cannot pass.
- Expired, not yet valid and withdrawn rules in the database behave exactly
  like built-in ones (`EVIDENCE_EXPIRED`). `--require-basis` applies to the
  database's rules and records as it does to the built-in ones.
- The knowledge database format does not carry line reviews, upgrade-path
  policies or reviewed served-API lists yet, and the built-in knowledge
  carries none either, so the related gaps (`LINE_NOT_ATTESTED`,
  `NO_REVIEWED_PATH_POLICY`, `API_VERSION_NOT_REVIEWED`) are named exactly as
  with the built-in knowledge. A database that carried such records would be
  refused when it is imported.

The report's provenance names the database: `knowledgeOrigin` is
`external_signed_local`, `knowledgeRevision` and `knowledgeDigest` identify
the selected target (the index in the per-project layout), and
`knowledgeStore` gives the database path, its layout, the target path, the
trust receipt digest, the purpose, when the revision was imported and, in the
per-project layout, the revision and digest of each targeted project's target.
SARIF output carries the same `knowledgeStore` object in its run properties,
and Markdown output lists the same lines as the human output in its
provenance block. With `--redact` the database path is replaced by its
`sha256:` digest in every format. Like the other redacted values, this is a
plain digest: a common path such as `~/.prufyx/db` can be recovered by
guessing. The human output ends with, for example:

```
evaluated at 2026-10-04T06:46:52Z; input sha256:706abd92d4968558d52e272d3f490af7280ce84a6011ae824a9fa9ae7b4c47f7; knowledge external_signed_local 5 sha256:8ee7da3043a69c79c8b75484444c996986abdad70f1f2157c9149a2807c9cf05
knowledge database knowledge-db; layout cncf-projects; target knowledge/cncf/index.v1.json; trust receipt sha256:7d92352be22ec77c9ceebe8c46a29bfd92dc53c9a5f8a33f690ba4e4b598be93
knowledge for kubernetes: target knowledge/cncf/projects/kubernetes.v1.json revision 5 digest sha256:f52033c5f46cb594b8a6d4fcb057cc3284df7b92f5c1702aeb950f6b4f937cad
```

(That database holds a test-signed copy of the built-in knowledge; no official
Prufyx knowledge feed or trust root is published yet.)

## Knowledge age note

When the knowledge a scan used is close to the end of its review window,
`scan` prints one line on standard error, after the report:

```text
prufyx: note: 166 knowledge rules expire within 30 days, the earliest on 2026-12-07 (in 17 days); update with `prufyx db update` and use --knowledge-db
```

The line appears when any active rule of the knowledge in use ends no later
than 30 days after the evaluation instant (exactly 30 days counts), and when a
rule has already ended, in which case it says so:

```text
prufyx: note: 50 knowledge rules have expired, the earliest on 2026-12-07 (2 days ago); update with `prufyx db update` and use --knowledge-db
```

The knowledge in use is the knowledge built into the binary, or, with
`--knowledge-db`, the targets opened from the database (the second form of the
line leaves out `and use --knowledge-db`, which you already do). The count
covers the active rules of that knowledge; withdrawn rules do not count. The
evaluation instant is the one printed in the report, so the line is the same
for the same `--now` and the same knowledge.

The line is a note, not a result. Standard output, the JSON, SARIF and
Markdown formats, the exit status and `--redact` are exactly what they are
without it. It names no path and no input, so `--redact` has nothing to hide
in it. `scan` has no option to silence it; redirect standard error if you do
not want it. It is not printed when the scan stops with an error.

## Answers and exit codes

See [exit-codes.md](exit-codes.md) for the one table covering `scan` and
`check`. Exit `0` here means the declared scope is complete; `check` exit `0`
means one scoped rule passed (use `check --strict-exit` to tell them apart).

| Exit | Headline | Meaning |
| --- | --- | --- |
| `10` | `BLOCKED: N problems must be fixed before this upgrade` | At least one reviewed rule matched an object in your manifests. Gaps may remain; they are still listed. |
| `11` | `NO BLOCKERS FOUND IN COVERED CHECKS: M areas were not checked` | Nothing blocked in what was checked, and `M` named gaps remain. |
| `0` | `PASS FOR THE DECLARED SCOPE` | Every hop is covered and nothing is missing (see below). |
| `2` | `prufyx: ...` on standard error | The command line or an input is not accepted. |
| `3` | `prufyx: KNOWLEDGE INTEGRITY FAILURE` | The built-in knowledge, or the `--knowledge-db` database, failed verification. |

The answers rank `BLOCKED` (`10`) over not checked (`11`) over `PASS` (`0`).
A blocker is reported whenever the documents that were read establish it,
even when other inputs could not be read or other areas could not be
checked: those still appear as gaps and omitted documents, and the findings
are always listed. A gap never hides a blocker, and it always prevents a pass.

**PASS is scoped and rare by design.** It requires all of the following:

- the resource scope is declared complete, the target apply is declared
  required, and the distribution is `official_upstream`;
- every input document was read: none is templated, unparseable, a nested or
  unresolved list, an object of a kind other than `List` that holds a
  top-level `items` array, a non-Kubernetes document, or a skipped symlink or
  special file;
- either the upgrade enters at most one new minor release line, or a current
  reviewed upgrade-path policy splits it so that every release line on the way
  is a hop;
- every object of a Kubernetes API group is at an API version the target
  serves. A Kubernetes API group is the core group, any group without a dot
  (`apps`, `batch`, but also misspellings such as `core` or `rbac`) and any
  `*.k8s.io` group. No object may be at a version removed on a line no
  evaluated hop enters (for example a `batch/v1beta1` CronJob when you are
  already on 1.25), and each must be named, with its kind, by a reviewed list
  of what the target line serves that is current and is for that line.
  Objects of custom resource groups (a group with a dot, not `*.k8s.io`) are
  not checked;
- for every hop, every rule that applies to any release of the hop covers the
  whole hop and reached a verdict, and a current review of the target line says
  these are all the rules for removed API versions on that line;
- no gap of any kind, including other targeted components.

Absence of evidence is never a pass: anything that could not be decided is a
named gap and the answer stays `11`.

## How an upgrade is planned and checked

Kubernetes upgrades one minor release line at a time. When the knowledge holds
a current, reviewed upgrade-path policy for Kubernetes, `scan` splits
`1.24.17 -> 1.30.4` into hops `1.24.17 -> 1.25`, `1.25 -> 1.26`, ...,
`1.29 -> 1.30.4`. An intermediate end such as `1.25` stands for every release
of that line, because you may stop at any of them. A rule decides such a hop
only if its reviewed version range covers the whole line on that side; a rule
reviewed for one exact pair of versions cannot. Without a reviewed policy the
upgrade is one direct hop, and an upgrade that skips release lines stays
unchecked (gap `NO_REVIEWED_PATH_POLICY`).

Each hop is evaluated with the same engine input that
`prufyx check cncf --project kubernetes --native-resource` builds for one
file holding the same documents. The whole upgrade is also evaluated as one
transition, so a rule reviewed for the exact end-to-end pair is never lost.

A blocker is reported once, at the first hop where it blocks; later hops where
it also blocks are listed in JSON as `alsoAt`.

Each hop has a status in JSON (`paths[].hops[].status`, and with `--verbose`):
`BLOCKED`, `COVERED`, `PARTIAL` (some rule or review is missing) or `NO_DATA`
(no rule and no current review). Every hop that is not `COVERED` or `BLOCKED`
lists the gap reasons that explain it.

## Gaps

Every gap has a reason, a detail and an action.

| Reason | When | What to do |
| --- | --- | --- |
| `LINE_NOT_ATTESTED` | The target line of a hop has no current review of its removed APIs, the review is inconsistent with the rules, the hop does not enter one line from the line before it, the hop stays within one line, or a removal on the way has no reviewed rule. | Check that line's release notes by hand, or request coverage. |
| `INTERMEDIATE_LINE_NOT_COVERED_BY_RANGE` | A rule applies to some releases of a hop's line and not to others. Its result is not used. | Scan the hop with exact versions, or request a rule that covers whole lines. |
| `NO_REVIEWED_PATH_POLICY` | No reviewed upgrade-path policy, and the upgrade skips release lines. | Upgrade one minor line at a time and scan each hop. |
| `PATH_POLICY_NOT_CURRENT` | A path policy exists but its review is expired or withdrawn. | Use knowledge with a current policy; until then scan one line at a time. |
| `PATH_NOT_PLANNABLE` | The versions cannot be planned (equal versions, too many hops, a major change). | Check the versions, or scan each step. |
| `DOWNGRADE_NOT_REVIEWED` | The target is older than the current version. | None: downgrades are not evaluated. |
| `COMPONENT_NOT_COVERED` | A targeted project is not evaluated by `scan` yet, or (Argo CD, Istio, Strimzi) only its custom-resource versions are. | Run `prufyx check cncf --project NAME`, or verify the rest of its upgrade notes by hand. |
| `PROJECT_NOT_IN_KNOWLEDGE` | With `--knowledge-db`, the selected per-project index has no target for a targeted project, so nothing about it was checked. | Update the knowledge database to a revision that covers it, or check by hand. |
| `VERSION_NOT_DETECTED` | No current version was declared. | Pass `--from kubernetes=VERSION` or set `current:` in `prufyx.yaml`. |
| `VERSION_CONFLICT` | Two different versions were declared for one project. | Declare one. |
| `DECLARATION_MISSING` | Scope completeness, target apply or the distribution is not declared. | Declare it with the flag or in `prufyx.yaml`, if it is true. |
| `DISTRIBUTION_NOT_COVERED` | The distribution is `custom_build`. | Check your distribution's release notes by hand. |
| `DOCUMENTS_TEMPLATED` | Documents with `{{ ... }}` or `${...}`. | Render them (`helm template`, `kustomize build`) and scan the output. |
| `DOCUMENTS_NOT_EVALUATED` | Nested or unresolved lists, paginated lists, objects of a kind other than `List` that hold a top-level `items` array, documents that are not Kubernetes objects, skipped symlinks or special files, or no manifests at all; for a project with custom-resource versions, also objects of custom-resource groups that no reviewed project owns. | Pass only rendered Kubernetes objects; check unowned custom resources by hand. |
| `UNSUPPORTED_COMBINATION` | A support-range rule finds the planned combination outside its documented support range (see "Unsupported combinations"). | Follow the rule's next action, or accept the risk knowingly; the answer cannot pass. |
| `API_VERSION_NOT_SERVED` | A manifest uses an API version that was removed on a release line at or below the target that no evaluated hop enters (typically one removed before your current version). | Migrate it to a served version and scan again. |
| `API_VERSION_NOT_REVIEWED` | A manifest uses a version of a reviewed kind that the reviewed removals do not name, or a version and kind of a Kubernetes API group that the reviewed list of the target line does not name as served; or that list is missing, not current, for another line or component, or rests on a basis `--require-basis` leaves out. The built-in knowledge does not carry such lists yet, so today every scan with Kubernetes manifests names this gap. | Check those versions against the target's API reference by hand, or request coverage. |
| `ALPHA_API_NOT_COVERED` | A manifest uses an alpha version of a Kubernetes API group (core, `apps`, `batch`, `autoscaling`, `policy`, `extensions` or `*.k8s.io`); removed-API reviews cover beta and stable versions only. | Check alpha APIs by hand for every line. |
| `EVIDENCE_EXPIRED` | The review of a rule is stale, withdrawn or not yet valid at `--now`. | Use a release with current knowledge, or check by hand. |
| `RULE_NOT_DECIDED` | A rule that applies could not reach a verdict, needs evidence `scan` does not collect, rests on consensus evidence that found nothing, or was left out by `--require-basis`. | Run the matching `prufyx check cncf` route, or check by hand. |

When an input document cannot be read as part of the apply set (for example a
templated document next to rendered ones), a removed API version used by a
document that was read is still a blocker, as long as that document is applied
as written whatever the unread documents hold. A document that may not be
rendered at all is not used as evidence:

- a document in a file where an unread document opens or closes a template
  action (`if`, `range`, `with`, `define`, `block`, `else`, `end`) that it does
  not close within one value, because the action can enclose the other
  documents of the file;
- in a raw Helm chart (a directory with a `Chart.yaml`), a document under
  `templates/tests/`, or under `charts/` in a subchart that `Chart.yaml` does
  not list as a dependency without a `condition`, `tags` or an `alias`;
- a Helm test hook (`helm.sh/hook: test...`), which only `helm test` applies.

Template actions in YAML comments are not seen; pass rendered output to be
sure. Absence is never concluded from a partial set, so every other
removed-API fact stays undecided, a rule that also depends on what the
unreadable documents contain stays undecided, the unreadable documents are
listed as omitted with their gap, and the answer is never a pass. This is the
same as for one file in `prufyx check cncf`. Fix the named documents and scan
again: a blocker may also be hidden inside them.

A patch upgrade within one minor line (for example `1.30.4 -> 1.30.5`) is
never covered by a line review and always names `LINE_NOT_ATTESTED`; check the
patch release notes by hand.

When the plan has more than one hop, the whole upgrade is also evaluated as one
transition. For an upgrade across several lines that transition carries only
the flow-control fact, so a rule reviewed for that exact pair but reading
another removal fact cannot be decided there; it is reported as a gap, never
as a pass, and a blocker is never lost.

## One-way changes

Some reviewed transitions cannot be rolled back. When such a notice applies to
a hop, the human output lists it after the gaps under `ONE-WAY CHANGES (N)` as
`cannot be rolled back: <rule>` with `before you upgrade: <reviewed text>`, and
JSON lists it in `notices`. A notice that applies but could not be established
(for example its review expired) is listed as not established, with the
reason. Notices never change the headline, the exit code, the gaps or the
findings, and the absence of a notice never means a rollback is possible.

## Evidence bases

Each finding names its evidence basis. A `consensus` rule (two independent
model readings with verified citations) may block, and the human output says
how many findings rely on model consensus; where a consensus rule finds
nothing, its hop is not decided (`RULE_NOT_DECIDED`), because consensus never
establishes a pass. A `lead` rule (one unverified model reading) never blocks
and never passes: when you add `lead` to `--require-basis`, a lead that would
block is listed under `UNVERIFIED LEADS (N)` (`leads` in JSON) as
`unverified lead (does not block)` with what is worth checking, and it never
changes the answer. Without `lead` in the list, leads are left out and only
counted. When the trust policy leaves out a rule that applies, the first lines
after the headline and `trustPolicy` in JSON say so.

The trust policy also selects the evidence that completeness rests on. A line
review, an upgrade-path policy or a served list whose evidence basis is not in
`--require-basis` is not used: the hop names `LINE_NOT_ATTESTED`, the path
names `NO_REVIEWED_PATH_POLICY`, and the manifests name
`API_VERSION_NOT_REVIEWED`, each saying that `--require-basis` left the
record out.

## Unsupported combinations

A support-range rule says that a combination is outside a documented support
range, which is not the same as broken. When one applies to a hop, the human
output lists it under `UNSUPPORTED COMBINATIONS (N)` with the rule, its reason
and its next action (`unsupported` in JSON). It is never a blocker and never a
pass: the hop names `UNSUPPORTED_COMBINATION`, so the answer cannot pass while
it stands.

## What is not checked

- Node and kubelet version skew.
- Anything other than API versions in the supplied manifests: live cluster
  objects, CRDs, stored versions, admission, and component configuration.
- Projects other than Kubernetes (reported as `COMPONENT_NOT_COVERED`); for
  Argo CD, Istio and Strimzi only custom-resource versions are checked.

## Locations and `--redact`

Each finding lists every object that matched: file (as you passed it),
document index, item index inside a `List` (`-1` otherwise), the line of its
`apiVersion` when known, kind, namespace and name. Values are never printed,
and Secret payloads are dropped when the input is read. With `--redact`, the
file, namespace and name are replaced by `sha256:` digests of their text, and
error messages leave out paths. These are plain digests, not anonymisation:
the same name always gives the same digest, so a short or common name (such as
the namespace `default`) can be recovered by guessing. Locations keep their
order by the original path.

## Input permissions

By default (`refuse-writable`) a file that other users can write is refused,
and a file that other users can read is accepted with one note:
`note: N input files are readable by other users; use --input-permissions strict to refuse them`.
`--input-permissions strict` refuses any group or other permission, a file
owned by another user and a file with several hard links. Standard input has no
mode, so the policy does not apply to it. `prufyx.yaml` is read under the same
policy.

## `prufyx.yaml`

See [scan-config.md](scan-config.md). A `prufyx.yaml` found among the inputs
(for example inside the scanned directory) is listed as omitted with reason
`CONFIG_DOCUMENT` and never evaluated as a manifest.

## JSON

`--format json` prints one object with schema `prufyx.io/scan-report/v1alpha1`,
described by [`generated/schemas/scan-report-v1alpha1.json`](generated/schemas/scan-report-v1alpha1.json):
`verdict` (`BLOCKED`, `UNKNOWN` or `SCOPE_COMPLETE_PASS`), `headline`,
`summary`, `inventory`, `paths` (with every hop, its status, its engine input
digest, the engine contract it was evaluated under and the line review it
used), `findings`, `gaps`, `passes`, `omitted`
(every document or file that was not evaluated, with the reason), `notices`
(one-way changes; never part of the verdict), `leads` (unverified leads;
never part of the verdict), `trustPolicy` (only when the trust policy left out
a rule that applies), `unsupported` (combinations outside a documented support
range), `omissions`, `notes` and `provenance` (evaluation instant, input digest, configuration
digest, knowledge origin, revision and digest, the engine contract digest of
the first evaluated transition, build identity, `networkUsed: false`, and
`knowledgeStore` when `--knowledge-db` was used). The engine contract
depends on the features of the rules a transition selects: when a one-way
notice, a lead or a support-range rule is selected, it differs from a hop
without one, with no change to the answer.

## SARIF

`--format sarif` prints a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
log that GitHub code scanning accepts. Redirect it to a file:

```sh
prufyx scan manifests/ --from kubernetes=1.24.17 --to kubernetes=1.25.3 \
  --distribution official_upstream --resource-scope-complete --target-api-apply-required \
  --format sarif > prufyx.sarif
```

The exit code is the same as for any other format (`10` for a blocker, `11`
for unchecked areas), so a workflow step that uploads the file should run even
when the scan fails:

```yaml
- name: Scan upgrade
  run: prufyx scan manifests/ --from kubernetes=1.24.17 --to kubernetes=1.25.3 --distribution official_upstream --resource-scope-complete --target-api-apply-required --format sarif > prufyx.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: prufyx.sarif
```

What the log holds:

- `tool.driver` is `prufyx` with the build version; `rules` has one rule per
  rule id in the report (`helpUri` is the first cited source at its pinned
  revision, `properties.basis` the evidence basis).
- One `results` entry per finding and location, with `level: "error"`, the
  message `<title> — fix: <fix>`, `physicalLocation.artifactLocation.uri`
  (the path relative to the repository root, forward slashes, percent-encoded)
  and `region.startLine` when the line of the `apiVersion` is known. Run
  `prufyx scan` from the repository root with relative paths so the paths match
  the repository; an absolute path or a path outside the working directory is
  written without its leading `/` or `..`. A stable `partialFingerprints`
  entry depends on the rule, the path and the position of the object in its
  file, not on the line.
- One `toolExecutionNotifications` entry per not-checked area (`warning`), per
  combination outside a documented support range (`warning`), per one-way
  change (`note`) and per unverified lead (`note`). Only a finding is an
  `error`; nothing that is not a blocker ever is.
- `runs[0].properties` holds the verdict, the headline, the summary counts, the
  evaluation instant, the digests needed to replay the scan, the trust policy
  when it left rules out, and `networkUsed: false`. The invocation carries the
  exit code.

Code scanning shows the results. The not-checked areas are in the uploaded
file, not in the alerts list; use the Markdown or human output to read them in
a job log. With `--redact`, every path becomes `redacted/<12 hex>` and every
name and namespace a digest, so the alerts cannot be placed in the repository.

## Markdown

`--format markdown` prints GitHub-flavoured Markdown for a pull request
comment or a change ticket: the headline, a table of problems per path (hop,
problem, where, fix), the not-checked areas, one-way changes, unsupported
combinations and unverified leads, a table of the cited sources (pinned
revision and lines), the scope limits and a `<details>` block with the
provenance. File paths and object names are in code spans; any other text from
rules or manifests is escaped, so a `|` or a backtick cannot break a table. It
accepts `--show-passes` and `--verbose` like the human output.

## Determinism

The same inputs, configuration, knowledge and `--now` give byte-identical
human, JSON, SARIF and Markdown output. With `--knowledge-db` the instant is the time of the
run; scanning the same inputs with the built-in knowledge and `--now` set to
the printed instant gives the same answer when the database holds the same
rules. The order of the paths on the command line does not
matter. Findings are ordered by hop, then rule id; locations by file, document
and item; gaps by component, hop and reason.
