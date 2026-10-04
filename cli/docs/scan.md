# `prufyx scan`

`prufyx scan` reads your rendered manifests and a target version and gives one
answer: can this upgrade go ahead, what must be fixed first (with the file and
object), and what was not checked. It never contacts a cluster or the network.

Today `scan` evaluates **Kubernetes**: API versions in your manifests that a
Kubernetes release on the way to the target stops serving. Other projects are
reported as not covered, with the `prufyx check cncf` command that covers them.

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

NOT CHECKED (1)
  kubernetes 1.24.17 -> 1.25.3   kubernetes 1.25 has not been reviewed for removed APIs - check the kubernetes 1.25 release notes for removed APIs by hand, or request coverage

Checked 1 hop, 2 documents, 1 component (1 covered). 6 checks passed (--show-passes).
Scope limits: node and kubelet version skew not evaluated; Kubernetes: only API versions in the supplied manifests are evaluated; live cluster objects, CRDs, stored versions, admission and component configuration are not.
Evidence: every finding cites pinned upstream source (--verbose). No network used.
evaluated at 2026-10-04T00:00:00Z; input sha256:706abd92d4968558d52e272d3f490af7280ce84a6011ae824a9fa9ae7b4c47f7; knowledge embedded cncf-2026-09-13.2 sha256:d91d0eca200dba55128726d1c5a497833f9ab74b2d95d5ef94c9e69cd0633922
```

The exit code is `10`. The built-in knowledge does not yet carry reviews of
whole release lines, so the hop also names the gap `LINE_NOT_ATTESTED`: the
answer can be `BLOCKED` or "not every area checked", but not yet a pass. `applyset.yaml:1` is the line of the CronJob's
`apiVersion`; for a document without a known line the location is
`file#document` (and `/item` for an object inside a `List`).

## Command

```text
prufyx scan [PATH ...] [-] --to COMPONENT=VERSION [--from COMPONENT=VERSION ...]
    [--config FILE]
    [--distribution official_upstream|custom_build]
    [--resource-scope-complete[=true|false]] [--target-api-apply-required[=true|false]]
    [--format human|json] [--show-passes] [--verbose] [--redact]
    [--input-permissions strict|refuse-writable] [--now RFC3339]
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
| `--format` | `human` (default) or `json`. |
| `--show-passes` | Lists every passed check (human output). |
| `--verbose` | Shows the status of every hop and the pinned sources of each finding (human output). |
| `--redact` | Prints `sha256:` digests instead of file paths, object names and namespaces. Human output shows the first 12 hex characters. |
| `--input-permissions` | `refuse-writable` (default) or `strict`. See below. |
| `--now` | The evaluation instant, canonical UTC with whole seconds (`2026-10-04T00:00:00Z`). Default: the current time, truncated to the second. It is printed in every report; pass it to replay a scan exactly. |

A component version is `X.Y.Z` with no prefix, suffix or leading zeros. An
unknown component name is refused and the three closest names are listed.
`--knowledge-db` is not accepted: `scan` uses the knowledge built into the
binary.

## Answers and exit codes

| Exit | Headline | Meaning |
| --- | --- | --- |
| `10` | `BLOCKED: N problems must be fixed before this upgrade` | At least one reviewed rule matched an object in your manifests. |
| `11` | `NO BLOCKERS FOUND IN COVERED CHECKS: M areas were not checked` | Nothing blocked in what was checked, and `M` named gaps remain. |
| `0` | `PASS FOR THE DECLARED SCOPE` | Every hop is covered and nothing is missing (see below). |
| `2` | `prufyx: ...` on standard error | The command line or an input is not accepted. |
| `3` | `prufyx: KNOWLEDGE INTEGRITY FAILURE` | The built-in knowledge failed its integrity checks. |

**PASS is scoped and rare by design.** It requires all of the following:

- the resource scope is declared complete, the target apply is declared
  required, and the distribution is `official_upstream`;
- every input document was read: none is templated, unparseable, a nested or
  unresolved list, a non-Kubernetes document, or a skipped symlink or special
  file;
- a reviewed upgrade-path policy that is current, so every release line on the
  way is a hop;
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
| `COMPONENT_NOT_COVERED` | A targeted project is not evaluated by `scan` yet. | Run `prufyx check cncf --project NAME`. |
| `VERSION_NOT_DETECTED` | No current version was declared. | Pass `--from kubernetes=VERSION` or set `current:` in `prufyx.yaml`. |
| `VERSION_CONFLICT` | Two different versions were declared for one project. | Declare one. |
| `DECLARATION_MISSING` | Scope completeness, target apply or the distribution is not declared. | Declare it with the flag or in `prufyx.yaml`, if it is true. |
| `DISTRIBUTION_NOT_COVERED` | The distribution is `custom_build`. | Check your distribution's release notes by hand. |
| `DOCUMENTS_TEMPLATED` | Documents with `{{ ... }}` or `${...}`. | Render them (`helm template`, `kustomize build`) and scan the output. |
| `DOCUMENTS_NOT_EVALUATED` | Nested or unresolved lists, paginated lists, documents that are not Kubernetes objects, skipped symlinks or special files, or no manifests at all. | Pass only rendered Kubernetes objects. |
| `API_VERSION_NOT_REVIEWED` | A manifest uses a version of a reviewed kind that the reviewed removals do not name. | Check that version against the release notes by hand. |
| `ALPHA_API_NOT_COVERED` | A manifest uses an alpha version of a Kubernetes API group (core, `apps`, `batch`, `autoscaling`, `policy`, `extensions` or `*.k8s.io`); removed-API reviews cover beta and stable versions only. | Check alpha APIs by hand for every line. |
| `EVIDENCE_EXPIRED` | The review of a rule is stale, withdrawn or not yet valid at `--now`. | Use a release with current knowledge, or check by hand. |
| `RULE_NOT_DECIDED` | A rule that applies could not reach a verdict, or needs evidence `scan` does not collect. | Run the matching `prufyx check cncf` route, or check by hand. |

When any input document cannot be read as part of the apply set (for example a
templated document next to rendered ones), the removed-API facts of the whole
set stay undecided, exactly as for one file in `prufyx check cncf`. Fix the
named documents first.

## What is not checked

- Node and kubelet version skew.
- Anything other than API versions in the supplied manifests: live cluster
  objects, CRDs, stored versions, admission, and component configuration.
- Projects other than Kubernetes (reported as `COMPONENT_NOT_COVERED`).

## Locations and `--redact`

Each finding lists every object that matched: file (as you passed it),
document index, item index inside a `List` (`-1` otherwise), the line of its
`apiVersion` when known, kind, namespace and name. Values are never printed,
and Secret payloads are dropped when the input is read. With `--redact`, the
file, namespace and name are replaced by `sha256:` digests of their text, and
error messages leave out paths.

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
digest and the line review it used), `findings`, `gaps`, `passes`, `omitted`
(every document or file that was not evaluated, with the reason), `omissions`,
`notes` and `provenance` (evaluation instant, input digest, configuration
digest, knowledge revision and digest, engine contract digest, build identity,
`networkUsed: false`).

## Determinism

The same inputs, configuration, knowledge and `--now` give byte-identical
human and JSON output. The order of the paths on the command line does not
matter. Findings are ordered by hop, then rule id; locations by file, document
and item; gaps by component, hop and reason.
