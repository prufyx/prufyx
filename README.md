# Prufyx

**Deterministic upgrade checks for Kubernetes and CNCF projects.**

Prufyx checks a planned upgrade against upstream evidence and returns
`PASS`, `BLOCKED`, or `UNKNOWN`. Every rule cites the exact upstream commit,
file, and line range it relies on, and says how it was established. Every rule
in the knowledge shipped today was reviewed by a person. Prufyx is built to
accept other ways of establishing a rule as well, for example deriving it
mechanically from upstream source with a program that is re-run and checked
before the rule is accepted; each rule states which way it was established, and
you can limit a `scan` to the ways you trust (by default `scan` uses every
basis except `lead`; `--require-basis reviewed` keeps only rules a person
reviewed). Prufyx evaluates locally and offline, uploads nothing, and a
deterministic engine computes every verdict: no model runs on your machine. When the
evidence does not decide the question, the answer is `UNKNOWN`, not a guess.

> **Status: early alpha.** Build from source. There is no published release,
> prebuilt binary, or official knowledge feed yet (release workflows exist in
> the repository but have not published anything). Results are scoped findings,
> not a guarantee that a whole upgrade is safe.

## Quickstart

Requires Go 1.26 (release builds use 1.26.8; see CONTRIBUTING.md).

```sh
git clone https://github.com/prufyx/prufyx.git
cd prufyx/cli
go build -buildvcs=false -o "$HOME/.local/bin/prufyx" ./cmd/prufyx-community
```

The [quickstart guide](cli/docs/quickstart.md) takes you from a clean clone to
a real `BLOCKED` verdict on a Kubernetes API removal, with its upstream source
citation, in under five minutes. It also shows how to wire the exit code into
CI (use `check --strict-exit` there).

Run `prufyx` for a short command overview and `prufyx <command> help` for one
command's details. Help text is coloured only on a terminal; `NO_COLOR` or
`PRUFYX_COLOR=never` turns it off and `PRUFYX_COLOR=always` forces it on (see
the quickstart guide). Reports are never coloured.

## What the verdicts mean

The table is for `check`, where `PASS` is scoped to the rules that were
checked. `scan` exit `0` means a complete scope. See [exit codes](cli/docs/exit-codes.md)
for the single table of both, and for `check --strict-exit`, which CI should
always use: a scoped `PASS` then exits `14`, so it cannot be read as a
complete pass.

| Verdict | Meaning | Exit code |
| --- | --- | --- |
| `PASS` | The input does not match the reviewed source condition for this rule. It is not a whole-upgrade certificate. | `0` |
| `BLOCKED` | The input matches a reviewed condition that the target release enforces, such as a removed API or flag. The output names the remediation. | `10` |
| `UNKNOWN` | The input does not contain enough to decide, or the transition is outside reviewed evidence. | `11` |
| invalid input / integrity failure | The input was rejected, or the built-in knowledge or the `--knowledge-db` database failed verification. | `2` / `3` |

A rule applies to the exact reviewed version pair, or to a version range only
where the cited evidence states that range. Outside it, the result is
`UNKNOWN`.

## What is covered

The [generated support inventory](cli/docs/community-support-inventory.md)
is the authoritative list of checks. A check covers exact reviewed versions;
the numbers below separate how many rules exist from how much of the recent
upgrade surface they decide.

## Coverage

<!-- coverage:begin -->
Generated on 2026-10-08 by `scripts/readme-coverage.sh` (do not edit this block by hand).

| Executable rules | Count |
| --- | --- |
| CNCF source rules, active | 190 across 53 projects (1 withdrawn, not used) |
| Rules for further, non-CNCF projects | 34 across 8 projects |
| Projects with at least one executable check | 65 |
| Projects catalogued with retained public sources | 58 (11 of them source-only, no check) |

Version-coverage depth, measured over the last five minor upgrades of each of the 55 projects with a release-line snapshot (275 upgrades between consecutive release lines):

| Status | Upgrades | Share |
| --- | --- | --- |
| Decided for the whole release-line pair (A attested, B bounded) | 0 | 0% |
| Rule for one exact version pair only (S) | 44 | 16% |
| Gap, no valid rule (G) | 231 | 84% |

Kubernetes: 26 valid rules, but 0 fall in its window 1.32 to 1.37; 5 of 5 upgrades in that window are gaps.

Decided means a valid rule or attestation covers every version of both release lines, so the answer is BLOCKED or UNKNOWN, never a whole-upgrade PASS. An exact-pair rule decides only the versions it names. The metric is defined in the [coverage report guide](cli/docs/coverage-report.md); it is not a statement that any upgrade is safe.
<!-- coverage:end -->

Update the block with `scripts/readme-coverage.sh` (`--check` fails when it is
stale). The method and the full per-project table are in the
[coverage report guide](cli/docs/coverage-report.md).

In plain terms: the rules are exact, reviewed transitions, mostly for older
releases. No upgrade between two release lines is decided as a whole yet, and
Kubernetes has no rule for upgrades after 1.32. Reviewed Kubernetes API
removals exist for upgrades to 1.22, 1.24-1.27, 1.29 and 1.32.

Further projects with executable checks: Argo Workflows, Ceph, Fluent Bit,
Grafana, Grafana Loki, Kibana, MariaDB and MariaDB Operator (community
projects), and named checks and profiles for cert-manager, Prometheus, SPIFFE
X.509-SVID, CloudEvents and TiKV.

CNCF projects with rules include Argo CD, Cilium, containerd, Contour, CoreDNS,
Cortex, CRI-O (its one rule is withdrawn), Crossplane, Envoy, etcd, Falco, Flux, Harbor, Helm, Istio,
Jaeger, Karmada, KEDA, Knative, KubeEdge, KubeVirt, Kyverno, Linkerd, Longhorn,
MetalLB, OPA, OpenTelemetry, Prometheus, Rook, SPIRE, Strimzi, Tekton, Thanos,
Velero and others.

Every rule in the CNCF and community-project packs is time-limited. The rules
shipped today stop being valid between 2026-12-07 and 2026-12-22 unless their
review is renewed; after that date a build without newer knowledge answers
`UNKNOWN` for them. The named cert-manager and Prometheus checks are pinned to
fixed versions and do not expire.

Run `prufyx catalog checks --project PROJECT` (for example `kubernetes`) to
list a project's embedded rules and the exact command and input each one reads. The [community checks reference](cli/docs/community-checks.md)
documents every input contract.

## What `scan` covers today

`prufyx scan` reads your rendered Kubernetes manifests and a target version and
reports which API versions in them a Kubernetes release on the way to the
target stops serving. It covers Kubernetes only; other projects are reported as
not covered, with the `prufyx check cncf` command that does cover them. It does
not look at a live cluster, custom resources, stored versions, admission or
component configuration, or node version skew.

`scan` cannot answer `PASS` (exit `0`) with the knowledge built into this
source tree. A pass needs three kinds of reviewed records that are not shipped
yet: reviews that a release line has no other removed APIs, a reviewed upgrade
path policy for skipping release lines, and a reviewed list of the API versions
each target release serves. Until they are, a scan with Kubernetes manifests
ends in `BLOCKED` (exit `10`) or "not every area checked" (exit `11`). See the
[`scan` guide](cli/docs/scan.md). To run it in a workflow, see the
[GitHub Action](cli/docs/github-action.md).

## Recent changes

The [changelog](CHANGELOG.md) is the full list. Merged and user-visible, by
status:

**Implemented in the source tree**

- **Coverage report** (maintainer command): measures how much of each
  project's last five minor upgrades the rules decide. See
  [coverage report](cli/docs/coverage-report.md).
- **Release-boundary rules:** a rule whose range pins a removal or change
  boundary no longer lets a hop that crosses that boundary pass; the result is
  `UNKNOWN` (`RULE_RELEASE_BOUNDARY_NOT_REVIEWED`), and `catalog checks` lists
  the `boundary-unreviewed` and `crossing` match modes.
- **Image-based detection for `assess`** (reads a cluster, opt-in): a reviewed
  registry maps container images to projects and reads a version only from a
  tag that follows the declared scheme. Unlisted, digest-only, `latest` and
  mirrored images give no version, so the component is indeterminate rather
  than a mismatch.
- **Knowledge store:** `check cncf` and `scan` use a verified database that
  `prufyx db update` installed, and refuse an invalid or expired one;
  `--knowledge=embedded` forces the built-in knowledge.
- **`check --strict-exit`:** a scoped `PASS` exits `14` instead of `0`. See
  [exit codes](cli/docs/exit-codes.md).
- **`scan` output is escaped:** terminal escape sequences, line breaks and
  bidirectional controls from the input or knowledge are shown as visible
  escapes, so a name or path cannot forge a report line.
- **Per-kind migration hints** with cited upstream passages for derived
  Kubernetes API-removal rules.
- **Helm subcharts:** `scan` answers `UNKNOWN` instead of `BLOCKED` for a
  removed API in a subchart that may not be rendered.
- **Hardening:** filesystem writes by maintainer tools and the collector do
  not follow symlinks; the GitHub Action passes its token only to the
  attestation check and requires an archive checksum to skip attestation;
  tagged release builds are reproducible and carry their build identity. See
  [releasing](cli/docs/releasing.md).

**Internal, not yet shipped in knowledge:** support for reviewed served-API
lists in `scan`. No such list is shipped, so `scan` still cannot answer `PASS`
as described above.

**Planned:** a published release with prebuilt binaries, an official signed
knowledge feed, and automated GitOps release gates. None exists today.

## Privacy and offline operation

- `check` and `scan` read local files you select. They do not contact a
  cluster, registry, or upstream project, and they do not execute supplied
  content. `prufyx assess` is the only command that reads a cluster: read-only,
  through kubectl, and only with an explicit kubeconfig, context and
  `--acknowledge-kubeconfig-exec-risk`.
- The `check` commands accept only private input files (owner-only, for
  example mode `0600`) and refuse anything group- or world-accessible. `scan`
  refuses files other users can write; by default it accepts files other users
  can read and prints a note, and `--input-permissions strict` applies the
  owner-only rule to `scan` as well.
- Reports omit raw values, paths, credentials, and configuration content.
- Knowledge can be refreshed explicitly with `prufyx db update` from a signed
  package you choose; nothing updates automatically.

## Support Prufyx

Prufyx is built in the open by an independent maintainer. Every check is tied to a
cited upstream source, and the tool runs locally with no account and no model in
the verdict path. Keeping that knowledge current across hundreds of cloud-native
projects takes real compute.

**What we need now: one build-and-research workstation.**

| Component | Target | What it unlocks |
|---|---|---|
| CPU | 32+ cores | Run the full test suite and knowledge re-verification in parallel instead of in one queue |
| Memory | 128 GB+ | Mirror and re-check upstream sources for many projects at once |
| GPU | 24 GB+ VRAM | Evaluate open-weight models locally for candidate discovery, so no source or user data has to leave the machine |
| Storage | 2 TB NVMe | Pinned upstream source mirrors and reproducible builds |

If you or your company would like to fund or provide hardware, please get in touch
by email at [airstand@gmail.com](mailto:airstand@gmail.com) or on
[LinkedIn](https://www.linkedin.com/in/spasatanasov/). Hardware sponsors are
acknowledged here and on [prufyx.com](https://prufyx.com) with their permission.
We will publish what any support paid for. Sponsorship does not buy influence over
verdicts: every rule still needs cited upstream evidence and review.

## Contributing

The most useful contribution is a reviewed upgrade fact: a public project, an
exact version pair, the setting or API that changed, and the upstream source
that proves it.

- Suggest a project with the
  [project source issue form](https://github.com/prufyx/prufyx/issues/new?template=project-knowledge.yml).
  The repository URL is enough to begin.
- Prepare evidence locally with the
  [project onboarding guide](cli/docs/project-onboarding.md) and the
  [upstream contribution guide](cli/docs/upstream-contributions.md).
- Propose a rule with the [rule contribution guide](cli/docs/contributing-rules.md).

Every contribution is reviewed by a maintainer before it becomes a rule. Never include customer
configuration, cluster snapshots, or credentials. See
[CONTRIBUTING.md](CONTRIBUTING.md) for build and test requirements.
Contributors sign the [Contributor License Agreement](CLA.md) once; the CLA
check guides you on your first pull request.

## License

- **Source code:** [GNU Affero General Public License v3.0 only](LICENSE)
  (`AGPL-3.0-only`).
- **Reviewed knowledge data** (rules, evidence, attestations):
  [CC BY-SA 4.0](DATA-LICENSE.md).
- **Third-party material** keeps its own license; see
  [THIRD-PARTY.md](THIRD-PARTY.md).

Prufyx is maintained by [Spas Atanasov](https://github.com/airstand).
Report security issues privately as described in [SECURITY.md](SECURITY.md).

## Limits

A finding covers only the named rule, version pair, and input it was given. It
does not prove migration completion, runtime compatibility, availability, data
safety, or security. Review the upstream documentation and test the complete
deployment before upgrading.
