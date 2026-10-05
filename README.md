# Prufyx

**Deterministic upgrade checks for Kubernetes and CNCF projects.**

Prufyx checks a planned upgrade against upstream evidence and returns
`PASS`, `BLOCKED`, or `UNKNOWN`. Every rule cites the exact upstream commit,
file, and line range it relies on, and says how it was established. Every rule
in the knowledge shipped today was reviewed by a person. Prufyx is built to
accept other ways of establishing a rule as well, for example deriving it
mechanically from upstream source with a program that is re-run and checked
before the rule is accepted; each rule states which way it was established, and
you can limit a `scan` to the ways you trust. Prufyx runs locally and offline,
uploads nothing, and a model never decides a verdict on your machine. When the
evidence does not decide the question, the answer is `UNKNOWN`, not a guess.

> **Status: early alpha.** Build from source. There is no published release,
> prebuilt binary, or official knowledge feed yet. Results are scoped findings,
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
CI.

## What the verdicts mean

The table is for `check`, where `PASS` is scoped to one rule. `scan` exit `0`
means a complete scope. See [exit codes](cli/docs/exit-codes.md) for the single
table of both, and for `check --strict-exit`, which makes a scoped `PASS` exit
`14` so CI cannot read it as a complete pass.

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
is the authoritative list. The numbers below were counted on 2026-10-04 from
the knowledge built into this source tree (revision `cncf-2026-09-13.4`) and
will drift as the knowledge changes. To recount the Kubernetes and CNCF rules:

```sh
jq '[.entries[] | select(.rule.evidence.state == "active")] | {rules: length, projects: (map(.project) | unique | length)}' \
  cli/internal/cncfcheck/data/rules.json
```

At that date it contains:

- **190 active CNCF source rules across 53 projects** (one further rule is
  withdrawn and not used), including Kubernetes
  API removals and changes for upgrades to 1.22, 1.24–1.27, 1.29 and 1.32.
- **34 rules across 8 further projects:** Argo Workflows, Ceph,
  Fluent Bit, Grafana, Grafana Loki, Kibana, MariaDB and MariaDB Operator.
- **65 projects with at least one executable check**, plus named checks and
  profiles for cert-manager, Prometheus, SPIFFE X.509-SVID, CloudEvents and
  TiKV.

CNCF projects with rules include Argo CD, Cilium, containerd, Contour, CoreDNS,
Cortex, CRI-O, Crossplane, Envoy, etcd, Falco, Flux, Harbor, Helm, Istio,
Jaeger, Karmada, KEDA, Knative, KubeEdge, KubeVirt, Kyverno, Linkerd, Longhorn,
MetalLB, OPA, OpenTelemetry, Prometheus, Rook, SPIRE, Strimzi, Tekton, Thanos,
Velero and others.

Every rule is time-limited. The rules shipped today stop being valid between
2026-12-07 and 2026-12-22 unless their review is renewed; after that date a
build without newer knowledge answers `UNKNOWN` for them.

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

## Privacy and offline operation

- Checks read local files you select. They do not contact a cluster, registry,
  or upstream project, and they do not execute supplied content.
- The `check` commands accept only private input files (owner-only, for
  example mode `0600`) and refuse anything group- or world-accessible. `scan`
  refuses files other users can write; by default it accepts files other users
  can read and prints a note, and `--input-permissions strict` applies the
  owner-only rule to `scan` as well.
- Reports omit raw values, paths, credentials, and configuration content.
- Knowledge can be refreshed explicitly with `prufyx db update` from a signed
  package you choose; nothing updates automatically.

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
