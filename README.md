# Prufyx

**Deterministic upgrade checks for Kubernetes and CNCF projects.**

Prufyx checks a planned upgrade against reviewed upstream evidence and returns
`PASS`, `BLOCKED`, or `UNKNOWN`. Every rule was reviewed by a person and cites
the exact upstream commit, file, and line range it relies on. Prufyx runs
locally and offline, uploads nothing, and never uses a model to reach a verdict.
When the evidence does not decide the question, the answer is `UNKNOWN`, not a
guess.

> **Status: early alpha.** Build from source. There is no published release,
> prebuilt binary, or official knowledge feed yet. Results are scoped findings,
> not a guarantee that a whole upgrade is safe.

## Quickstart

Requires Go 1.26.8.

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

| Verdict | Meaning | Exit code |
| --- | --- | --- |
| `PASS` | The input does not match the reviewed source condition for this rule. It is not a whole-upgrade certificate. | `0` |
| `BLOCKED` | The input matches a reviewed condition that the target release enforces, such as a removed API or flag. The output names the remediation. | `10` |
| `UNKNOWN` | The input does not contain enough to decide, or the transition is outside reviewed evidence. | `11` |
| invalid input / integrity failure | The input was rejected, or embedded knowledge failed verification. | `2` / `3` |

A rule applies to the exact reviewed version pair, or to a version range only
where the cited evidence states that range. Outside it, the result is
`UNKNOWN`.

## What is covered

The [generated support inventory](cli/docs/community-support-inventory.md)
is the authoritative list. At the time of writing it contains:

- **190 reviewed CNCF source rules across 53 projects**, including Kubernetes
  API removals and changes for upgrades to 1.22, 1.24–1.27, 1.29 and 1.32.
- **34 reviewed rules across 8 further projects:** Argo Workflows, Ceph,
  Fluent Bit, Grafana, Grafana Loki, Kibana, MariaDB and MariaDB Operator.
- **65 projects with at least one executable check**, plus named checks and
  profiles for cert-manager, Prometheus, SPIFFE X.509-SVID, CloudEvents and
  TiKV.

CNCF projects with rules include Argo CD, Cilium, containerd, Contour, CoreDNS,
Cortex, CRI-O, Crossplane, Envoy, etcd, Falco, Flux, Harbor, Helm, Istio,
Jaeger, Karmada, KEDA, Knative, KubeEdge, KubeVirt, Kyverno, Linkerd, Longhorn,
MetalLB, OPA, OpenTelemetry, Prometheus, Rook, SPIRE, Strimzi, Tekton, Thanos,
Velero and others.

Run `prufyx catalog checks --project PROJECT` (for example `kubernetes`) to
list a project's embedded rules and the exact command and input each one reads. The [community checks reference](cli/docs/community-checks.md)
documents every input contract.

## Privacy and offline operation

- Checks read local files you select. They do not contact a cluster, registry,
  or upstream project, and they do not execute supplied content.
- Inputs must be private files (mode `0600`); world-readable inputs are
  refused.
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

Every contribution is reviewed before it becomes a rule. Never include customer
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
