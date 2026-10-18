# Declarations

A declaration is a fact about your upgrade that Prufyx cannot read from your
files and will not guess. You assert it with a flag (or in
[`prufyx.yaml`](scan-config.md)). Prufyx never defaults a declaration to
`true`: a declaration you leave out stays unset, and the rules that need it
answer `UNKNOWN`, never `PASS`. See [verdicts.md](verdicts.md).

**Only declare what is true.** A declaration is your statement, and the verdict
is only as good as it is. A false `--resource-scope-complete` can turn "the
removed API is not in the file you showed me" into a pass that is wrong for the
part of the cluster you did not show.

## The three declarations of a Kubernetes scan

These are the ones the first `scan` or `check cncf --project kubernetes` asks
for. Without them the answer is `UNKNOWN`; the report lists the missing ones
(`scan`: under `NOT CHECKED`, with the flag to add; `check`: the `next action:`
of each undecided rule).

| Flag | In `prufyx.yaml` (`declarations.kubernetes.`) | True when | Leave it out when |
| --- | --- | --- | --- |
| `--resource-scope-complete` | `resourceScopeComplete: true` | The files you pass are every manifest you apply, not an excerpt: the whole `helm template` or `kustomize build` output, and no other chart, overlay, operator-created object or hand-applied file adds to it. | You pass one chart of several, a sample, or part of an apply set. |
| `--target-api-apply-required` | `targetApplyRequired: true` | These manifests are what you send to the Kubernetes API of the target version. | The files are a reference copy, or are applied to another cluster. |
| `--distribution official_upstream` | `distribution: official_upstream` | The cluster runs an upstream Kubernetes build. | It runs a vendor or modified build: declare `custom_build`. |

Why Prufyx cannot infer them:

- **Scope.** A `PASS` from "the removed kind is absent from what I was shown" is
  worthless if what you were shown was half the picture. `scan` and `check` read
  local files and never talk to a cluster or a Git repository, so only you know.
- **Target apply.** A file that exists is not a file that is applied. The
  declaration ties the finding to "this is really sent to the target API".
- **Distribution.** Only `official_upstream` is evaluated. With `custom_build`
  Prufyx reports that the distribution is not evaluated and leaves the result
  `UNKNOWN`; check your distribution's release notes by hand.

What the declarations do not do: they do not widen what Prufyx checks. Even with
all three, `scan` reads only the API versions in your manifests; live objects,
CRDs, stored versions, admission and component configuration stay outside, and
the whole upgrade stays `UNKNOWN`.

### Flags

```sh
prufyx scan rendered.yaml \
  --from kubernetes=1.24.0 --to kubernetes=1.25.0 \
  --distribution official_upstream \
  --resource-scope-complete \
  --target-api-apply-required
```

`prufyx check cncf --project kubernetes --native-resource FILE ...` takes the
same three flags.

### In `prufyx.yaml`

```yaml
apiVersion: prufyx.io/v1alpha1
kind: ScanConfig
inputs: [rendered.yaml]
current: {kubernetes: 1.24.0}
target:  {kubernetes: 1.25.0}
declarations:
  kubernetes:
    distribution: official_upstream
    resourceScopeComplete: true
    targetApplyRequired: true
```

Then run `prufyx scan` in that directory. A flag overrides the same key in the
file. The file format is in [scan-config.md](scan-config.md).

## Helm values

`--helm-values-complete` (`declarations.helm.<project>.complete`) declares that
the values files and `--helm-set` assignments you pass are every values source
of the release. True when no other values file or `--set` is used at install time. Without it, no required values key is
confirmed. See "Helm chart values" in [scan.md](scan.md).

## Other routes

Each `prufyx check cncf --project NAME` route reads one project input and has
its own declaration flags, named after what they assert. The common ones:

| Flag pattern | Asserts |
| --- | --- |
| `--effective-config-complete`, `--scrape-config-complete`, `--alertmanager-config-complete`, `--containerd-config-complete`, `--cilium-config-complete`, `--otel-config-complete`, and similar | The file you pass is the complete configuration of that component, not a fragment. Some routes also ask for the resolved result (for example OpenFGA: file, environment and flag precedence resolved); the route's help says which. |
| `--custom-resources-complete`, `--resource-complete` | The resources you pass for that route are the complete selected set (for example `--custom-resources-complete`: the manifests you apply). `--workload-complete` declares that the selected workload's command line is complete. |
| `--<project>-distribution` (for example `--strimzi-distribution official_upstream`) | The project build is the declared distribution (`official_upstream` is the one the reviewed rules cover). |
| `--target-kafka-crd-admission-required`, `--crossplane-schema-validation-required`, `--keda-legacy-tls-transport-required` and similar `*-required` flags | A named condition holds in your target environment (some take `true` or `false`; `false` is a declaration too). |

The table is a guide, not a contract: the exact meaning is per route. Do not guess. For one project, list the exact command and
every flag a route needs:

```sh
prufyx catalog checks --project strimzi
```

and see [community-checks.md](community-checks.md) for what each flag asserts.
The same rule applies to all of them: declare it only if it is true.
