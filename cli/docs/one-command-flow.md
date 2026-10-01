# One-command flow (`prufyx assess`)

Each of the 194 registered native check routes requires hand-authored
caller JSON and per-project flags. Getting one answer takes an hour of manual input preparation. This
command is the fast path layered on top of those routes; it does not replace
them, and it does not change `checkroutemetadata/catalog.go` or
`communityapp/cncf.go`.

## What it does

```
prufyx assess --kubeconfig FILE --acknowledge-kubeconfig-exec-risk [OPTIONS] CONTEXT...
```

1. Collects a current bundle from the declared kubeconfig context(s) using
   the existing `prufyx-collector` machinery
   (`cli/internal/localcollector`), unmodified. Read-only, offline beyond
   the Kubernetes API the collector already talks to, no credentials beyond
   the kubeconfig the operator points at, `--acknowledge-kubeconfig-exec-risk`
   required exactly as it already is for `prufyx-collector collect`.
2. Projects that bundle through the existing, unmodified
   `internal/currentbundle` boundary into the canonical `CurrentBundle`
   schema.
3. Loads the full 194-route catalog via
   `checkroutemetadata.Discover("", "", "")`, filtered to entries whose
   `NativeDescriptor.State == DescriptorExact` (the routes with a working
   native command, not just a generic declaration route).
4. Classifies every one of those 194 routes against the bundle and emits one
   combined report (`internal/onecommand.Report`), in human or JSON form.

It authors zero new compatibility claims. The classification never decides
whether a transition is safe; it only decides whether a check *could* be
attempted from what was collected, and if not, exactly why.

## The three-way (in practice four-way) applicability split

For each of the 194 native routes, against each collected kubeconfig
context, exactly one outcome is assigned:

| Outcome | Meaning |
|---|---|
| `APPLICABLE_FULLY_SATISFIED` | The observed component version matches the check's declared origin, and the route needs no caller declaration beyond the version pair. **Always empty today** — see below. |
| `APPLICABLE_NEEDS_DECLARATION` | The observed component version matches the check's declared origin, but the route needs operator declarations the collector cannot supply. The report names exactly which flags are missing and why each one can't be inferred. |
| `NOT_APPLICABLE_VERSION_MISMATCH` | The component was observed, but at a version that doesn't match this check's declared origin. |
| `NOT_APPLICABLE_COMPONENT_ABSENT` | The component was not observed running in this cluster context at all. |
| `INDETERMINATE_NOT_OBSERVABLE` | The check's project is not one of the handful of components the collector's already-reviewed component-configuration adapter registry can identify from container images. Presence, absence, and version are all unknown from collected state. This is *not* folded into "not applicable" — asserting non-applicability would be a claim collected state cannot support. |
| `INDETERMINATE_PARTIAL_COLLECTION` | An absence conclusion (component or Kubernetes version) was about to be drawn, but this context's collection was partial (a declared API read failed). Absence is not confirmed, so the check is reported as indeterminate rather than not-applicable. A *positive* observation elsewhere in the same partial context is not weakened by this: an unrelated failed read (e.g. `storageclasses`) does not cast doubt on a component that genuinely was found. |

The natural split is three buckets — (a) fully satisfiable, (b) applicable
but needs declarations, (c) doesn't apply. The two indeterminate outcomes
are a deliberate refinement of (c): "this check does not apply" and "we
cannot tell whether this check applies" are different claims, and collapsing
them would assert something collected state does not support. Never invent
a declaration to make a check run; never treat a missing declaration as a
default; never emit a negative-presence PASS. A confirmed absence
(`NOT_APPLICABLE_COMPONENT_ABSENT`) and an unconfirmed one
(`INDETERMINATE_*`) must not look the same in the output.

## How applicability is determined

**Component identity.** The catalog's native routes are keyed by a
`pkg:github/...`-style project identity (e.g. `pkg:github/cilium/cilium`);
the collector's component-configuration adapter registry
(`cli/internal/localcollector/assets/component-configuration-adapters*.json`)
identifies exactly five components from container images by a
`pkg:oci/...` identity: `prometheus/prometheus`, `cilium/cilium`,
`argoproj/argo-cd`, `argoproj/argo-workflows`, and `cert-manager/cert-manager`
(cert-manager has no native routes in the current catalog, so it never
appears in classification). `internal/onecommand.observableComponents` is a
four-entry, hardcoded table correlating the catalog's project slug
(`prometheus`, `cilium`, `argo-cd`, `argo-workflows`) with the matching
`pkg:oci/...` id. This is not a new compatibility claim — it only says two
already-reviewed sources are naming the same upstream project — and it is
the *entire* observation surface this command has. Kubernetes itself is a
fifth, special-cased "component": its version is read from the collector's
always-attempted `/version` query, independent of the adapter registry.

Every other catalog project (grafana, kibana, loki, mariadb, ceph, thanos,
flux, coredns, nats, cortex, opentelemetry, containerd, kubevirt, metallb,
contour, cloudnativepg, linkerd, karmada, kubeedge, tekton, cri-o, cubefs,
tuf, in-toto, knative, kubeflow, buildpacks, emissary-ingress, openfga,
distribution, cni-spec, envoy, strimzi, falco, kuma, crossplane, velero,
keda, spire, etcd, kyverno, jaeger, harbor, fluentd, opencost,
cloud-custodian, mariadb-operator, fluent-bit — 48 projects) has no identity
in the collector's adapter registry at all. Every one of their checks is
`INDETERMINATE_NOT_OBSERVABLE`.

**Version match.** For an observable project, if the component was found,
its observed version (an exact semver tag, from the image tag the collector
already parsed) is compared to the check's declared origin (`From`). Equal
→ candidate for (b)/(a) below. Not equal → confirmed not applicable. Not
found at all → confirmed absent, unless this context's collection was
partial, in which case it is indeterminate instead.

**Declaration gap.** For a version-matched check, its native command
template (`checkroutemetadata.Check.NativeDescriptor.Command`) is walked
argument by argument. `literal` and `timestamp_placeholder` (`--now`, which
this command already supplies) need nothing further. `file_placeholder`,
`name_placeholder`, and `boolean_operator_declaration` are reported as
missing declarations, each with its exact flag name and a one-line
explanation of what kind of thing it is and why it isn't observable.

## The honest finding: 0 of 194 are fully satisfiable today

Every single one of the 194 native descriptors requires at least one
`file_placeholder` argument beyond the version pair — a caller-supplied
resource, configuration, or argv declaration
(`--alertmanager-config`, `--native-resource`, `--kafka-resource`,
`--repository-secret`, `--cilium-policy`, ...). None of these match what the
collector gathers: the collector deliberately minimizes what it retains
(image identity, version, and a handful of narrow boolean/enum predicates
for five components — never full resource bodies), and most of the
requested content is not a *fact about the cluster* at all but a caller
*intent* declaration (e.g. opencost's target cloud-cost source selection,
Falco's "official distribution" flag, "this config is complete"). This was
verified mechanically, not assumed: `TestNoNativeRouteIsFullySatisfiedByVersionAlone`
in `cli/internal/onecommand/onecommand_test.go` asserts every native
descriptor has at least one missing declaration, and fails the build the day
that stops being true.

Because of this, `APPLICABLE_FULLY_SATISFIED` is a real, tested, but
currently *empty* bucket, and this command does not attempt to run any
check automatically. The `CheckAssessment.Result` field in the report
schema is reserved for the day a zero-declaration route exists, so a future
change can populate it without a schema break — but no execution is wired
today, and none should be added speculatively for a bucket with zero live
members.

## What this command refuses to auto-fill

- A `file_placeholder` value (an Alertmanager config, a Kyverno resource, an
  effective config, an argv, a repository secret, ...): the collector does
  not collect most of these at all, and where it collects something
  adjacent (the five components' narrow predicate surface) that is a
  different, already-reviewed schema, not the check's expected input.
- A `name_placeholder` (container name, distribution name, OSD id, ...):
  disambiguation the operator must supply.
- A `boolean_operator_declaration` (an intent flag like
  "I require HTTP/2", "this config is complete", "official upstream
  distribution"): these are never inferred and an absent declaration is
  never treated as `false`.
- The target version of an upgrade the operator has not stated: this
  command classifies against the *observed* component version as the
  declared origin; it never guesses what the operator intends to upgrade
  to beyond the fixed target each descriptor already specifies.
- A component scope. Without `--scope-input` the report's `aggregate` field
  is `{"assessment":"UNKNOWN","reasonCode":"SCOPE_DECLARATION_NOT_SUPPLIED"}`
  — a stated limitation, not a fabricated verdict.
  `APPLICABLE_NEEDS_DECLARATION` or `APPLICABLE_FULLY_SATISFIED` on an
  individual check is never itself a PASS for anything, and this command
  never synthesises a scope declaration from what it collected.

## The scope-completeness aggregate

With `--scope-input FILE`, where FILE is an operator-declared constraint
input (`prufyx.io/operator-declared-constraint-input/v1alpha1`) carrying a
`scope` declaration, the `aggregate` field becomes the constraint engine's
own recomputed scope-completeness verdict, and `scopeAssessment` carries the
enumerated evidence behind it.

What makes that honest:

- The engine evaluates the **whole** embedded community rule corpus, not a
  selected rule. `projectcheck.ruleSetSelected` — the path `check project`
  uses — narrows the pack to one project and one exact from/to pair *before*
  parsing, which structurally cannot support a completeness statement. The
  scope path assembles every entry in the pack instead and lets the engine
  decide applicability from declared versions and declared fact values.
- The corpus carries the maintainer's completeness attestation, emitted by
  `prufyx-maintainer corpus-attestation generate` over the unfiltered pack
  and bound to it by the engine's own `RuleSetDigest`. An attestation naming
  a component the pack holds no reviewed rule for is rejected at parse time,
  so "complete" cannot be satisfied by attesting an empty set.
- Applicability is computed independently of evidence freshness. One expired
  rule does not destroy completeness verdicts for unrelated components.
- Your scope declaration is validated, not trusted: it must match your own
  declared bundle exactly and name only components the corpus has a compiled
  identity for. It is **not** cross-checked against observed cluster state,
  and the report says so.
- The strongest reachable verdict is `SCOPE_COMPLETE_PASS`. It is never
  `SAFE`. It states only that every reviewed constraint applicable to the
  declared components was evaluated and passed, and it enumerates, per
  component, every rule that was not evaluated and why. Absence of evidence
  is `UNKNOWN`.

## Why one collection run per context

`internal/observation.Import` (a reviewed, unmodified boundary) refuses to
import an observation root whose `index.json` declares more than one
context. `prufyx-collector` can be given several contexts in one invocation,
but `assess` calls the collector once per declared context, each into its
own private temporary directory, so each resulting root satisfies that
existing constraint. This is a consequence of an existing boundary, not a
design choice made here.

## Time to first answer

Against a reachable cluster with a valid, already-trusted kubeconfig:
`prufyx assess --kubeconfig ~/.kube/config --acknowledge-kubeconfig-exec-risk my-context`
completes in one command and one confirmation flag, versus hand-authoring
per-project JSON and flags for each of 194 routes beforehand. The answer it
gives is a triage list, not a verdict — but going from "194 routes, unknown
which apply" to "here are the N that apply to what you actually have
running, and exactly what each one still needs from you" is the whole
value: it turns an hour of guessing which of 194 routes are even worth
hand-authoring input for into a single command's output.
