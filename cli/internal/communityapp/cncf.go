// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

func (r runtime) cncfCatalog(args []string) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, "Usage: prufyx catalog cncf [--priority] [--project SLUG] [--format human|json]\nCatalogue identity, generic source-rule coverage and runtime reproduction are separate. This command reads embedded public metadata only.")
		return ExitOK
	}
	fs := flag.NewFlagSet("catalog cncf", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	priority := fs.Bool("priority", false, "show the initial maintainer-selected portfolio")
	project := fs.String("project", "", "inspect a specific project and its rules")
	format := fs.String("format", "human", "human or json")
	if duplicateFlags(args) || fs.Parse(args) != nil || fs.NArg() != 0 || (*format != "human" && *format != "json") {
		return r.usage("invalid CNCF catalogue arguments; use --help")
	}
	catalogue, err := cncfcheck.Catalog(*priority, *project)
	if err != nil {
		return r.cncfError("CNCF catalogue could not be loaded", err)
	}
	if *format == "json" {
		if json.NewEncoder(r.stdout).Encode(catalogue) != nil {
			return ExitIntegrity
		}
		return ExitOK
	}
	fmt.Fprintf(r.stdout, "CNCF catalogue: %d projects; initial priority: %d\ngeneric source-rule preview: %d projects; runtime transitions reproduced: %d\nlandscape revision: %s\npriority is maintainer selection, not an adoption ranking\n", catalogue.Catalogued, catalogue.PriorityProjects, catalogue.SourceRuleCovered, catalogue.RuntimeReproduced, catalogue.LandscapeRevision)
	for _, item := range catalogue.Projects {
		fmt.Fprintf(r.stdout, "%s: %s (%s); %d generic source rules\n", item.Slug, item.Name, item.CNCFStage, item.SourceRuleCount)
		for _, route := range item.ExistingChecks {
			fmt.Fprintf(r.stdout, "  existing named check: %s\n", route)
		}
		if *project != "" {
			for _, entry := range item.Checks {
				fmt.Fprintf(r.stdout, "  %s\n", entry.Description)
				for _, fact := range entry.RequiredFacts {
					fmt.Fprintf(r.stdout, "    %s: %s\n", fact.ID, fact.Description)
				}
			}
		}
	}
	return ExitOK
}

func (r runtime) cncf(args []string) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, `Usage: prufyx check cncf --project SLUG --input FILE (--now RFC3339 | --knowledge-db DIR) [--input-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project argo-cd --config-map FILE --from 2.14.0 --to 3.0.0 [--requires-inherited-application-permissions true|false] --now RFC3339 [--config-map-digest SHA256] [--format human|json]
   or: prufyx check cncf --project argo-cd --resource-exclusions-config-map FILE --from 2.14.0 --to 3.0.0 --resource-exclusions-config-complete --resource-exclusions-precedence-resolved [--requires-v2-visibility-of-v3-default-excluded-resources true] --now RFC3339 [--resource-exclusions-config-map-digest SHA256] [--format human|json]
   or: prufyx check cncf --project knative --service FILE --from VERSION --to VERSION (--now RFC3339 | --knowledge-db DIR) [--service-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project in-toto --in-toto-run-argv FILE --from 2.2.0 --to 3.0.0 (--now RFC3339 | --knowledge-db DIR) [--in-toto-run-argv-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project the-update-framework-tuf --python-source FILE --from 6.0.0 --to 7.0.0 (--now RFC3339 | --knowledge-db DIR) [--python-source-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project kubeflow --python-source FILE --from 1.8.22 --to 2.0.0 (--now RFC3339 | --knowledge-db DIR) [--python-source-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project cubefs --metanode-config FILE --from 3.2.1 --to 3.3.2 [--phase metanode-upgrade] (--now RFC3339 | --knowledge-db DIR) [--metanode-config-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project cri-o --image-status-request FILE --artifact-operation named-reference-resolution --from 1.34.0 --to 1.35.0 (--now RFC3339 | --knowledge-db DIR) [--image-status-request-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project distribution --image-manifest FILE --from 2.8.3 --to 3.0.0 (--now RFC3339 | --knowledge-db DIR) [--image-manifest-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project container-network-interface-cni --cni-configuration FILE --from 0.4.0 --to 1.0.0 [--operation configuration-spec-migration] (--now RFC3339 | --knowledge-db DIR) [--cni-configuration-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project containerd --containerd-config FILE --runtime-handler NAME --from 1.7.28 --to 2.0.0 --containerd-config-complete --containerd-config-precedence-resolved --containerd-official-upstream --containerd-official-bundled-runtimes-only (--now RFC3339 | --knowledge-db DIR) [--containerd-config-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project emissary-ingress --diagd-argv FILE --from 3.10.0 --to 4.0.1 (--now RFC3339 | --knowledge-db DIR) [--diagd-argv-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project openfga --effective-config FILE --from 1.17.1 --to 1.18.0 [--effective-config-complete] (--now RFC3339 | --knowledge-db DIR) [--effective-config-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project buildpacks --current-lifecycle-config FILE --proposed-lifecycle-config FILE --from 0.16.5 --to 0.17.7 --current-platform-api 0.11 --proposed-platform-api 0.12|0.13 (--now RFC3339 | --knowledge-db DIR) [--current-lifecycle-config-digest SHA256] [--proposed-lifecycle-config-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project metallb|contour|kubevirt|thanos|cortex --native-resource FILE --from VERSION --to VERSION (--now RFC3339 | --knowledge-db DIR) [--native-resource-digest SHA256] [--replay-report FILE] [--format human|json]
	 or: prufyx check cncf --project flux --native-resource FILE --from VERSION --to VERSION [--resource-scope-complete] (--now RFC3339 | --knowledge-db DIR) [--native-resource-digest SHA256] [--replay-report FILE] [--format human|json]
	 or: prufyx check cncf --project kubernetes --native-resource FILE --from 1.31.0 --to 1.32.0 --distribution official_upstream|custom_build --target-api-apply-required --resource-scope-complete (--now RFC3339 | --knowledge-db DIR) [--native-resource-digest SHA256] [--replay-report FILE] [--format human|json]
	 or: prufyx check cncf --project kubernetes --component-config FILE --from VERSION --to VERSION --distribution official_upstream|custom_build --now RFC3339 [--component-config-digest SHA256] [--format human|json]
	 or: prufyx check cncf --project cilium --cilium-config-map FILE --from 1.16.19 --to 1.17.18 --cilium-distribution official_upstream|custom_build --cilium-config-complete --cilium-config-precedence-resolved (--now RFC3339 | --knowledge-db DIR) [--cilium-config-map-digest SHA256] [--replay-report FILE] [--format human|json]
	 or: prufyx check cncf --project coredns --coredns-corefile FILE --from 1.6.9 --to 1.7.0 or 1.9.4|1.10.1|1.11.4|1.12.4|1.13.2 --to 1.14.7 --coredns-distribution official --coredns-corefile-complete (--now RFC3339 | --knowledge-db DIR) [--coredns-corefile-digest SHA256] [--replay-report FILE] [--format human|json]
	 or: prufyx check cncf --project envoy --envoy-bootstrap FILE --envoy-bootstrap-selected --from 1.34.14|1.35.13|1.36.10|1.37.6|1.38.4 --to 1.39.1 (--now RFC3339 | --knowledge-db DIR) [--envoy-bootstrap-digest SHA256] [--replay-report FILE] [--format human|json]
	 or: prufyx check cncf --project nats --nats-config FILE --from VERSION --to VERSION (--now RFC3339 | --knowledge-db DIR) [--nats-config-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project falco --falco-argv FILE --falco-distribution official_upstream|custom_build --from 0.40.0 --to 0.41.0|0.42.0 (--now RFC3339 | --knowledge-db DIR) [--falco-argv-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project kuma --kumactl-argv FILE --kuma-distribution official_upstream|custom_build --from 2.8.0 --to 2.9.0 (--now RFC3339 | --knowledge-db DIR) [--kumactl-argv-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project crossplane --composition FILE --crossplane-distribution official_upstream|custom_build --crossplane-schema-validation-required --from 1.20.0 --to 2.0.0 (--now RFC3339 | --knowledge-db DIR) [--composition-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project velero --upgrade-plan FILE --velero-server-deployment NAME --velero-plan-order-declared --from 1.17.0|1.16.2 --to 1.18.0 (--now RFC3339 | --knowledge-db DIR) [--upgrade-plan-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project keda --keda-scaled-object FILE --keda-scaled-object-complete --from 2.16.0 --to 2.17.0 [--keda-legacy-tls-transport-required true|false] (--now RFC3339 | --knowledge-db DIR) [--keda-scaled-object-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project spire --spire-entry-argv FILE --spire-distribution official_upstream|custom_build --from 1.10.4 --to 1.11.0 (--now RFC3339 | --knowledge-db DIR) [--spire-entry-argv-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project opentelemetry --otel-collector-config FILE --otel-distribution official|custom --otel-config-complete --otel-config-precedence-resolved --from 0.110.0 --to 0.111.0 (--now RFC3339 | --knowledge-db DIR) [--otel-collector-config-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project opentelemetry --otel-rule internal-telemetry-default-bind --otel-collector-config FILE --otel-distribution official --otel-config-complete --otel-config-precedence-resolved --otel-metrics-localhost-default true|false --otel-metrics-remote-scrape-required true|false --from 0.110.0 --to 0.111.0 (--now RFC3339 | --knowledge-db DIR) [--otel-collector-config-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project prometheus --scrape-config FILE --scrape-job NAME --from 2.55.1 --to 3.1.0 --scrape-config-complete --scrape-config-precedence-resolved (--now RFC3339 | --knowledge-db DIR) [--scrape-config-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project prometheus --alertmanager-config FILE --from 2.55.1 --to 3.1.0 --alertmanager-config-complete --alertmanager-config-precedence-resolved (--now RFC3339 | --knowledge-db DIR) [--alertmanager-config-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project prometheus --prometheus-config FILE --prometheus-config-complete --prometheus-config-precedence-resolved --prometheus-rule remote-write-http2-default --prometheus-remote-write-name NAME --prometheus-remote-write-http2-required=true|false --from 2.55.1 --to 3.14.0 (--now RFC3339 | --knowledge-db DIR) [--prometheus-config-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project strimzi --kafka-resource FILE --strimzi-distribution official_upstream|custom_build --target-kafka-crd-admission-required --from 0.51.0 --to 1.0.0 (--now RFC3339 | --knowledge-db DIR) [--kafka-resource-digest SHA256] [--replay-report FILE] [--format human|json]
   or: prufyx check cncf --project argo-cd|istio|strimzi --custom-resources FILE --from VERSION --to VERSION --now RFC3339 [--custom-resources-complete] [--custom-resources-digest SHA256] [--format human|json]
   or: prufyx check cncf --project tekton --tekton-config-observability FILE --tekton-distribution official_upstream|custom_build --tekton-system-namespace NAME --tekton-config-observability-complete true|false --retain-prometheus-metrics-required true|false --from 1.9.0 --to 1.10.0 --now RFC3339 [--tekton-config-observability-digest SHA256] [--format human|json]
   or: prufyx check cncf --project kubeedge --keadm-init-argv FILE --kubeedge-distribution official_upstream|custom_build --keadm-argv-complete true|false --from 1.18.0 --to 1.19.0 --now RFC3339 [--keadm-init-argv-digest SHA256] [--format human|json]
   or: prufyx check cncf --project cloudnativepg --current-resource FILE --resource FILE --from 1.29.0 --to 1.30.0 (--now RFC3339 | --knowledge-db DIR) [--current-resource-digest SHA256] [--resource-digest SHA256] [--replay-report FILE] [--format human|json]

Optional, local source-constraint preview using minimized operator declarations.
Inspect inputs with: prufyx catalog cncf --project SLUG --format json
Input and replay files must be regular private files (mode 0600 or stricter, with no group or other access), without symlinks.
Embedded rules use explicit canonical UTC with whole-second precision. Replay
compares the exact prior JSON at its original time, without current freshness.
Without --knowledge-db and --now, the check uses the verified knowledge database
that prufyx db update installed in the default store location
($XDG_DATA_HOME/prufyx/knowledge/cncf-projects, else ~/.local/share/...), and
the embedded knowledge when none is installed. A default store that is present
but invalid or expired is refused, never replaced silently; --knowledge=embedded
forces the embedded knowledge at the current time. --now keeps selecting the
embedded knowledge for replay. The source is shown on standard error and in the
human output.
Select a separate local signed CNCF store with --knowledge-db DIR. Current
external checks use the verifier's actual clock; omit --now. External replay
with --input FILE requires --replay-report FILE, --input-digest SHA256,
--knowledge-revision REV,
--knowledge-bundle-digest SHA256 and --knowledge-trust-receipt-digest SHA256;
its original time comes from the exact report. There is no embedded fallback.
No cluster, network, model, or database download is used by this command.
The Argo CD ConfigMap mode prepares and checks the local file in memory. The resource-exclusions mode admits one complete, precedence-resolved argocd-cm YAML and only exact target default, absent, or explicit empty values; it never infers v2 visibility intent, resource existence, watches, UI, reconciliation, or runtime behavior.
It
does not write canonical input, infer RBAC intent, or edit the ConfigMap.
The CoreDNS Corefile mode reads a caller-selected complete local Corefile and
recognizes only a literal federation directive at a direct server-block
position. The official distribution and completeness declarations remain
caller authority. Balanced brace-delimited plugin bodies are structurally
admitted up to 32 levels but their properties are ignored. Imports, snippets,
substitutions, quotes, escapes, malformed structure, plugin validity, included
files, DNS behavior, and runtime state remain UNKNOWN.
The Envoy bootstrap mode reads a caller-selected local JSON bootstrap and can
derive only a literal V2 xDS transport blocker at three direct DynamicResources
paths. It never derives a V3/PASS result from an absent, AUTO, or V3 field, and
does not parse YAML, other ConfigSource paths, Any/typed_config, fetched xDS,
or runtime state.
The Knative Serving Service mode derives only the target named HTTP startup-
probe port-match fact. Embedded knowledge reviews only 1.22.0 -> 1.23.0.
An explicit external store is authoritative and never falls back to embedded
rules. Unsupported shapes and version pairs without a selected rule stay
UNKNOWN; this does not edit the Service or validate other admission, startup,
traffic, or runtime behavior. External replay requires --service-digest and
all three knowledge pins. Its report binds minimized prepared input, so retain
the raw Service and its digest separately when raw-byte identity matters.
The Buildpacks mode reads two private Lifecycle config-shaped JSON files and compares
explicit CNB_PLATFORM_API selections with their declared lifecycle support.
Those labels and optional raw digests authenticate only supplied bytes, not
registry provenance. Embedded knowledge covers Lifecycle 0.16.5 -> 0.17.7;
external knowledge is authoritative with no embedded fallback. Historical
replay requires both raw config digests and all three knowledge pins.
The in-toto mode reads one private JSON argv array and inspects only a fixed
in-toto-run prefix before the first valid -- delimiter. Everything after it is
opaque. Embedded knowledge covers Python CLI 2.2.0 -> 3.0.0. A PASS clears
only removal of -k/--key; it does not load or convert keys or run the command.
Historical replay requires the raw argv digest and all three knowledge pins.
The Prometheus mode reads one caller-selected native scrape_config YAML mapping.
It retains only whether the reviewed old or new key is present; job names,
targets and unrelated settings are discarded. Completeness and precedence are
caller declarations. PASS covers only the selected key rename, not parsing the
whole prometheus.yml, startup, scraping, or native-histogram behavior.
The Prometheus Alertmanager mode reads one caller-selected native
alerting.alertmanagers entry. It retains only the API-version selection class;
addresses, credentials, paths and unrelated settings are discarded. An omitted
api_version can PASS only as the exact target source-derived v2 default with
both caller declarations. PASS does not establish that Alertmanager supports
v2, is reachable, or can receive alerts; validate compatibility and the complete
target Prometheus configuration separately.
The Prometheus remote-write HTTP/2 mode reads one full caller-supplied
prometheus.yml and selects exactly one remote_write mapping by literal name.
It classifies only the direct inline enable_http2 key or its exact source-
derived default and compares that with an explicit endpoint requirement.
Nested http_config lookalikes, aliases, merges, substitutions, ambiguous names,
unresolved completeness or precedence, and other version pairs stay UNKNOWN.
PASS does not prove HTTP/2 negotiation, endpoint support, delivery, startup,
runtime flag precedence, included configuration, or whole-config validity.
The TUF mode uses a Go lexical parser that admits one unaliased direct import
and one top-level direct Updater call. It reads private Python source as data
and never imports or executes it. Source outside that narrow grammar remains
UNKNOWN. Embedded knowledge covers Updater 6.0.0 -> 7.0.0 and checks only
explicit bootstrap keyword presence in one admitted direct call. Historical
replay requires the raw source digest and all three knowledge pins.
The Kubeflow mode uses a Go lexical parser to recognize only one
unaliased bare create_component_from_func or dsl.component decorator. It never
imports or executes supplied Python source and does not require an interpreter.
Embedded knowledge covers KFP Python SDK 1.8.22 -> 2.0.0 and checks only the
removed authoring API. PASS does not validate component inputs, outputs,
dependencies, compilation, backend, installed package, or runtime behavior.
Historical replay requires the raw source digest and all three knowledge pins.
The CubeFS mode reads one caller-supplied planned MetaNode JSON config and a
caller-declared phase. It checks only the raftSyncSnapFormatVersion guard for
the exact 3.2.1 -> 3.3.2 metanode-upgrade phase. Missing or unsupported phase,
role, setting types, values, and version pairs stay UNKNOWN. PASS does not
verify peer versions, rollout completion, restarts, client ordering, mounts,
runtime behavior, or data safety. Historical replay requires the raw config
digest and all three knowledge pins.
The CRI-O mode reads one caller-supplied native CRI ImageStatusRequest JSON file
and a caller-declared ArtifactStore named-reference-resolution operation. It
classifies only a strict explicit-tag short or fully-qualified image.image for
exact CRI-O 1.34.0 -> 1.35.0. PASS clears only the target short-name guard;
registry aliases, store contents, request routing, access and runtime remain
UNKNOWN. Historical replay requires the raw request digest and all three
knowledge pins.
The Distribution mode reads one private image manifest and classifies only its
bounded schema1, Docker schema2, or OCI image-manifest form for the exact
2.8.3 -> 3.0.0 source plan. It never contacts a registry or validates content,
storage, pull, platform, or runtime behavior. The CNI mode reads one private
configuration for specification 0.4.0 -> 1.0.0 and keeps library/plugin/runtime
identity separate. It requires caller-declared configuration-spec-migration
intent for a scoped result; missing or unsupported intent stays UNKNOWN.
The custom-resource mode reads one private file of rendered manifests and
records the group/version/Kind of every object in the API groups that the
project's own CustomResourceDefinitions define (a reviewed, compiled table);
objects of other projects' groups are ignored. It evaluates only published
rules about custom-resource versions the target release no longer serves. A
listed version blocks (exit 10). A rule passes only with
--custom-resources-complete and when every object of a non-Kubernetes API
group in the file belongs to a group the table assigns to exactly one
project, but the mode never exits 0: nothing yet shows that the published
rules name every version a release stops serving, so the best answer is
UNKNOWN (exit 11). Embedded knowledge only. See docs/custom-resources.md.
The same cap holds for the generic --input route (embedded or --knowledge-db,
and replay): when any evaluated rule reads a custom-resource version set, the
check never exits 0.
The Kubernetes component-configuration mode reads one private selection
document naming private local files (static pod manifests, kubelet flag files,
argument lists, kubelet, scheduler, kube-proxy and admission configuration,
kubeadm configuration, rendered manifests) and the scopes the caller declares
complete. It evaluates only published rules for removed component settings on
the crossed minor line. A supplied removed setting blocks; absence passes only
for scopes declared complete whose every source was understood; everything else
stays UNKNOWN. See docs/kubernetes-component-config.md.
The containerd mode reads one private config.toml and one explicitly selected
CRI runtime handler for 1.7.28 -> 2.0.0. It accepts config versions 2 and 3 at
their reviewed plugin paths and never treats version 2 itself as a blocker.
Imports, custom runtime types, runtime_path overrides, missing handlers, and
unresolved completeness, precedence, distribution, or bundled-runtime scope
stay UNKNOWN. PASS clears only the selected removed-official-shim constraint.
The Emissary-Ingress mode reads one private direct diagd JSON argv array for
the exact 3.10.0 -> 4.0.1 reviewed option removal. The OpenFGA mode reads one
private, strictly parsed nested effective-configuration JSON file for 1.17.1
-> 1.18.0. effective-config-complete is optional: omitted or false keeps
the scoped claim UNKNOWN, while true declares file, environment, and flag
precedence resolved. Neither mode runs a process, reads a cluster, or validates
runtime behavior. Optional raw-input digests bind supplied bytes.
Selected-store checks have no embedded fallback. Historical replay requires
the matching raw native-input digest and all three knowledge pins.
Exit 0: all selected nonempty claims PASS; 10: at least one claim BLOCKED;
11: UNKNOWN, UNSUPPORTED, NO_KNOWN_ISSUE or no rules; 2: invalid input; 3: integrity failure.
Whole-upgrade compatibility remains UNKNOWN in every case.
Add --show-passes with --format human on the Kubernetes native-resource route and the generic --input preview to list PASS claims; by default they are counted. JSON is unaffected.
--require-basis LIST (every route, embedded and external knowledge) evaluates only rules whose evidence basis is in LIST, a comma-separated subset of reviewed, mechanical, empirical, consensus, lead. The default is reviewed,mechanical,empirical,consensus. The report counts the rules it left out; a check that left out a rule never passes. A consensus rule may block but never passes: where it finds nothing its claim is NO_KNOWN_ISSUE (exit 11). A lead is shown only when lead is listed, and never blocks.`)
		return ExitOK
	}
	fs := flag.NewFlagSet("check cncf", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "catalogue project slug")
	input := fs.String("input", "", "minimized current and proposed declarations")
	pin := fs.String("input-digest", "", "optional exact input file SHA-256")
	configMap := fs.String("config-map", "", "private proposed Argo CD argocd-cm JSON")
	configMapPin := fs.String("config-map-digest", "", "optional exact ConfigMap SHA-256")
	resourceExclusionsConfigMap := fs.String("resource-exclusions-config-map", "", "private Argo CD argocd-cm YAML for resource.exclusions")
	resourceExclusionsConfigMapPin := fs.String("resource-exclusions-config-map-digest", "", "optional exact ConfigMap SHA-256")
	resourceExclusionsComplete := fs.Bool("resource-exclusions-config-complete", false, "caller declaration that selected argocd-cm data is complete")
	resourceExclusionsPrecedence := fs.Bool("resource-exclusions-precedence-resolved", false, "caller declaration that resource.exclusions precedence is resolved")
	requiresV2Visibility := fs.String("requires-v2-visibility-of-v3-default-excluded-resources", "", "explicit Argo CD v2 visibility preservation intent: true")
	repositorySecret := fs.String("repository-secret", "", "private pre-apply Argo CD repository Secret JSON using stringData")
	repositorySecretPin := fs.String("repository-secret-digest", "", "optional exact repository Secret SHA-256")
	repositoryDistribution := fs.String("repository-distribution", "", "Argo CD distribution: official_upstream or custom_build")
	repositorySettingsResolved := fs.String("repository-settings-resolved", "", "explicit Argo CD repository setting completeness and precedence: true or false")
	repositoryUsesPlainHTTP := fs.String("repository-uses-plain-http", "", "explicit selected Argo CD repository transport intent: true or false")
	linkerdResource := fs.String("linkerd-resource", "", "private proposed Linkerd MeshTLSAuthentication JSON resource")
	linkerdResourcePin := fs.String("linkerd-resource-digest", "", "optional exact Linkerd resource SHA-256")
	linkerdDistribution := fs.String("linkerd-distribution", "", "Linkerd distribution: official_upstream or custom_build")
	linkerdSchemaValidation := fs.String("schema-validation", "", "Linkerd schema intent: required or disabled")
	karmadaResource := fs.String("karmada-resource", "", "private proposed Karmada PropagationPolicy or ClusterPropagationPolicy JSON resource")
	karmadaResourcePin := fs.String("karmada-resource-digest", "", "optional exact Karmada resource SHA-256")
	karmadaDistribution := fs.String("karmada-distribution", "", "Karmada distribution: official_upstream or custom_build")
	karmadaTargetPolicyCRDAdmission := fs.String("target-policy-crd-admission", "", "Karmada target policy CRD intent: required or disabled")
	ciliumPolicy := fs.String("cilium-policy", "", "private proposed CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, or flat v1/typed List JSON")
	ciliumPolicyPin := fs.String("cilium-policy-digest", "", "optional exact Cilium policy SHA-256")
	ciliumCompleteCNPCCNPSet := fs.String("complete-cnp-ccnp-set", "", "explicit Cilium CNP and CCNP policy-set completeness: true or false")
	keadmInitArgv := fs.String("keadm-init-argv", "", "private planned keadm init JSON argv array")
	keadmInitArgvPin := fs.String("keadm-init-argv-digest", "", "optional exact keadm init argv SHA-256")
	kubeEdgeDistribution := fs.String("kubeedge-distribution", "", "KubeEdge distribution: official_upstream or custom_build")
	keadmArgvComplete := fs.String("keadm-argv-complete", "", "explicit KubeEdge effective keadm init argv completeness: true or false")
	tektonConfigObservability := fs.String("tekton-config-observability", "", "private proposed Tekton config-observability v1 ConfigMap YAML or JSON")
	tektonConfigObservabilityPin := fs.String("tekton-config-observability-digest", "", "optional exact Tekton ConfigMap SHA-256")
	tektonDistribution := fs.String("tekton-distribution", "", "Tekton distribution: official_upstream or custom_build")
	tektonSystemNamespace := fs.String("tekton-system-namespace", "", "explicit proposed Tekton system namespace the selected ConfigMap must be bound to")
	tektonConfigObservabilityComplete := fs.String("tekton-config-observability-complete", "", "explicit Tekton complete effective config-observability composition: true or false")
	tektonRetainPrometheus := fs.String("retain-prometheus-metrics-required", "", "explicit Tekton Prometheus metrics retention requirement: true or false")
	service := fs.String("service", "", "private proposed Knative Serving Service JSON")
	servicePin := fs.String("service-digest", "", "optional exact Service SHA-256")
	currentLifecycleConfig := fs.String("current-lifecycle-config", "", "private current Lifecycle config-shaped JSON")
	proposedLifecycleConfig := fs.String("proposed-lifecycle-config", "", "private proposed Lifecycle config-shaped JSON")
	currentLifecyclePin := fs.String("current-lifecycle-config-digest", "", "optional exact current Lifecycle config SHA-256")
	proposedLifecyclePin := fs.String("proposed-lifecycle-config-digest", "", "optional exact proposed Lifecycle config SHA-256")
	currentPlatformAPI := fs.String("current-platform-api", "", "explicit current CNB_PLATFORM_API")
	proposedPlatformAPI := fs.String("proposed-platform-api", "", "explicit proposed CNB_PLATFORM_API")
	inTotoRunArgv := fs.String("in-toto-run-argv", "", "private planned in-toto-run JSON argv array")
	inTotoRunArgvPin := fs.String("in-toto-run-argv-digest", "", "optional exact argv file SHA-256")
	pythonSource := fs.String("python-source", "", "private Python source for a supported source-call check")
	pythonSourcePin := fs.String("python-source-digest", "", "optional exact Python source file SHA-256")
	metanodeConfig := fs.String("metanode-config", "", "private planned CubeFS MetaNode JSON config")
	metanodeConfigPin := fs.String("metanode-config-digest", "", "optional exact MetaNode config SHA-256")
	phase := fs.String("phase", "", "caller-declared upgrade phase")
	imageStatusRequest := fs.String("image-status-request", "", "private CRI ImageStatusRequest JSON")
	imageStatusRequestPin := fs.String("image-status-request-digest", "", "optional exact ImageStatusRequest SHA-256")
	artifactOperation := fs.String("artifact-operation", "", "caller-declared artifact operation")
	imageManifest := fs.String("image-manifest", "", "private Distribution image manifest JSON")
	imageManifestPin := fs.String("image-manifest-digest", "", "optional exact image manifest SHA-256")
	cniConfiguration := fs.String("cni-configuration", "", "private CNI configuration JSON")
	cniConfigurationPin := fs.String("cni-configuration-digest", "", "optional exact CNI configuration SHA-256")
	containerdConfig := fs.String("containerd-config", "", "private effective containerd config.toml")
	containerdConfigPin := fs.String("containerd-config-digest", "", "optional exact containerd config.toml SHA-256")
	containerdRuntimeHandler := fs.String("runtime-handler", "", "explicit selected containerd CRI runtime handler")
	containerdConfigComplete := fs.Bool("containerd-config-complete", false, "caller declaration that selected containerd configuration is complete")
	containerdConfigPrecedenceResolved := fs.Bool("containerd-config-precedence-resolved", false, "caller declaration that containerd configuration precedence is resolved")
	containerdOfficialUpstream := fs.Bool("containerd-official-upstream", false, "bind the target to the reviewed upstream containerd distribution")
	containerdOfficialBundledRuntimesOnly := fs.Bool("containerd-official-bundled-runtimes-only", false, "declare that no separately installed custom shim supplies the selected runtime")
	diagdArgv := fs.String("diagd-argv", "", "private direct Emissary diagd JSON argv array")
	diagdArgvPin := fs.String("diagd-argv-digest", "", "optional exact diagd argv SHA-256")
	effectiveConfig := fs.String("effective-config", "", "private resolved OpenFGA effective configuration JSON")
	effectiveConfigPin := fs.String("effective-config-digest", "", "optional exact effective configuration SHA-256")
	effectiveConfigComplete := fs.Bool("effective-config-complete", false, "caller declaration that OpenFGA file, environment, and flag precedence is resolved")
	operation := fs.String("operation", "", "caller-declared scoped operation")
	componentConfig := fs.String("component-config", "", "private Kubernetes component-configuration selection document")
	componentConfigPin := fs.String("component-config-digest", "", "optional exact selection document SHA-256")
	nativeResource := fs.String("native-resource", "", "private selected native Kubernetes JSON resource")
	nativeResourcePin := fs.String("native-resource-digest", "", "optional exact native resource SHA-256")
	resourceScopeComplete := fs.Bool("resource-scope-complete", false, "caller declaration that the selected rendered-resource JSON set is complete")
	distribution := fs.String("distribution", "", "Kubernetes distribution: official_upstream or custom_build")
	targetAPIApplyRequired := fs.Bool("target-api-apply-required", false, "caller declaration that the selected resource set is required for target API apply")
	ciliumConfigMap := fs.String("cilium-config-map", "", "private selected Cilium v1 ConfigMap YAML or JSON")
	ciliumConfigMapPin := fs.String("cilium-config-map-digest", "", "optional exact Cilium ConfigMap SHA-256")
	ciliumConfigComplete := fs.Bool("cilium-config-complete", false, "caller declaration that the selected Cilium ConfigMap is complete")
	ciliumConfigPrecedenceResolved := fs.Bool("cilium-config-precedence-resolved", false, "caller declaration that Cilium ConfigMap precedence is resolved")
	ciliumDistribution := fs.String("cilium-distribution", "", "Cilium distribution: official_upstream or custom_build")
	corednsCorefile := fs.String("coredns-corefile", "", "private selected complete CoreDNS Corefile")
	corednsCorefilePin := fs.String("coredns-corefile-digest", "", "optional exact Corefile SHA-256")
	corednsCorefileComplete := fs.Bool("coredns-corefile-complete", false, "caller declaration that the selected Corefile is complete")
	corednsDistribution := fs.String("coredns-distribution", "", "CoreDNS distribution: official")
	envoyBootstrap := fs.String("envoy-bootstrap", "", "private selected Envoy JSON bootstrap")
	envoyBootstrapPin := fs.String("envoy-bootstrap-digest", "", "optional exact Envoy bootstrap SHA-256")
	envoyBootstrapSelected := fs.Bool("envoy-bootstrap-selected", false, "caller declaration that this is the directly loaded Envoy bootstrap")
	natsConfig := fs.String("nats-config", "", "private standalone NATS JSON-like configuration")
	natsConfigPin := fs.String("nats-config-digest", "", "optional exact NATS configuration SHA-256")
	customResources := fs.String("custom-resources", "", "private rendered manifests (YAML or JSON) whose custom-resource versions are checked")
	customResourcesPin := fs.String("custom-resources-digest", "", "optional exact custom-resource manifests SHA-256")
	customResourcesComplete := fs.Bool("custom-resources-complete", false, "caller declaration that the manifests are the complete set that is applied")
	kafkaResource := fs.String("kafka-resource", "", "private selected rendered Strimzi Kafka resource or flat v1 List JSON")
	kafkaResourcePin := fs.String("kafka-resource-digest", "", "optional exact Kafka resource SHA-256")
	strimziDistribution := fs.String("strimzi-distribution", "", "Strimzi distribution: official_upstream or custom_build")
	targetKafkaCRDAdmissionRequired := fs.Bool("target-kafka-crd-admission-required", false, "caller declaration that the selected Kafka resources must be admitted by the target Kafka CRD")
	falcoArgv := fs.String("falco-argv", "", "private explicit effective Falco JSON argv array")
	falcoArgvPin := fs.String("falco-argv-digest", "", "optional exact Falco argv SHA-256")
	falcoDistribution := fs.String("falco-distribution", "", "Falco distribution: official_upstream or custom_build")
	kumactlArgv := fs.String("kumactl-argv", "", "private explicit effective kumactl install transparent-proxy JSON argv array")
	kumactlArgvPin := fs.String("kumactl-argv-digest", "", "optional exact kumactl argv SHA-256")
	kumaDistribution := fs.String("kuma-distribution", "", "Kuma distribution: official_upstream or custom_build")
	composition := fs.String("composition", "", "private selected rendered Crossplane Composition or flat v1 List JSON")
	compositionPin := fs.String("composition-digest", "", "optional exact Composition SHA-256")
	crossplaneDistribution := fs.String("crossplane-distribution", "", "Crossplane distribution: official_upstream or custom_build")
	crossplaneSchemaValidationRequired := fs.Bool("crossplane-schema-validation-required", false, "caller declaration that the selected Compositions must validate against the official target CRD schema")
	upgradePlan := fs.String("upgrade-plan", "", "private selected flat v1 List of rendered Velero upgrade documents in declared apply order")
	upgradePlanPin := fs.String("upgrade-plan-digest", "", "optional exact upgrade plan SHA-256")
	veleroServerDeployment := fs.String("velero-server-deployment", "", "literal metadata.name of the Velero server Deployment inside the selected plan")
	veleroPlanOrderDeclared := fs.Bool("velero-plan-order-declared", false, "caller declaration that the supplied item order is the declared apply order")
	spireEntryArgv := fs.String("spire-entry-argv", "", "private explicit effective spire-server entry create JSON argv array")
	spireEntryArgvPin := fs.String("spire-entry-argv-digest", "", "optional exact SPIRE argv SHA-256")
	spireDistribution := fs.String("spire-distribution", "", "SPIRE distribution: official_upstream or custom_build")
	kedaScaledObject := fs.String("keda-scaled-object", "", "private selected rendered KEDA ScaledObject JSON, or one flat v1 List")
	kedaScaledObjectPin := fs.String("keda-scaled-object-digest", "", "optional exact KEDA ScaledObject SHA-256")
	kedaScaledObjectComplete := fs.Bool("keda-scaled-object-complete", false, "caller declaration that the selected ScaledObject set is complete")
	kedaLegacyTransport := fs.String("keda-legacy-tls-transport-required", "", "explicit declaration that the External Scaler relies on the removed direct tlsCertFile transport: true or false")
	otelCollectorConfig := fs.String("otel-collector-config", "", "private selected OpenTelemetry Collector YAML configuration")
	otelCollectorConfigPin := fs.String("otel-collector-config-digest", "", "optional exact Collector configuration SHA-256")
	otelDistribution := fs.String("otel-distribution", "", "declared Collector distribution: official or custom")
	otelConfigComplete := fs.Bool("otel-config-complete", false, "caller declaration that the selected Collector configuration is complete")
	otelConfigPrecedenceResolved := fs.Bool("otel-config-precedence-resolved", false, "caller declaration that Collector provider and CLI precedence is resolved")
	otelRule := fs.String("otel-rule", "", "explicit OpenTelemetry native rule selector")
	otelMetricsLocalhostDefault := fs.String("otel-metrics-localhost-default", "", "declared effective target internal-metrics localhost-default gate: true or false")
	otelMetricsRemoteScrapeRequired := fs.String("otel-metrics-remote-scrape-required", "", "declared requirement for non-loopback internal-metrics scraping: true or false")
	scrapeConfig := fs.String("scrape-config", "", "private selected native Prometheus scrape_config YAML")
	scrapeConfigPin := fs.String("scrape-config-digest", "", "optional exact selected scrape_config SHA-256")
	scrapeJob := fs.String("scrape-job", "", "exact job_name selecting the supplied scrape_config")
	scrapeConfigComplete := fs.Bool("scrape-config-complete", false, "caller declaration that the selected scrape_config is complete")
	scrapeConfigPrecedenceResolved := fs.Bool("scrape-config-precedence-resolved", false, "caller declaration that configuration precedence is resolved")
	prometheusConfig := fs.String("prometheus-config", "", "private complete Prometheus YAML configuration")
	prometheusConfigPin := fs.String("prometheus-config-digest", "", "optional exact Prometheus configuration SHA-256")
	prometheusConfigComplete := fs.Bool("prometheus-config-complete", false, "caller declaration that the selected remote_write subtree is complete")
	prometheusConfigPrecedenceResolved := fs.Bool("prometheus-config-precedence-resolved", false, "caller declaration that selected remote_write precedence is resolved")
	prometheusRule := fs.String("prometheus-rule", "", "explicit Prometheus rule selector")
	prometheusRemoteWriteName := fs.String("prometheus-remote-write-name", "", "literal name selecting one remote_write entry")
	prometheusRemoteWriteHTTP2Required := fs.String("prometheus-remote-write-http2-required", "", "declared endpoint HTTP/2 requirement: true or false")
	alertmanagerConfig := fs.String("alertmanager-config", "", "private selected native Prometheus alerting.alertmanagers entry YAML")
	alertmanagerConfigPin := fs.String("alertmanager-config-digest", "", "optional exact selected Alertmanager config SHA-256")
	alertmanagerConfigComplete := fs.Bool("alertmanager-config-complete", false, "caller declaration that the selected Alertmanager mapping is complete")
	alertmanagerConfigPrecedenceResolved := fs.Bool("alertmanager-config-precedence-resolved", false, "caller declaration that Alertmanager API-version precedence is resolved")
	kyvernoResource := fs.String("kyverno-resource", "", "private selected native Kubernetes Pod or Deployment JSON resource")
	kyvernoResourcePin := fs.String("kyverno-resource-digest", "", "optional exact Kyverno resource SHA-256")
	container := fs.String("container", "", "explicit selected Kyverno container name")
	kyvernoDistribution := fs.String("kyverno-distribution", "", "Kyverno distribution: official_upstream or custom_build")
	jaegerArgv := fs.String("jaeger-argv", "", "private explicit direct Jaeger v2 invocation JSON declaration")
	jaegerArgvPin := fs.String("jaeger-argv-digest", "", "optional exact Jaeger argv declaration SHA-256")
	jaegerNonMemoryStorage := fs.String("non-memory-storage-required", "", "explicit Jaeger non-memory storage requirement: true or false")
	jaegerOfficialDistribution := fs.String("official-jaeger-distribution", "", "explicit Jaeger official distribution declaration: true or false")
	currentResource := fs.String("current-resource", "", "private current native Kubernetes JSON resource")
	currentResourcePin := fs.String("current-resource-digest", "", "optional exact current resource SHA-256")
	resource := fs.String("resource", "", "private proposed native Kubernetes JSON resource")
	resourcePin := fs.String("resource-digest", "", "optional exact proposed resource SHA-256")
	from := fs.String("from", "", "actual declared current component version")
	to := fs.String("to", "", "actual declared proposed component version")
	requiresInheritedPermissions := fs.String("requires-inherited-application-permissions", "", "explicit Argo CD v2 inheritance access intent: true or false")
	nowText := fs.String("now", "", "explicit UTC evaluation time")
	replay := fs.String("replay-report", "", "prior exact JSON output")
	knowledgeDB := fs.String("knowledge-db", "", "explicit separate signed CNCF store")
	knowledgeMode := fs.String("knowledge", "", "auto (default) or embedded")
	knowledgeRevision := fs.String("knowledge-revision", "", "optional exact selected revision")
	knowledgeBundleDigest := fs.String("knowledge-bundle-digest", "", "optional exact target digest")
	knowledgeTrustReceiptDigest := fs.String("knowledge-trust-receipt-digest", "", "optional exact trust receipt digest")
	format := fs.String("format", "human", "human or json")
	showPasses := fs.Bool("show-passes", false, "human output: list PASS claims instead of counting them")
	requireBasis := fs.String("require-basis", "", "comma-separated evidence bases whose rules are evaluated")
	digestRE := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	if duplicateFlags(args) || fs.Parse(args) != nil || fs.NArg() != 0 || *project == "" || (*format != "human" && *format != "json") || (flagProvided(args, "input-digest") && !digestRE.MatchString(*pin)) || (flagProvided(args, "config-map-digest") && !digestRE.MatchString(*configMapPin)) || (flagProvided(args, "resource-exclusions-config-map-digest") && !digestRE.MatchString(*resourceExclusionsConfigMapPin)) || (flagProvided(args, "repository-secret-digest") && !digestRE.MatchString(*repositorySecretPin)) || (flagProvided(args, "linkerd-resource-digest") && !digestRE.MatchString(*linkerdResourcePin)) || (flagProvided(args, "karmada-resource-digest") && !digestRE.MatchString(*karmadaResourcePin)) || (flagProvided(args, "cilium-policy-digest") && !digestRE.MatchString(*ciliumPolicyPin)) || (flagProvided(args, "keadm-init-argv-digest") && !digestRE.MatchString(*keadmInitArgvPin)) || (flagProvided(args, "tekton-config-observability-digest") && !digestRE.MatchString(*tektonConfigObservabilityPin)) || (flagProvided(args, "service-digest") && !digestRE.MatchString(*servicePin)) || (flagProvided(args, "current-lifecycle-config-digest") && !digestRE.MatchString(*currentLifecyclePin)) || (flagProvided(args, "proposed-lifecycle-config-digest") && !digestRE.MatchString(*proposedLifecyclePin)) || (flagProvided(args, "in-toto-run-argv-digest") && !digestRE.MatchString(*inTotoRunArgvPin)) || (flagProvided(args, "python-source-digest") && !digestRE.MatchString(*pythonSourcePin)) || (flagProvided(args, "metanode-config-digest") && !digestRE.MatchString(*metanodeConfigPin)) || (flagProvided(args, "image-status-request-digest") && !digestRE.MatchString(*imageStatusRequestPin)) || (flagProvided(args, "native-resource-digest") && !digestRE.MatchString(*nativeResourcePin)) || (flagProvided(args, "component-config-digest") && !digestRE.MatchString(*componentConfigPin)) || (flagProvided(args, "cilium-config-map-digest") && !digestRE.MatchString(*ciliumConfigMapPin)) || (flagProvided(args, "coredns-corefile-digest") && !digestRE.MatchString(*corednsCorefilePin)) || (flagProvided(args, "envoy-bootstrap-digest") && !digestRE.MatchString(*envoyBootstrapPin)) || (flagProvided(args, "nats-config-digest") && !digestRE.MatchString(*natsConfigPin)) || (flagProvided(args, "kafka-resource-digest") && !digestRE.MatchString(*kafkaResourcePin)) || (flagProvided(args, "falco-argv-digest") && !digestRE.MatchString(*falcoArgvPin)) || (flagProvided(args, "kumactl-argv-digest") && !digestRE.MatchString(*kumactlArgvPin)) || (flagProvided(args, "composition-digest") && !digestRE.MatchString(*compositionPin)) || (flagProvided(args, "upgrade-plan-digest") && !digestRE.MatchString(*upgradePlanPin)) || (flagProvided(args, "spire-entry-argv-digest") && !digestRE.MatchString(*spireEntryArgvPin)) || (flagProvided(args, "keda-scaled-object-digest") && !digestRE.MatchString(*kedaScaledObjectPin)) || (flagProvided(args, "otel-collector-config-digest") && !digestRE.MatchString(*otelCollectorConfigPin)) || (flagProvided(args, "scrape-config-digest") && !digestRE.MatchString(*scrapeConfigPin)) || (flagProvided(args, "prometheus-config-digest") && !digestRE.MatchString(*prometheusConfigPin)) || (flagProvided(args, "alertmanager-config-digest") && !digestRE.MatchString(*alertmanagerConfigPin)) || (flagProvided(args, "kyverno-resource-digest") && !digestRE.MatchString(*kyvernoResourcePin)) || (flagProvided(args, "jaeger-argv-digest") && !digestRE.MatchString(*jaegerArgvPin)) || (flagProvided(args, "current-resource-digest") && !digestRE.MatchString(*currentResourcePin)) || (flagProvided(args, "resource-digest") && !digestRE.MatchString(*resourcePin)) || (flagProvided(args, "image-manifest-digest") && !digestRE.MatchString(*imageManifestPin)) || (flagProvided(args, "cni-configuration-digest") && !digestRE.MatchString(*cniConfigurationPin)) || (flagProvided(args, "containerd-config-digest") && !digestRE.MatchString(*containerdConfigPin)) || (flagProvided(args, "diagd-argv-digest") && !digestRE.MatchString(*diagdArgvPin)) || (flagProvided(args, "effective-config-digest") && !digestRE.MatchString(*effectiveConfigPin)) || (flagProvided(args, "replay-report") && *replay == "") {
		return r.usage("invalid CNCF check arguments; use --help")
	}
	trust, ok := trustPolicyFlag(args, *requireBasis)
	if !ok {
		return r.usage("invalid --require-basis; use a comma-separated list of reviewed, mechanical, empirical, consensus, lead")
	}
	r.trust = trust
	for _, name := range []string{"knowledge-db", "knowledge-revision", "knowledge-bundle-digest", "knowledge-trust-receipt-digest"} {
		if flagProvided(args, name) && fs.Lookup(name).Value.String() == "" {
			return r.usage("invalid external CNCF knowledge selection; use --help")
		}
	}
	if flagProvided(args, "knowledge-db") && flagProvided(args, "now") {
		return r.usage("external CNCF checks use verifier time; omit --now")
	}
	if code, stop := r.resolveCNCFKnowledge(args, *knowledgeMode, *project, knowledgeDB, knowledgeRevision, knowledgeBundleDigest, knowledgeTrustReceiptDigest, nowText, *replay); stop {
		return code
	}
	if anyFlagProvided(args, cncfCustomResourceFlags...) {
		return r.cncfCustomResourceCheck(customResourceRequest{
			project: *project, path: *customResources, pin: *customResourcesPin, complete: *customResourcesComplete,
			from: *from, to: *to, nowText: *nowText, externalKnowledge: *knowledgeDB != "",
			revision: *knowledgeRevision, bundle: *knowledgeBundleDigest, receipt: *knowledgeTrustReceiptDigest,
			replayPath: *replay, format: *format, args: args,
		})
	}
	componentConfigFlags := anyFlagProvided(args, "component-config", "component-config-digest")
	if componentConfigFlags {
		if *project != "kubernetes" {
			return r.usage("component configuration flags require project kubernetes; use --help")
		}
		if *componentConfig == "" || *from == "" || *to == "" || cncfUnexpectedModeFlag(args, "component-config", "component-config-digest", "distribution") {
			return r.usage("invalid Kubernetes component configuration check arguments; use --help")
		}
		return r.cncfKubernetesComponentConfig(*componentConfig, *componentConfigPin, *from, *to, *distribution, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format)
	}
	nativeFlags := anyFlagProvided(args, "native-resource", "native-resource-digest", "current-resource", "current-resource-digest", "resource", "resource-digest")
	fluxNativeRequested := *project == "flux" && anyFlagProvided(args, "native-resource", "native-resource-digest", "resource-scope-complete")
	kubernetesNativeRequested := *project == "kubernetes" && anyFlagProvided(args, "native-resource", "native-resource-digest", "resource-scope-complete", "distribution", "target-api-apply-required")
	ciliumNativeRequested := *project == "cilium" && anyFlagProvided(args, "cilium-config-map", "cilium-config-map-digest", "cilium-config-complete", "cilium-config-precedence-resolved", "cilium-distribution")
	corednsNativeRequested := *project == "coredns" && anyFlagProvided(args, "coredns-corefile", "coredns-corefile-digest", "coredns-corefile-complete", "coredns-distribution")
	envoyNativeRequested := *project == "envoy" && anyFlagProvided(args, "envoy-bootstrap", "envoy-bootstrap-digest", "envoy-bootstrap-selected")
	natsFlags := anyFlagProvided(args, "nats-config", "nats-config-digest")
	strimziFlags := anyFlagProvided(args, "kafka-resource", "kafka-resource-digest", "strimzi-distribution", "target-kafka-crd-admission-required")
	falcoFlags := anyFlagProvided(args, "falco-argv", "falco-argv-digest", "falco-distribution")
	kumaFlags := anyFlagProvided(args, "kumactl-argv", "kumactl-argv-digest", "kuma-distribution")
	crossplaneFlags := anyFlagProvided(args, "composition", "composition-digest", "crossplane-distribution", "crossplane-schema-validation-required")
	veleroFlags := anyFlagProvided(args, "upgrade-plan", "upgrade-plan-digest", "velero-server-deployment", "velero-plan-order-declared")
	spireFlags := anyFlagProvided(args, "spire-entry-argv", "spire-entry-argv-digest", "spire-distribution")
	kedaFlags := anyFlagProvided(args, "keda-scaled-object", "keda-scaled-object-digest", "keda-scaled-object-complete", "keda-legacy-tls-transport-required")
	otelFlags := anyFlagProvided(args, "otel-collector-config", "otel-collector-config-digest", "otel-distribution", "otel-config-complete", "otel-config-precedence-resolved", "otel-rule", "otel-metrics-localhost-default", "otel-metrics-remote-scrape-required")
	prometheusScrapeFlags := anyFlagProvided(args, "scrape-config", "scrape-config-digest", "scrape-job", "scrape-config-complete", "scrape-config-precedence-resolved")
	prometheusAlertmanagerFlags := anyFlagProvided(args, "alertmanager-config", "alertmanager-config-digest", "alertmanager-config-complete", "alertmanager-config-precedence-resolved")
	prometheusRemoteWriteFlags := anyFlagProvided(args, "prometheus-config", "prometheus-config-digest", "prometheus-config-complete", "prometheus-config-precedence-resolved", "prometheus-rule", "prometheus-remote-write-name", "prometheus-remote-write-http2-required")
	nativeProject := *project == "metallb" || *project == "contour" || *project == "kubevirt" || *project == "thanos" || *project == "cortex" || *project == "cloudnativepg" || *project == "flux" || *project == "kubernetes" || *project == "cilium" || *project == "etcd" || *project == "harbor" || *project == "fluentd" || *project == "opencost" || *project == "cloud-custodian"
	containerdFlags := anyFlagProvided(args, "containerd-config", "containerd-config-digest", "runtime-handler", "containerd-config-complete", "containerd-config-precedence-resolved", "containerd-official-upstream", "containerd-official-bundled-runtimes-only")
	kyvernoFlags := anyFlagProvided(args, "kyverno-resource", "kyverno-resource-digest", "container", "kyverno-distribution")
	jaegerFlags := anyFlagProvided(args, "jaeger-argv", "jaeger-argv-digest", "non-memory-storage-required", "official-jaeger-distribution")
	if (nativeFlags || flagProvided(args, "resource-scope-complete") || flagProvided(args, "distribution") || flagProvided(args, "target-api-apply-required") || ciliumNativeRequested) && !nativeProject {
		return r.usage("native resource flags require metallb, contour, kubevirt, thanos, cortex, cloudnativepg, flux, kubernetes, cilium, etcd, harbor, fluentd, opencost, or cloud-custodian; use --help")
	}
	if nativeProject && (nativeFlags || fluxNativeRequested || kubernetesNativeRequested) {
		return r.cncfNativeResourceCheck(*project, *nativeResource, *nativeResourcePin, *currentResource, *currentResourcePin, *resource, *resourcePin, "", false, false, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, *resourceScopeComplete, *distribution, *targetAPIApplyRequired, "", "", "", "", args, nil, "")
	}
	if kyvernoFlags && *project != "kyverno" {
		return r.usage("Kyverno resource flags require project kyverno; use --help")
	}
	if kyvernoFlags {
		if *kyvernoResource == "" || *container == "" || (*kyvernoDistribution != "" && *kyvernoDistribution != cncfprepare.KyvernoDistributionOfficial && *kyvernoDistribution != cncfprepare.KyvernoDistributionCustom) || cncfUnexpectedModeFlag(args, "kyverno-resource", "kyverno-resource-digest", "container", "kyverno-distribution") {
			return r.usage("invalid Kyverno resource arguments; use --help")
		}
		return r.cncfNativeResourceCheck(*project, *kyvernoResource, *kyvernoResourcePin, *currentResource, *currentResourcePin, *resource, *resourcePin, *kyvernoDistribution, false, false, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, false, "", false, "", "", "", "", args, nil, *container)
	}
	if jaegerFlags && *project != "jaeger" {
		return r.usage("Jaeger argv flags require project jaeger; use --help")
	}
	if jaegerFlags {
		if *jaegerArgv == "" || (*jaegerNonMemoryStorage != "" && *jaegerNonMemoryStorage != "true" && *jaegerNonMemoryStorage != "false") || (*jaegerOfficialDistribution != "" && *jaegerOfficialDistribution != "true" && *jaegerOfficialDistribution != "false") || cncfUnexpectedModeFlag(args, "jaeger-argv", "jaeger-argv-digest", "non-memory-storage-required", "official-jaeger-distribution") {
			return r.usage("invalid Jaeger argv arguments; use --help")
		}
		var nonMemoryStorage, officialDistribution *bool
		if *jaegerNonMemoryStorage != "" {
			value := *jaegerNonMemoryStorage == "true"
			nonMemoryStorage = &value
		}
		if *jaegerOfficialDistribution != "" {
			value := *jaegerOfficialDistribution == "true"
			officialDistribution = &value
		}
		return r.cncfJaegerNativeCheck(*jaegerArgv, *jaegerArgvPin, nonMemoryStorage, officialDistribution, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format)
	}
	if ciliumNativeRequested {
		return r.cncfNativeResourceCheck(*project, *ciliumConfigMap, *ciliumConfigMapPin, *currentResource, *currentResourcePin, *resource, *resourcePin, "", *ciliumConfigComplete, *ciliumConfigPrecedenceResolved, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, false, "", false, *ciliumDistribution, "", "", "", args, nil, "")
	}
	if anyFlagProvided(args, "coredns-corefile", "coredns-corefile-digest", "coredns-corefile-complete", "coredns-distribution") && *project != "coredns" {
		return r.usage("CoreDNS Corefile flags require project coredns; use --help")
	}
	if corednsNativeRequested && *corednsDistribution != "" && *corednsDistribution != "official" && *corednsDistribution != "custom" {
		return r.usage("invalid CoreDNS distribution; use --help")
	}
	if corednsNativeRequested {
		return r.cncfNativeResourceCheck(*project, *corednsCorefile, *corednsCorefilePin, *currentResource, *currentResourcePin, *resource, *resourcePin, *corednsDistribution, *corednsCorefileComplete, false, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, false, "", false, "", "", "", "", args, nil, "")
	}
	if anyFlagProvided(args, "envoy-bootstrap", "envoy-bootstrap-digest", "envoy-bootstrap-selected") && *project != "envoy" {
		return r.usage("Envoy bootstrap flags require project envoy; use --help")
	}
	if envoyNativeRequested {
		return r.cncfNativeResourceCheck(*project, *envoyBootstrap, *envoyBootstrapPin, *currentResource, *currentResourcePin, *resource, *resourcePin, "", *envoyBootstrapSelected, false, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, false, "", false, "", "", "", "", args, nil, "")
	}
	if strimziFlags && *project != "strimzi" {
		return r.usage("Strimzi Kafka resource flags require project strimzi; use --help")
	}
	if strimziFlags {
		if *kafkaResource == "" || (*strimziDistribution != "" && *strimziDistribution != cncfprepare.StrimziDistributionOfficial && *strimziDistribution != cncfprepare.StrimziDistributionCustom) || cncfUnexpectedModeFlag(args, "kafka-resource", "kafka-resource-digest", "strimzi-distribution", "target-kafka-crd-admission-required") {
			return r.usage("invalid Strimzi Kafka resource arguments; use --help")
		}
		return r.cncfNativeResourceCheck(*project, *kafkaResource, *kafkaResourcePin, *currentResource, *currentResourcePin, *resource, *resourcePin, *strimziDistribution, *targetKafkaCRDAdmissionRequired, false, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, false, "", false, "", "", "", "", args, nil, "")
	}
	if falcoFlags && *project != "falco" {
		return r.usage("Falco argv flags require project falco; use --help")
	}
	if falcoFlags {
		if *falcoArgv == "" || (*falcoDistribution != "" && *falcoDistribution != cncfprepare.FalcoDistributionOfficial && *falcoDistribution != cncfprepare.FalcoDistributionCustom) || cncfUnexpectedModeFlag(args, "falco-argv", "falco-argv-digest", "falco-distribution") {
			return r.usage("invalid Falco argv arguments; use --help")
		}
		return r.cncfNativeResourceCheck(*project, *falcoArgv, *falcoArgvPin, *currentResource, *currentResourcePin, *resource, *resourcePin, *falcoDistribution, false, false, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, false, "", false, "", "", "", "", args, nil, "")
	}
	if kumaFlags && *project != "kuma" {
		return r.usage("Kuma kumactl argv flags require project kuma; use --help")
	}
	if kumaFlags {
		if *kumactlArgv == "" || (*kumaDistribution != "" && *kumaDistribution != cncfprepare.KumaDistributionOfficial && *kumaDistribution != cncfprepare.KumaDistributionCustom) || cncfUnexpectedModeFlag(args, "kumactl-argv", "kumactl-argv-digest", "kuma-distribution") {
			return r.usage("invalid Kuma kumactl argv arguments; use --help")
		}
		return r.cncfNativeResourceCheck(*project, *kumactlArgv, *kumactlArgvPin, *currentResource, *currentResourcePin, *resource, *resourcePin, *kumaDistribution, false, false, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, false, "", false, "", "", "", "", args, nil, "")
	}
	if crossplaneFlags && *project != "crossplane" {
		return r.usage("Crossplane Composition flags require project crossplane; use --help")
	}
	if crossplaneFlags {
		if *composition == "" || (*crossplaneDistribution != "" && *crossplaneDistribution != cncfprepare.CrossplaneDistributionOfficial && *crossplaneDistribution != cncfprepare.CrossplaneDistributionCustom) || cncfUnexpectedModeFlag(args, "composition", "composition-digest", "crossplane-distribution", "crossplane-schema-validation-required") {
			return r.usage("invalid Crossplane Composition arguments; use --help")
		}
		return r.cncfNativeResourceCheck(*project, *composition, *compositionPin, *currentResource, *currentResourcePin, *resource, *resourcePin, *crossplaneDistribution, *crossplaneSchemaValidationRequired, false, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, false, "", false, "", "", "", "", args, nil, "")
	}
	if veleroFlags && *project != "velero" {
		return r.usage("Velero upgrade plan flags require project velero; use --help")
	}
	if veleroFlags {
		if *upgradePlan == "" || cncfUnexpectedModeFlag(args, "upgrade-plan", "upgrade-plan-digest", "velero-server-deployment", "velero-plan-order-declared") {
			return r.usage("invalid Velero upgrade plan arguments; use --help")
		}
		return r.cncfNativeResourceCheck(*project, *upgradePlan, *upgradePlanPin, *currentResource, *currentResourcePin, *resource, *resourcePin, *veleroServerDeployment, *veleroPlanOrderDeclared, false, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, false, "", false, "", "", "", "", args, nil, "")
	}
	if kedaFlags && *project != "keda" {
		return r.usage("KEDA ScaledObject flags require project keda; use --help")
	}
	if kedaFlags {
		if *kedaScaledObject == "" || (*kedaLegacyTransport != "" && *kedaLegacyTransport != cncfprepare.KEDADeclarationRequired && *kedaLegacyTransport != cncfprepare.KEDADeclarationNotRequired) || cncfUnexpectedModeFlag(args, "keda-scaled-object", "keda-scaled-object-digest", "keda-scaled-object-complete", "keda-legacy-tls-transport-required") {
			return r.usage("invalid KEDA ScaledObject arguments; use --help")
		}
		return r.cncfNativeResourceCheck(*project, *kedaScaledObject, *kedaScaledObjectPin, *currentResource, *currentResourcePin, *resource, *resourcePin, *kedaLegacyTransport, *kedaScaledObjectComplete, false, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, false, "", false, "", "", "", "", args, nil, "")
	}
	if spireFlags && *project != "spire" {
		return r.usage("SPIRE argv flags require project spire; use --help")
	}
	if spireFlags {
		if *spireEntryArgv == "" || (*spireDistribution != "" && *spireDistribution != cncfprepare.SpireDistributionOfficial && *spireDistribution != cncfprepare.SpireDistributionCustom) || cncfUnexpectedModeFlag(args, "spire-entry-argv", "spire-entry-argv-digest", "spire-distribution") {
			return r.usage("invalid SPIRE argv arguments; use --help")
		}
		return r.cncfNativeResourceCheck(*project, *spireEntryArgv, *spireEntryArgvPin, *currentResource, *currentResourcePin, *resource, *resourcePin, *spireDistribution, false, false, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, false, "", false, "", "", "", "", args, nil, "")
	}
	if natsFlags && *project != "nats" {
		return r.usage("NATS configuration flags require project nats; use --help")
	}
	if *project == "nats" && natsFlags {
		return r.cncfNativeResourceCheck(*project, *natsConfig, *natsConfigPin, *currentResource, *currentResourcePin, *resource, *resourcePin, "", false, false, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, false, "", false, "", "", "", "", args, nil, "")
	}
	if otelFlags && *project != "opentelemetry" {
		return r.usage("OpenTelemetry Collector configuration flags require project opentelemetry; use --help")
	}
	if *project == "opentelemetry" && otelFlags {
		if *otelCollectorConfig == "" || *otelDistribution == "" || cncfUnexpectedModeFlag(args, "otel-collector-config", "otel-collector-config-digest", "otel-distribution", "otel-config-complete", "otel-config-precedence-resolved", "otel-rule", "otel-metrics-localhost-default", "otel-metrics-remote-scrape-required") || (*otelRule == "" && (*otelMetricsLocalhostDefault != "" || *otelMetricsRemoteScrapeRequired != "")) {
			return r.usage("invalid OpenTelemetry Collector configuration arguments; use --help")
		}
		if *otelRule != "" && *otelRule != cncfprepare.OpenTelemetryInternalMetricsRuleID {
			if *otelRule == "internal-telemetry-default-bind" {
				*otelRule = cncfprepare.OpenTelemetryInternalMetricsRuleID
			} else {
				return r.usage("invalid OpenTelemetry rule selector; use --help")
			}
		}
		return r.cncfNativeResourceCheck(*project, *otelCollectorConfig, *otelCollectorConfigPin, *currentResource, *currentResourcePin, *resource, *resourcePin, *otelDistribution, *otelConfigComplete, *otelConfigPrecedenceResolved, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, false, "", false, "", *otelRule, *otelMetricsLocalhostDefault, *otelMetricsRemoteScrapeRequired, args, nil, "")
	}
	if prometheusRemoteWriteFlags && *project != "prometheus" {
		return r.usage("Prometheus remote-write configuration flags require project prometheus; use --help")
	}
	if *project == "prometheus" && prometheusRemoteWriteFlags {
		if *prometheusConfig == "" || (*prometheusRemoteWriteHTTP2Required != "" && *prometheusRemoteWriteHTTP2Required != "true" && *prometheusRemoteWriteHTTP2Required != "false") || cncfUnexpectedModeFlag(args, "prometheus-config", "prometheus-config-digest", "prometheus-config-complete", "prometheus-config-precedence-resolved", "prometheus-rule", "prometheus-remote-write-name", "prometheus-remote-write-http2-required") {
			return r.usage("invalid Prometheus remote-write HTTP/2 arguments; use --help")
		}
		var required *bool
		if *prometheusRule == cncfprepare.PrometheusRemoteWriteHTTP2Rule && *prometheusRemoteWriteHTTP2Required != "" {
			value := *prometheusRemoteWriteHTTP2Required == "true"
			required = &value
		}
		return r.cncfNativeResourceCheck(*project, *prometheusConfig, *prometheusConfigPin, *currentResource, *currentResourcePin, *resource, *resourcePin, *prometheusRemoteWriteName, *prometheusConfigComplete, *prometheusConfigPrecedenceResolved, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, false, "", false, "", "", "", "", args, required, "")
	}
	if prometheusScrapeFlags && *project != "prometheus" {
		return r.usage("Prometheus scrape configuration flags require project prometheus; use --help")
	}
	if *project == "prometheus" && prometheusScrapeFlags {
		return r.cncfNativeResourceCheck(*project, *scrapeConfig, *scrapeConfigPin, *currentResource, *currentResourcePin, *resource, *resourcePin, *scrapeJob, *scrapeConfigComplete, *scrapeConfigPrecedenceResolved, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, false, "", false, "", "", "", "", args, nil, "")
	}
	if prometheusAlertmanagerFlags && *project != "prometheus" {
		return r.usage("Prometheus Alertmanager configuration flags require project prometheus; use --help")
	}
	if *project == "prometheus" && prometheusAlertmanagerFlags {
		return r.cncfNativeResourceCheck(*project, *alertmanagerConfig, *alertmanagerConfigPin, *currentResource, *currentResourcePin, *resource, *resourcePin, "", *alertmanagerConfigComplete, *alertmanagerConfigPrecedenceResolved, *from, *to, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format, false, "", false, "", "", "", "", args, nil, "")
	}
	if containerdFlags && *project != "containerd" {
		return r.usage("containerd configuration flags require project containerd; use --help")
	}
	if *project == "containerd" && containerdFlags {
		if *containerdConfig == "" || *containerdRuntimeHandler == "" || *from == "" || *to == "" || cncfUnexpectedModeFlag(args, "containerd-config", "containerd-config-digest", "runtime-handler", "containerd-config-complete", "containerd-config-precedence-resolved", "containerd-official-upstream", "containerd-official-bundled-runtimes-only") {
			return r.usage("invalid containerd configuration check arguments; use --help")
		}
		return r.cncfContainerdConfig(*containerdConfig, *containerdConfigPin, *containerdRuntimeHandler, *from, *to, *containerdConfigComplete, *containerdConfigPrecedenceResolved, *containerdOfficialUpstream, *containerdOfficialBundledRuntimesOnly, *nowText, *knowledgeDB, *knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest, *replay, *format)
	}
	resourceExclusionsArgoRequested := *project == "argo-cd" && anyFlagProvided(args, "resource-exclusions-config-map", "resource-exclusions-config-map-digest", "resource-exclusions-config-complete", "resource-exclusions-precedence-resolved", "requires-v2-visibility-of-v3-default-excluded-resources")
	argoCDLatestRequested := *project == "argo-cd" && !resourceExclusionsArgoRequested && anyFlagProvided(args, "repository-secret", "repository-secret-digest", "repository-distribution", "repository-settings-resolved", "repository-uses-plain-http")
	rawArgoRequested := *project == "argo-cd" && !resourceExclusionsArgoRequested && !argoCDLatestRequested && anyFlagProvided(args, "config-map", "config-map-digest", "from", "to", "requires-inherited-application-permissions")
	linkerdRequested := *project == "linkerd" && anyFlagProvided(args, "linkerd-resource", "linkerd-resource-digest", "linkerd-distribution", "schema-validation", "from", "to")
	karmadaRequested := *project == "karmada" && anyFlagProvided(args, "karmada-resource", "karmada-resource-digest", "karmada-distribution", "target-policy-crd-admission", "from", "to")
	ciliumPolicyRequested := *project == "cilium" && !ciliumNativeRequested && anyFlagProvided(args, "cilium-policy", "cilium-policy-digest", "complete-cnp-ccnp-set")
	kubeEdgeRequested := *project == "kubeedge" && anyFlagProvided(args, "keadm-init-argv", "keadm-init-argv-digest", "kubeedge-distribution", "keadm-argv-complete")
	tektonRequested := *project == "tekton" && anyFlagProvided(args, "tekton-config-observability", "tekton-config-observability-digest", "tekton-distribution", "tekton-system-namespace", "tekton-config-observability-complete", "retain-prometheus-metrics-required")
	rawKnativeRequested := *project == "knative" && anyFlagProvided(args, "service", "service-digest", "from", "to")
	rawBuildpacksRequested := *project == "buildpacks" && anyFlagProvided(args, "current-lifecycle-config", "proposed-lifecycle-config", "current-lifecycle-config-digest", "proposed-lifecycle-config-digest", "current-platform-api", "proposed-platform-api", "from", "to")
	rawInTotoRequested := *project == "in-toto" && anyFlagProvided(args, "in-toto-run-argv", "in-toto-run-argv-digest", "from", "to")
	rawTUFRequested := *project == "the-update-framework-tuf" && anyFlagProvided(args, "python-source", "python-source-digest", "from", "to")
	rawKubeflowRequested := *project == "kubeflow" && anyFlagProvided(args, "python-source", "python-source-digest", "from", "to")
	rawCubeFSRequested := *project == "cubefs" && anyFlagProvided(args, "metanode-config", "metanode-config-digest", "phase", "from", "to")
	rawCRIORequested := *project == "cri-o" && anyFlagProvided(args, "image-status-request", "image-status-request-digest", "artifact-operation", "from", "to")
	rawDistributionRequested := *project == "distribution" && anyFlagProvided(args, "image-manifest", "image-manifest-digest", "from", "to")
	rawCNISpecRequested := *project == "container-network-interface-cni" && anyFlagProvided(args, "cni-configuration", "cni-configuration-digest", "operation", "from", "to")
	rawEmissaryRequested := *project == "emissary-ingress" && anyFlagProvided(args, "diagd-argv", "diagd-argv-digest", "from", "to")
	rawOpenFGARequested := *project == "openfga" && anyFlagProvided(args, "effective-config", "effective-config-digest", "effective-config-complete", "from", "to")
	formatFlagsProvided := anyFlagProvided(args, "image-manifest", "image-manifest-digest", "cni-configuration", "cni-configuration-digest", "operation", "diagd-argv", "diagd-argv-digest", "effective-config", "effective-config-digest", "effective-config-complete")
	if formatFlagsProvided && !rawDistributionRequested && !rawCNISpecRequested && !rawEmissaryRequested && !rawOpenFGARequested {
		return r.usage("invalid native format check arguments; use --help")
	}
	if rawDistributionRequested || rawCNISpecRequested || rawEmissaryRequested || rawOpenFGARequested {
		if *from == "" || *to == "" || (*knowledgeDB == "" && flagProvided(args, "replay-report")) || (rawDistributionRequested && (*imageManifest == "" || cncfUnexpectedModeFlag(args, "image-manifest", "image-manifest-digest"))) || (rawCNISpecRequested && (*cniConfiguration == "" || cncfUnexpectedModeFlag(args, "cni-configuration", "cni-configuration-digest", "operation"))) || (rawEmissaryRequested && (*diagdArgv == "" || cncfUnexpectedModeFlag(args, "diagd-argv", "diagd-argv-digest"))) || (rawOpenFGARequested && (*effectiveConfig == "" || cncfUnexpectedModeFlag(args, "effective-config", "effective-config-digest", "effective-config-complete"))) {
			return r.usage("invalid native format check arguments; use --help")
		}
	}
	if rawDistributionRequested || rawCNISpecRequested || rawEmissaryRequested || rawOpenFGARequested {
		// The closed selector checks above admitted the selected format route.
	} else if resourceExclusionsArgoRequested {
		if *resourceExclusionsConfigMap == "" || !*resourceExclusionsComplete || !*resourceExclusionsPrecedence || (*requiresV2Visibility != "" && *requiresV2Visibility != "true") || cncfUnexpectedModeFlag(args, "resource-exclusions-config-map", "resource-exclusions-config-map-digest", "resource-exclusions-config-complete", "resource-exclusions-precedence-resolved", "requires-v2-visibility-of-v3-default-excluded-resources") || *from == "" || *to == "" || *nowText == "" || flagProvided(args, "knowledge-db") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest") || flagProvided(args, "replay-report") {
			return r.usage("invalid Argo CD resource-exclusions check arguments; use --help")
		}
	} else if rawArgoRequested {
		if *configMap == "" || cncfUnexpectedModeFlag(args, "config-map", "config-map-digest", "requires-inherited-application-permissions") || *from == "" || *to == "" || *nowText == "" || flagProvided(args, "knowledge-db") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest") || flagProvided(args, "replay-report") || (flagProvided(args, "requires-inherited-application-permissions") && *requiresInheritedPermissions != "true" && *requiresInheritedPermissions != "false") {
			return r.usage("invalid Argo CD ConfigMap check arguments; use --help")
		}
	} else if argoCDLatestRequested {
		if *repositorySecret == "" || cncfUnexpectedModeFlag(args, "repository-secret", "repository-secret-digest", "repository-distribution", "repository-settings-resolved", "repository-uses-plain-http") || *from == "" || *to == "" || *nowText == "" || flagProvided(args, "knowledge-db") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest") || flagProvided(args, "replay-report") || (*repositoryDistribution != "" && *repositoryDistribution != cncfprepare.ArgoCDLatestDistributionOfficial && *repositoryDistribution != cncfprepare.ArgoCDLatestDistributionCustom) || (*repositorySettingsResolved != "" && *repositorySettingsResolved != "true" && *repositorySettingsResolved != "false") || (*repositoryUsesPlainHTTP != "" && *repositoryUsesPlainHTTP != "true" && *repositoryUsesPlainHTTP != "false") {
			return r.usage("invalid Argo CD repository check arguments; use --help")
		}
	} else if linkerdRequested {
		if *linkerdResource == "" || cncfUnexpectedModeFlag(args, "linkerd-resource", "linkerd-resource-digest", "linkerd-distribution", "schema-validation") || *from == "" || *to == "" || *nowText == "" || flagProvided(args, "knowledge-db") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest") || flagProvided(args, "replay-report") || (*linkerdDistribution != "" && *linkerdDistribution != cncfprepare.LinkerdDistributionOfficial && *linkerdDistribution != cncfprepare.LinkerdDistributionCustom) || (*linkerdSchemaValidation != "" && *linkerdSchemaValidation != cncfprepare.LinkerdSchemaRequired && *linkerdSchemaValidation != cncfprepare.LinkerdSchemaDisabled) {
			return r.usage("invalid Linkerd resource check arguments; use --help")
		}
	} else if karmadaRequested {
		if *karmadaResource == "" || cncfUnexpectedModeFlag(args, "karmada-resource", "karmada-resource-digest", "karmada-distribution", "target-policy-crd-admission") || *from == "" || *to == "" || *nowText == "" || flagProvided(args, "knowledge-db") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest") || flagProvided(args, "replay-report") || (*karmadaDistribution != "" && *karmadaDistribution != cncfprepare.KarmadaDistributionOfficial && *karmadaDistribution != cncfprepare.KarmadaDistributionCustom) || (*karmadaTargetPolicyCRDAdmission != "" && *karmadaTargetPolicyCRDAdmission != cncfprepare.KarmadaAdmissionRequired && *karmadaTargetPolicyCRDAdmission != cncfprepare.KarmadaAdmissionDisabled) {
			return r.usage("invalid Karmada resource check arguments; use --help")
		}
	} else if ciliumPolicyRequested {
		if *ciliumPolicy == "" || cncfUnexpectedModeFlag(args, "cilium-policy", "cilium-policy-digest", "complete-cnp-ccnp-set") || *from == "" || *to == "" || *nowText == "" || flagProvided(args, "knowledge-db") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest") || flagProvided(args, "replay-report") || (*ciliumCompleteCNPCCNPSet != "" && *ciliumCompleteCNPCCNPSet != "true" && *ciliumCompleteCNPCCNPSet != "false") {
			return r.usage("invalid Cilium policy check arguments; use --help")
		}
	} else if kubeEdgeRequested {
		if *keadmInitArgv == "" || cncfUnexpectedModeFlag(args, "keadm-init-argv", "keadm-init-argv-digest", "kubeedge-distribution", "keadm-argv-complete") || *from == "" || *to == "" || *nowText == "" || flagProvided(args, "knowledge-db") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest") || flagProvided(args, "replay-report") || (*kubeEdgeDistribution != "" && *kubeEdgeDistribution != cncfprepare.KubeEdgeDistributionOfficial && *kubeEdgeDistribution != cncfprepare.KubeEdgeDistributionCustom) || (*keadmArgvComplete != "" && *keadmArgvComplete != "true" && *keadmArgvComplete != "false") {
			return r.usage("invalid KubeEdge keadm init argv check arguments; use --help")
		}
	} else if tektonRequested {
		if *tektonConfigObservability == "" || cncfUnexpectedModeFlag(args, "tekton-config-observability", "tekton-config-observability-digest", "tekton-distribution", "tekton-system-namespace", "tekton-config-observability-complete", "retain-prometheus-metrics-required") || *from == "" || *to == "" || *nowText == "" || flagProvided(args, "knowledge-db") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest") || flagProvided(args, "replay-report") || (*tektonDistribution != "" && *tektonDistribution != cncfprepare.TektonDistributionOfficial && *tektonDistribution != cncfprepare.TektonDistributionCustom) || (*tektonConfigObservabilityComplete != "" && *tektonConfigObservabilityComplete != "true" && *tektonConfigObservabilityComplete != "false") || (*tektonRetainPrometheus != "" && *tektonRetainPrometheus != "true" && *tektonRetainPrometheus != "false") {
			return r.usage("invalid Tekton config-observability check arguments; use --help")
		}
	} else if rawKnativeRequested {
		if *service == "" || cncfUnexpectedModeFlag(args, "service", "service-digest") || *from == "" || *to == "" || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid Knative Serving Service check arguments; use --help")
		}
	} else if rawBuildpacksRequested {
		if *currentLifecycleConfig == "" || *proposedLifecycleConfig == "" || *currentPlatformAPI == "" || *proposedPlatformAPI == "" || *from == "" || *to == "" || cncfUnexpectedModeFlag(args, "current-lifecycle-config", "proposed-lifecycle-config", "current-lifecycle-config-digest", "proposed-lifecycle-config-digest", "current-platform-api", "proposed-platform-api") || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid Buildpacks Lifecycle check arguments; use --help")
		}
	} else if rawInTotoRequested {
		if *inTotoRunArgv == "" || *from == "" || *to == "" || cncfUnexpectedModeFlag(args, "in-toto-run-argv", "in-toto-run-argv-digest") || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid in-toto-run argv check arguments; use --help")
		}
	} else if rawTUFRequested {
		if *pythonSource == "" || *from == "" || *to == "" || cncfUnexpectedModeFlag(args, "python-source", "python-source-digest") || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid TUF Updater Python source check arguments; use --help")
		}
	} else if rawKubeflowRequested {
		if *pythonSource == "" || *from == "" || *to == "" || cncfUnexpectedModeFlag(args, "python-source", "python-source-digest") || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid KFP Python source check arguments; use --help")
		}
	} else if rawCubeFSRequested {
		if *metanodeConfig == "" || *from == "" || *to == "" || cncfUnexpectedModeFlag(args, "metanode-config", "metanode-config-digest", "phase") || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid CubeFS MetaNode config check arguments; use --help")
		}
	} else if rawCRIORequested {
		if *imageStatusRequest == "" || *from == "" || *to == "" || cncfUnexpectedModeFlag(args, "image-status-request", "image-status-request-digest", "artifact-operation") || (*knowledgeDB == "" && (*nowText == "" || flagProvided(args, "replay-report") || flagProvided(args, "knowledge-revision") || flagProvided(args, "knowledge-bundle-digest") || flagProvided(args, "knowledge-trust-receipt-digest"))) {
			return r.usage("invalid CRI-O ImageStatusRequest check arguments; use --help")
		}
	} else if *input == "" || cncfUnexpectedModeFlag(args, "input", "input-digest") || anyFlagProvided(args, "from", "to") {
		return r.usage("invalid CNCF check arguments; use --help")
	}
	var now time.Time
	var err error
	if *knowledgeDB == "" {
		if *knowledgeRevision != "" || *knowledgeBundleDigest != "" || *knowledgeTrustReceiptDigest != "" || *nowText == "" {
			return r.usage("invalid CNCF check arguments; use --help")
		}
		now, err = parseUTC(*nowText)
		if err != nil || now.Nanosecond() != 0 || now.Format(time.RFC3339) != *nowText {
			return r.usage("CNCF check time must be explicit canonical UTC with whole seconds")
		}
	} else if flagProvided(args, "now") || (*replay != "" && ((!rawKnativeRequested && !rawBuildpacksRequested && !rawInTotoRequested && !rawTUFRequested && !rawKubeflowRequested && !rawCubeFSRequested && !rawCRIORequested && !rawDistributionRequested && !rawCNISpecRequested && !rawEmissaryRequested && !rawOpenFGARequested && *pin == "") || (rawKnativeRequested && *servicePin == "") || (rawBuildpacksRequested && (*currentLifecyclePin == "" || *proposedLifecyclePin == "")) || (rawInTotoRequested && *inTotoRunArgvPin == "") || ((rawTUFRequested || rawKubeflowRequested) && *pythonSourcePin == "") || (rawCubeFSRequested && *metanodeConfigPin == "") || (rawCRIORequested && *imageStatusRequestPin == "") || (rawDistributionRequested && *imageManifestPin == "") || (rawCNISpecRequested && *cniConfigurationPin == "") || (rawEmissaryRequested && *diagdArgvPin == "") || (rawOpenFGARequested && *effectiveConfigPin == "") || *knowledgeRevision == "" || *knowledgeBundleDigest == "" || *knowledgeTrustReceiptDigest == "")) {
		return r.usage("external CNCF checks use verifier time; historical replay requires complete input and knowledge pins")
	}
	if _, err := cncfcheck.Catalog(false, *project); err != nil {
		return r.cncfError("CNCF project selection failed", err)
	}
	if resourceExclusionsArgoRequested {
		return r.cncfArgoCDResourceExclusions(*resourceExclusionsConfigMap, *resourceExclusionsConfigMapPin, *from, *to, *resourceExclusionsComplete, *resourceExclusionsPrecedence, *requiresV2Visibility, now, *format)
	}
	if rawArgoRequested {
		return r.cncfArgoCDConfigMap(*configMap, *configMapPin, *from, *to, *requiresInheritedPermissions, now, *format)
	}
	if argoCDLatestRequested {
		return r.cncfArgoCDLatestRepository(*repositorySecret, *repositorySecretPin, *from, *to, *repositoryDistribution, *repositorySettingsResolved, *repositoryUsesPlainHTTP, now, *format)
	}
	if linkerdRequested {
		return r.cncfLinkerdCheck(*linkerdResource, *linkerdResourcePin, *from, *to, *linkerdDistribution, *linkerdSchemaValidation, now, *format)
	}
	if karmadaRequested {
		return r.cncfKarmadaCheck(*karmadaResource, *karmadaResourcePin, *from, *to, *karmadaDistribution, *karmadaTargetPolicyCRDAdmission, now, *format)
	}
	if ciliumPolicyRequested {
		return r.cncfCiliumPolicyCheck(*ciliumPolicy, *ciliumPolicyPin, *from, *to, *ciliumCompleteCNPCCNPSet, now, *format)
	}
	if kubeEdgeRequested {
		return r.cncfKubeEdgeInitArgvCheck(*keadmInitArgv, *keadmInitArgvPin, *from, *to, *kubeEdgeDistribution, *keadmArgvComplete, now, *format)
	}
	if tektonRequested {
		return r.cncfTektonConfigObservabilityCheck(*tektonConfigObservability, *tektonConfigObservabilityPin, *from, *to, *tektonDistribution, *tektonSystemNamespace, *tektonConfigObservabilityComplete, *tektonRetainPrometheus, now, *format)
	}
	if rawKnativeRequested {
		if *knowledgeDB != "" {
			selection := knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
			return r.cncfKnativeService(*service, *servicePin, *from, *to, now, *format, &selection, *replay)
		}
		return r.cncfKnativeService(*service, *servicePin, *from, *to, now, *format, nil, "")
	}
	if rawBuildpacksRequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfBuildpacksLifecycle(*currentLifecycleConfig, *proposedLifecycleConfig, *currentLifecyclePin, *proposedLifecyclePin, *from, *to, *currentPlatformAPI, *proposedPlatformAPI, now, *format, selection, *replay)
	}
	if rawInTotoRequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfInTotoRun(*inTotoRunArgv, *inTotoRunArgvPin, *from, *to, now, *format, selection, *replay)
	}
	if rawTUFRequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfTUFUpdater(*pythonSource, *pythonSourcePin, *from, *to, now, *format, selection, *replay)
	}
	if rawKubeflowRequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfKubeflowKFP(*pythonSource, *pythonSourcePin, *from, *to, now, *format, selection, *replay)
	}
	if rawCubeFSRequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfCubeFSMetaNode(*metanodeConfig, *metanodeConfigPin, *from, *to, *phase, now, *format, selection, *replay)
	}
	if rawCRIORequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfCRIOArtifactName(*imageStatusRequest, *imageStatusRequestPin, *from, *to, *artifactOperation, now, *format, selection, *replay)
	}
	if rawDistributionRequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfNativeFormat("distribution", *imageManifest, *imageManifestPin, *from, *to, "", now, *format, selection, *replay)
	}
	if rawCNISpecRequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfNativeFormat("container-network-interface-cni", *cniConfiguration, *cniConfigurationPin, *from, *to, *operation, now, *format, selection, *replay)
	}
	if rawEmissaryRequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		return r.cncfNativeFormat("emissary-ingress", *diagdArgv, *diagdArgvPin, *from, *to, "", now, *format, selection, *replay)
	}
	if rawOpenFGARequested {
		var selection *knowledge.SelectionRequest
		if *knowledgeDB != "" {
			selection = &knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest}
		}
		complete := ""
		if flagProvided(args, "effective-config-complete") {
			complete = strconv.FormatBool(*effectiveConfigComplete)
		}
		return r.cncfNativeFormat("openfga", *effectiveConfig, *effectiveConfigPin, *from, *to, complete, now, *format, selection, *replay)
	}
	raw, err := readCNCFPrivate(*input, 1<<20)
	if err != nil {
		return r.cncfError("CNCF input failed local admission", err)
	}
	if *pin != "" {
		sum := sha256.Sum256(raw)
		if "sha256:"+hex.EncodeToString(sum[:]) != *pin {
			return r.fail("CNCF input digest does not match", ExitIntegrity)
		}
	}
	if *knowledgeDB != "" {
		return r.externalCNCF(cncfknowledge.Request{
			Selection: knowledge.SelectionRequest{StoreRoot: *knowledgeDB, ExpectedRevision: *knowledgeRevision, ExpectedBundleDigest: *knowledgeBundleDigest, ExpectedTrustReceiptDigest: *knowledgeTrustReceiptDigest},
			Project:   *project, Input: raw, InputDigest: *pin,
		}, *replay, *format)
	}
	var report cncfcheck.Report
	if *replay != "" {
		expected, readErr := readCNCFPrivate(*replay, 4<<20)
		if readErr != nil {
			return r.cncfError("CNCF replay report failed local admission", readErr)
		}
		report, err = r.cncfChecker().Replay(*project, raw, now, expected)
	} else {
		report, err = r.cncfChecker().Check(*project, raw, now)
	}
	if err != nil {
		return r.cncfError("CNCF source-constraint check failed", err)
	}
	encoded, err := cncfcheck.MarshalReport(report)
	if err != nil {
		return r.fail("CNCF report integrity failure", ExitIntegrity)
	}
	if *format == "json" {
		if _, err := fmt.Fprintln(r.stdout, string(encoded)); err != nil {
			return ExitIntegrity
		}
	} else {
		fmt.Fprintf(r.stdout, "%s source-constraint preview\ninput authority: %s\nknowledge: embedded revision %s\nruntime transitions reproduced: 0\nnetwork used: false\n", report.Project, report.Check.InputAuthority, report.KnowledgeRevision)
		if r.knowledgeSource != "" {
			fmt.Fprintf(r.stdout, "knowledge source: %s\n", r.knowledgeSource)
		}
		if err := writeBasisHeadline(r.stdout, report.Check.Claims, report.TrustPolicy); err != nil {
			return ExitIntegrity
		}
		summary := summarizeClaims(report.Check.Claims, *showPasses)
		if summary.allUnreviewed {
			from, to, _ := canonicalTransition(raw)
			if err := writeUnreviewedTransition(r.stdout, report.Project, from, to); err != nil {
				return ExitIntegrity
			}
		}
		for _, claim := range summary.shown {
			fmt.Fprintf(r.stdout, "%s: %s (%s)\nnext action: %s\n", claim.RuleID, claim.Status, claim.ReasonCode, claim.NextAction)
			if line, ok := claim.MatchedMembersLine(); ok {
				fmt.Fprintln(r.stdout, line)
			}
			fmt.Fprintln(r.stdout, claim.EvidenceBasisLine())
		}
		if err := writeNotices(r.stdout, summary.notices); err != nil {
			return ExitIntegrity
		}
		if err := writeNoVerdictLine(r.stdout, report.Check.Claims); err != nil {
			return ExitIntegrity
		}
		if err := writeCustomResourceScope(r.stdout, report.Check.Claims); err != nil {
			return ExitIntegrity
		}
		if !summary.allUnreviewed {
			if err := writeCollapsedNotes(r.stdout, summary); err != nil {
				return ExitIntegrity
			}
		}
		fmt.Fprintln(r.stdout, "aggregate: UNKNOWN")
		fmt.Fprintf(r.stdout, "input digest: %s\nknowledge pack digest: %s\nnext action: %s\n", report.InputFileDigest, report.KnowledgePackDigest, report.NextAction)
		if *replay != "" {
			fmt.Fprintln(r.stdout, "historical replay: MATCH; current freshness and non-revocation are not established")
		}
	}
	return cncfcheck.ClaimExit(report)
}

func anyFlagProvided(args []string, names ...string) bool {
	for _, name := range names {
		if flagProvided(args, name) {
			return true
		}
	}
	return false
}

// cncfUnexpectedModeFlag rejects an explicitly supplied input selector that
// belongs to another CNCF check mode. Keep this complete when adding a new
// check input flag: otherwise a later route can parse a supplied selector and
// silently ignore it. Common selection, replay, output, and time flags do not
// belong here because their validation is shared by the selected mode.
func cncfUnexpectedModeFlag(args []string, allowed ...string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}
	for _, name := range cncfModeInputFlags {
		if flagProvided(args, name) {
			if _, ok := allowedSet[name]; !ok {
				return true
			}
		}
	}
	return false
}

// cncfModeInputFlags is the closed set of input selectors admitted by check
// cncf. Some names are reserved for accepted upcoming format adapters so their
// eventual FlagSet registration cannot create an ignored cross-mode input.
var cncfModeInputFlags = []string{
	"input", "input-digest",
	"config-map", "config-map-digest", "requires-inherited-application-permissions",
	"resource-exclusions-config-map", "resource-exclusions-config-map-digest", "resource-exclusions-config-complete", "resource-exclusions-precedence-resolved", "requires-v2-visibility-of-v3-default-excluded-resources",
	"repository-secret", "repository-secret-digest", "repository-distribution", "repository-settings-resolved", "repository-uses-plain-http",
	"linkerd-resource", "linkerd-resource-digest", "linkerd-distribution", "schema-validation",
	"karmada-resource", "karmada-resource-digest", "karmada-distribution", "target-policy-crd-admission",
	"cilium-policy", "cilium-policy-digest", "complete-cnp-ccnp-set",
	"keadm-init-argv", "keadm-init-argv-digest", "kubeedge-distribution", "keadm-argv-complete",
	"tekton-config-observability", "tekton-config-observability-digest", "tekton-distribution", "tekton-system-namespace", "tekton-config-observability-complete", "retain-prometheus-metrics-required",
	"service", "service-digest",
	"current-lifecycle-config", "proposed-lifecycle-config",
	"current-lifecycle-config-digest", "proposed-lifecycle-config-digest",
	"current-platform-api", "proposed-platform-api",
	"in-toto-run-argv", "in-toto-run-argv-digest",
	"python-source", "python-source-digest",
	"metanode-config", "metanode-config-digest", "phase",
	"image-status-request", "image-status-request-digest", "artifact-operation",
	"native-resource", "native-resource-digest",
	"component-config", "component-config-digest",
	"resource-scope-complete", "distribution", "target-api-apply-required",
	"cilium-config-map", "cilium-config-map-digest", "cilium-config-complete", "cilium-config-precedence-resolved", "cilium-distribution",
	"nats-config", "nats-config-digest",
	"kafka-resource", "kafka-resource-digest", "strimzi-distribution", "target-kafka-crd-admission-required",
	"falco-argv", "falco-argv-digest", "falco-distribution",
	"kumactl-argv", "kumactl-argv-digest", "kuma-distribution",
	"composition", "composition-digest", "crossplane-distribution", "crossplane-schema-validation-required",
	"upgrade-plan", "upgrade-plan-digest", "velero-server-deployment", "velero-plan-order-declared",
	"spire-entry-argv", "spire-entry-argv-digest", "spire-distribution",
	"keda-scaled-object", "keda-scaled-object-digest", "keda-scaled-object-complete", "keda-legacy-tls-transport-required",
	"otel-collector-config", "otel-collector-config-digest", "otel-distribution", "otel-config-complete", "otel-config-precedence-resolved",
	"scrape-config", "scrape-config-digest", "scrape-job", "scrape-config-complete", "scrape-config-precedence-resolved",
	"alertmanager-config", "alertmanager-config-digest", "alertmanager-config-complete", "alertmanager-config-precedence-resolved",
	"current-resource", "current-resource-digest", "resource", "resource-digest",
	"image-manifest", "image-manifest-digest",
	"cni-configuration", "cni-configuration-digest", "operation",
	"containerd-config", "containerd-config-digest", "runtime-handler", "containerd-config-complete", "containerd-config-precedence-resolved", "containerd-official-upstream", "containerd-official-bundled-runtimes-only",
	"effective-config", "effective-config-complete",
	"effective-config-digest", "diagd-argv", "diagd-argv-digest",
	"jaeger-argv", "jaeger-argv-digest", "non-memory-storage-required", "official-jaeger-distribution",
	"custom-resources", "custom-resources-digest", "custom-resources-complete",
}

func (r runtime) knativeInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.knativeIntegrityFailure()
	}
	return r.fail(withPermissionHint("KNATIVE_SERVING_PREPARATION_INPUT_INVALID", err), ExitUsage)
}

func (r runtime) buildpacksInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.knativeIntegrityFailure()
	}
	return r.fail(withPermissionHint("BUILDPACKS_LIFECYCLE_PREPARATION_INPUT_INVALID", err), ExitUsage)
}

func (r runtime) inTotoInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.knativeIntegrityFailure()
	}
	return r.fail(withPermissionHint("IN_TOTO_RUN_PREPARATION_INPUT_INVALID", err), ExitUsage)
}

func (r runtime) tufInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.knativeIntegrityFailure()
	}
	if errors.Is(err, cncfprepare.ErrTUFSourceParse) {
		return r.fail("TUF_SOURCE_OUTSIDE_ADMITTED_GO_LEXICAL_SYNTAX", ExitUsage)
	}
	return r.fail(withPermissionHint("TUF_UPDATER_SOURCE_PREPARATION_INPUT_INVALID", err), ExitUsage)
}

func (r runtime) kubeflowKFPInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.knativeIntegrityFailure()
	}
	if errors.Is(err, cncfprepare.ErrKubeflowKFPSourceParse) {
		return r.fail("KUBEFLOW_KFP_SOURCE_OUTSIDE_ADMITTED_GO_LEXICAL_SYNTAX", ExitUsage)
	}
	return r.fail(withPermissionHint("KUBEFLOW_KFP_SOURCE_PREPARATION_INPUT_INVALID", err), ExitUsage)
}

func (r runtime) cubeFSInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.knativeIntegrityFailure()
	}
	return r.fail(withPermissionHint("CUBEFS_METANODE_PREPARATION_INPUT_INVALID", err), ExitUsage)
}

func (r runtime) crioInputFailure(err error) int {
	if errors.Is(err, currentbundle.ErrIntegrity) {
		return r.knativeIntegrityFailure()
	}
	return r.fail(withPermissionHint("CRIO_IMAGE_STATUS_REQUEST_PREPARATION_INPUT_INVALID", err), ExitUsage)
}

func (r runtime) knativeIntegrityFailure() int {
	return r.fail("CNCF_PREPARATION_INTEGRITY_FAILURE", ExitIntegrity)
}

// ErrInsecurePermissions is the sentinel readCNCFPrivate returns when an
// otherwise-readable input file exists but is not owner-only (mode 0600).
// It is always wrapped alongside cncfcheck.ErrInvalid so every existing
// errors.Is(err, cncfcheck.ErrInvalid) / exit-code path is unaffected;
// callers that want the human-readable hint check for it explicitly via
// withPermissionHint or permissionHintFor.
var ErrInsecurePermissions = errors.New("input file must be readable and writable by its owner only (mode 0600)")

// permissionHintFor returns the human-readable, actionable suffix for a
// readCNCFPrivate failure caused specifically by insecure file permissions,
// or "" for every other failure (missing file, wrong size, symlink, not a
// regular file, changed during read, and so on), which keep their existing
// unadorned messages. It never repeats file contents or the caller's actual
// path; "<file>" is a literal placeholder.
func permissionHintFor(err error) string {
	if !errors.Is(err, ErrInsecurePermissions) {
		return ""
	}
	return "input file is readable or writable by group or others; prufyx requires owner-only permissions to protect its private contents; run `chmod 600 <file>` and retry"
}

// withPermissionHint appends permissionHintFor's guidance to message when
// err was caused by insecure permissions, leaving every other message,
// reason code, and exit code exactly as before.
func withPermissionHint(message string, err error) string {
	if hint := permissionHintFor(err); hint != "" {
		return message + ": " + hint
	}
	return message
}

func readCNCFPrivate(path string, limit int) ([]byte, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, cncfcheck.ErrInvalid
	}
	raw, info, err := currentbundle.ReadBoundedFileInfo(absolute, limit)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, cncfcheck.ErrInvalid
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %w", ErrInsecurePermissions, cncfcheck.ErrInvalid)
	}
	return raw, nil
}

func (r runtime) cncfError(message string, err error) int {
	if errors.Is(err, cncfcheck.ErrIntegrity) || errors.Is(err, currentbundle.ErrIntegrity) {
		return r.fail(message, ExitIntegrity)
	}
	return r.fail(withPermissionHint(message, err), ExitUsage)
}
