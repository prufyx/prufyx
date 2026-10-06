// SPDX-License-Identifier: AGPL-3.0-only

// Package checkroutemetadata exposes compiled rule identities and a small,
// declarative index of native public routes. It never reads caller files or
// evaluates rules.
package checkroutemetadata

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/projectcheck"
)

const Schema = "prufyx.io/check-route-catalog/v1alpha1"

const (
	FamilyCNCF      = "cncf_embedded_source_rule"
	FamilyCommunity = "community_project_embedded_source_rule"
	RouteExposed    = "EXPOSED_CANONICAL_INPUT"
	RouteNotExposed = "NOT_EXPOSED_BY_PUBLIC_CLI"
	DescriptorExact = "EXACT_PAIR_NATIVE_ROUTE"
	DescriptorNone  = "NO_NATIVE_DESCRIPTOR"
)

var ErrIntegrity = errors.New("check-route metadata integrity failure")

type Scope struct {
	IncludedFamilies        []string `json:"includedFamilies"`
	ExcludedFamilies        []string `json:"excludedFamilies"`
	CoverageMeaning         string   `json:"coverageMeaning"`
	SourceEvidenceFreshness string   `json:"sourceEvidenceFreshness"`
}

type Query struct {
	Project string `json:"project"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
}

type NamedCheckHint struct {
	Command  []Argument `json:"command"`
	HelpOnly bool       `json:"helpOnly"`
}

type Argument struct {
	Name          string   `json:"name"`
	Kind          string   `json:"kind"`
	Literal       string   `json:"literal,omitempty"`
	AllowedValues []string `json:"allowedValues,omitempty"`
}

type Route struct {
	State      string     `json:"state"`
	Command    []Argument `json:"command,omitempty"`
	Limit      string     `json:"limit,omitempty"`
	NativePass string     `json:"nativePass,omitempty"`
}

type Check struct {
	Family                  string `json:"family"`
	Project                 string `json:"project"`
	Component               string `json:"component"`
	RuleID                  string `json:"ruleId"`
	From                    string `json:"from"`
	To                      string `json:"to"`
	GenericDeclarationRoute Route  `json:"genericDeclarationRoute"`
	NativeDescriptor        Route  `json:"nativeDescriptor"`
	// Range and MatchMode are present only for a rule with a reviewed range.
	// MatchMode is "range" only when the query pair matched the range rather
	// than the anchor pair. Native descriptors stay exact-pair.
	Range     *constraintengine.VersionRange `json:"range,omitempty"`
	MatchMode string                         `json:"matchMode,omitempty"`
}

// Transition returns the check's reviewed subject for the shared matcher.
func (c Check) Transition() constraintengine.RuleTransition {
	return constraintengine.RuleTransition{Component: c.Component, From: c.From, To: c.To, Range: c.Range}
}

type Result struct {
	Schema            string           `json:"schema"`
	MetadataSource    string           `json:"metadataSource"`
	SourceOnlyState   string           `json:"sourceOnlyState"`
	RuleCoverageState string           `json:"ruleCoverageState"`
	Scope             Scope            `json:"scope"`
	Query             Query            `json:"query"`
	NamedCheckHints   []NamedCheckHint `json:"namedCheckHints"`
	Checks            []Check          `json:"checks"`
}

type descriptor struct {
	family, project, component, ruleID, from, to string
	command                                      []Argument
	limit, nativePass                            string
}

// LegacyInventoryRoute is a lossless adapter for the published support
// inventory records that describe the exact Prometheus and Envoy routes above.
// It keeps that inventory's v1 shape outside the public catalog schema.
type LegacyInventoryRoute struct {
	Command       []any
	MetadataState string
	Limit         string
}

// LegacyInventoryRoutes returns the unchanged support-inventory route records
// for the two projects whose public native routes are also mechanically bound
// in this package. Other inventory routes intentionally remain local to the
// maintainer-only generator.
func LegacyInventoryRoutes(project string) ([]LegacyInventoryRoute, bool) {
	routes := make([]LegacyInventoryRoute, 0, 3)
	for _, item := range descriptorSet() {
		if item.project != project {
			continue
		}
		state := ""
		switch item.ruleID {
		case "envoy.xds-v2-unsupported-at-1-39-1-from-1-38-4":
			state = "implemented_native_selected_envoy_bootstrap_minimizer"
		case "prometheus.alertmanager-api-v1-removed.3-1":
			state = "implemented_native_selected_alertmanager_config_minimizer"
		case "prometheus.scrape-classic-histograms-key-renamed.3-1":
			state = "implemented_native_selected_scrape_config_minimizer"
		case "prometheus.remote-write-http2-default.2-55-1-to-3-14-0":
			state = "implemented_native_selected_remote_write_http2_minimizer"
		}
		if state != "" {
			routes = append(routes, LegacyInventoryRoute{Command: legacyCommandFor(item.ruleID, item.command), MetadataState: state, Limit: legacyLimit(item.ruleID)})
		}
	}
	return routes, len(routes) != 0
}

// LegacyCommunityInventoryRoute supplies the existing MariaDB Operator
// preparer record from the same exact descriptor used by catalog checks.
func LegacyCommunityInventoryRoute(project string) (LegacyInventoryRoute, bool) {
	if project != "mariadb-operator" {
		return LegacyInventoryRoute{}, false
	}
	for _, item := range descriptorSet() {
		if item.project != project || item.ruleID != "mariadb-operator.upgrade-26-6.requires-dataplane-prerequisite" {
			continue
		}
		command := legacyCommandFor(item.ruleID, item.command)
		if len(command) > 0 {
			command[0] = "prepare"
		}
		return LegacyInventoryRoute{Command: command, MetadataState: "implemented_native_mariadb_operator_resource_minimizer", Limit: "Requires one caller-selected complete native apiVersion k8s.mariadb.com/v1alpha1, kind MariaDB resource, explicit Galera-only scope, and the pre-operator-update declaration. It checks only the documented autoUpdateDataPlane prerequisite; admission, cluster state, runtime behavior, controller progress, data-plane completion, and whole-upgrade safety remain UNKNOWN."}, true
	}
	return LegacyInventoryRoute{}, false
}

func legacyCommand(args []Argument) []any {
	result := make([]any, 0, len(args)*2)
	for _, arg := range args {
		switch arg.Kind {
		case "literal":
			result = append(result, arg.Literal)
		case "file_placeholder":
			result = append(result, arg.Name, "FILE")
		case "name_placeholder":
			result = append(result, arg.Name, "NAME")
		case "boolean_operator_declaration":
			result = append(result, arg.Name+"=true|false")
		case "timestamp_placeholder":
			continue
		}
	}
	return result
}

func legacyCommandFor(ruleID string, args []Argument) []any {
	values := legacyCommand(args)
	if ruleID == "prometheus.scrape-classic-histograms-key-renamed.3-1" {
		return withoutOption(values, "--from", "--to")
	}
	if ruleID != "prometheus.alertmanager-api-v1-removed.3-1" && ruleID != "mariadb-operator.upgrade-26-6.requires-dataplane-prerequisite" {
		return values
	}
	deferred := make([]any, 0, 2)
	kept := make([]any, 0, len(values))
	for _, value := range values {
		if value == "--alertmanager-config-complete" || value == "--alertmanager-config-precedence-resolved" || value == "--resource-complete" || value == "--pre-operator-update" {
			deferred = append(deferred, value)
			continue
		}
		kept = append(kept, value)
	}
	return append(kept, deferred...)
}

func withoutOption(values []any, names ...string) []any {
	drop := map[string]bool{}
	for _, name := range names {
		drop[name] = true
	}
	result := make([]any, 0, len(values))
	for index := 0; index < len(values); index++ {
		value, _ := values[index].(string)
		if drop[value] {
			index++
			continue
		}
		result = append(result, values[index])
	}
	return result
}

func legacyLimit(ruleID string) string {
	switch ruleID {
	case "envoy.xds-v2-unsupported-at-1-39-1-from-1-38-4":
		return "Blocker-only route checking direct V2 transport_api_version at ADS, LDS, or CDS api_config_source paths in one caller-selected directly loaded JSON bootstrap. It is limited to origins 1.34.14, 1.35.13, 1.36.10, 1.37.6, or 1.38.4 to target 1.39.1. V3, AUTO, absence, and unsupported structure remain UNKNOWN; there is no native PASS or historical 1.18 native route. Bootstrap completeness, distribution identity, xDS behavior, runtime state, and whole-upgrade safety remain UNKNOWN."
	case "prometheus.alertmanager-api-v1-removed.3-1":
		return "Checks only literal api_version in one caller-selected complete native alerting.alertmanagers entry; an omitted key uses the exact target source-derived v2 default. Addresses, credentials, paths, full configuration, Alertmanager compatibility, reachability, alert delivery, runtime behavior, and whole-upgrade safety remain unresolved."
	case "prometheus.scrape-classic-histograms-key-renamed.3-1":
		return "Checks only the reviewed old/new key in one caller-selected complete native scrape_config; job names, targets, full configuration, startup, scraping, native-histogram behavior, and whole-upgrade safety remain unresolved."
	default:
		return "Checks one literal-name remote_write entry's direct inline enable_http2 value or exact reviewed omitted default against an explicit endpoint requirement. It does not validate the whole configuration, runtime flags, endpoint support, protocol negotiation, delivery, startup, or whole-upgrade safety."
	}
}

func literal(value string) Argument  { return Argument{Kind: "literal", Literal: value} }
func file(name string) Argument      { return Argument{Name: name, Kind: "file_placeholder"} }
func name(name string) Argument      { return Argument{Name: name, Kind: "name_placeholder"} }
func timestamp(name string) Argument { return Argument{Name: name, Kind: "timestamp_placeholder"} }
func boolean(name string) Argument {
	return Argument{Name: name, Kind: "boolean_operator_declaration", AllowedValues: []string{"true", "false"}}
}

func cncfBase(project string) []Argument {
	return []Argument{literal("check"), literal("cncf"), literal("--project"), literal(project)}
}

func projectBase(project string) []Argument {
	return []Argument{literal("check"), literal("project"), literal("--project"), literal(project)}
}

func extend(base []Argument, values ...Argument) []Argument {
	return append(append([]Argument(nil), base...), values...)
}

func exactPair(base []Argument, from, to string) []Argument {
	return extend(base, literal("--from"), literal(from), literal("--to"), literal(to), timestamp("--now"))
}

func descriptorSet() []descriptor {
	result := make([]descriptor, 0, 194)
	alertPairs := []struct{ from, id string }{
		{"2.55.1", "prometheus.alertmanager-api-v1-removed.3-1"},
		{"3.9.1", "prometheus.alertmanager-api-v1.target-config.3-9-1-to-3-14-0"},
		{"3.10.0", "prometheus.alertmanager-api-v1.target-config.3-10-0-to-3-14-0"},
		{"3.11.3", "prometheus.alertmanager-api-v1.target-config.3-11-3-to-3-14-0"},
		{"3.12.0", "prometheus.alertmanager-api-v1.target-config.3-12-0-to-3-14-0"},
		{"3.13.3", "prometheus.alertmanager-api-v1.target-config.3-13-3-to-3-14-0"},
	}
	for _, pair := range alertPairs {
		to := "3.14.0"
		if pair.from == "2.55.1" {
			to = "3.1.0"
		}
		result = append(result, descriptor{family: FamilyCNCF, project: "prometheus", component: "pkg:github/prometheus/prometheus", ruleID: pair.id, from: pair.from, to: to, command: exactPair(extend(cncfBase("prometheus"), file("--alertmanager-config"), literal("--alertmanager-config-complete"), literal("--alertmanager-config-precedence-resolved")), pair.from, to), limit: "Selected Alertmanager mapping only; completeness and precedence remain caller declarations."})
	}
	scrapePairs := []struct{ from, id string }{
		{"2.55.1", "prometheus.scrape-classic-histograms-key-renamed.3-1"},
		{"3.9.1", "prometheus.scrape-classic-histograms.target-config.3-9-1-to-3-14-0"},
		{"3.10.0", "prometheus.scrape-classic-histograms.target-config.3-10-0-to-3-14-0"},
		{"3.11.3", "prometheus.scrape-classic-histograms.target-config.3-11-3-to-3-14-0"},
		{"3.12.0", "prometheus.scrape-classic-histograms.target-config.3-12-0-to-3-14-0"},
		{"3.13.3", "prometheus.scrape-classic-histograms.target-config.3-13-3-to-3-14-0"},
	}
	for _, pair := range scrapePairs {
		to := "3.14.0"
		if pair.from == "2.55.1" {
			to = "3.1.0"
		}
		result = append(result, descriptor{family: FamilyCNCF, project: "prometheus", component: "pkg:github/prometheus/prometheus", ruleID: pair.id, from: pair.from, to: to, command: exactPair(extend(cncfBase("prometheus"), file("--scrape-config"), name("--scrape-job"), literal("--scrape-config-complete"), literal("--scrape-config-precedence-resolved")), pair.from, to), limit: "One selected scrape_config only; completeness and precedence remain caller declarations."})
	}
	result = append(result, descriptor{family: FamilyCNCF, project: "prometheus", component: "pkg:github/prometheus/prometheus", ruleID: "prometheus.remote-write-http2-default.2-55-1-to-3-14-0", from: "2.55.1", to: "3.14.0", command: exactPair(extend(cncfBase("prometheus"), file("--prometheus-config"), literal("--prometheus-config-complete"), literal("--prometheus-config-precedence-resolved"), literal("--prometheus-rule"), literal("remote-write-http2-default"), name("--prometheus-remote-write-name"), boolean("--prometheus-remote-write-http2-required")), "2.55.1", "3.14.0"), limit: "One selected remote_write entry only; endpoint behavior remains unassessed."})
	for _, from := range []string{"1.34.14", "1.35.13", "1.36.10", "1.37.6", "1.38.4"} {
		result = append(result, descriptor{family: FamilyCNCF, project: "envoy", component: "pkg:github/envoyproxy/envoy", ruleID: "envoy.xds-v2-unsupported-at-1-39-1-from-" + strings.ReplaceAll(from, ".", "-"), from: from, to: "1.39.1", command: exactPair(extend(cncfBase("envoy"), file("--envoy-bootstrap"), literal("--envoy-bootstrap-selected")), from, "1.39.1"), limit: "Direct V2 transport blocker only; dynamic xDS and runtime behavior are unassessed.", nativePass: "NOT_AVAILABLE_BLOCKER_ONLY"})
	}
	result = append(result, descriptor{family: FamilyCNCF, project: "strimzi", component: "pkg:github/strimzi/strimzi-kafka-operator", ruleID: "strimzi.kafka-v1beta2-api-removed.1-0", from: "0.51.0", to: "1.0.0", command: exactPair(extend(cncfBase("strimzi"), file("--kafka-resource"), name("--strimzi-distribution"), literal("--target-kafka-crd-admission-required")), "0.51.0", "1.0.0"), limit: "One caller-selected rendered kind Kafka resource, or one flat v1 List of rendered resources, only; CRD installation, admission, conversion, and runtime behavior are unassessed."})
	for _, to := range []string{"0.41.0", "0.42.0"} {
		result = append(result, descriptor{family: FamilyCNCF, project: "falco", component: "pkg:github/falcosecurity/falco", ruleID: "falco.deprecated-cli-flags-removed.0-40-to-" + strings.ReplaceAll(strings.TrimSuffix(to, ".0"), ".", "-"), from: "0.40.0", to: to, command: exactPair(extend(cncfBase("falco"), file("--falco-argv"), name("--falco-distribution")), "0.40.0", to), limit: "One caller-declared explicit effective Falco argv only; wrappers, entrypoints, images, environment, defaults, and runtime behavior are unassessed."})
	}
	result = append(result, descriptor{family: FamilyCNCF, project: "kuma", component: "pkg:github/kumahq/kuma", ruleID: "kuma.deprecated-exclude-uid-flags-removed.2-8-to-2-9", from: "2.8.0", to: "2.9.0", command: exactPair(extend(cncfBase("kuma"), file("--kumactl-argv"), name("--kuma-distribution")), "2.8.0", "2.9.0"), limit: "One caller-declared explicit effective kumactl install transparent-proxy argv only; wrappers, images, defaults, consolidated-flag equivalence, Dataplane migration, and runtime behavior are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "crossplane", component: "pkg:github/crossplane/crossplane", ruleID: "crossplane.composition-resources-mode-removed.1-20-2-0", from: "1.20.0", to: "2.0.0", command: exactPair(extend(cncfBase("crossplane"), file("--composition"), name("--crossplane-distribution"), literal("--crossplane-schema-validation-required")), "1.20.0", "2.0.0"), limit: "One caller-selected rendered Composition, or one flat v1 List of rendered resources, only; an omitted spec.mode, target CRD installation, admission, conversion, and runtime behavior are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "velero", component: "pkg:github/velero-io/velero", ruleID: "velero.crd-update-order.1-18", from: "1.17.0", to: "1.18.0", command: exactPair(extend(cncfBase("velero"), file("--upgrade-plan"), name("--velero-server-deployment"), literal("--velero-plan-order-declared")), "1.17.0", "1.18.0"), limit: "One caller-declared ordered upgrade plan only; the plan is a declaration, not an apply or execution receipt, and applied CRDs, plugins, node agents, backups and restores are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "velero", component: "pkg:github/velero-io/velero", ruleID: "velero.intermediate-1-17.1-18", from: "1.16.2", to: "1.18.0", command: exactPair(extend(cncfBase("velero"), file("--upgrade-plan"), name("--velero-server-deployment"), literal("--velero-plan-order-declared")), "1.16.2", "1.18.0"), limit: "The reviewed mandatory 1.17.x intermediate blocks this direct transition on the declared pair alone; no supplied plan can establish a PASS here.", nativePass: "NOT_AVAILABLE_BLOCKER_ONLY"})
	result = append(result, descriptor{family: FamilyCNCF, project: "keda", component: "pkg:github/kedacore/keda", ruleID: "keda.external-scaler-legacy-tls-transport.2-17", from: "2.16.0", to: "2.17.0", command: exactPair(extend(cncfBase("keda"), file("--keda-scaled-object"), literal("--keda-scaled-object-complete"), boolean("--keda-legacy-tls-transport-required")), "2.16.0", "2.17.0"), limit: "One caller-selected rendered ScaledObject set only; a raw tlsCertFile metadata field never establishes reliance on the removed direct transport, and TriggerAuthentication material, scaler reachability, and runtime behavior are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "spire", component: "pkg:github/spiffe/spire", ruleID: "spire.removed-entry-ttl.1-11", from: "1.10.4", to: "1.11.0", command: exactPair(extend(cncfBase("spire"), file("--spire-entry-argv"), name("--spire-distribution")), "1.10.4", "1.11.0"), limit: "One caller-declared explicit effective spire-server entry create argv only; wrappers, entrypoints, images, environment, defaults, replacement TTL values, registration entries, and runtime behavior are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "etcd", component: "pkg:github/etcd-io/etcd", ruleID: "etcd.v2-proxy-flags-removed.3-6", from: "3.5.17", to: "3.6.0", command: exactPair(extend(cncfBase("etcd"), file("--native-resource")), "3.5.17", "3.6.0"), limit: "Removal of the eight named etcd v2/proxy options only, from one caller-declared complete direct effective argv; data migration and quorum health are unverified."})
	etcdExperimentalFlagPairs := []struct{ from, id string }{
		{"3.2.32", "etcd.experimental-flags-unsupported.3-2-32-to-3-7-1"},
		{"3.3.27", "etcd.experimental-flags-unsupported.3-3-27-to-3-7-1"},
		{"3.4.45", "etcd.experimental-flags-unsupported.3-4-45-to-3-7-1"},
		{"3.5.33", "etcd.experimental-flags-unsupported.3-5-33-to-3-7-1"},
		{"3.6.14", "etcd.experimental-flags-unsupported.3-6-14-to-3-7-1"},
	}
	for _, pair := range etcdExperimentalFlagPairs {
		result = append(result, descriptor{family: FamilyCNCF, project: "etcd", component: "pkg:github/etcd-io/etcd", ruleID: pair.id, from: pair.from, to: "3.7.1", command: exactPair(extend(cncfBase("etcd"), file("--native-resource")), pair.from, "3.7.1"), limit: "etcd 3.7 rejects only the finite reviewed removed experimental flag names, checked against one caller-declared complete direct proposed argv; unknown experimental names, indirect configuration, and the separate mandatory minor-version-skip blocker are unassessed by this route."})
	}
	// etcd direct-minor-skip: an unconditional forbid_target_version blocker
	// (requiredFacts is empty) for the same four multi-minor origins already
	// routed above to 3.7.1. It shares the identical --native-resource command
	// already wired for etcd.experimental-flags-unsupported.*; no facts are
	// needed because the rule fires purely from the declared component/from/to
	// identity. TestEtcdNativeCheck_AllLatestOriginsAreRouted in
	// internal/communityapp already exercises this exact claim end to end for
	// these four origins.
	etcdDirectMinorSkipFroms := []string{"3.2.32", "3.3.27", "3.4.45", "3.5.33"}
	for _, from := range etcdDirectMinorSkipFroms {
		result = append(result, descriptor{family: FamilyCNCF, project: "etcd", component: "pkg:github/etcd-io/etcd", ruleID: "etcd.direct-minor-skip." + strings.ReplaceAll(from, ".", "-") + "-to-3-7-1", from: from, to: "3.7.1", command: exactPair(extend(cncfBase("etcd"), file("--native-resource")), from, "3.7.1"), limit: "etcd supports one minor release at a time; this exact direct skip is blocked without a claim about cluster health or a complete staged route. No supplied native-resource content can establish a PASS for this identity.", nativePass: "NOT_AVAILABLE_BLOCKER_ONLY"})
	}
	kyvernoNativeBase := extend(cncfBase("kyverno"), file("--kyverno-resource"), name("--container"), name("--kyverno-distribution"))
	result = append(result, descriptor{family: FamilyCNCF, project: "kyverno", component: "pkg:github/kyverno/kyverno", ruleID: "kyverno.reports-chunk-size-removed.1-13", from: "1.12.5", to: "1.13.0", command: exactPair(kyvernoNativeBase, "1.12.5", "1.13.0"), limit: "One caller-selected container's explicitly declared official-upstream bare literal reports-controller command only; image provenance, wrappers, other command surfaces, controller behavior, and whole-upgrade compatibility are unverified."})
	kyvernoLatestReportsChunkSizePairs := []struct{ from, id string }{
		{"1.14.5", "kyverno.reports-chunk-size-unsupported-at-1-19-1-from-1-14-5"},
		{"1.15.3", "kyverno.reports-chunk-size-unsupported-at-1-19-1-from-1-15-3"},
		{"1.16.4", "kyverno.reports-chunk-size-unsupported-at-1-19-1-from-1-16-4"},
		{"1.17.2", "kyverno.reports-chunk-size-unsupported-at-1-19-1-from-1-17-2"},
		{"1.18.2", "kyverno.reports-chunk-size-unsupported-at-1-19-1-from-1-18-2"},
	}
	for _, pair := range kyvernoLatestReportsChunkSizePairs {
		result = append(result, descriptor{family: FamilyCNCF, project: "kyverno", component: "pkg:github/kyverno/kyverno", ruleID: pair.id, from: pair.from, to: "1.19.1", command: exactPair(kyvernoNativeBase, pair.from, "1.19.1"), limit: "Target-only Kyverno 1.19.1 reportsChunkSize constraint for one caller-selected container's explicitly declared official-upstream bare reports-controller invocation; it does not identify when removal occurred, establish image provenance, inspect wrappers, or prove controller runtime or whole-upgrade safety."})
	}
	jaegerNativeBase := extend(cncfBase("jaeger"), file("--jaeger-argv"), boolean("--non-memory-storage-required"), boolean("--official-jaeger-distribution"))
	result = append(result, descriptor{family: FamilyCNCF, project: "jaeger", component: "pkg:github/jaegertracing/jaeger", ruleID: "jaeger.explicit-config-required-for-non-memory.1-76-2-20", from: "1.76.0", to: "2.20.0", command: exactPair(jaegerNativeBase, "1.76.0", "2.20.0"), limit: "One caller-declared direct Jaeger v2 invocation only; declared non-memory storage requirement and official distribution are operator declarations, not inferred, and config content, backend, credentials, and runtime remain unverified."})
	jaegerTargetPairs := []struct{ from, id string }{
		{"2.15.1", "jaeger.explicit-config-required-for-non-memory.target.2-15-to-2-20"},
		{"2.16.0", "jaeger.explicit-config-required-for-non-memory.target.2-16-to-2-20"},
		{"2.17.0", "jaeger.explicit-config-required-for-non-memory.target.2-17-to-2-20"},
		{"2.18.0", "jaeger.explicit-config-required-for-non-memory.target.2-18-to-2-20"},
		{"2.19.0", "jaeger.explicit-config-required-for-non-memory.target.2-19-to-2-20"},
	}
	for _, pair := range jaegerTargetPairs {
		result = append(result, descriptor{family: FamilyCNCF, project: "jaeger", component: "pkg:github/jaegertracing/jaeger", ruleID: pair.id, from: pair.from, to: "2.20.0", command: exactPair(jaegerNativeBase, pair.from, "2.20.0"), limit: "Target-only Jaeger 2.20 explicit-config constraint for one caller-declared direct v2 invocation; declared non-memory storage requirement and official distribution are operator declarations, not inferred, and config content, backend, credentials, and runtime remain unverified."})
	}
	harborNativeBase := extend(cncfBase("harbor"), file("--native-resource"))
	result = append(result, descriptor{family: FamilyCNCF, project: "harbor", component: "pkg:github/goharbor/harbor", ruleID: "harbor.installer-with-chartmuseum-flag-removed.2-8", from: "2.7.0", to: "2.8.0", command: exactPair(harborNativeBase, "2.7.0", "2.8.0"), limit: "One caller-declared complete literal make/install.sh argv only; the installer is never executed, and wrapper, environment, response-file, chart, and database state are unassessed."})
	harborChartMuseumPairs := []struct{ from, id string }{
		{"2.10.3", "harbor.installer-with-chartmuseum-flag-removed.2-10-to-2-15"},
		{"2.11.2", "harbor.installer-with-chartmuseum-flag-removed.2-11-to-2-15"},
		{"2.12.4", "harbor.installer-with-chartmuseum-flag-removed.2-12-to-2-15"},
		{"2.13.5", "harbor.installer-with-chartmuseum-flag-removed.2-13-to-2-15"},
		{"2.14.4", "harbor.installer-with-chartmuseum-flag-removed.2-14-to-2-15"},
	}
	for _, pair := range harborChartMuseumPairs {
		result = append(result, descriptor{family: FamilyCNCF, project: "harbor", component: "pkg:github/goharbor/harbor", ruleID: pair.id, from: pair.from, to: "2.15.2", command: exactPair(harborNativeBase, pair.from, "2.15.2"), limit: "One caller-declared complete literal make/install.sh argv only; the installer is never executed, and wrapper, environment, response-file, chart, and database state are unassessed."})
	}
	fluentDNativeBase := extend(cncfBase("fluentd"), file("--native-resource"))
	result = append(result, descriptor{family: FamilyCNCF, project: "fluentd", component: "pkg:github/fluent/fluentd", ruleID: "fluentd.z-literal-treatment.1-17-1-to-1-18-0", from: "1.17.1", to: "1.18.0", command: exactPair(fluentDNativeBase, "1.17.1", "1.18.0"), limit: "One paired current/proposed selected classic-config literal declaration with completeness, current-default, and preservation guards only; Ruby, interpolation, plugins, and runtime behavior are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "fluentd", component: "pkg:github/fluent/fluentd", ruleID: "fluentd.ruby-minimum.1-16-to-1-17", from: "1.16.0", to: "1.17.0", command: exactPair(fluentDNativeBase, "1.16.0", "1.17.0"), limit: "One caller-declared proposed distribution and proposed Ruby version target only; no Ruby interpreter, package, plugin, or runtime is observed."})
	fluentDRubyTargetPairs := []struct{ from, id string }{
		{"1.14.6", "fluentd.ruby-minimum-target.1-14-6-to-1-19-3"},
		{"1.15.3", "fluentd.ruby-minimum-target.1-15-3-to-1-19-3"},
		{"1.16.11", "fluentd.ruby-minimum-target.1-16-11-to-1-19-3"},
		{"1.17.1", "fluentd.ruby-minimum-target.1-17-1-to-1-19-3"},
		{"1.18.0", "fluentd.ruby-minimum-target.1-18-0-to-1-19-3"},
	}
	for _, pair := range fluentDRubyTargetPairs {
		result = append(result, descriptor{family: FamilyCNCF, project: "fluentd", component: "pkg:github/fluent/fluentd", ruleID: pair.id, from: pair.from, to: "1.19.3", command: exactPair(fluentDNativeBase, pair.from, "1.19.3"), limit: "One caller-declared proposed distribution and proposed Ruby version target only; no Ruby interpreter, package, plugin, or runtime is observed."})
	}
	opencostNativeBase := extend(cncfBase("opencost"), file("--native-resource"))
	result = append(result, descriptor{family: FamilyCNCF, project: "opencost", component: "pkg:github/opencost/opencost", ruleID: "opencost.cloud-cost-source-migration.1-119-to-1-120", from: "1.119.0", to: "1.120.0", command: exactPair(opencostNativeBase, "1.119.0", "1.120.0"), limit: "One caller-declared current and proposed cloud-cost source selection only; file contents, credentials, provider access, and runtime behavior are unassessed."})
	opencostLatestOrigins := []string{"1.116.0", "1.117.6", "1.118.0", "1.119.2", "1.120.4"}
	for _, from := range opencostLatestOrigins {
		result = append(result, descriptor{family: FamilyCNCF, project: "opencost", component: "pkg:github/opencost/opencost", ruleID: "opencost.cloud-cost-source-migration." + strings.ReplaceAll(from, ".", "-") + "-to-1-121-2", from: from, to: "1.121.2", command: exactPair(opencostNativeBase, from, "1.121.2"), limit: "One caller-declared current and proposed cloud-cost source selection only; file contents, credentials, provider access, and runtime behavior are unassessed."})
	}
	// Cloud Custodian: PrepareCloudCustodian already has a working single-step
	// native input route (wired here); it already handled all six reviewed
	// rule pairs via the two-step prepare/check flow before this route existed.
	cloudCustodianNativeBase := extend(cncfBase("cloud-custodian"), file("--native-resource"))
	result = append(result, descriptor{family: FamilyCNCF, project: "cloud-custodian", component: "pkg:github/cloud-custodian/cloud-custodian", ruleID: "cloud-custodian.iam-access-key-json-diff-removed.0-9-50-to-0-9-51", from: "0.9.50", to: "0.9.51", command: exactPair(cloudCustodianNativeBase, "0.9.50", "0.9.51"), limit: "One caller-selected complete JSON policy document with exactly one iam-access-key resource-typed policy only; variables, includes, dynamic resource selection, AWS API execution, and whole-upgrade compatibility are unassessed."})
	cloudCustodianLatestOriginPairs := []struct{ from, id string }{
		{"0.9.47", "cloud-custodian.iam-access-key-json-diff-rejected.0-9-47-to-0-9-52"},
		{"0.9.48", "cloud-custodian.iam-access-key-json-diff-rejected.0-9-48-to-0-9-52"},
		{"0.9.49", "cloud-custodian.iam-access-key-json-diff-rejected.0-9-49-to-0-9-52"},
		{"0.9.50", "cloud-custodian.iam-access-key-json-diff-rejected.0-9-50-to-0-9-52"},
		{"0.9.51", "cloud-custodian.iam-access-key-json-diff-rejected.0-9-51-to-0-9-52"},
	}
	for _, pair := range cloudCustodianLatestOriginPairs {
		result = append(result, descriptor{family: FamilyCNCF, project: "cloud-custodian", component: "pkg:github/cloud-custodian/cloud-custodian", ruleID: pair.id, from: pair.from, to: "0.9.52", command: exactPair(cloudCustodianNativeBase, pair.from, "0.9.52"), limit: "One caller-selected complete JSON policy document with exactly one iam-access-key resource-typed policy only; variables, includes, dynamic resource selection, AWS API execution, and whole-upgrade compatibility are unassessed."})
	}

	result = append(result, descriptor{family: FamilyCommunity, project: "mariadb-operator", component: "pkg:github/mariadb-operator/mariadb-operator", ruleID: "mariadb-operator.upgrade-26-6.requires-dataplane-prerequisite", from: "26.3.0", to: "26.6.0", command: exactPair([]Argument{literal("check"), literal("project"), literal("--project"), literal("mariadb-operator"), file("--mariadb-resource"), literal("--resource-complete"), literal("--pre-operator-update")}, "26.3.0", "26.6.0"), limit: "One complete selected MariaDB resource before the operator update; controller and data-plane behavior are unassessed."})

	grafanaBase := extend(projectBase("grafana"), file("--effective-config"), literal("--effective-config-complete"), literal("--precedence-resolved"))
	grafanaPairs := []struct{ from, to, id string }{
		{"10.4.0", "11.0.0", "grafana.legacy-alerting-config.10-4-to-11-0"},
		{"12.2.10", "13.2.1", "grafana.legacy-alerting-config.12-2-10-to-13-2-1"},
		{"12.3.11", "13.2.1", "grafana.legacy-alerting-config.12-3-11-to-13-2-1"},
		{"12.4.10", "13.2.1", "grafana.legacy-alerting-config.12-4-10-to-13-2-1"},
		{"13.0.8", "13.2.1", "grafana.legacy-alerting-config.13-0-8-to-13-2-1"},
		{"13.1.5", "13.2.1", "grafana.legacy-alerting-config.13-1-5-to-13-2-1"},
	}
	for _, pair := range grafanaPairs {
		result = append(result, descriptor{family: FamilyCommunity, project: "grafana", component: "pkg:github/grafana/grafana", ruleID: pair.id, from: pair.from, to: pair.to, command: exactPair(grafanaBase, pair.from, pair.to), limit: "One selected [alerting] enabled key only; completeness and precedence remain caller declarations. Full configuration, alert-data migration, and whole-upgrade safety remain unassessed."})
	}

	kibanaReportingBase := extend(projectBase("kibana"), file("--effective-config"), literal("--effective-config-complete"), literal("--precedence-resolved"))
	result = append(result, descriptor{family: FamilyCommunity, project: "kibana", component: "pkg:github/elastic/kibana", ruleID: "kibana.reporting-roles-allow.8-18-to-9-0", from: "8.18.0", to: "9.0.0", command: exactPair(kibanaReportingBase, "8.18.0", "9.0.0"), limit: "One selected xpack.reporting.roles.allow key only; completeness and precedence remain caller declarations. Feature privileges, reporting access, and whole-upgrade safety remain unassessed."})
	kibanaStatusBase := extend(kibanaReportingBase, literal("--full-status-without-monitor-required"))
	kibanaStatusPairs := []struct{ from, id string }{
		{"9.0.8", "kibana.status-page-monitor-bypass.9-0-8-to-9-5-3"},
		{"9.1.10", "kibana.status-page-monitor-bypass.9-1-10-to-9-5-3"},
		{"9.2.8", "kibana.status-page-monitor-bypass.9-2-8-to-9-5-3"},
		{"9.3.8", "kibana.status-page-monitor-bypass.9-3-8-to-9-5-3"},
		{"9.4.6", "kibana.status-page-monitor-bypass.9-4-6-to-9-5-3"},
	}
	for _, pair := range kibanaStatusPairs {
		result = append(result, descriptor{family: FamilyCommunity, project: "kibana", component: "pkg:github/elastic/kibana", ruleID: pair.id, from: pair.from, to: "9.5.3", command: exactPair(kibanaStatusBase, pair.from, "9.5.3"), limit: "One selected status.allowAnonymous and status.statusPageBypassMonitorPrivilege pair plus an explicit full-status-without-monitor intent only; client monitor privilege, route runtime behavior, and whole-upgrade safety remain unassessed."})
	}

	fluentBitSettingBase := extend(projectBase("fluent-bit"), file("--effective-config"), literal("--effective-config-complete"), literal("--current-default-was-used"), literal("--preserve-http2-enabled"))
	result = append(result, descriptor{family: FamilyCommunity, project: "fluent-bit", component: "pkg:github/fluent/fluent-bit", ruleID: "fluent-bit.http2-setting.3-2-to-4-0", from: "3.2.0", to: "4.0.0", command: exactPair(fluentBitSettingBase, "3.2.0", "4.0.0"), limit: "One selected OpenTelemetry output enable_http2 setting only, with explicit current-default and preservation-intent declarations; full configuration, protocol negotiation, and whole-upgrade safety remain unassessed."})
	fluentBitTargetBase := extend(projectBase("fluent-bit"), file("--effective-config"), literal("--effective-config-complete"), literal("--require-http2"))
	fluentBitTargetPairs := []struct{ from, id string }{
		{"3.2.10", "fluent-bit.http2-target-required.3-2-to-5-1"},
		{"4.0.14", "fluent-bit.http2-target-required.4-0-to-5-1"},
		{"4.1.2", "fluent-bit.http2-target-required.4-1-to-5-1"},
		{"4.2.8", "fluent-bit.http2-target-required.4-2-to-5-1"},
		{"5.0.10", "fluent-bit.http2-target-required.5-0-to-5-1"},
	}
	for _, pair := range fluentBitTargetPairs {
		result = append(result, descriptor{family: FamilyCommunity, project: "fluent-bit", component: "pkg:github/fluent/fluent-bit", ruleID: pair.id, from: pair.from, to: "5.1.2", command: exactPair(fluentBitTargetBase, pair.from, "5.1.2"), limit: "One selected OpenTelemetry output HTTP/2 requirement only; protocol negotiation, connectivity, and whole-upgrade safety remain unassessed."})
	}

	cephBase := extend(projectBase("ceph"), file("--selected-osd-metadata"), name("--selected-osd-id"), literal("--selected-osd-metadata-complete"))
	cephPairs := []struct{ from, to, id string }{
		{"17.2.7", "18.2.0", "ceph.selected-osd-filestore.17-2-to-18-2"},
		{"15.2.17", "20.2.4", "ceph.selected-osd-filestore.15-2-17-to-20-2-4"},
		{"16.2.15", "20.2.4", "ceph.selected-osd-filestore.16-2-15-to-20-2-4"},
		{"17.2.9", "20.2.4", "ceph.selected-osd-filestore.17-2-9-to-20-2-4"},
		{"18.2.8", "20.2.4", "ceph.selected-osd-filestore.18-2-8-to-20-2-4"},
		{"19.2.6", "20.2.4", "ceph.selected-osd-filestore.19-2-6-to-20-2-4"},
	}
	for _, pair := range cephPairs {
		result = append(result, descriptor{family: FamilyCommunity, project: "ceph", component: "pkg:github/ceph/ceph", ruleID: pair.id, from: pair.from, to: pair.to, command: exactPair(cephBase, pair.from, pair.to), limit: "One caller-selected current per-OSD metadata object only, identified by an explicit selected OSD id; cluster inventory, live observation, and whole-upgrade safety remain unassessed."})
	}

	argoWorkflowsBase := extend(projectBase("argo-workflows"), file("--workload"), literal("--workload-complete"))
	argoWorkflowsPairs := []struct{ from, to, id string }{
		{"3.5.0", "3.6.0", "argo-workflows.server-basehref.3-5-to-3-6"},
		{"3.4.18", "4.1.3", "argo-workflows.server-basehref.3-4-18-to-4-1-3"},
		{"3.5.15", "4.1.3", "argo-workflows.server-basehref.3-5-15-to-4-1-3"},
		{"3.6.19", "4.1.3", "argo-workflows.server-basehref.3-6-19-to-4-1-3"},
		{"3.7.18", "4.1.3", "argo-workflows.server-basehref.3-7-18-to-4-1-3"},
		{"4.0.11", "4.1.3", "argo-workflows.server-basehref.4-0-11-to-4-1-3"},
	}
	for _, pair := range argoWorkflowsPairs {
		result = append(result, descriptor{family: FamilyCommunity, project: "argo-workflows", component: "pkg:github/argoproj/argo-workflows", ruleID: pair.id, from: pair.from, to: pair.to, command: exactPair(argoWorkflowsBase, pair.from, pair.to), limit: "One caller-selected complete argo-server workload argv only; wrappers, images, defaults, deployment, and whole-upgrade safety remain unassessed."})
	}

	result = append(result, descriptor{family: FamilyCommunity, project: "loki", component: "pkg:github/grafana/loki", ruleID: "loki.compactor-shared-store.2-9-to-3-0", from: "2.9.8", to: "3.0.0", command: exactPair(extend(projectBase("loki"), file("--effective-config"), literal("--effective-config-complete"), literal("--precedence-resolved")), "2.9.8", "3.0.0"), limit: "One selected complete native Loki compactor mapping only; storage, retention, data, and whole-upgrade safety remain unassessed."})
	result = append(result, descriptor{family: FamilyCommunity, project: "loki", component: "pkg:github/grafana/loki", ruleID: "loki.structured-metadata-tsdb-v13.2-9-8-to-3-0-0", from: "2.9.8", to: "3.0.0", command: exactPair(extend(projectBase("loki"), file("--loki-schema-config"), literal("--effective-config-complete"), literal("--precedence-resolved")), "2.9.8", "3.0.0"), limit: "One selected complete native Loki schema_config period only; storage migration, retention, data access, and whole-upgrade safety remain unassessed."})

	result = append(result, descriptor{family: FamilyCommunity, project: "mariadb", component: "pkg:github/mariadb/server", ruleID: "mariadb.innodb-defragmentation-required.10-11-8-to-11-4-2", from: "10.11.8", to: "11.4.2", command: exactPair(extend(projectBase("mariadb"), file("--effective-config"), literal("--effective-config-complete"), literal("--precedence-resolved"), literal("--upstream-distribution"), boolean("--require-innodb-defragmentation")), "10.11.8", "11.4.2"), limit: "One selected complete native option file only, with explicit upstream-distribution and InnoDB-defragmentation-requirement declarations; runtime behavior and whole-upgrade safety remain unassessed."})

	thanosBase := extend(cncfBase("thanos"), file("--native-resource"))
	thanosPairs := []struct{ from, to, id string }{
		{"0.41.0", "0.42.0", "thanos.receive-store-flags-removed.0-42"},
		{"0.37.2", "0.42.4", "thanos.receive-store-flags-target-argv.0-37-2-to-0-42-4"},
		{"0.38.0", "0.42.4", "thanos.receive-store-flags-target-argv.0-38-0-to-0-42-4"},
		{"0.39.2", "0.42.4", "thanos.receive-store-flags-target-argv.0-39-2-to-0-42-4"},
		{"0.40.1", "0.42.4", "thanos.receive-store-flags-target-argv.0-40-1-to-0-42-4"},
		{"0.41.0", "0.42.4", "thanos.receive-store-flags-target-argv.0-41-0-to-0-42-4"},
	}
	for _, pair := range thanosPairs {
		result = append(result, descriptor{family: FamilyCNCF, project: "thanos", component: "pkg:github/thanos-io/thanos", ruleID: pair.id, from: pair.from, to: pair.to, command: exactPair(thanosBase, pair.from, pair.to), limit: "One caller-supplied Kubernetes workload object's single named thanos container args only; generated arguments, image provenance, Query, storage, compaction, and whole-upgrade safety remain unassessed."})
	}

	// Flux: existing beta-API removal rules already have a working single-step
	// native input route (PrepareFlux). This registers that already-working
	// route; it authors no new compatibility claim or evaluation logic.
	result = append(result, descriptor{family: FamilyCNCF, project: "flux", component: "pkg:github/fluxcd/flux2", ruleID: "flux.beta-api-removal.2-7", from: "2.6.4", to: "2.7.0", command: exactPair(extend(cncfBase("flux"), file("--native-resource"), literal("--resource-scope-complete")), "2.6.4", "2.7.0"), limit: "One caller-selected rendered resource JSON object, or one flat v1 List of rendered resources, only; a positive removed beta-API witness is conclusive alone, but a clear result also requires the declared complete scope with no pagination. Stored CRD versions, cluster inventory, reconciliation, and runtime behavior are unassessed."})
	for _, from := range []string{"2.4.0", "2.5.1", "2.6.4", "2.7.5", "2.8.8"} {
		result = append(result, descriptor{family: FamilyCNCF, project: "flux", component: "pkg:github/fluxcd/flux2", ruleID: "flux.latest-beta-api-removal." + from + "-to-2-9", from: from, to: "2.9.5", command: exactPair(extend(cncfBase("flux"), file("--native-resource"), literal("--resource-scope-complete")), from, "2.9.5"), limit: "Limited to the five reviewed origins 2.4.0, 2.5.1, 2.6.4, 2.7.5, and 2.8.8; other origins are unsupported. One caller-selected rendered resource JSON object, or one flat v1 List of rendered resources, only; stored CRD versions, cluster inventory, reconciliation, and runtime behavior are unassessed."})
	}

	// CoreDNS: existing federation-directive rules already have a working
	// single-step native input route (PrepareCoreDNSCorefile).
	result = append(result, descriptor{family: FamilyCNCF, project: "coredns", component: "pkg:github/coredns/coredns", ruleID: "coredns.federation-removed.1-7", from: "1.6.9", to: "1.7.0", command: exactPair(extend(cncfBase("coredns"), file("--coredns-corefile"), name("--coredns-distribution"), literal("--coredns-corefile-complete")), "1.6.9", "1.7.0"), limit: "Checks only a literal federation directive directly in one caller-selected local Corefile server block; imports, snippets, substitutions, and escaped syntax remain UNKNOWN. Distribution and completeness are caller declarations."})
	for _, from := range []string{"1.9.4", "1.10.1", "1.11.4", "1.12.4", "1.13.2"} {
		result = append(result, descriptor{family: FamilyCNCF, project: "coredns", component: "pkg:github/coredns/coredns", ruleID: "coredns.official-federation-absent-at-1-14-7-from-" + strings.ReplaceAll(from, ".", "-"), from: from, to: "1.14.7", command: exactPair(extend(cncfBase("coredns"), file("--coredns-corefile"), name("--coredns-distribution"), literal("--coredns-corefile-complete")), from, "1.14.7"), limit: "Limited to the five reviewed origins 1.9.4, 1.10.1, 1.11.4, 1.12.4, and 1.13.2; other origins are unsupported. Checks only a literal federation directive directly in one caller-selected local Corefile server block; imports, snippets, substitutions, and escaped syntax remain UNKNOWN."})
	}

	// NATS: existing ASCII-space-in-name rules already have a working
	// single-step native input route (PrepareNATS); it does not gate on origin.
	for _, pair := range []struct{ from, to string }{
		{"2.10.0", "2.11.0"},
		{"2.8.4", "2.14.6"},
		{"2.9.25", "2.14.6"},
		{"2.10.29", "2.14.6"},
		{"2.11.17", "2.14.6"},
		{"2.12.15", "2.14.6"},
	} {
		result = append(result, descriptor{family: FamilyCNCF, project: "nats", component: "pkg:github/nats-io/nats-server", ruleID: "nats.names-with-ascii-spaces-rejected." + strings.ReplaceAll(pair.from, ".", "-") + "-to-" + strings.ReplaceAll(pair.to, ".", "-"), from: pair.from, to: pair.to, command: exactPair(extend(cncfBase("nats"), file("--nats-config")), pair.from, pair.to), limit: "One caller-selected standalone JSON-like NATS configuration object only; classic blocks, includes, environment references, dotted descendant paths, duplicates, and unsupported parent shapes remain UNKNOWN."})
	}

	// Cortex: existing removed-flag rules already have a working single-step
	// native input route (PrepareCortex).
	result = append(result, descriptor{family: FamilyCNCF, project: "cortex", component: "pkg:github/cortexproject/cortex", ruleID: "cortex.querier-at-modifier-flag-removed.1-21", from: "1.17.2", to: "1.21.1", command: exactPair(extend(cncfBase("cortex"), file("--native-resource")), "1.17.2", "1.21.1"), limit: "Limited to the five reviewed origins 1.16.1, 1.17.2, 1.18.1, 1.19.1, and 1.20.1; other origins are unsupported. One caller-selected apps/v1 Deployment, StatefulSet, or DaemonSet with one explicitly named cortex container only; generated arguments, query behavior, storage, tenancy, and runtime state remain unassessed."})
	for _, from := range []string{"1.16.1", "1.18.1", "1.19.1", "1.20.1"} {
		result = append(result, descriptor{family: FamilyCNCF, project: "cortex", component: "pkg:github/cortexproject/cortex", ruleID: "cortex.querier-at-modifier-flag-target-argv." + strings.ReplaceAll(from, ".", "-") + "-to-1-21-1", from: from, to: "1.21.1", command: exactPair(extend(cncfBase("cortex"), file("--native-resource")), from, "1.21.1"), limit: "Limited to the five reviewed origins 1.16.1, 1.17.2, 1.18.1, 1.19.1, and 1.20.1; other origins are unsupported. One caller-selected apps/v1 Deployment, StatefulSet, or DaemonSet with one explicitly named cortex container only; generated arguments, query behavior, storage, tenancy, and runtime state remain unassessed."})
	}

	// OpenTelemetry: existing Collector-config rules already have a working
	// single-step native input route (PrepareOpenTelemetryCollector for the
	// default rule, PrepareOpenTelemetryInternalMetrics when --otel-rule
	// internal-telemetry-default-bind is selected); both are dispatched from
	// cncfNativeResourceCheck via the "opentelemetry" case.
	otelBase := extend(cncfBase("opentelemetry"), file("--otel-collector-config"), name("--otel-distribution"), literal("--otel-config-complete"), literal("--otel-config-precedence-resolved"))
	result = append(result, descriptor{family: FamilyCNCF, project: "opentelemetry", component: "pkg:github/open-telemetry/opentelemetry-collector", ruleID: "opentelemetry.logging-exporter-removed.0-111", from: "0.110.0", to: "0.111.0", command: exactPair(otelBase, "0.110.0", "0.111.0"), limit: "One caller-selected complete, precedence-resolved OpenTelemetry Collector configuration only; replacement exporter availability and telemetry delivery are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "opentelemetry", component: "pkg:github/open-telemetry/opentelemetry-collector", ruleID: "opentelemetry.internal-telemetry-default-bind.0-110-to-0-111", from: "0.110.0", to: "0.111.0", command: exactPair(extend(otelBase, literal("--otel-rule"), literal("internal-telemetry-default-bind"), boolean("--otel-metrics-localhost-default"), boolean("--otel-metrics-remote-scrape-required")), "0.110.0", "0.111.0"), limit: "One caller-selected complete, precedence-resolved configuration with no service.telemetry.metrics override, plus explicit non-loopback scrape declarations only; feature-gate effectiveness and telemetry delivery are unassessed."})

	// containerd: cncfContainerdConfig has a working single-step native input
	// route, but it only ever evaluates
	// containerd.selected-official-runtime-shim-removed.1-7-28-to-2-0-0 (see
	// the hardcoded containerdRemovedOfficialShimRuleID in
	// internal/communityapp/cncf_containerd.go). containerd.cri-v1alpha2-removed.2-0
	// is deliberately NOT registered: no preparer, dispatch branch, or fact
	// produces that rule's identity anywhere in cncfprepare or communityapp,
	// contradicting the survey. Registering it would require inventing new
	// dispatch/evaluation logic, which is out of scope for pure route
	// registration.
	result = append(result, descriptor{family: FamilyCNCF, project: "containerd", component: "pkg:github/containerd/containerd", ruleID: "containerd.selected-official-runtime-shim-removed.1-7-28-to-2-0-0", from: "1.7.28", to: "2.0.0", command: exactPair(extend(cncfBase("containerd"), file("--containerd-config"), name("--runtime-handler"), literal("--containerd-config-complete"), literal("--containerd-config-precedence-resolved"), literal("--containerd-official-upstream"), literal("--containerd-official-bundled-runtimes-only")), "1.7.28", "2.0.0"), limit: "One caller-selected effective CRI runtime handler bound to the reviewed upstream distribution and official bundled runtimes only; external runtime_path overrides, configuration migration, and whole-upgrade compatibility remain unassessed."})

	// Argo CD: cncfArgoCDConfigMap and cncfArgoCDResourceExclusions each have a
	// working single-step native input route already dispatched from cncf().
	result = append(result, descriptor{family: FamilyCNCF, project: "argo-cd", component: "pkg:github/argoproj/argo-cd", ruleID: "argo-cd.required-rbac-inheritance.3-0", from: "2.14.0", to: "3.0.0", command: exactPair(extend(cncfBase("argo-cd"), file("--config-map"), boolean("--requires-inherited-application-permissions")), "2.14.0", "3.0.0"), limit: "One caller-selected ConfigMap plus an explicit inherited-application-permissions intent only; user authorization and the whole RBAC policy are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "argo-cd", component: "pkg:github/argoproj/argo-cd", ruleID: "argo-cd.resource-exclusions-v2-visibility-preservation.3-0", from: "2.14.0", to: "3.0.0", command: exactPair(extend(cncfBase("argo-cd"), file("--resource-exclusions-config-map"), literal("--resource-exclusions-config-complete"), literal("--resource-exclusions-precedence-resolved"), boolean("--requires-v2-visibility-of-v3-default-excluded-resources")), "2.14.0", "3.0.0"), limit: "One complete, precedence-resolved argocd-cm ConfigMap plus an explicit v2-visibility-preservation intent only; resource existence, watches, UI, reconciliation, and runtime behavior are unassessed."})

	// Argo CD: PrepareArgoCDLatestRepository already has a working single-step
	// native input route (wired here); it already handled all five reviewed
	// 3.5.2 latest-target origins via the two-step prepare/check flow before
	// this route existed.
	argoCDLatestBase := extend(cncfBase("argo-cd"), file("--repository-secret"), name("--repository-distribution"), boolean("--repository-settings-resolved"), boolean("--repository-uses-plain-http"))
	argoCDLatestOriginPairs := []struct{ from, id string }{
		{"3.0.23", "argo-cd.plain-http-oci-repository-helm4.3-0-23-to-3-5-2"},
		{"3.1.16", "argo-cd.plain-http-oci-repository-helm4.3-1-16-to-3-5-2"},
		{"3.2.12", "argo-cd.plain-http-oci-repository-helm4.3-2-12-to-3-5-2"},
		{"3.3.14", "argo-cd.plain-http-oci-repository-helm4.3-3-14-to-3-5-2"},
		{"3.4.8", "argo-cd.plain-http-oci-repository-helm4.3-4-8-to-3-5-2"},
	}
	for _, pair := range argoCDLatestOriginPairs {
		result = append(result, descriptor{family: FamilyCNCF, project: "argo-cd", component: "pkg:github/argoproj/argo-cd", ruleID: pair.id, from: pair.from, to: "3.5.2", command: exactPair(argoCDLatestBase, pair.from, "3.5.2"), limit: "One caller-selected pre-apply repository Secret using stringData, plus explicit distribution, settings-resolved, and plain-HTTP declarations only; Secret values, names, URLs, credentials, repository connectivity, Helm execution, and whole-upgrade compatibility are unassessed."})
	}

	// 17 already-routed singleton projects: each has exactly one reviewed rule
	// with a working preparer and CLI dispatch already wired, verified against
	// current main rather than assumed from the survey.
	result = append(result, descriptor{family: FamilyCNCF, project: "kubevirt", component: "pkg:github/kubevirt/kubevirt", ruleID: "kubevirt.interface-binding-cardinality.1-8-4-to-1-9-0", from: "1.8.4", to: "1.9.0", command: exactPair(extend(cncfBase("kubevirt"), file("--native-resource")), "1.8.4", "1.9.0"), limit: "One caller-selected rendered VM or VMI resource only; admission, feature gates, plugins, and runtime behavior are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "metallb", component: "pkg:github/metallb/metallb", ruleID: "metallb.legacy-configmap-removed.0-12-1-to-0-13-2", from: "0.12.1", to: "0.13.2", command: exactPair(extend(cncfBase("metallb"), file("--native-resource")), "0.12.1", "0.13.2"), limit: "One caller-selected submitted ConfigMap only; other cluster configuration migration is unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "contour", component: "pkg:github/projectcontour/contour", ruleID: "contour.gateway-v1alpha1-removed.1-19-0-to-1-20-0", from: "1.19.0", to: "1.20.0", command: exactPair(extend(cncfBase("contour"), file("--native-resource")), "1.19.0", "1.20.0"), limit: "One caller-selected submitted Gateway API resource only; full schema conversion and runtime compatibility are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "cloudnativepg", component: "pkg:github/cloudnative-pg/cloudnative-pg", ruleID: "cloudnativepg.cluster-reference-immutable.1-29-to-1-30", from: "1.29.0", to: "1.30.0", command: exactPair(extend(cncfBase("cloudnativepg"), file("--current-resource"), file("--resource")), "1.29.0", "1.30.0"), limit: "One caller-supplied current/proposed resource pair with matching identity only; admission, controller, and runtime behavior are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.flowcontrol-v1beta3-removed.1-31-0-to-1-32-0", from: "1.31.0", to: "1.32.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.31.0", "1.32.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.admissionwebhook-v1beta1-removed.1-21-0-to-1-22-0", from: "1.21.0", to: "1.22.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.21.0", "1.22.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.apiservice-v1beta1-removed.1-21-0-to-1-22-0", from: "1.21.0", to: "1.22.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.21.0", "1.22.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.crd-v1beta1-removed.1-21-0-to-1-22-0", from: "1.21.0", to: "1.22.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.21.0", "1.22.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.csr-v1beta1-removed.1-21-0-to-1-22-0", from: "1.21.0", to: "1.22.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.21.0", "1.22.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.ingress-extensions-v1beta1-removed.1-21-0-to-1-22-0", from: "1.21.0", to: "1.22.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.21.0", "1.22.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.ingress-networking-v1beta1-removed.1-21-0-to-1-22-0", from: "1.21.0", to: "1.22.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.21.0", "1.22.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.ingressclass-v1beta1-removed.1-21-0-to-1-22-0", from: "1.21.0", to: "1.22.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.21.0", "1.22.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.lease-v1beta1-removed.1-21-0-to-1-22-0", from: "1.21.0", to: "1.22.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.21.0", "1.22.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.priorityclass-v1beta1-removed.1-21-0-to-1-22-0", from: "1.21.0", to: "1.22.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.21.0", "1.22.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.rbac-v1beta1-removed.1-21-0-to-1-22-0", from: "1.21.0", to: "1.22.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.21.0", "1.22.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.storage-v1beta1-removed.1-21-0-to-1-22-0", from: "1.21.0", to: "1.22.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.21.0", "1.22.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.subjectaccessreview-v1beta1-removed.1-21-0-to-1-22-0", from: "1.21.0", to: "1.22.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.21.0", "1.22.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.tokenreview-v1beta1-removed.1-21-0-to-1-22-0", from: "1.21.0", to: "1.22.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.21.0", "1.22.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0", from: "1.24.0", to: "1.25.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.24.0", "1.25.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.csistoragecapacity-v1beta1-removed.1-26-0-to-1-27-0", from: "1.26.0", to: "1.27.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.26.0", "1.27.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.endpointslice-v1beta1-removed.1-24-0-to-1-25-0", from: "1.24.0", to: "1.25.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.24.0", "1.25.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.event-v1beta1-removed.1-24-0-to-1-25-0", from: "1.24.0", to: "1.25.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.24.0", "1.25.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.flowcontrol-v1beta1-removed.1-25-0-to-1-26-0", from: "1.25.0", to: "1.26.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.25.0", "1.26.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.flowcontrol-v1beta2-removed.1-28-0-to-1-29-0", from: "1.28.0", to: "1.29.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.28.0", "1.29.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.hpa-v2beta1-removed.1-24-0-to-1-25-0", from: "1.24.0", to: "1.25.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.24.0", "1.25.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.hpa-v2beta2-removed.1-25-0-to-1-26-0", from: "1.25.0", to: "1.26.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.25.0", "1.26.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.pdb-v1beta1-removed.1-24-0-to-1-25-0", from: "1.24.0", to: "1.25.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.24.0", "1.25.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.psp-v1beta1-removed.1-24-0-to-1-25-0", from: "1.24.0", to: "1.25.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.24.0", "1.25.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubernetes", component: "pkg:github/kubernetes/kubernetes", ruleID: "kubernetes.runtimeclass-v1beta1-removed.1-24-0-to-1-25-0", from: "1.24.0", to: "1.25.0", command: exactPair(extend(cncfBase("kubernetes"), file("--native-resource"), name("--distribution"), literal("--target-api-apply-required"), literal("--resource-scope-complete")), "1.24.0", "1.25.0"), limit: "One caller-selected complete rendered apply-set, bound to the official upstream distribution and target-apply intent only; general manifest schema, CRDs, persisted objects, runtime clients, and API server configuration are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "cilium", component: "pkg:github/cilium/cilium", ruleID: "cilium.cluster-name-invalid.1-16-19-to-1-17-18", from: "1.16.19", to: "1.17.18", command: exactPair(extend(cncfBase("cilium"), file("--cilium-config-map"), name("--cilium-distribution"), literal("--cilium-config-complete"), literal("--cilium-config-precedence-resolved")), "1.16.19", "1.17.18"), limit: "One caller-selected complete, precedence-resolved official-upstream ConfigMap only; ClusterMesh, networking, name-collision, runtime, and whole-upgrade safety are unassessed."})

	// Linkerd: PrepareLinkerd already has a working single-step native input
	// route (wired here); it already evaluated the 2.13.7 -> 2.14.0 pair via
	// the two-step prepare/check flow before this route existed.
	result = append(result, descriptor{family: FamilyCNCF, project: "linkerd", component: "pkg:github/linkerd/linkerd2", ruleID: "linkerd.mtls-identity-selector-minitems.2-13-2-14", from: "2.13.7", to: "2.14.0", command: exactPair(extend(cncfBase("linkerd"), file("--linkerd-resource"), name("--linkerd-distribution"), name("--schema-validation")), "2.13.7", "2.14.0"), limit: "One caller-selected proposed MeshTLSAuthentication resource, plus explicit distribution and schema-validation declarations only; selector cardinality is derived from the resource, but CRD schema validation, cluster admission, and whole-upgrade compatibility are unassessed."})

	// Karmada: PrepareKarmada already has a working single-step native input
	// route (wired here); it already evaluated the 1.18.3 -> 1.19.0 pair via
	// the two-step prepare/check flow before this route existed.
	result = append(result, descriptor{family: FamilyCNCF, project: "karmada", component: "pkg:github/karmada-io/karmada", ruleID: "karmada.application-purge-mode-legacy-values-removed.1-19", from: "1.18.3", to: "1.19.0", command: exactPair(extend(cncfBase("karmada"), file("--karmada-resource"), name("--karmada-distribution"), name("--target-policy-crd-admission")), "1.18.3", "1.19.0"), limit: "One caller-selected proposed PropagationPolicy or ClusterPropagationPolicy resource, plus explicit distribution and target-policy-CRD-admission declarations only; a legacy witness is conclusive, but absence across all proposed resources is never proven, and CRD schema, cluster admission, and whole-upgrade compatibility are unassessed."})

	// Cilium: PrepareCilium already has a working single-step native input
	// route (wired here) for the reviewed nonempty fromRequires/toRequires
	// removal; it already evaluated both reviewed pairs via the two-step
	// prepare/check flow before this route existed. A completeSet declaration
	// can only ever project an absent witness; it never discovers set
	// completeness from a cluster.
	ciliumNonemptyBase := extend(cncfBase("cilium"), file("--cilium-policy"), boolean("--complete-cnp-ccnp-set"))
	result = append(result, descriptor{family: FamilyCNCF, project: "cilium", component: "pkg:github/cilium/cilium", ruleID: "cilium.nonempty-requires-rejected.1-19", from: "1.18.6", to: "1.19.0", command: exactPair(ciliumNonemptyBase, "1.18.6", "1.19.0"), limit: "One caller-selected CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, or flat list, plus an explicit CNP/CCNP policy-set completeness declaration only; a nonempty fromRequires/toRequires witness is conclusive, but an absence result requires the declared complete set, pagination is never assumed complete, and whole-upgrade compatibility is unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "cilium", component: "pkg:github/cilium/cilium", ruleID: "cilium.nonempty-requires-crd-maxitems.1-18-13-to-1-19-7", from: "1.18.13", to: "1.19.7", command: exactPair(ciliumNonemptyBase, "1.18.13", "1.19.7"), limit: "One caller-selected CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, or flat list, plus an explicit CNP/CCNP policy-set completeness declaration only; a nonempty fromRequires/toRequires witness is conclusive, but an absence result requires the declared complete set, pagination is never assumed complete, and whole-upgrade compatibility is unassessed."})

	// KubeEdge: the reviewed rule's own fact description states the whole
	// selector grammar this route decides, and the pinned v1.18 install path,
	// v1.18 --profile flag help, v1.19 install path and v1.19 release note
	// establish each form. The route derives only which of the two reviewed
	// forms one caller-declared argv literally uses; no --profile values file
	// is ever opened.
	result = append(result, descriptor{family: FamilyCNCF, project: "kubeedge", component: "pkg:github/kubeedge/kubeedge", ruleID: "kubeedge.keadm-init-profile-version-selector.1-18-to-1-19", from: "1.18.0", to: "1.19.0", command: exactPair(extend(cncfBase("kubeedge"), file("--keadm-init-argv"), name("--kubeedge-distribution"), boolean("--keadm-argv-complete")), "1.18.0", "1.19.0"), limit: "One caller-declared effective keadm init argv, plus explicit distribution and argv-completeness declarations only; a literal --profile version= selector is conclusive and an explicit --kubeedge-version=v1.19.0 with no --profile is a scoped PASS, while an external --profile values file, both selectors together, neither selector, shorthand spellings, option delimiters, and unresolved rendering stay UNKNOWN. The argv is never executed, no values file is opened, and wrappers, Helm values, chart defaults, runtime behavior and whole-upgrade compatibility are unassessed."})

	// Tekton Pipelines: the pinned v1.10 config-observability.yaml sets the
	// reviewed metrics-protocol key, the pinned v1.10 knative.dev/pkg metrics
	// config declares the protocol tokens and a ProtocolNone default, and the
	// pinned v1.9 parser plus the v1.10 legacy note establish that
	// metrics.backend-destination is the removed spelling. The route reads only
	// the one reviewed data key; it never reads the legacy key as a protocol.
	result = append(result, descriptor{family: FamilyCNCF, project: "tekton", component: "pkg:github/tektoncd/pipeline", ruleID: "tekton.metrics-protocol-prometheus.1-10", from: "1.9.0", to: "1.10.0", command: exactPair(extend(cncfBase("tekton"), file("--tekton-config-observability"), name("--tekton-distribution"), name("--tekton-system-namespace"), boolean("--tekton-config-observability-complete"), boolean("--retain-prometheus-metrics-required")), "1.9.0", "1.10.0"), limit: "The one reviewed metrics-protocol data key in one caller-selected v1 ConfigMap named config-observability, bound to the caller-declared proposed system namespace, plus explicit distribution, complete-effective-composition and Prometheus-retention declarations only; an exact prometheus value is a scoped PASS and a definite absence is BLOCKED against the reviewed ProtocolNone target default, while a recognized non-Prometheus token, an empty or ambiguous value, a near-miss or duplicate key, binaryData overlap, and unresolved documents stay UNKNOWN. The removed legacy metrics.backend-destination key is never read as a protocol, no ConfigMap is discovered from a cluster, and effective composition, endpoint configuration, scrape availability, dashboards, alerts, runtime rollout and whole-upgrade compatibility are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "cri-o", component: "pkg:github/cri-o/cri-o", ruleID: "cri-o.artifact-short-name-rejected.1-35", from: "1.34.0", to: "1.35.0", command: exactPair(extend(cncfBase("cri-o"), file("--image-status-request"), literal("--artifact-operation"), literal("named-reference-resolution")), "1.34.0", "1.35.0"), limit: "One explicitly declared named-reference resolution plan only; store contents, caller branch, ordinary images, and runtime remain unverified."})
	result = append(result, descriptor{family: FamilyCNCF, project: "cubefs", component: "pkg:github/cubefs/cubefs", ruleID: "cubefs.metanode-raft-snapshot-format.3-2-1-to-3-3-2", from: "3.2.1", to: "3.3.2", command: exactPair(extend(cncfBase("cubefs"), file("--metanode-config"), literal("--phase"), literal("metanode-upgrade")), "3.2.1", "3.3.2"), limit: "One caller-supplied MetaNode configuration and planned-phase guard only; peers, the running CubeFS cluster, and whole-upgrade safety are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "the-update-framework-tuf", component: "pkg:github/theupdateframework/python-tuf", ruleID: "tuf.updater-bootstrap-keyword.6-to-7", from: "6.0.0", to: "7.0.0", command: exactPair(extend(cncfBase("the-update-framework-tuf"), file("--python-source")), "6.0.0", "7.0.0"), limit: "One conservatively bound direct tuf.ngclient.Updater call in caller-supplied Python source only; aliases, rebinding, dynamic calls, and source outside this grammar remain UNKNOWN."})
	result = append(result, descriptor{family: FamilyCNCF, project: "in-toto", component: "pkg:github/in-toto/in-toto", ruleID: "in-toto.run-legacy-key-argument-removed.2-2-to-3-0", from: "2.2.0", to: "3.0.0", command: exactPair(extend(cncfBase("in-toto"), file("--in-toto-run-argv")), "2.2.0", "3.0.0"), limit: "One conservatively parsed planned in-toto-run argv only; a running process, key material, and the opaque wrapped command are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "knative", component: "pkg:github/knative/serving", ruleID: "knative.serving-startup-http-named-port.1-22-to-1-23", from: "1.22.0", to: "1.23.0", command: exactPair(extend(cncfBase("knative"), file("--service")), "1.22.0", "1.23.0"), limit: "One proposed Service with a single user container, one explicit named startup-probe port, and one explicit supported named container port only; every absent or ambiguous shape remains UNKNOWN."})
	result = append(result, descriptor{family: FamilyCNCF, project: "kubeflow", component: "pkg:pypi/kfp", ruleID: "kubeflow.kfp-create-component-from-func-removed.1-8-22-to-2-0-0", from: "1.8.22", to: "2.0.0", command: exactPair(extend(cncfBase("kubeflow"), file("--python-source")), "1.8.22", "2.0.0"), limit: "One conservatively bound bare decorator form in caller-supplied Python source only; source outside this deliberately small subset remains UNKNOWN."})
	result = append(result, descriptor{family: FamilyCNCF, project: "buildpacks", component: "pkg:oci/buildpacksio/lifecycle", ruleID: "buildpacks.lifecycle-platform-api-support.0-16-5-to-0-17-7", from: "0.16.5", to: "0.17.7", command: exactPair(extend(cncfBase("buildpacks"), file("--current-lifecycle-config"), file("--proposed-lifecycle-config"), name("--current-platform-api"), name("--proposed-platform-api")), "0.16.5", "0.17.7"), limit: "One 0.16.5 to 0.17.7 plan whose current Platform API request is declared supported in two caller-supplied Lifecycle config documents only; registry provenance and runtime behavior are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "emissary-ingress", component: "pkg:github/emissary-ingress/emissary", ruleID: "emissary-ingress.metrics-endpoint-removed.3-10-to-4-0", from: "3.10.0", to: "4.0.1", command: exactPair(extend(cncfBase("emissary-ingress"), file("--diagd-argv")), "3.10.0", "4.0.1"), limit: "One caller-declared direct diagd argv only; the banner endpoint's default change is not treated as option removal, and runtime behavior is unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "openfga", component: "pkg:github/openfga/openfga", ruleID: "openfga.oidc-required-fields.1-17-1-to-1-18-0", from: "1.17.1", to: "1.18.0", command: exactPair(extend(cncfBase("openfga"), file("--effective-config"), literal("--effective-config-complete")), "1.17.1", "1.18.0"), limit: "One caller-declared effective configuration only; startup, reachability, and runtime behavior are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "distribution", component: "pkg:github/distribution/distribution", ruleID: "distribution.schema1-manifest-removed.2-8-3-to-3-0-0", from: "2.8.3", to: "3.0.0", command: exactPair(extend(cncfBase("distribution"), file("--image-manifest")), "2.8.3", "3.0.0"), limit: "One caller-supplied image manifest JSON document only; schema1 enablement in a given deployment, storage, pull, content, platform, and runtime behavior are unassessed."})
	result = append(result, descriptor{family: FamilyCNCF, project: "container-network-interface-cni", component: "pkg:generic/cni-configuration-spec", ruleID: "cni-spec.non-list-configuration-removed.0-4-0-to-1-0-0", from: "0.4.0", to: "1.0.0", command: exactPair(extend(cncfBase("container-network-interface-cni"), file("--cni-configuration"), literal("--operation"), literal("configuration-spec-migration")), "0.4.0", "1.0.0"), limit: "One caller-supplied configuration shape and explicit specification-migration intent only; it does not identify the CNI library, plugins, or a runtime."})

	// NOTE: prometheus.alertmanager-api-v1-removed.2-55-1-to-3-14-0 and
	// prometheus.scrape-classic-histograms-key-renamed.2-55-1-to-3-14-0 are
	// deliberately NOT registered here. Verification showed
	// prometheusReviewedTransition (internal/cncfprepare/prometheus.go) does
	// not admit the (2.55.1, 3.14.0) origin/target pair for either the
	// alertmanager or scrape-config preparer, so no working native route
	// exists for these two rule identities today, contradicting the survey.
	// TestDiscoverExactPairExcludesCrossMode in catalog_test.go independently
	// asserts that only prometheus.remote-write-http2-default.2-55-1-to-3-14-0
	// is bound for that pair, confirming this gap. Registering these two would
	// require adding new dispatch/evaluation logic, which is out of scope for
	// pure route registration.

	// NOTE: none of the eleven rook.* rule identities are registered here.
	// Verification (not survey) showed rook has no working native route at
	// all today:
	//   - internal/communityapp/cncf_native_resource.go's project switch does
	//     not list "rook"; `check cncf --project rook --native-resource FILE
	//     --from X --to Y --now T` fails with "native resource flags require
	//     metallb, contour, kubevirt, thanos, cortex, cloudnativepg, flux,
	//     kubernetes, cilium, etcd, harbor, fluentd, opencost, or
	//     cloud-custodian".
	//   - internal/communityapp/cncf_prepare.go's project switch does not
	//     list "rook" either; `prepare cncf --project rook ...` fails with
	//     "invalid CNCF preparation project; use --help".
	//   - No cncfprepare.PrepareRook (or equivalent) function exists, and
	//     cncfprepare.PrepareNativeMigration only recognizes "metallb" and
	//     "contour".
	// Rook's only reachable route is the generic operator-declared minimized
	// --input path (see internal/communityapp/cncf_rook_latest_test.go),
	// which by design embeds the from/to pair inside the canonical JSON and
	// admits no --from/--to flags, so it can never satisfy validDescriptor's
	// requirement of literal "--from FROM --to TO" segments. The four
	// rook.direct-minor-skip.* (forbid_target_version) rules need no facts
	// to evaluate, but still have no adapter to bind to; the six
	// rook.minimum-kubernetes.* (require_component_version) rules would
	// additionally need a genuinely new adapter that extracts a Kubernetes
	// dependency version from a real Rook resource; and
	// rook.helm-intermediate-1-19-5.1-20 (require_intermediate_version)
	// would need one that extracts component.rook.deployment_mode. Building
	// any of that is new adapter/preparer work, which is out of scope for
	// pure route registration. TestDiscoverRookHasNoWorkingNativeRoute in
	// catalog_test.go independently asserts this gap.

	// NOTE: opa (6 reviewed rule identities: opa.v0-consumer-producer-option.1-0
	// plus the five opa.v0-consumer-producer-option-at-1-20-2-from-* target
	// pairs) and dragonfly (2 reviewed rule identities:
	// dragonfly.manager-retained-debug.2-2-3-2-2-4 and
	// dragonfly.scheduler-retained-debug.2-2-3-2-2-4) are deliberately NOT
	// registered here. Verification found no native-format preparer, no
	// cncfNativeFormat dispatch case, and no dedicated CLI flags for either
	// project anywhere in internal/cncfprepare or internal/communityapp/cncf.go.
	// The only route either project has today is the generic
	// `check cncf --project <opa|dragonfly> --input FILE` minimized-declaration
	// path already covered by GenericDeclarationRoute; runOPALatestExample in
	// internal/communityapp/community_examples.go exercises exactly that path by
	// hand-authoring the already-minimized operator-declared JSON directly, not
	// by deriving it from any real native OPA or Dragonfly artifact. There is no
	// working single-step native exact-pair route and no two-step prepare/check
	// flow for either project, so both are Class C (no adapter at all).
	// Registering descriptors for them would require building new preparers,
	// which is out of scope for pure route registration.
	return result
}

func identityKey(family, project, component, ruleID, from, to string) string {
	return family + "\x00" + project + "\x00" + component + "\x00" + ruleID + "\x00" + from + "\x00" + to
}

func genericRoute(family, project, from, to string) Route {
	if family == FamilyCommunity {
		return Route{State: RouteNotExposed, Limit: "Community embedded rules have no generic public canonical-input command."}
	}
	return Route{State: RouteExposed, Command: []Argument{literal("check"), literal("cncf"), literal("--project"), literal(project), file("--input"), timestamp("--now")}, Limit: "The canonical minimized declaration itself binds this identity's own from/to pair; generic CLI --from/--to flags are not admitted."}
}

// Discover returns all compiled source-rule identities, optionally narrowed by
// project and a queried from/to pair. A queried pair narrows to identities the
// range matcher accepts, whether that is the reviewed anchor or, for a rule
// with a reviewed range, a transition inside it. It neither reads inputs nor
// evaluates rules.
func Discover(selectedProject, selectedFrom, selectedTo string) (Result, error) {
	cncf, err := cncfcheck.EmbeddedRuleIdentities()
	if err != nil {
		return Result{}, fmt.Errorf("load CNCF identities: %w", err)
	}
	community, err := projectcheck.EmbeddedRuleIdentities()
	if err != nil {
		return Result{}, fmt.Errorf("load community identities: %w", err)
	}
	descriptors := map[string]descriptor{}
	for _, item := range descriptorSet() {
		key := identityKey(item.family, item.project, item.component, item.ruleID, item.from, item.to)
		if _, found := descriptors[key]; found || !validDescriptor(item) {
			return Result{}, ErrIntegrity
		}
		descriptors[key] = item
	}
	knownProjects := map[string]bool{}
	known := map[string]bool{}
	for _, item := range cncf {
		knownProjects[item.Project] = true
		known[identityKey(FamilyCNCF, item.Project, item.Component, item.RuleID, item.From, item.To)] = true
	}
	for _, item := range community {
		knownProjects[item.Project] = true
		known[identityKey(FamilyCommunity, item.Project, item.Component, item.RuleID, item.From, item.To)] = true
	}
	if len(descriptors) != 194 {
		return Result{}, fmt.Errorf("%w: descriptor count=%d", ErrIntegrity, len(descriptors))
	}
	for key := range descriptors {
		if !known[key] {
			return Result{}, fmt.Errorf("%w: descriptor does not bind an embedded identity", ErrIntegrity)
		}
	}
	coverage := "MATCHED"
	if !knownProjects[selectedProject] {
		coverage = "PROJECT_NOT_IN_EMBEDDED_RULE_PACK"
	} else if selectedFrom != "" && selectedTo != "" {
		coverage = "NO_MATCHING_EMBEDDED_RULE"
	}
	result := Result{Schema: Schema, MetadataSource: "EMBEDDED_COMPILED_BUNDLES_ONLY", SourceOnlyState: "NOT_ENUMERATED", RuleCoverageState: coverage, Scope: Scope{IncludedFamilies: []string{FamilyCNCF, FamilyCommunity}, ExcludedFamilies: []string{"named_check", "standards_conformance", "target_preflight"}, CoverageMeaning: "exact embedded source-rule identity discovery only", SourceEvidenceFreshness: "NOT_EVALUATED"}, Query: Query{Project: selectedProject, From: selectedFrom, To: selectedTo}, NamedCheckHints: namedHints(selectedProject), Checks: make([]Check, 0, len(cncf)+len(community))}
	appendIdentity := func(family, project, component, ruleID, from, to string, subject constraintengine.RuleTransition) {
		if projectFilter(selectedProject, selectedFrom, selectedTo, project, subject) {
			return
		}
		item := Check{Family: family, Project: project, Component: component, RuleID: ruleID, From: from, To: to, GenericDeclarationRoute: genericRoute(family, project, from, to), NativeDescriptor: Route{State: DescriptorNone}, Range: subject.Range}
		if selectedFrom != "" && selectedTo != "" {
			if mode := subject.Match(selectedFrom, selectedTo); mode == constraintengine.MatchRange || mode == constraintengine.MatchCrossing {
				item.MatchMode = string(mode)
			}
		}
		if descriptor, found := descriptors[identityKey(family, project, component, ruleID, from, to)]; found {
			item.NativeDescriptor = Route{State: DescriptorExact, Command: descriptor.command, Limit: descriptor.limit, NativePass: descriptor.nativePass}
		}
		result.Checks = append(result.Checks, item)
	}
	for _, item := range cncf {
		appendIdentity(FamilyCNCF, item.Project, item.Component, item.RuleID, item.From, item.To, item.Transition())
	}
	for _, item := range community {
		appendIdentity(FamilyCommunity, item.Project, item.Component, item.RuleID, item.From, item.To, item.Transition())
	}
	sort.Slice(result.Checks, func(i, j int) bool {
		if result.Checks[i].Project != result.Checks[j].Project {
			return result.Checks[i].Project < result.Checks[j].Project
		}
		if result.Checks[i].To != result.Checks[j].To {
			return result.Checks[i].To < result.Checks[j].To
		}
		if result.Checks[i].From != result.Checks[j].From {
			return result.Checks[i].From < result.Checks[j].From
		}
		return result.Checks[i].RuleID < result.Checks[j].RuleID
	})
	if len(result.Checks) != 0 {
		result.RuleCoverageState = "MATCHED"
	}
	return result, nil
}

func validDescriptor(item descriptor) bool {
	if item.family == "" || item.project == "" || item.component == "" || item.ruleID == "" || item.from == "" || item.to == "" || item.limit == "" || len(item.command) == 0 {
		return false
	}
	if len(item.command) < 8 || !isLiteral(item.command[0], "check") || item.command[1].Kind != "literal" || (item.command[1].Literal != "cncf" && item.command[1].Literal != "project") || !isLiteral(item.command[2], "--project") || !isLiteral(item.command[3], item.project) {
		return false
	}
	seen := map[string]bool{}
	for _, arg := range item.command {
		switch arg.Kind {
		case "literal":
			if arg.Literal == "" || strings.ContainsAny(arg.Literal, "\t\r\n") {
				return false
			}
		case "file_placeholder", "name_placeholder", "timestamp_placeholder":
			if !strings.HasPrefix(arg.Name, "--") || seen[arg.Name] {
				return false
			}
			seen[arg.Name] = true
		case "boolean_operator_declaration":
			if !strings.HasPrefix(arg.Name, "--") || seen[arg.Name] || len(arg.AllowedValues) != 2 || arg.AllowedValues[0] != "true" || arg.AllowedValues[1] != "false" {
				return false
			}
			seen[arg.Name] = true
		default:
			return false
		}
	}
	return containsLiteralSequence(item.command, "--from", item.from) && containsLiteralSequence(item.command, "--to", item.to) && containsTimestamp(item.command, "--now")
}

func containsLiteralSequence(args []Argument, first, second string) bool {
	for index := 0; index+1 < len(args); index++ {
		if isLiteral(args[index], first) && isLiteral(args[index+1], second) {
			return true
		}
	}
	return false
}

func isLiteral(arg Argument, value string) bool {
	return arg.Kind == "literal" && arg.Literal == value && arg.Name == "" && len(arg.AllowedValues) == 0
}

func containsTimestamp(args []Argument, name string) bool {
	for _, arg := range args {
		if arg.Kind == "timestamp_placeholder" && arg.Name == name {
			return true
		}
	}
	return false
}

func namedHints(project string) []NamedCheckHint {
	switch project {
	case "cert-manager":
		return []NamedCheckHint{{Command: []Argument{literal("check"), literal("cert-manager-values"), literal("--help")}, HelpOnly: true}}
	case "prometheus":
		return []NamedCheckHint{{Command: []Argument{literal("check"), literal("prometheus-mode"), literal("--help")}, HelpOnly: true}}
	default:
		return []NamedCheckHint{}
	}
}

// projectFilter reports whether an identity is excluded by the query. Version
// filters go through the shared matcher: with both versions the pair must
// match the anchor or the reviewed range; with one, that side alone must.
func projectFilter(selectedProject, selectedFrom, selectedTo, project string, subject constraintengine.RuleTransition) bool {
	if selectedProject != "" && selectedProject != project {
		return true
	}
	if selectedFrom != "" && selectedTo != "" {
		return subject.Match(selectedFrom, selectedTo) == constraintengine.MatchNone
	}
	return selectedFrom != "" && !subject.MatchesFrom(selectedFrom) || selectedTo != "" && !subject.MatchesTo(selectedTo)
}
