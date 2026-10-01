// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	TektonComponent = "pkg:github/tektoncd/pipeline"

	TektonDistributionFact   = "component.tekton.distribution"
	TektonIdentityBoundFact  = "component.tekton.config_observability_identity_bound"
	TektonCompleteFact       = "component.tekton.proposed_config_observability_complete_effective"
	TektonRetainRequiredFact = "component.tekton.retain_prometheus_metrics_required"
	TektonPrometheusFact     = "component.tekton.proposed_metrics_protocol_prometheus"

	TektonDistributionOfficial = "official_upstream"
	TektonDistributionCustom   = "custom_build"

	TektonFrom = "1.9.0"
	TektonTo   = "1.10.0"

	// tektonConfigMapName and tektonMetricsProtocolKey are the exact literal
	// identity and data key the reviewed evidence names. tektonProtocolPrometheus
	// is the exact protocol token from the pinned knative.dev/pkg observability
	// metrics constants; the other three are listed so a recognized non-Prometheus
	// value is reported as unsupported instead of silently becoming false.
	tektonConfigMapName      = "config-observability"
	tektonMetricsProtocolKey = "metrics-protocol"
	tektonProtocolPrometheus = "prometheus"
)

// tektonOtherProtocols are the remaining protocol tokens the pinned v1.10
// knative.dev/pkg/observability/metrics/config.go constants declare. They exist
// only so the adapter can say "recognized but not Prometheus" rather than
// treating them as an absence.
var tektonOtherProtocols = map[string]bool{"grpc": true, "http/protobuf": true, "none": true}

const (
	ReasonTektonPrometheusDeclared    Reason = "TEKTON_METRICS_PROTOCOL_PROMETHEUS_DECLARED"
	ReasonTektonPrometheusAbsent      Reason = "TEKTON_METRICS_PROTOCOL_DEFINITELY_ABSENT"
	ReasonTektonProtocolNotPrometheus Reason = "TEKTON_METRICS_PROTOCOL_NOT_PROMETHEUS"
	ReasonTektonProtocolUnsupported   Reason = "TEKTON_METRICS_PROTOCOL_VALUE_UNSUPPORTED"
	ReasonTektonIdentityUnresolved    Reason = "TEKTON_CONFIG_OBSERVABILITY_IDENTITY_UNRESOLVED"
	ReasonTektonGuardMissing          Reason = "TEKTON_GUARD_DECLARATION_MISSING"
	ReasonTektonPairUnsupported       Reason = "TEKTON_TRANSITION_NOT_REVIEWED"
)

// PrepareTektonConfigObservability derives the five facts the reviewed Tekton
// Pipelines 1.9.0 -> 1.10.0 metrics rule already requires from one
// caller-selected config-observability ConfigMap, instead of making an operator
// hand-author the canonical declaration.
//
// It authors no new compatibility claim. The reviewed evidence already states
// everything this adapter decides:
//
//   - the pinned v1.10 config/config-observability.yaml sets
//     "metrics-protocol: prometheus" in its data block, under apiVersion v1,
//     kind ConfigMap, name config-observability;
//   - the pinned v1.10 knative.dev/pkg/observability/metrics/config.go declares
//     the protocol tokens grpc, http/protobuf, prometheus and none, parses only
//     the flat key "metrics-protocol", and its DefaultConfig returns
//     ProtocolNone -- so a definite absence of that key is definitively not
//     Prometheus rather than an unknown;
//   - the pinned v1.10 config-observability.yaml note and the pinned v1.9
//     knative.dev/pkg/metrics/config.go parser show that the old
//     metrics.backend-destination key is the removed OpenCensus spelling the
//     target parser no longer recognizes.
//
// So the adapter decides only whether the selected proposed data has exactly
// one functional metrics-protocol value of prometheus. A definite absence is
// false, which blocks. A recognized non-Prometheus token, an empty value, a
// duplicate or oddly-spelled key, a non-string value, or an unresolved document
// stays unsupported and UNKNOWN, exactly as the reviewed fact description
// requires. The legacy metrics.backend-destination key is deliberately not read
// as a protocol: the reviewed evidence states the target parser no longer
// recognizes it, and reading it would invent a claim.
//
// Identity binding compares the document's apiVersion, kind and name with the
// exact reviewed identity and its namespace with systemNamespace, which is the
// caller's own declaration of the proposed system namespace. No ConfigMap is
// discovered, no cluster is read, and effective composition, endpoint
// configuration, scrape availability, dashboards, alerts and runtime rollout
// are not evaluated.
func PrepareTektonConfigObservability(raw []byte, from, to, distribution, systemNamespace string, complete, retainRequired *bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	if distribution != "" && distribution != TektonDistributionOfficial && distribution != TektonDistributionCustom {
		return Prepared{}, ErrInvalid
	}
	if strings.TrimSpace(systemNamespace) != systemNamespace {
		return Prepared{}, ErrInvalid
	}
	facts := []inputFact{
		{ID: TektonIdentityBoundFact, State: "unsupported"},
		{ID: TektonDistributionFact, State: "missing"},
		{ID: TektonCompleteFact, State: "missing"},
		{ID: TektonPrometheusFact, State: "unsupported"},
		{ID: TektonRetainRequiredFact, State: "missing"},
	}
	if distribution != "" {
		facts[1] = inputFact{ID: TektonDistributionFact, State: "declared", EnumValue: distribution}
	}
	if complete != nil {
		facts[2] = inputFact{ID: TektonCompleteFact, State: "declared", BoolValue: complete}
	}
	if retainRequired != nil {
		facts[4] = inputFact{ID: TektonRetainRequiredFact, State: "declared", BoolValue: retainRequired}
	}
	state, reason := StateUnknown, ReasonTektonGuardMissing
	switch {
	case !tektonReviewedPair(from, to):
		reason = ReasonTektonPairUnsupported
	case facts[1].State != "declared" || facts[2].State != "declared" || facts[4].State != "declared" || systemNamespace == "":
		reason = ReasonTektonGuardMissing
	default:
		bound, prometheus, inspectReason := inspectTektonConfigObservability(raw, systemNamespace)
		reason = inspectReason
		if bound {
			value := true
			facts[0] = inputFact{ID: TektonIdentityBoundFact, State: "declared", BoolValue: &value}
		}
		if bound && prometheus != nil {
			facts[3] = inputFact{ID: TektonPrometheusFact, State: "declared", BoolValue: prometheus}
			state = StatePrepared
		}
	}
	canonical, err := marshalComponentInput(TektonComponent, from, to, facts)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"CALLER_SELECTED_CONFIGMAP_IS_NOT_LIVE_CLUSTER_DISCOVERY",
			"EFFECTIVE_COMPOSITION_AND_OVERLAYS_NOT_RESOLVED",
			"METRICS_ENDPOINT_SCRAPE_AVAILABILITY_DASHBOARDS_AND_ALERTS_NOT_EVALUATED",
			OmissionNoLiveObservation,
			OmissionNoWholeUpgrade,
		},
	}, nil
}

// inspectTektonConfigObservability binds the reviewed ConfigMap identity and
// then reads the one reviewed data key. prometheus stays nil whenever the key's
// value cannot be resolved against the reviewed protocol tokens.
func inspectTektonConfigObservability(raw []byte, systemNamespace string) (bound bool, prometheus *bool, reason Reason) {
	root, ok := ciliumClusterSingleYAML(raw)
	if !ok || root.Kind != yaml.MappingNode {
		return false, nil, ReasonTektonIdentityUnresolved
	}
	api, fieldState := argoCDExactField(root, "apiVersion")
	if fieldState != argoCDFieldFound || !argoCDString(api, "v1") {
		return false, nil, ReasonTektonIdentityUnresolved
	}
	kind, fieldState := argoCDExactField(root, "kind")
	if fieldState != argoCDFieldFound || !argoCDString(kind, "ConfigMap") {
		return false, nil, ReasonTektonIdentityUnresolved
	}
	metadata, fieldState := argoCDExactField(root, "metadata")
	if fieldState != argoCDFieldFound || metadata.Kind != yaml.MappingNode {
		return false, nil, ReasonTektonIdentityUnresolved
	}
	name, fieldState := argoCDExactField(metadata, "name")
	if fieldState != argoCDFieldFound || !argoCDString(name, tektonConfigMapName) {
		return false, nil, ReasonTektonIdentityUnresolved
	}
	namespace, fieldState := argoCDExactField(metadata, "namespace")
	if fieldState != argoCDFieldFound || !argoCDString(namespace, systemNamespace) {
		return false, nil, ReasonTektonIdentityUnresolved
	}
	// binaryData could carry the reviewed key in a shape this adapter cannot
	// decode, so any overlap leaves the whole document unresolved rather than
	// producing a definite absence.
	if binaryData, binaryState := argoCDExactField(root, "binaryData"); binaryState == argoCDFieldInvalid || (binaryState == argoCDFieldFound && tektonBinaryProtocolOverlap(binaryData)) {
		return false, nil, ReasonTektonIdentityUnresolved
	}
	data, fieldState := argoCDExactField(root, "data")
	switch fieldState {
	case argoCDFieldInvalid:
		return false, nil, ReasonTektonIdentityUnresolved
	case argoCDFieldMissing:
		// No data block at all. The pinned target parser receives an empty map
		// and its DefaultConfig yields ProtocolNone, so this is a definite
		// absence of a Prometheus protocol, not an unknown.
		absent := false
		return true, &absent, ReasonTektonPrometheusAbsent
	}
	if data.Kind != yaml.MappingNode || !argoCDStrictStringData(data) {
		return false, nil, ReasonTektonIdentityUnresolved
	}
	// A key that only differs from the reviewed spelling by case or surrounding
	// space is ambiguous, so it must not be read as an absence.
	if argoCDNearField(data, tektonMetricsProtocolKey) {
		return true, nil, ReasonTektonProtocolUnsupported
	}
	value, fieldState := argoCDExactField(data, tektonMetricsProtocolKey)
	switch fieldState {
	case argoCDFieldInvalid:
		return true, nil, ReasonTektonProtocolUnsupported
	case argoCDFieldMissing:
		absent := false
		return true, &absent, ReasonTektonPrometheusAbsent
	}
	if value.Kind != yaml.ScalarNode || value.ShortTag() != yamlStrTag {
		return true, nil, ReasonTektonProtocolUnsupported
	}
	switch {
	case value.Value == tektonProtocolPrometheus:
		present := true
		return true, &present, ReasonTektonPrometheusDeclared
	case tektonOtherProtocols[value.Value]:
		// Recognized, but not the Prometheus protocol. The reviewed fact
		// description keeps a non-Prometheus value UNKNOWN rather than false.
		return true, nil, ReasonTektonProtocolNotPrometheus
	default:
		// Empty, whitespace-padded, differently-cased, or unrecognized.
		return true, nil, ReasonTektonProtocolUnsupported
	}
}

func tektonBinaryProtocolOverlap(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.MappingNode || len(node.Content)%2 != 0 {
		return true
	}
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i]
		if key.Kind != yaml.ScalarNode || key.ShortTag() != yamlStrTag {
			return true
		}
		if strings.EqualFold(strings.TrimSpace(key.Value), tektonMetricsProtocolKey) {
			return true
		}
	}
	return false
}

// tektonReviewedPair covers exactly the one packaged Tekton transition; no
// other origin or target is admitted.
func tektonReviewedPair(from, to string) bool {
	return from == TektonFrom && to == TektonTo
}
