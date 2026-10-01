// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"io"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// PrepareOpenTelemetryCollector reads a deliberately small native Collector
// YAML subset. It establishes only whether a logging exporter is configured
// under top-level exporters. Pipeline references are checked for dangling or
// connector-only names, but cannot create that fact by themselves.
const (
	OpenTelemetryComponent                 = "pkg:github/open-telemetry/opentelemetry-collector"
	OpenTelemetryDistributionFact          = "component.opentelemetry.distribution"
	OpenTelemetryLoggingExporterFact       = "component.opentelemetry.logging_exporter_present"
	OpenTelemetryMetricsOverrideAbsentFact = "component.opentelemetry.internal_metrics_override_absent"
	OpenTelemetryMetricsGateFact           = "component.opentelemetry.telemetry_use_localhost_default_metrics_address_effective"
	OpenTelemetryMetricsRemoteRequiredFact = "component.opentelemetry.internal_metrics_remote_scrape_required"
	OpenTelemetryMetricsConflictFact       = "component.opentelemetry.internal_metrics_localhost_remote_conflict"
	OpenTelemetryConfigCompleteFact        = "component.opentelemetry.config_complete"
	OpenTelemetryConfigPrecedenceFact      = "component.opentelemetry.config_precedence_resolved"
	OpenTelemetryOfficialDistribution      = "official"
	OpenTelemetryCustomDistribution        = "custom"
	OpenTelemetryFrom                      = "0.110.0"
	OpenTelemetryTo                        = "0.111.0"
)

const OpenTelemetryInternalMetricsRuleID = "opentelemetry.internal-telemetry-default-bind.0-110-to-0-111"

const (
	ReasonOpenTelemetryPresent     Reason = "OPENTELEMETRY_LOGGING_EXPORTER_CONFIGURED"
	ReasonOpenTelemetryAbsent      Reason = "OPENTELEMETRY_LOGGING_EXPORTER_ABSENT_FROM_SELECTED_EXPORTERS"
	ReasonOpenTelemetryUnsupported Reason = "OPENTELEMETRY_SELECTED_CONFIG_UNSUPPORTED"
	ReasonOpenTelemetryIncomplete  Reason = "OPENTELEMETRY_CONFIG_INCOMPLETE_OR_PRECEDENCE_UNRESOLVED"
)

// PrepareOpenTelemetryCollector does not resolve providers, environment
// substitution, includes, or command-line overrides. The two completeness
// arguments are caller declarations, never observations.
func PrepareOpenTelemetryCollector(raw []byte, from, to, distribution string, complete, precedenceResolved bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	if distribution != "" && distribution != OpenTelemetryOfficialDistribution && distribution != OpenTelemetryCustomDistribution {
		return Prepared{}, ErrInvalid
	}
	found, supported := parseOpenTelemetryConfig(raw)
	exactPair := from == OpenTelemetryFrom && to == OpenTelemetryTo
	facts := []inputFact{
		{ID: OpenTelemetryDistributionFact, State: "unsupported"},
		{ID: OpenTelemetryLoggingExporterFact, State: "unsupported"},
	}
	state, reason := StateUnknown, ReasonOpenTelemetryUnsupported
	if distribution != "" {
		facts[0] = inputFact{ID: OpenTelemetryDistributionFact, State: "declared", EnumValue: distribution}
	}
	if !exactPair || distribution == "" || distribution == OpenTelemetryCustomDistribution {
		reason = ReasonOpenTelemetryUnsupported
	} else if !supported {
		reason = ReasonOpenTelemetryUnsupported
	} else if !complete || !precedenceResolved {
		reason = ReasonOpenTelemetryIncomplete
	} else {
		facts[1] = otelBoolFact(OpenTelemetryLoggingExporterFact, found)
		state = StatePrepared
		if found {
			reason = ReasonOpenTelemetryPresent
		} else {
			reason = ReasonOpenTelemetryAbsent
		}
	}
	canonical, err := marshalComponentInput(OpenTelemetryComponent, from, to, facts)
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
			"CALLER_SUPPLIED_COLLECTOR_CONFIG_NOT_LIVE_OBSERVATION",
			"DISTRIBUTION_COMPLETENESS_AND_PRECEDENCE_ARE_CALLER_DECLARATIONS",
			"PROVIDERS_INCLUDES_ENVIRONMENT_AND_COMMAND_LINE_OVERRIDES_NOT_RESOLVED",
			"ONLY_LOGGING_EXPORTER_CONFIGURATION_IS_EVALUATED;_PIPELINES_CONNECTORS_STARTUP_AND_TELEMETRY_DELIVERY_REMAIN_UNASSESSED",
			"WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
		},
	}, nil
}

// PrepareOpenTelemetryInternalMetrics derives the narrow internal-metrics
// default predicate. The feature-gate and remote-scrape values are explicit
// caller declarations; the local YAML only establishes that it has no
// service.telemetry.metrics override.
func PrepareOpenTelemetryInternalMetrics(raw []byte, from, to, distribution, gateEffective, remoteScrapeRequired string, complete, precedenceResolved bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	if distribution != "" && distribution != OpenTelemetryOfficialDistribution && distribution != OpenTelemetryCustomDistribution {
		return Prepared{}, ErrInvalid
	}
	gate, gateKnown := parseOpenTelemetryAuthority(gateEffective)
	remote, remoteKnown := parseOpenTelemetryAuthority(remoteScrapeRequired)
	overrideAbsent, supported := parseOpenTelemetryMetricsDefaultConfig(raw)
	exactPair := from == OpenTelemetryFrom && to == OpenTelemetryTo
	facts := []inputFact{
		{ID: OpenTelemetryConfigCompleteFact, State: "unsupported"},
		{ID: OpenTelemetryConfigPrecedenceFact, State: "unsupported"},
		{ID: OpenTelemetryDistributionFact, State: "unsupported"},
		{ID: OpenTelemetryMetricsConflictFact, State: "unsupported"},
		{ID: OpenTelemetryMetricsOverrideAbsentFact, State: "unsupported"},
		{ID: OpenTelemetryMetricsRemoteRequiredFact, State: "unsupported"},
		{ID: OpenTelemetryMetricsGateFact, State: "unsupported"},
	}
	state, reason := StateUnknown, ReasonOpenTelemetryUnsupported
	if distribution != "" {
		facts[2] = inputFact{ID: OpenTelemetryDistributionFact, State: "declared", EnumValue: distribution}
	}
	if exactPair && distribution == OpenTelemetryOfficialDistribution && supported {
		facts[0] = otelBoolFact(OpenTelemetryConfigCompleteFact, complete)
		facts[1] = otelBoolFact(OpenTelemetryConfigPrecedenceFact, precedenceResolved)
		facts[4] = otelBoolFact(OpenTelemetryMetricsOverrideAbsentFact, overrideAbsent)
		if gateKnown {
			facts[6] = otelBoolFact(OpenTelemetryMetricsGateFact, gate)
		}
		if remoteKnown {
			facts[5] = otelBoolFact(OpenTelemetryMetricsRemoteRequiredFact, remote)
		}
		if gateKnown && remoteKnown {
			facts[3] = otelBoolFact(OpenTelemetryMetricsConflictFact, gate && remote)
		}
		switch {
		case !gateKnown || !remoteKnown:
			reason = ReasonOpenTelemetryMetricsAuthorityMissing
		case !complete || !precedenceResolved:
			reason = ReasonOpenTelemetryIncomplete
		case !overrideAbsent:
			reason = ReasonOpenTelemetryMetricsOverride
		default:
			state, reason = StatePrepared, ReasonOpenTelemetryMetricsPrepared
		}
	} else if distribution == OpenTelemetryCustomDistribution {
		reason = ReasonOpenTelemetryCustomDistribution
	} else if !exactPair {
		reason = ReasonOpenTelemetryUnsupported
	} else if !supported {
		reason = ReasonOpenTelemetryUnsupported
	}
	canonical, err := marshalComponentInput(OpenTelemetryComponent, from, to, facts)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{CanonicalInputJSON: canonical, SourceDigest: digestBytes(raw), InputDigest: digestBytes(canonical), State: state, Reason: reason, Omissions: []string{
		"CALLER_SUPPLIED_COLLECTOR_CONFIG_NOT_LIVE_OBSERVATION",
		"FEATURE_GATE_AND_REMOTE_SCRAPE_REQUIREMENT_ARE_CALLER_DECLARATIONS",
		"SERVICE_TELEMETRY_METRICS_OVERRIDE_IS_OUT_OF_SCOPE",
		"NO_LISTENER_SERVICE_DNS_NETWORK_POLICY_OR_SCRAPE_BEHAVIOR_EVALUATED",
		"WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
	}}, nil
}

const (
	ReasonOpenTelemetryMetricsPrepared         Reason = "OPENTELEMETRY_INTERNAL_METRICS_DEFAULT_SCOPE_PREPARED"
	ReasonOpenTelemetryMetricsAuthorityMissing Reason = "OPENTELEMETRY_INTERNAL_METRICS_AUTHORITY_MISSING_OR_INVALID"
	ReasonOpenTelemetryMetricsOverride         Reason = "OPENTELEMETRY_INTERNAL_METRICS_OVERRIDE_OUT_OF_SCOPE"
	ReasonOpenTelemetryCustomDistribution      Reason = "OPENTELEMETRY_CUSTOM_DISTRIBUTION_DECLARED"
)

func parseOpenTelemetryAuthority(value string) (bool, bool) {
	switch value {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func parseOpenTelemetryMetricsDefaultConfig(raw []byte) (bool, bool) {
	_, supported := parseOpenTelemetryConfig(raw)
	if !supported {
		return false, false
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || len(document.Content) != 1 {
		return false, false
	}
	root := document.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "service" {
			continue
		}
		service := root.Content[i+1]
		if service.Kind != yaml.MappingNode || service.ShortTag() != "!!map" {
			return false, false
		}
		for j := 0; j+1 < len(service.Content); j += 2 {
			if service.Content[j].Value != "telemetry" {
				continue
			}
			telemetry := service.Content[j+1]
			if telemetry.Kind != yaml.MappingNode || telemetry.ShortTag() != "!!map" {
				return false, false
			}
			for k := 0; k+1 < len(telemetry.Content); k += 2 {
				if telemetry.Content[k].Value == "metrics" {
					return false, true
				}
			}
		}
	}
	return true, true
}

func otelBoolFact(id string, value bool) inputFact {
	return inputFact{ID: id, State: "declared", BoolValue: &value}
}

// parseOpenTelemetryConfig admits one YAML document and returns a fact only
// when the selected exporters map is present and nonempty. The parser is
// intentionally stricter than the full Collector config model.
func parseOpenTelemetryConfig(raw []byte) (bool, bool) {
	if !utf8.Valid(raw) {
		return false, false
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || len(document.Content) != 1 || !otelSafeYAMLNode(&document) {
		return false, false
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		return false, false
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode || root.ShortTag() != "!!map" {
		return false, false
	}
	return parseOTelRoot(root)
}

func parseOTelRoot(root *yaml.Node) (bool, bool) {
	var exporters, connectors *yaml.Node
	var serviceSeen bool
	for i := 0; i < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		if key.Value == "exporters" {
			if exporters != nil {
				return false, false
			}
			exporters = value
		} else if key.Value == "connectors" {
			if connectors != nil {
				return false, false
			}
			connectors = value
		} else if key.Value == "service" {
			if serviceSeen || !parseOTelService(value) {
				return false, false
			}
			serviceSeen = true
		} else if otelReservedVariant(key.Value) != "" {
			return false, false
		} else if !otelScanUnrelated(value) {
			return false, false
		}
	}
	if exporters == nil || exporters.Kind != yaml.MappingNode || exporters.ShortTag() != "!!map" || len(exporters.Content) == 0 {
		return false, false
	}
	exporterIDs, logging, ok := parseOTelComponentMap(exporters)
	if !ok {
		return false, false
	}
	connectorIDs := map[string]bool{}
	if connectors != nil {
		if connectors.Kind != yaml.MappingNode || connectors.ShortTag() != "!!map" || len(connectors.Content) == 0 {
			return false, false
		}
		connectorIDs, _, ok = parseOTelComponentMap(connectors)
		if !ok {
			return false, false
		}
		for id := range connectorIDs {
			if exporterIDs[id] {
				return false, false
			}
		}
	}
	if serviceSeen {
		// The service parser validates references after both component maps are known.
		// Re-run the narrow reference walk to keep connector IDs distinct.
		if !validateOTelPipelineRefs(root, exporterIDs, connectorIDs) {
			return false, false
		}
	}
	return logging, true
}

func parseOTelComponentMap(node *yaml.Node) (map[string]bool, bool, bool) {
	ids := map[string]bool{}
	logging := false
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || !otelComponentID(key.Value) || (otelLooksLikeLoggingID(key.Value) && !otelCanonicalLoggingID(key.Value)) || value.Kind != yaml.MappingNode || value.ShortTag() != "!!map" || !otelScanUnrelated(value) {
			return nil, false, false
		}
		ids[key.Value] = true
		if key.Value == "logging" || strings.HasPrefix(key.Value, "logging/") {
			logging = true
		}
	}
	return ids, logging, true
}

func otelLooksLikeLoggingID(value string) bool {
	lower := strings.ToLower(value)
	return lower == "logging" || strings.HasPrefix(lower, "logging/")
}

func otelCanonicalLoggingID(value string) bool {
	return value == "logging" || strings.HasPrefix(value, "logging/")
}

func parseOTelService(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.MappingNode || node.ShortTag() != "!!map" {
		return false
	}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Value == "pipelines" {
			if !parseOTelPipelineMap(value) {
				return false
			}
		} else if otelReservedVariant(key.Value) != "" {
			return false
		} else if !otelScanUnrelated(value) {
			return false
		}
	}
	return true
}

func parseOTelPipelineMap(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.MappingNode || node.ShortTag() != "!!map" {
		return false
	}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || !otelComponentID(key.Value) || value.Kind != yaml.MappingNode || value.ShortTag() != "!!map" {
			return false
		}
		for j := 0; j < len(value.Content); j += 2 {
			field, fieldValue := value.Content[j], value.Content[j+1]
			if field.Value == "exporters" {
				if fieldValue.Kind != yaml.SequenceNode || len(fieldValue.Content) == 0 {
					return false
				}
				for _, ref := range fieldValue.Content {
					if ref.Kind != yaml.ScalarNode || ref.ShortTag() != "!!str" || !otelComponentID(ref.Value) {
						return false
					}
				}
			} else if otelReservedVariant(field.Value) != "" {
				return false
			} else if !otelScanUnrelated(fieldValue) {
				return false
			}
		}
	}
	return true
}

func validateOTelPipelineRefs(root *yaml.Node, exporters, connectors map[string]bool) bool {
	var service *yaml.Node
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == "service" {
			service = root.Content[i+1]
		}
	}
	if service == nil {
		return true
	}
	for i := 0; i < len(service.Content); i += 2 {
		if service.Content[i].Value != "pipelines" {
			continue
		}
		pipelines := service.Content[i+1]
		for j := 0; j < len(pipelines.Content); j += 2 {
			pipeline := pipelines.Content[j+1]
			for k := 0; k < len(pipeline.Content); k += 2 {
				if pipeline.Content[k].Value != "exporters" {
					continue
				}
				refs := pipeline.Content[k+1]
				seen := map[string]bool{}
				for _, ref := range refs.Content {
					name := ref.Value
					if seen[name] || exporters[name] && connectors[name] || !exporters[name] {
						return false
					}
					seen[name] = true
				}
			}
		}
	}
	return true
}

func otelSafeYAMLNode(node *yaml.Node) bool {
	if node == nil || node.Kind == yaml.AliasNode || node.Alias != nil || node.Anchor != "" || node.Style&yaml.TaggedStyle != 0 {
		return false
	}
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			if !otelSafeYAMLNode(child) {
				return false
			}
		}
	case yaml.MappingNode:
		if node.ShortTag() != "!!map" || len(node.Content)%2 != 0 {
			return false
		}
		seen := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || key.Anchor != "" || key.Alias != nil || key.Style&yaml.TaggedStyle != 0 || key.Value == "<<" || strings.Contains(key.Value, "$") || strings.Contains(key.Value, "{{") || strings.Contains(key.Value, "{%") || seen[key.Value] || !otelSafeYAMLNode(value) {
				return false
			}
			seen[key.Value] = true
		}
	case yaml.SequenceNode:
		if node.ShortTag() != "!!seq" {
			return false
		}
		for _, child := range node.Content {
			if !otelSafeYAMLNode(child) {
				return false
			}
		}
	case yaml.ScalarNode:
		if node.ShortTag() != "!!null" && node.ShortTag() != "!!bool" && node.ShortTag() != "!!str" && node.ShortTag() != "!!int" && node.ShortTag() != "!!float" && node.ShortTag() != "!!timestamp" {
			return false
		}
		if node.ShortTag() == "!!str" && (strings.Contains(node.Value, "$") || strings.Contains(node.Value, "{{") || strings.Contains(node.Value, "{%") || strings.ContainsAny(node.Value, "\r\n") || strings.ContainsRune(node.Value, '\uFFFD')) {
			return false
		}
	default:
		return false
	}
	return true
}

func otelScanUnrelated(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			if otelReservedVariant(node.Content[i].Value) != "" || !otelScanUnrelated(node.Content[i+1]) {
				return false
			}
		}
		return true
	}
	for _, child := range node.Content {
		if !otelScanUnrelated(child) {
			return false
		}
	}
	return true
}

func otelReservedVariant(value string) string {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	for _, candidate := range []string{"exporters", "connectors", "service", "pipelines", "include", "includes", "providers", "provider", "env", "environment"} {
		if lower == candidate {
			return candidate
		}
	}
	return ""
}

func otelComponentID(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "$\\\r\n\t ") || strings.Count(value, "/") > 1 {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
				return false
			}
		}
	}
	return true
}
