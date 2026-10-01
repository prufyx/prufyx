// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"io"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// This adapter inspects one caller-selected native alerting.alertmanagers
// mapping. It does not load a full prometheus.yml, resolve configuration
// precedence, or validate Alertmanager reachability or API support.
const (
	PrometheusAlertmanagerAPIVersionFact = "component.prometheus.alertmanager_api_version_selection"
	prometheusAlertmanagerAPIV1          = "v1"
	prometheusAlertmanagerAPIV2          = "v2"
	prometheusAlertmanagerDefaultV2      = "omitted_default_v2"
)

const (
	ReasonPrometheusAlertmanagerAPIV1Present Reason = "PROMETHEUS_ALERTMANAGER_API_V1_SELECTED"
	ReasonPrometheusAlertmanagerAPIV2Present Reason = "PROMETHEUS_ALERTMANAGER_API_V2_SELECTED"
	ReasonPrometheusAlertmanagerAPIDefaultV2 Reason = "PROMETHEUS_ALERTMANAGER_API_VERSION_OMITTED_SOURCE_DEFAULT_V2"
	ReasonPrometheusAlertmanagerUnsupported  Reason = "PROMETHEUS_SELECTED_ALERTMANAGER_CONFIG_UNSUPPORTED"
)

// PreparePrometheusAlertmanagerConfig derives only the selected mapping's
// literal API-version choice. An omitted key is represented as the exact
// target source-derived v2 default, never as a live observation.
func PreparePrometheusAlertmanagerConfig(raw []byte, from, to string, complete, precedenceResolved bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	selection, ok := "", false
	if prometheusReviewedTransition(from, to) {
		selection, ok = prometheusAlertmanagerAPISelection(raw)
	}
	fact := inputFact{ID: PrometheusAlertmanagerAPIVersionFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonPrometheusAlertmanagerUnsupported
	if complete && precedenceResolved && ok {
		fact.State = "declared"
		fact.EnumValue = selection
		state = StatePrepared
		switch selection {
		case prometheusAlertmanagerAPIV1:
			reason = ReasonPrometheusAlertmanagerAPIV1Present
		case prometheusAlertmanagerAPIV2:
			reason = ReasonPrometheusAlertmanagerAPIV2Present
		default:
			reason = ReasonPrometheusAlertmanagerAPIDefaultV2
		}
	}
	canonical, err := marshalComponentInput(PrometheusComponent, from, to, []inputFact{fact})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	omissions := []string{
		"SELECTED_ALERTMANAGER_MAPPING_IS_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION",
	}
	if reason == ReasonPrometheusAlertmanagerAPIDefaultV2 {
		omissions = append(omissions, "OMITTED_API_VERSION_USES_EXACT_TARGET_SOURCE_DERIVED_V2_DEFAULT")
	}
	omissions = append(omissions,
		"FULL_PROMETHEUS_CONFIGURATION_AND_OVERRIDE_SOURCES_NOT_EVALUATED",
		"ALERTMANAGER_VERSION_REACHABILITY_ALERT_DELIVERY_STARTUP_AND_WHOLE_UPGRADE_NOT_EVALUATED",
	)
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions:          omissions,
	}, nil
}

func prometheusAlertmanagerAPISelection(raw []byte) (string, bool) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || len(document.Content) != 1 {
		return "", false
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		return "", false
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode || root.ShortTag() != yamlMapTag || !prometheusSafeYAMLNode(root) || prometheusAlertmanagerUnresolvedNode(root) {
		return "", false
	}
	selectedShape, versionSeen := false, false
	selection := prometheusAlertmanagerDefaultV2
	for index := 0; index < len(root.Content); index += 2 {
		key, value := root.Content[index], root.Content[index+1]
		lower := strings.ToLower(key.Value)
		if prometheusAlertmanagerWrapperKey(lower) || prometheusNestedAlertmanagerAPIKey(value) {
			return "", false
		}
		if prometheusAlertmanagerAPIKey(key.Value) {
			if key.Value != "api_version" || versionSeen || value.Kind != yaml.ScalarNode || value.ShortTag() != yamlStrTag {
				return "", false
			}
			versionSeen, selectedShape = true, true
			switch value.Value {
			case prometheusAlertmanagerAPIV1, prometheusAlertmanagerAPIV2:
				selection = value.Value
			default:
				return "", false
			}
			continue
		}
		if prometheusAlertmanagerSelectedKey(lower) {
			selectedShape = true
		}
	}
	if !selectedShape {
		return "", false
	}
	return selection, true
}

func prometheusAlertmanagerWrapperKey(lower string) bool {
	for _, key := range []string{
		"alerting", "alertmanagers", "global", "rule_files", "scrape_configs",
		"scrape_config_files", "storage", "tracing", "remote_write", "remote_read",
		"otlp", "runtime", "include", "includes", "config_file", "config_files",
	} {
		if lower == key || strings.HasPrefix(lower, key+".") {
			return true
		}
	}
	return false
}

func prometheusAlertmanagerSelectedKey(lower string) bool {
	for _, key := range []string{
		"scheme", "path_prefix", "timeout", "relabel_configs", "alert_relabel_configs",
		"basic_auth", "authorization", "oauth2", "tls_config", "proxy_url", "no_proxy",
		"proxy_from_environment", "proxy_connect_header", "follow_redirects", "enable_http2",
		"sigv4", "static_configs",
	} {
		if lower == key {
			return true
		}
	}
	return strings.HasSuffix(lower, "_sd_configs")
}

// prometheusAlertmanagerAPIKey classifies the only reserved field after
// trimming presentation whitespace so a malformed near-match cannot become an
// omitted key and inherit the reviewed default. Only the direct canonical
// spelling is admitted by prometheusAlertmanagerAPISelection.
func prometheusAlertmanagerAPIKey(value string) bool {
	key := strings.ToLower(strings.TrimSpace(value))
	return key == "api_version" || strings.HasPrefix(key, "api_version.")
}

func prometheusNestedAlertmanagerAPIKey(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.MappingNode {
		for index := 0; index < len(node.Content); index += 2 {
			if prometheusAlertmanagerAPIKey(node.Content[index].Value) || prometheusNestedAlertmanagerAPIKey(node.Content[index+1]) {
				return true
			}
		}
		return false
	}
	for _, child := range node.Content {
		if prometheusNestedAlertmanagerAPIKey(child) {
			return true
		}
	}
	return false
}

func prometheusAlertmanagerUnresolvedNode(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.ScalarNode && node.ShortTag() == yamlStrTag && (strings.Contains(node.Value, "$") || strings.Contains(node.Value, "{{") || strings.Contains(node.Value, "{%")) {
		return true
	}
	for _, child := range node.Content {
		if prometheusAlertmanagerUnresolvedNode(child) {
			return true
		}
	}
	return false
}
