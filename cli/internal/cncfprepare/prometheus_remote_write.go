// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"io"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	PrometheusRemoteWriteHTTP2Fact                     = "component.prometheus.remote_write_enable_http2"
	PrometheusRemoteWriteHTTP2UnsatisfiedFact          = "component.prometheus.remote_write_http2_requirement_unsatisfied"
	PrometheusRemoteWriteHTTP2Rule                     = "remote-write-http2-default"
	PrometheusRemoteWriteHTTP2RuleID                   = "prometheus.remote-write-http2-default.2-55-1-to-3-14-0"
	PrometheusRemoteWriteHTTP2From                     = "2.55.1"
	PrometheusRemoteWriteHTTP2To                       = "3.14.0"
	ReasonPrometheusRemoteWriteHTTP2Satisfied   Reason = "PROMETHEUS_REMOTE_WRITE_HTTP2_REQUIREMENT_SATISFIED"
	ReasonPrometheusRemoteWriteHTTP2Unsatisfied Reason = "PROMETHEUS_REMOTE_WRITE_HTTP2_REQUIREMENT_UNSATISFIED"
	ReasonPrometheusRemoteWriteHTTP2Unsupported Reason = "PROMETHEUS_REMOTE_WRITE_HTTP2_INPUT_UNSUPPORTED"
)

// PreparePrometheusRemoteWriteConfig observes only one caller-selected named
// remote_write entry in a full configuration. It never validates the rest of
// the configuration or resolves substitutions, files, flags, or endpoint use.
func PreparePrometheusRemoteWriteConfig(raw []byte, name, from, to string, complete, precedence bool, required *bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to || name != "" && !prometheusLiteralJob(name) {
		return Prepared{}, ErrInvalid
	}
	value, ok := "", false
	if name != "" {
		value, ok = prometheusRemoteWriteHTTP2(raw, name)
	}
	setting := inputFact{ID: PrometheusRemoteWriteHTTP2Fact, State: "unsupported"}
	unsatisfied := inputFact{ID: PrometheusRemoteWriteHTTP2UnsatisfiedFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonPrometheusRemoteWriteHTTP2Unsupported
	if from == PrometheusRemoteWriteHTTP2From && to == PrometheusRemoteWriteHTTP2To && complete && precedence && required != nil && ok {
		setting.State, setting.EnumValue = "declared", value
		blocked := *required && value != "true"
		unsatisfied.State, unsatisfied.BoolValue = "declared", &blocked
		state = StatePrepared
		if blocked {
			reason = ReasonPrometheusRemoteWriteHTTP2Unsatisfied
		} else {
			reason = ReasonPrometheusRemoteWriteHTTP2Satisfied
		}
	}
	canonical, err := marshalComponentInput(PrometheusComponent, from, to, []inputFact{setting, unsatisfied})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{CanonicalInputJSON: canonical, SourceDigest: digestBytes(raw), InputDigest: digestBytes(canonical), State: state, Reason: reason,
		Omissions: []string{"CALLER_SELECTED_REMOTE_WRITE_ENTRY_NOT_LIVE_OBSERVATION", "ONLY_DIRECT_ENABLE_HTTP2_IS_OBSERVED", "WHOLE_PROMETHEUS_CONFIGURATION_AND_RUNTIME_NOT_EVALUATED"}}, nil
}

func prometheusRemoteWriteHTTP2(raw []byte, selected string) (string, bool) {
	d := yaml.NewDecoder(bytes.NewReader(raw))
	var doc yaml.Node
	if d.Decode(&doc) != nil || len(doc.Content) != 1 {
		return "", false
	}
	var trailing yaml.Node
	if d.Decode(&trailing) != io.EOF {
		return "", false
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode || root.ShortTag() != yamlMapTag || !prometheusSafeYAMLNode(root) || prometheusAlertmanagerUnresolvedNode(root) {
		return "", false
	}
	var entries *yaml.Node
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == "remote_write" {
			if entries != nil {
				return "", false
			}
			entries = root.Content[i+1]
		}
	}
	if entries == nil || entries.Kind != yaml.SequenceNode || entries.ShortTag() != yamlSeqTag {
		return "", false
	}
	seen := false
	value := ""
	for _, e := range entries.Content {
		if e.Kind != yaml.MappingNode || e.ShortTag() != yamlMapTag {
			return "", false
		}
		name := ""
		hasName := false
		directSeen := false
		nested := false
		direct := "omitted"
		for i := 0; i < len(e.Content); i += 2 {
			k, v := e.Content[i], e.Content[i+1]
			if k.Value == "name" {
				if hasName || v.Kind != yaml.ScalarNode || v.ShortTag() != yamlStrTag {
					return "", false
				}
				hasName = true
				name = v.Value
			}
			if k.Value == "enable_http2" {
				if directSeen || !prometheusYAMLBool(v) {
					return "", false
				}
				directSeen = true
				direct = v.Value
			}
			if k.Value == "http_config" && prometheusContainsHTTP2(v) {
				nested = true
			}
		}
		if hasName && name == selected {
			if seen || nested {
				return "", false
			}
			seen = true
			value = direct
		}
	}
	return value, seen
}

func prometheusContainsHTTP2(n *yaml.Node) bool {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(n.Content); i += 2 {
			if n.Content[i].Value == "enable_http2" {
				return true
			}
			if prometheusContainsHTTP2(n.Content[i+1]) {
				return true
			}
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if prometheusContainsHTTP2(c) {
				return true
			}
		}
	}
	return false
}
