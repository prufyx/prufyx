// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Prometheus 3 renames one scrape_config key. This adapter inspects one
// caller-selected, complete native scrape_config mapping. It does not load a
// full prometheus.yml, resolve YAML aliases, environment or command-line
// precedence, or validate scraping and native-histogram behavior.
const (
	PrometheusComponent     = "pkg:github/prometheus/prometheus"
	PrometheusScrapeKeyFact = "component.prometheus.scrape_classic_histograms_key"
	PrometheusFrom          = "2.55.1"
	PrometheusTo            = "3.1.0"
	PrometheusLatestTo      = "3.14.0"
	prometheusOldKey        = "scrape_classic_histograms"
	prometheusNewKey        = "always_scrape_classic_histograms"
	yamlMapTag              = "!!map"
	yamlSeqTag              = "!!seq"
	yamlStrTag              = "!!str"
	yamlNullTag             = "!!null"
	yamlBoolTag             = "!!bool"
	yamlIntTag              = "!!int"
	yamlFloatTag            = "!!float"
	yamlTimestampTag        = "!!timestamp"
)

const (
	ReasonPrometheusOldKeyPresent           Reason = "PROMETHEUS_OLD_SCRAPE_CLASSIC_HISTOGRAMS_KEY_PRESENT"
	ReasonPrometheusNewKeyPresent           Reason = "PROMETHEUS_NEW_ALWAYS_SCRAPE_CLASSIC_HISTOGRAMS_KEY_PRESENT"
	ReasonPrometheusScrapeConfigUnsupported Reason = "PROMETHEUS_SELECTED_SCRAPE_CONFIG_UNSUPPORTED"
)

// PreparePrometheusScrapeConfig derives only which reviewed histogram key is
// explicitly present. selectedJob binds the caller's selection but is never
// retained. complete and precedenceResolved are explicit caller declarations;
// absence cannot establish that a key is absent from the effective job.
func PreparePrometheusScrapeConfig(raw []byte, selectedJob, from, to string, complete, precedenceResolved bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to || !prometheusLiteralJob(selectedJob) {
		return Prepared{}, ErrInvalid
	}
	key, ok := "", false
	if prometheusReviewedTransition(from, to) {
		key, ok = prometheusScrapeKey(raw, selectedJob)
	}
	fact := inputFact{ID: PrometheusScrapeKeyFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonPrometheusScrapeConfigUnsupported
	if complete && precedenceResolved && ok {
		fact.State = "declared"
		fact.EnumValue = key
		state = StatePrepared
		if key == prometheusOldKey {
			reason = ReasonPrometheusOldKeyPresent
		} else {
			reason = ReasonPrometheusNewKeyPresent
		}
	}
	canonical, err := marshalComponentInput(PrometheusComponent, from, to, []inputFact{fact})
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
			"SELECTED_SCRAPE_CONFIG_IS_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION",
			"FULL_PROMETHEUS_CONFIGURATION_AND_OVERRIDE_SOURCES_NOT_EVALUATED",
			"SCRAPING_NATIVE_HISTOGRAMS_STARTUP_AND_WHOLE_UPGRADE_NOT_EVALUATED",
		},
	}, nil
}

// prometheusReviewedTransition admits the retained 2.55.1 -> 3.1.0 route and
// five exact origins to 3.14.0. The latter are target configuration
// constraints; they do not claim a newly introduced change on every path.
func prometheusReviewedTransition(from, to string) bool {
	if from == PrometheusFrom && to == PrometheusTo {
		return true
	}
	if to != PrometheusLatestTo {
		return false
	}
	switch from {
	case "3.9.1", "3.10.0", "3.11.3", "3.12.0", "3.13.3":
		return true
	default:
		return false
	}
}

func prometheusLiteralJob(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "$\r\n\t") {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// prometheusScrapeKey parses one native YAML mapping but projects only three
// reviewed top-level keys. The node walk rejects duplicate mappings, aliases,
// merge keys, custom tags and relevant keys hidden below another value.
func prometheusScrapeKey(raw []byte, selectedJob string) (string, bool) {
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
	if root.Kind != yaml.MappingNode || root.ShortTag() != yamlMapTag || !prometheusSafeYAMLNode(root) {
		return "", false
	}
	jobSeen, jobMatches := false, false
	oldSeen, newSeen := false, false
	for index := 0; index < len(root.Content); index += 2 {
		key, value := root.Content[index], root.Content[index+1]
		if prometheusNestedRelevantKey(value) {
			return "", false
		}
		lower := strings.ToLower(key.Value)
		if !prometheusRelevantKey(lower) {
			continue
		}
		if key.Value != lower || strings.Contains(lower, ".") {
			return "", false
		}
		switch key.Value {
		case "job_name":
			if jobSeen {
				return "", false
			}
			jobSeen = true
			if value.Kind != yaml.ScalarNode || value.ShortTag() != yamlStrTag || !prometheusLiteralJob(value.Value) {
				return "", false
			}
			jobMatches = value.Value == selectedJob
		case prometheusOldKey:
			if oldSeen || !prometheusYAMLBool(value) {
				return "", false
			}
			oldSeen = true
		case prometheusNewKey:
			if newSeen || !prometheusYAMLBool(value) {
				return "", false
			}
			newSeen = true
		}
	}
	if !jobSeen || !jobMatches || oldSeen == newSeen {
		return "", false
	}
	if oldSeen {
		return prometheusOldKey, true
	}
	return prometheusNewKey, true
}

func prometheusSafeYAMLNode(node *yaml.Node) bool {
	if node == nil || node.Kind == yaml.AliasNode || node.Alias != nil || node.Anchor != "" {
		return false
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.ShortTag() != yamlMapTag || len(node.Content)%2 != 0 {
			return false
		}
		seen := map[string]bool{}
		for index := 0; index < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != yamlStrTag || key.Anchor != "" || key.Alias != nil || key.Value == "<<" || seen[key.Value] {
				return false
			}
			seen[key.Value] = true
			if !prometheusSafeYAMLNode(value) {
				return false
			}
		}
	case yaml.SequenceNode:
		if node.ShortTag() != yamlSeqTag {
			return false
		}
		for _, child := range node.Content {
			if !prometheusSafeYAMLNode(child) {
				return false
			}
		}
	case yaml.ScalarNode:
		switch node.ShortTag() {
		case yamlNullTag, yamlBoolTag, yamlStrTag, yamlIntTag, yamlFloatTag, yamlTimestampTag:
		default:
			return false
		}
	default:
		return false
	}
	return true
}

func prometheusRelevantKey(lower string) bool {
	for _, key := range []string{"job_name", prometheusOldKey, prometheusNewKey} {
		if lower == key || strings.HasPrefix(lower, key+".") {
			return true
		}
	}
	return false
}

func prometheusNestedRelevantKey(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.MappingNode {
		for index := 0; index < len(node.Content); index += 2 {
			if prometheusRelevantKey(strings.ToLower(node.Content[index].Value)) || prometheusNestedRelevantKey(node.Content[index+1]) {
				return true
			}
		}
		return false
	}
	for _, child := range node.Content {
		if prometheusNestedRelevantKey(child) {
			return true
		}
	}
	return false
}

func prometheusYAMLBool(node *yaml.Node) bool {
	return node.Kind == yaml.ScalarNode && node.ShortTag() == yamlBoolTag && (node.Value == "true" || node.Value == "false")
}
