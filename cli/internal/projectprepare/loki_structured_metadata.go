// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bytes"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// PrepareLokiStructuredMetadata reads a deliberately small native Loki YAML
// subset. It emits only the typed target constraint fact; selected YAML values
// never enter the canonical input or preparation result.
func PrepareLokiStructuredMetadata(raw []byte, from, to string, complete, precedenceResolved, useReviewedTargetDefault bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !versionRE.MatchString(from) || !versionRE.MatchString(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	allow, allowPresent, store, schema, supported := parseLokiStructuredMetadata(raw)
	state, reason := "UNKNOWN", "LOKI_SCHEMA_SELECTED_INPUT_UNSUPPORTED"
	var fact *inputFact
	exactPair := from == LokiFrom && to == LokiTo
	defaultAuthorized := !allowPresent && useReviewedTargetDefault && exactPair
	if !exactPair {
		reason = "LOKI_SCHEMA_UNSUPPORTED_VERSION_PAIR"
	} else if supported {
		reason = "EFFECTIVE_CONFIG_INCOMPLETE_OR_PRECEDENCE_UNRESOLVED"
		if exactPair && complete && precedenceResolved && (allowPresent || defaultAuthorized) {
			enabled := allow
			if !allowPresent {
				enabled = true
			}
			violates := enabled && (schema != "v13" || store != "tsdb")
			fact = &inputFact{ID: LokiStructuredMetadataFact, State: "declared", BoolValue: &violates}
			state, reason = "PREPARED", "NATIVE_LOKI_SCHEMA_LIMITS_SELECTED"
		} else if complete && precedenceResolved && !allowPresent {
			reason = "LOKI_TARGET_DEFAULT_REQUIRES_EXPLICIT_OPT_IN"
		}
	}
	if fact == nil {
		fact = &inputFact{ID: LokiStructuredMetadataFact, State: "unsupported"}
	}
	canonical, err := marshalInputSides(LokiComponent, from, to, nil, []inputFact{*fact})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	omissions := []string{
		"CALLER_SUPPLIED_CONFIG_NOT_LIVE_OBSERVATION",
		"ENVIRONMENT_AND_CLI_PRECEDENCE_DECLARED_NOT_OBSERVED",
		"WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
		"LOKI_STORAGE_INDEX_RETENTION_DATA_AND_STARTUP_NOT_EVALUATED",
	}
	if defaultAuthorized && fact.State == "declared" {
		omissions = append(omissions, "OMITTED_ALLOW_USES_SOURCE_DERIVED_TARGET_DEFAULT_AUTHORIZED_BY_EXPLICIT_FLAG")
	}
	return Prepared{CanonicalInputJSON: canonical, SourceDigest: digest(raw), InputDigest: digest(canonical), State: state, Reason: reason, Omissions: omissions}, nil
}

// parseLokiStructuredMetadata admits only one schema period and the two
// source-bound store literals. It returns supported=false for syntax that is
// valid YAML but outside the closed native subset, preserving UNKNOWN.
func parseLokiStructuredMetadata(raw []byte) (allow bool, allowPresent bool, store, schema string, supported bool) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return false, false, "", "", false
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		return false, false, "", "", false
	}
	if len(document.Content) != 1 || !lokiSchemaSafeYAMLNode(&document) || lokiSchemaUnresolvedYAML(&document) {
		return false, false, "", "", false
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode || root.ShortTag() != "!!map" {
		return false, false, "", "", false
	}
	if !lokiSchemaValidateContext(root, "root") {
		return false, false, "", "", false
	}
	var limits, schemaConfig *yaml.Node
	for index := 0; index < len(root.Content); index += 2 {
		key, value := root.Content[index], root.Content[index+1]
		switch {
		case key.Value == "limits_config":
			limits = value
		case lokiSchemaKeyVariant(key.Value, "limits_config"):
			return false, false, "", "", false
		case key.Value == "schema_config":
			schemaConfig = value
		case lokiSchemaKeyVariant(key.Value, "schema_config"):
			return false, false, "", "", false
		}
	}
	if limits == nil || limits.Kind != yaml.MappingNode || limits.ShortTag() != "!!map" || schemaConfig == nil || schemaConfig.Kind != yaml.MappingNode || schemaConfig.ShortTag() != "!!map" {
		return false, false, "", "", false
	}
	for index := 0; index < len(limits.Content); index += 2 {
		key, value := limits.Content[index], limits.Content[index+1]
		if key.Value == "allow_structured_metadata" {
			if allowPresent || value.Kind != yaml.ScalarNode || value.ShortTag() != "!!bool" || (value.Value != "true" && value.Value != "false") {
				return false, false, "", "", false
			}
			allowPresent, allow = true, value.Value == "true"
		} else if lokiSchemaKeyVariant(key.Value, "allow_structured_metadata") {
			return false, false, "", "", false
		}
	}
	var configs *yaml.Node
	for index := 0; index < len(schemaConfig.Content); index += 2 {
		key, value := schemaConfig.Content[index], schemaConfig.Content[index+1]
		if key.Value == "configs" {
			if configs != nil {
				return false, false, "", "", false
			}
			configs = value
		} else if lokiSchemaKeyVariant(key.Value, "configs") {
			return false, false, "", "", false
		}
	}
	if configs == nil || configs.Kind != yaml.SequenceNode || configs.ShortTag() != "!!seq" || len(configs.Content) != 1 {
		return false, false, "", "", false
	}
	period := configs.Content[0]
	if period.Kind != yaml.MappingNode || period.ShortTag() != "!!map" {
		return false, false, "", "", false
	}
	var from, storeNode, schemaNode *yaml.Node
	for index := 0; index < len(period.Content); index += 2 {
		key, value := period.Content[index], period.Content[index+1]
		switch {
		case key.Value == "from":
			from = value
		case lokiSchemaKeyVariant(key.Value, "from"):
			return false, false, "", "", false
		case key.Value == "store":
			storeNode = value
		case lokiSchemaKeyVariant(key.Value, "store"):
			return false, false, "", "", false
		case key.Value == "schema":
			schemaNode = value
		case lokiSchemaKeyVariant(key.Value, "schema"):
			return false, false, "", "", false
		}
	}
	if from == nil || !lokiCanonicalDate(from) || storeNode == nil || schemaNode == nil || !lokiStringScalar(storeNode) || !lokiStringScalar(schemaNode) {
		return false, false, "", "", false
	}
	store, schema = storeNode.Value, schemaNode.Value
	if strings.ContainsAny(store, "$\n\r") || strings.ContainsAny(schema, "$\n\r") || strings.Contains(store, "{{") || strings.Contains(store, "{%") || strings.Contains(schema, "{{") || strings.Contains(schema, "{%") {
		return false, false, "", "", false
	}
	if (store != "tsdb" && store != "boltdb-shipper") || (schema != "v9" && schema != "v10" && schema != "v11" && schema != "v12" && schema != "v13") {
		return false, false, "", "", false
	}
	return allow, allowPresent, store, schema, true
}

func lokiSchemaKeyVariant(value, expected string) bool {
	trimmed := strings.TrimSpace(value)
	normalized := strings.ReplaceAll(strings.ToLower(trimmed), "-", "_")
	return normalized == expected || strings.HasPrefix(normalized, expected+".")
}

func lokiStringScalar(node *yaml.Node) bool {
	return node != nil && node.Kind == yaml.ScalarNode && node.ShortTag() == "!!str" && !strings.ContainsAny(node.Value, "$\n\r") && !strings.Contains(node.Value, "{{") && !strings.Contains(node.Value, "{%")
}

func lokiCanonicalDate(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.ScalarNode || (node.ShortTag() != "!!timestamp" && node.ShortTag() != "!!str") || len(node.Value) != len("2000-01-01") {
		return false
	}
	parsed, err := time.Parse("2006-01-02", node.Value)
	return err == nil && parsed.Format("2006-01-02") == node.Value
}

func lokiSchemaSafeYAMLNode(node *yaml.Node) bool {
	if node == nil || node.Kind == yaml.AliasNode || node.Alias != nil || node.Anchor != "" || node.Style&yaml.TaggedStyle != 0 {
		return false
	}
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			if !lokiSchemaSafeYAMLNode(child) {
				return false
			}
		}
	case yaml.MappingNode:
		if node.ShortTag() != "!!map" || len(node.Content)%2 != 0 {
			return false
		}
		seen := map[string]bool{}
		for index := 0; index < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || key.Anchor != "" || key.Alias != nil || key.Style&yaml.TaggedStyle != 0 || key.Value == "<<" || lokiSchemaReservedKey(key.Value) || seen[key.Value] || !lokiSchemaSafeYAMLNode(value) {
				return false
			}
			seen[key.Value] = true
		}
	case yaml.SequenceNode:
		if node.ShortTag() != "!!seq" {
			return false
		}
		for _, child := range node.Content {
			if !lokiSchemaSafeYAMLNode(child) {
				return false
			}
		}
	case yaml.ScalarNode:
		switch node.ShortTag() {
		case "!!null", "!!bool", "!!str", "!!int", "!!float", "!!timestamp":
		default:
			return false
		}
	default:
		return false
	}
	return true
}

func lokiSchemaReservedKey(value string) bool {
	normalized := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "_")
	switch normalized {
	case "include", "includes", "config_file", "config_files":
		return true
	default:
		return false
	}
}

func lokiSchemaValidateContext(node *yaml.Node, context string) bool {
	if node == nil {
		return false
	}
	switch context {
	case "root", "limits", "schema", "period":
		if node.Kind != yaml.MappingNode {
			return false
		}
		for index := 0; index < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" {
				return false
			}
			reserved := lokiSchemaReservedName(key.Value)
			if reserved == "" {
				if !lokiSchemaValidateUnscoped(value) {
					return false
				}
				continue
			}
			allowed := context == "root" && (reserved == "limits_config" || reserved == "schema_config") || context == "limits" && reserved == "allow_structured_metadata" || context == "schema" && reserved == "configs" || context == "period" && (reserved == "from" || reserved == "store" || reserved == "schema")
			if !allowed || key.Value != reserved {
				return false
			}
			next := ""
			switch reserved {
			case "limits_config":
				next = "limits"
			case "schema_config":
				next = "schema"
			case "configs":
				if value.Kind != yaml.SequenceNode || len(value.Content) != 1 {
					return false
				}
				if !lokiSchemaValidateContext(value.Content[0], "period") {
					return false
				}
				continue
			default:
				continue
			}
			if !lokiSchemaValidateContext(value, next) {
				return false
			}
		}
		return true
	default:
		return lokiSchemaValidateUnscoped(node)
	}
}

func lokiSchemaValidateUnscoped(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.MappingNode {
		if len(node.Content)%2 != 0 {
			return false
		}
		for index := 0; index < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || lokiSchemaReservedName(key.Value) != "" || !lokiSchemaValidateUnscoped(value) {
				return false
			}
		}
		return true
	}
	for _, child := range node.Content {
		if !lokiSchemaValidateUnscoped(child) {
			return false
		}
	}
	return true
}

func lokiSchemaReservedName(value string) string {
	for _, candidate := range []string{"limits_config", "schema_config", "allow_structured_metadata", "configs", "from", "store", "schema"} {
		if lokiSchemaKeyVariant(value, candidate) {
			return candidate
		}
	}
	return ""
}

func lokiSchemaUnresolvedYAML(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.ScalarNode && node.ShortTag() == "!!str" && (strings.Contains(node.Value, "$") || strings.Contains(node.Value, "{{") || strings.Contains(node.Value, "{%")) {
		return true
	}
	for _, child := range node.Content {
		if lokiSchemaUnresolvedYAML(child) {
			return true
		}
	}
	return false
}
