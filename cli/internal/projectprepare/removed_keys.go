// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	AirflowProject   = "airflow"
	AirflowComponent = "pkg:github/apache/airflow"

	OpenSearchProject   = "opensearch"
	OpenSearchComponent = "pkg:github/opensearch-project/opensearch"
)

// removedKey names one setting that a reviewed release note lists as removed,
// the fact that records whether a caller-selected config contains it, and the
// place the setting lives: an INI section for airflow.cfg, empty for the dotted
// path of opensearch.yml.
type removedKey struct {
	Fact    string
	Section string
	Key     string
}

var airflowRemovedKeys = []removedKey{
	{Fact: "component.airflow.api_enable_xcom_deserialize_support_present", Section: "api", Key: "enable_xcom_deserialize_support"},
	{Fact: "component.airflow.scheduler_dag_stale_not_seen_duration_present", Section: "scheduler", Key: "dag_stale_not_seen_duration"},
	{Fact: "component.airflow.webserver_instance_name_has_markup_present", Section: "webserver", Key: "instance_name_has_markup"},
	{Fact: "component.airflow.webserver_warn_deployment_exposure_present", Section: "webserver", Key: "warn_deployment_exposure"},
}

var openSearchRemovedKeys = []removedKey{
	{Fact: "component.opensearch.gateway_expected_master_nodes_present", Key: "gateway.expected_master_nodes"},
	{Fact: "component.opensearch.gateway_expected_nodes_present", Key: "gateway.expected_nodes"},
	{Fact: "component.opensearch.gateway_recover_after_master_nodes_present", Key: "gateway.recover_after_master_nodes"},
	{Fact: "component.opensearch.gateway_recover_after_nodes_present", Key: "gateway.recover_after_nodes"},
}

// AirflowFacts and OpenSearchFacts list the fact ids a preparation declares, for
// tests and documentation.
func AirflowFacts() []string    { return factIDs(airflowRemovedKeys) }
func OpenSearchFacts() []string { return factIDs(openSearchRemovedKeys) }

func factIDs(keys []removedKey) []string {
	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, k.Fact)
	}
	return ids
}

// prepareAirflowConfig reports whether one caller-selected airflow.cfg sets any of the options the 3.1.0
// release notes list as removed (the rules bind the reviewed 3.0.6 to 3.1.0 pair; the
// rule engine matches the pair, so any other pair finds no rule). The file is read as the INI surface of
// Python's ConfigParser: a spelling that could change which option is meant
// (case variants, _cmd/_secret forms, DEFAULT, duplicates) is UNKNOWN. Absence
// is only meaningful when the caller declares the file complete and
// precedence-resolved (environment variables and secrets backends applied).
func prepareAirflowConfig(raw []byte, from, to string, complete, precedenceResolved bool) (Prepared, error) {
	return prepareRemovedKeys(raw, from, to, complete, precedenceResolved, AirflowComponent, airflowRemovedKeys, scanAirflowCfg,
		"AIRFLOW_CFG_REMOVED_OPTIONS_INSPECTED", "AIRFLOW_CFG_SHAPE_UNSUPPORTED",
		"AIRFLOW_ENVIRONMENT_VARIABLES_AND_SECRETS_BACKENDS_ARE_CALLER_DECLARATIONS")
}

// prepareOpenSearchConfig is the same for one caller-selected opensearch.yml and
// the four gateway settings the 3.0.0 release notes list as removed.
func prepareOpenSearchConfig(raw []byte, from, to string, complete, precedenceResolved bool) (Prepared, error) {
	return prepareRemovedKeys(raw, from, to, complete, precedenceResolved, OpenSearchComponent, openSearchRemovedKeys, scanOpenSearchYAML,
		"OPENSEARCH_YML_REMOVED_SETTINGS_INSPECTED", "OPENSEARCH_YML_SHAPE_UNSUPPORTED",
		"OPENSEARCH_COMMAND_LINE_AND_ENVIRONMENT_SETTINGS_ARE_CALLER_DECLARATIONS")
}

type removedKeyScanner func(raw []byte, keys []removedKey) (found map[string]bool, supported bool, err error)

func prepareRemovedKeys(raw []byte, from, to string, complete, precedenceResolved bool, component string, keys []removedKey, scan removedKeyScanner, preparedReason, shapeReason, declarationOmission string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 || !versionRE.MatchString(from) || !versionRE.MatchString(to) {
		return Prepared{}, ErrInvalid
	}
	found, supported, err := scan(raw, keys)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	facts := make([]inputFact, 0, len(keys))
	for _, k := range keys {
		facts = append(facts, inputFact{ID: k.Fact, State: "unsupported"})
	}
	state, reason := "UNKNOWN", "EFFECTIVE_CONFIG_INCOMPLETE_OR_PRECEDENCE_UNRESOLVED"
	switch {
	case !supported:
		reason = shapeReason
	case complete && precedenceResolved:
		for i, k := range keys {
			value := found[k.Fact]
			facts[i] = inputFact{ID: k.Fact, State: "declared", BoolValue: &value}
		}
		state, reason = "PREPARED", preparedReason
	}
	canonical, err := marshalInput(component, from, to, facts)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digest(raw),
		InputDigest:        digest(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"CALLER_SUPPLIED_CONFIG_NOT_LIVE_OBSERVATION",
			declarationOmission,
			"ONLY_THE_LISTED_REMOVED_KEYS_INSPECTED_NOT_THEIR_VALUES_OR_ANY_OTHER_SETTING",
			"WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
		},
	}, nil
}

// scanAirflowCfg reads the INI surface of airflow.cfg far enough to see whether
// a listed [section] option is set. Lines before the first section, and an
// option line without a delimiter, are malformed input. Anything that could
// change which option a line names without being visible here is unsupported.
func scanAirflowCfg(raw []byte, keys []removedKey) (map[string]bool, bool, error) {
	targetSections := map[string]bool{}
	for _, k := range keys {
		targetSections[k.Section] = true
	}
	found := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), maxInputBytes)
	section, sectionKnown := "", false
	seenSections := map[string]bool{}
	optionInSection := false
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		indented := line[0] == ' ' || line[0] == '\t'
		if indented {
			// A continuation of the previous value, which cannot start an option.
			if !sectionKnown || !optionInSection {
				return nil, false, nil
			}
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			if !strings.HasSuffix(trimmed, "]") || len(trimmed) < 3 || strings.Count(trimmed, "[") != 1 || strings.Count(trimmed, "]") != 1 {
				return nil, false, nil
			}
			section, sectionKnown, optionInSection = trimmed[1:len(trimmed)-1], true, false
			for target := range targetSections {
				if section != target && strings.EqualFold(section, target) {
					return nil, false, nil
				}
			}
			if targetSections[section] {
				if seenSections[section] {
					return nil, false, nil
				}
				seenSections[section] = true
			}
			continue
		}
		if !sectionKnown {
			return nil, false, ErrInvalid
		}
		delimiter := strings.IndexAny(trimmed, "=:")
		if delimiter < 0 {
			return nil, false, ErrInvalid
		}
		optionInSection = true
		key := strings.TrimSpace(trimmed[:delimiter])
		lower := strings.ToLower(key)
		for _, k := range keys {
			if section == "DEFAULT" || strings.EqualFold(section, "default") {
				// DEFAULT values apply to every section.
				if lower == k.Key || lower == k.Key+"_cmd" || lower == k.Key+"_secret" {
					return nil, false, nil
				}
				continue
			}
			if section != k.Section {
				continue
			}
			switch {
			case key == k.Key:
				if found[k.Fact] {
					return nil, false, nil
				}
				found[k.Fact] = true
			case lower == k.Key, lower == k.Key+"_cmd", lower == k.Key+"_secret":
				return nil, false, nil
			}
		}
	}
	if scanner.Err() != nil {
		return nil, false, ErrInvalid
	}
	return found, true, nil
}

// scanOpenSearchYAML flattens one plain YAML mapping into dotted setting paths,
// the way opensearch.yml names settings, and reports which listed paths occur.
// Documents, anchors, aliases, tags, merge keys, non-string keys, repeated
// paths, scalar/mapping conflicts on a listed path and case variants of a listed
// path are unsupported: each can change which setting a line names.
func scanOpenSearchYAML(raw []byte, keys []removedKey) (map[string]bool, bool, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		if err == io.EOF {
			return map[string]bool{}, true, nil
		}
		return nil, false, ErrInvalid
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, false, nil
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, false, nil
	}
	leaves := map[string]bool{}
	parents := map[string]bool{}
	if !flattenSettings(document.Content[0], "", leaves, parents) {
		return nil, false, nil
	}
	// A file that wraps opensearch.yml (Helm values, a ConfigMap, a Kubernetes
	// manifest) names top-level keys that are not node settings; the settings
	// inside it would then be read under a wrong path, and an absent removed key
	// would be a wrong PASS. Every top-level key must start with a known
	// setting namespace, otherwise the shape is unsupported.
	for _, paths := range []map[string]bool{leaves, parents} {
		for path := range paths {
			if !openSearchSettingPath(path) {
				return nil, false, nil
			}
		}
	}
	found := map[string]bool{}
	for _, k := range keys {
		for path := range leaves {
			lowerPath := strings.ToLower(path)
			lowerKey := strings.ToLower(k.Key)
			switch {
			case path == k.Key:
				found[k.Fact] = true
			case lowerPath == lowerKey, strings.HasPrefix(lowerPath, lowerKey+"."):
				return nil, false, nil
			case strings.HasPrefix(lowerKey, lowerPath+"."):
				// A scalar sits on a prefix of the listed key.
				return nil, false, nil
			}
		}
		for parent := range parents {
			if strings.EqualFold(parent, k.Key) {
				return nil, false, nil
			}
		}
	}
	return found, true, nil
}

func flattenSettings(node *yaml.Node, prefix string, leaves, parents map[string]bool) bool {
	if node.Anchor != "" || node.Alias != nil || node.Kind == yaml.AliasNode || node.Style&yaml.TaggedStyle != 0 {
		return false
	}
	if node.Kind != yaml.MappingNode {
		return true
	}
	if len(node.Content)%2 != 0 {
		return false
	}
	if prefix != "" {
		parents[prefix] = true
	}
	for index := 0; index < len(node.Content); index += 2 {
		key, value := node.Content[index], node.Content[index+1]
		if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || key.Value == "" || key.Value == "<<" || key.Anchor != "" || key.Alias != nil || key.Style&yaml.TaggedStyle != 0 {
			return false
		}
		path := key.Value
		if prefix != "" {
			path = prefix + "." + key.Value
		}
		if leaves[path] || parents[path] {
			return false
		}
		switch value.Kind {
		case yaml.MappingNode:
			if value.Anchor != "" || value.Alias != nil || value.Style&yaml.TaggedStyle != 0 {
				return false
			}
			if !flattenSettings(value, path, leaves, parents) {
				return false
			}
		case yaml.SequenceNode:
			if !plainNodes(value) {
				return false
			}
			leaves[path] = true
		case yaml.ScalarNode:
			if value.Anchor != "" || value.Alias != nil || value.Style&yaml.TaggedStyle != 0 {
				return false
			}
			// A multi-line value is how a whole file is embedded in a Helm values
			// file or a ConfigMap; opensearch.yml settings are single-line scalars.
			if strings.ContainsAny(value.Value, "\r\n") {
				return false
			}
			leaves[path] = true
		default:
			return false
		}
	}
	return true
}

// plainNodes reports that a value subtree carries no anchor, alias or tag.
func plainNodes(node *yaml.Node) bool {
	if node.Anchor != "" || node.Alias != nil || node.Kind == yaml.AliasNode || node.Style&yaml.TaggedStyle != 0 {
		return false
	}
	for _, child := range node.Content {
		if !plainNodes(child) {
			return false
		}
	}
	return true
}

// openSearchSettingNamespaces are the first path segments that opensearch.yml
// node settings (core and bundled plugins) start with. An unknown first segment
// makes the whole file unsupported, so a rarely used namespace only costs an
// UNKNOWN answer, never a wrong PASS.
var openSearchSettingNamespaces = map[string]bool{
	"action": true, "aux": true, "azure": true, "bootstrap": true, "cache": true, "client": true,
	"cluster": true, "compatibility": true, "discovery": true, "extensions": true, "gateway": true, "gcs": true,
	"http": true, "indices": true, "ingest": true, "logger": true, "monitor": true, "network": true,
	"node": true, "opendistro_security": true, "opensearch": true, "path": true, "plugins": true,
	"processors": true, "reindex": true, "remote_store": true, "repositories": true, "rest": true,
	"s3": true, "script": true, "search": true, "snapshot": true, "telemetry": true, "thread_pool": true,
	"tracer": true, "transport": true,
}

// openSearchWrapperSegments are path segments that name an embedded file or a
// chart/manifest layer, never an opensearch.yml setting.
var openSearchWrapperSegments = map[string]bool{
	"config": true, "configmap": true, "extraenvs": true, "opensearchconfig": true,
	"values": true, "metadata": true, "spec": true, "apiversion": true, "kind": true,
}

// openSearchSettingPath reports whether a flattened path can be an opensearch.yml
// setting: its first segment is a known namespace, the broad "opensearch"
// namespace only continues with "experimental", no segment names a file
// (.yml, .yaml) or a wrapper layer.
func openSearchSettingPath(path string) bool {
	segments := strings.Split(path, ".")
	if !openSearchSettingNamespaces[segments[0]] {
		return false
	}
	if segments[0] == "opensearch" && (len(segments) < 2 || segments[1] != "experimental") {
		return false
	}
	for _, segment := range segments {
		lower := strings.ToLower(segment)
		if openSearchWrapperSegments[lower] || strings.HasSuffix(lower, "yml") || strings.HasSuffix(lower, "yaml") {
			return false
		}
	}
	return true
}
