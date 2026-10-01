// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	ArgoCDResourceExclusionsFact          = "component.argo_cd.resource_exclusions_source_default_selected"
	ArgoCDResourceExclusionsIntentFact    = "component.argo_cd.requires_v2_visibility_of_v3_default_excluded_resources"
	argoCDResourceExclusionsKey           = "resource.exclusions"
	argoCDResourceExclusionsDefaultDigest = "8d5107861e8471ddcd7ab0d0e900c5a22f1c28d3a11dd73cbe1c303c83cb555f"
)

const (
	ReasonArgoCDResourceExclusionsDefault     Reason = "ARGO_CD_RESOURCE_EXCLUSIONS_EXACT_V3_DEFAULT"
	ReasonArgoCDResourceExclusionsAbsent      Reason = "ARGO_CD_RESOURCE_EXCLUSIONS_KEY_ABSENT"
	ReasonArgoCDResourceExclusionsEmpty       Reason = "ARGO_CD_RESOURCE_EXCLUSIONS_EXPLICIT_EMPTY"
	ReasonArgoCDResourceExclusionsUnsupported Reason = "ARGO_CD_RESOURCE_EXCLUSIONS_UNSUPPORTED"
)

// PrepareArgoCDResourceExclusions examines one private, caller-selected v1
// argocd-cm. Its inner YAML comparison canonicalizes the sequence into JSON
// and compares the exact source-reviewed sequence/key/value digest; extra
// entries, keys, duplicates, aliases, tags, templates, and documents stay
// unsupported. It never observes a cluster or claims watched/UI behavior.
func PrepareArgoCDResourceExclusions(raw []byte, from, to string, complete, precedence bool, preserveV2Visibility *bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalidArgoCD
	}
	selected, reason := argoCDResourceExclusionsSelection(raw)
	fact := inputFact{ID: ArgoCDResourceExclusionsFact, State: "unsupported"}
	intent := inputFact{ID: ArgoCDResourceExclusionsIntentFact, State: "unsupported"}
	state := StateUnknown
	if from == ArgoCDFrom && to == ArgoCDTo && complete && precedence && selected != "unsupported" {
		fact.State = "declared"
		value := selected == "default"
		fact.BoolValue = &value
	}
	if preserveV2Visibility != nil {
		intent.State = "declared"
		intent.BoolValue = preserveV2Visibility
	}
	if fact.State == "declared" && intent.State == "declared" && *intent.BoolValue {
		state = StatePrepared
	}
	canonical, err := marshalComponentInput(ArgoCDComponent, from, to, []inputFact{intent, fact})
	if err != nil {
		return Prepared{}, ErrInvalidArgoCD
	}
	return Prepared{CanonicalInputJSON: canonical, SourceDigest: digestBytes(raw), InputDigest: digestBytes(canonical), State: state, Reason: reason,
		Omissions: []string{"CALLER_SELECTED_CONFIGMAP_NOT_LIVE_OBSERVATION", "RESOURCE_EXISTENCE_WATCH_UI_RECONCILIATION_AND_RUNTIME_NOT_EVALUATED", OmissionNoWholeUpgrade}}, nil
}

func argoCDResourceExclusionsSelection(raw []byte) (string, Reason) {
	root, ok := argoCDSingleSafeYAML(raw)
	if !ok || root.Kind != yaml.MappingNode {
		return "unsupported", ReasonArgoCDResourceExclusionsUnsupported
	}
	api, state := argoCDExactField(root, "apiVersion")
	if state != argoCDFieldFound || !argoCDString(api, "v1") {
		return "unsupported", ReasonArgoCDResourceExclusionsUnsupported
	}
	kind, state := argoCDExactField(root, "kind")
	if state != argoCDFieldFound || !argoCDString(kind, "ConfigMap") {
		return "unsupported", ReasonArgoCDResourceExclusionsUnsupported
	}
	metadata, state := argoCDExactField(root, "metadata")
	if state != argoCDFieldFound || metadata.Kind != yaml.MappingNode {
		return "unsupported", ReasonArgoCDResourceExclusionsUnsupported
	}
	name, state := argoCDExactField(metadata, "name")
	if state != argoCDFieldFound || !argoCDString(name, "argocd-cm") {
		return "unsupported", ReasonArgoCDResourceExclusionsUnsupported
	}
	data, state := argoCDExactField(root, "data")
	if state == argoCDFieldMissing {
		return "absent", ReasonArgoCDResourceExclusionsAbsent
	}
	if state != argoCDFieldFound || data.Kind != yaml.MappingNode || !argoCDStrictStringData(data) {
		return "unsupported", ReasonArgoCDResourceExclusionsUnsupported
	}
	value, state := argoCDExactField(data, argoCDResourceExclusionsKey)
	if state == argoCDFieldMissing {
		return "absent", ReasonArgoCDResourceExclusionsAbsent
	}
	if state != argoCDFieldFound || value.Kind != yaml.ScalarNode || value.ShortTag() != yamlStrTag {
		return "unsupported", ReasonArgoCDResourceExclusionsUnsupported
	}
	inner, ok := argoCDSingleSafeYAML([]byte(value.Value))
	if !ok || inner.Kind != yaml.SequenceNode {
		return "unsupported", ReasonArgoCDResourceExclusionsUnsupported
	}
	if len(inner.Content) == 0 {
		return "empty", ReasonArgoCDResourceExclusionsEmpty
	}
	canonical, ok := argoCDCanonicalExclusions(inner)
	if !ok {
		return "unsupported", ReasonArgoCDResourceExclusionsUnsupported
	}
	sum := sha256.Sum256(canonical)
	if hex.EncodeToString(sum[:]) != argoCDResourceExclusionsDefaultDigest {
		return "unsupported", ReasonArgoCDResourceExclusionsUnsupported
	}
	return "default", ReasonArgoCDResourceExclusionsDefault
}

func argoCDSingleSafeYAML(raw []byte) (*yaml.Node, bool) {
	d := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if d.Decode(&document) != nil || len(document.Content) != 1 {
		return nil, false
	}
	var trailing yaml.Node
	if d.Decode(&trailing) != io.EOF || !argoCDSafeNode(document.Content[0]) {
		return nil, false
	}
	return document.Content[0], true
}

// argoCDSafeNode permits only plain YAML maps, sequences, and string scalars.
// It validates every mapping (including metadata and inner exclusions), so
// aliases, anchors, explicit tags, merges, and duplicate keys cannot affect a
// selected absence/default classification.
func argoCDSafeNode(n *yaml.Node) bool {
	if n == nil || n.Kind == yaml.AliasNode || n.Alias != nil || n.Anchor != "" || n.Style&yaml.TaggedStyle != 0 {
		return false
	}
	switch n.Kind {
	case yaml.MappingNode:
		if n.ShortTag() != yamlMapTag || len(n.Content)%2 != 0 {
			return false
		}
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			key, value := n.Content[i], n.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != yamlStrTag || key.Value == "<<" || seen[key.Value] || !argoCDSafeNode(key) || !argoCDSafeNode(value) {
				return false
			}
			seen[key.Value] = true
		}
		return true
	case yaml.SequenceNode:
		if n.ShortTag() != yamlSeqTag {
			return false
		}
		for _, child := range n.Content {
			if !argoCDSafeNode(child) {
				return false
			}
		}
		return true
	case yaml.ScalarNode:
		return n.ShortTag() == yamlStrTag && !strings.Contains(n.Value, "${") && !strings.Contains(n.Value, "{{") && !strings.Contains(n.Value, "{%")
	default:
		return false
	}
}

type argoCDFieldState uint8

const (
	argoCDFieldMissing argoCDFieldState = iota
	argoCDFieldFound
	argoCDFieldInvalid
)

// argoCDExactField distinguishes a true omission from an invalid spelling or
// duplicate, so malformed present data is never converted into a source-default
// absence.
func argoCDExactField(m *yaml.Node, wanted string) (*yaml.Node, argoCDFieldState) {
	if m == nil || m.Kind != yaml.MappingNode || len(m.Content)%2 != 0 {
		return nil, argoCDFieldInvalid
	}
	var found *yaml.Node
	target := strings.ToLower(wanted)
	for i := 0; i < len(m.Content); i += 2 {
		key, value := m.Content[i], m.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.ShortTag() != yamlStrTag {
			return nil, argoCDFieldInvalid
		}
		if strings.ToLower(strings.TrimSpace(key.Value)) != target {
			continue
		}
		if key.Value != wanted || found != nil {
			return nil, argoCDFieldInvalid
		}
		found = value
	}
	if found == nil {
		return nil, argoCDFieldMissing
	}
	return found, argoCDFieldFound
}

func argoCDString(n *yaml.Node, wanted string) bool {
	return n != nil && n.Kind == yaml.ScalarNode && n.ShortTag() == yamlStrTag && n.Value == wanted
}

func argoCDCanonicalExclusions(sequence *yaml.Node) ([]byte, bool) {
	values := make([]map[string][]string, 0, len(sequence.Content))
	for _, entry := range sequence.Content {
		if entry.Kind != yaml.MappingNode {
			return nil, false
		}
		value := map[string][]string{}
		for i := 0; i < len(entry.Content); i += 2 {
			key, node := entry.Content[i], entry.Content[i+1]
			if !argoCDString(key, "apiGroups") && !argoCDString(key, "kinds") || node.Kind != yaml.SequenceNode {
				return nil, false
			}
			if _, exists := value[key.Value]; exists {
				return nil, false
			}
			list := make([]string, 0, len(node.Content))
			for _, item := range node.Content {
				if item.Kind != yaml.ScalarNode || item.ShortTag() != "!!str" {
					return nil, false
				}
				list = append(list, item.Value)
			}
			value[key.Value] = list
		}
		if len(value) != 2 || value["apiGroups"] == nil || value["kinds"] == nil {
			return nil, false
		}
		values = append(values, value)
	}
	raw, err := json.Marshal(values)
	return raw, err == nil
}

func argoCDNearField(m *yaml.Node, wanted string) bool {
	if m == nil || m.Kind != yaml.MappingNode {
		return false
	}
	target := strings.ToLower(wanted)
	for i := 0; i < len(m.Content); i += 2 {
		key := m.Content[i]
		if key.Kind == yaml.ScalarNode && key.ShortTag() == "!!str" && strings.ToLower(strings.TrimSpace(key.Value)) == target && key.Value != wanted {
			return true
		}
	}
	return false
}

func argoCDStrictStringData(data *yaml.Node) bool {
	seen := map[string]bool{}
	for i := 0; i < len(data.Content); i += 2 {
		key, value := data.Content[i], data.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.ShortTag() != yamlStrTag || value.Kind != yaml.ScalarNode || value.ShortTag() != yamlStrTag || seen[key.Value] {
			return false
		}
		seen[key.Value] = true
	}
	return len(data.Content)%2 == 0
}
