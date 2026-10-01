// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bytes"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	lokiCompactorKey         = "compactor"
	lokiSharedStoreKey       = "shared_store"
	lokiSharedStorePrefixKey = "shared_store_key_prefix"
)

// lokiCompactorLegacySharedStore inspects one complete, caller-selected native
// Loki YAML document. It retains only whether either reviewed legacy key is
// present directly in the selected top-level compactor mapping.
func lokiCompactorLegacySharedStore(raw []byte) (found, supported bool, err error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if decodeErr := decoder.Decode(&document); decodeErr != nil || len(document.Content) != 1 {
		return false, false, nil
	}
	var trailing yaml.Node
	if decodeErr := decoder.Decode(&trailing); decodeErr != io.EOF {
		return false, false, nil
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode || root.ShortTag() != "!!map" {
		return false, false, nil
	}
	if valid, duplicate := lokiSafeYAMLNode(root); !valid {
		if duplicate {
			return false, false, ErrInvalid
		}
		return false, false, nil
	}
	if lokiUnresolvedYAML(root) {
		return false, false, nil
	}
	var compactor *yaml.Node
	for index := 0; index < len(root.Content); index += 2 {
		key, value := root.Content[index], root.Content[index+1]
		trimmed := strings.TrimSpace(key.Value)
		lower := strings.ToLower(trimmed)
		if lower == lokiCompactorKey || strings.HasPrefix(lower, lokiCompactorKey+".") {
			if key.Value != lokiCompactorKey || lower != lokiCompactorKey || compactor != nil {
				return false, false, nil
			}
			compactor = value
		}
	}
	if compactor == nil || compactor.Kind != yaml.MappingNode || compactor.ShortTag() != "!!map" {
		return false, false, nil
	}
	found = false
	for index := 0; index < len(compactor.Content); index += 2 {
		key, value := compactor.Content[index], compactor.Content[index+1]
		trimmed := strings.TrimSpace(key.Value)
		lower := strings.ToLower(trimmed)
		if lokiRelevantCompactorKey(lower) {
			if key.Value != lower || strings.Contains(lower, ".") {
				return false, false, nil
			}
			if value.Kind != yaml.ScalarNode || value.ShortTag() != "!!str" {
				return false, false, nil
			}
			found = true
		}
		if lokiNestedRelevantCompactorKey(value) {
			return false, false, nil
		}
	}
	return found, true, nil
}

// lokiSafeYAMLNode rejects aliases, anchors, merge keys, custom tags and
// duplicate mapping keys throughout the supplied document. Duplicate keys are
// a malformed input; other unsupported YAML features produce UNKNOWN.
func lokiSafeYAMLNode(node *yaml.Node) (valid, duplicate bool) {
	if node == nil || node.Kind == yaml.AliasNode || node.Alias != nil || node.Anchor != "" || node.Style&yaml.TaggedStyle != 0 {
		return false, false
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.ShortTag() != "!!map" || len(node.Content)%2 != 0 {
			return false, false
		}
		seen := map[string]bool{}
		for index := 0; index < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || key.Anchor != "" || key.Alias != nil || key.Style&yaml.TaggedStyle != 0 || key.Value == "<<" {
				return false, false
			}
			if seen[key.Value] {
				return false, true
			}
			seen[key.Value] = true
			if childValid, childDuplicate := lokiSafeYAMLNode(value); !childValid {
				return false, childDuplicate
			}
		}
	case yaml.SequenceNode:
		if node.ShortTag() != "!!seq" {
			return false, false
		}
		for _, child := range node.Content {
			if childValid, childDuplicate := lokiSafeYAMLNode(child); !childValid {
				return false, childDuplicate
			}
		}
	case yaml.ScalarNode:
		switch node.ShortTag() {
		case "!!null", "!!bool", "!!str", "!!int", "!!float", "!!timestamp":
		default:
			return false, false
		}
	default:
		return false, false
	}
	return true, false
}

func lokiRelevantCompactorKey(lower string) bool {
	return lower == lokiSharedStoreKey || strings.HasPrefix(lower, lokiSharedStoreKey+".") || lower == lokiSharedStorePrefixKey || strings.HasPrefix(lower, lokiSharedStorePrefixKey+".")
}

func lokiNestedRelevantCompactorKey(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.MappingNode {
		for index := 0; index < len(node.Content); index += 2 {
			if lokiRelevantCompactorKey(strings.ToLower(strings.TrimSpace(node.Content[index].Value))) || lokiNestedRelevantCompactorKey(node.Content[index+1]) {
				return true
			}
		}
		return false
	}
	for _, child := range node.Content {
		if lokiNestedRelevantCompactorKey(child) {
			return true
		}
	}
	return false
}

func lokiUnresolvedYAML(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.ScalarNode && node.ShortTag() == "!!str" && (strings.Contains(node.Value, "$") || strings.Contains(node.Value, "{{") || strings.Contains(node.Value, "{%")) {
		return true
	}
	for _, child := range node.Content {
		if lokiUnresolvedYAML(child) {
			return true
		}
	}
	return false
}
