// SPDX-License-Identifier: AGPL-3.0-only

package intake

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"gopkg.in/yaml.v3"
)

// The Kubernetes component-configuration route accepts the formats operators
// actually hold: YAML (single or multi-document) and JSON, which is a YAML
// subset. Decoding is deliberately narrower than the YAML language. Anchors,
// aliases, merge keys, custom tags, non-string keys and duplicate keys are
// rejected, because each of them can make the bytes a reader sees differ from
// the value a Kubernetes component decodes.

const (
	// MaxDocuments and MaxNodes bound one decode call.
	MaxDocuments = 256
	MaxNodes     = 200000
	// MaxDepth, MaxObjectMembers and MaxArrayItems bound one document. They
	// equal the limits of the strict JSON decoder used by the preparers.
	MaxDepth         = 32
	MaxObjectMembers = 4096
	MaxArrayItems    = 2048
)

// ErrUnsupported reports bytes outside the accepted YAML subset or outside the
// bounds.
var ErrUnsupported = errors.New("unsupported Kubernetes component YAML")

var errK8sComponentYAML = ErrUnsupported

// DecodeDocuments returns every non-empty document as plain values:
// map[string]any, []any, string, bool, json.Number or nil.
func DecodeDocuments(raw []byte) ([]any, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	documents := make([]any, 0, 1)
	budget := MaxNodes
	for {
		var node yaml.Node
		err := decoder.Decode(&node)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errK8sComponentYAML
		}
		if node.Kind != yaml.DocumentNode {
			return nil, errK8sComponentYAML
		}
		if len(node.Content) == 0 {
			continue
		}
		if len(node.Content) != 1 {
			return nil, errK8sComponentYAML
		}
		if root := node.Content[0]; root.Kind == yaml.ScalarNode && root.ShortTag() == "!!null" {
			// An empty document between separators carries no configuration.
			continue
		}
		value, err := yamlValue(node.Content[0], 0, &budget)
		if err != nil {
			return nil, err
		}
		documents = append(documents, value)
		if len(documents) > MaxDocuments {
			return nil, errK8sComponentYAML
		}
	}
	return documents, nil
}

func yamlValue(node *yaml.Node, depth int, budget *int) (any, error) {
	*budget--
	if *budget < 0 || depth > MaxDepth || node == nil || node.Anchor != "" || node.Alias != nil || node.Kind == yaml.AliasNode {
		return nil, errK8sComponentYAML
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.ShortTag() != "!!map" || len(node.Content)%2 != 0 || len(node.Content)/2 > MaxObjectMembers {
			return nil, errK8sComponentYAML
		}
		object := make(map[string]any, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || key.Anchor != "" || key.Alias != nil || key.Value == "" || key.Value == "<<" {
				return nil, errK8sComponentYAML
			}
			if _, duplicate := object[key.Value]; duplicate {
				return nil, errK8sComponentYAML
			}
			value, err := yamlValue(node.Content[index+1], depth+1, budget)
			if err != nil {
				return nil, err
			}
			object[key.Value] = value
		}
		return object, nil
	case yaml.SequenceNode:
		if node.ShortTag() != "!!seq" || len(node.Content) > MaxArrayItems {
			return nil, errK8sComponentYAML
		}
		items := make([]any, 0, len(node.Content))
		for _, child := range node.Content {
			value, err := yamlValue(child, depth+1, budget)
			if err != nil {
				return nil, err
			}
			items = append(items, value)
		}
		return items, nil
	case yaml.ScalarNode:
		switch node.ShortTag() {
		case "!!str":
			return node.Value, nil
		case "!!bool":
			switch node.Value {
			case "true", "True", "TRUE":
				return true, nil
			case "false", "False", "FALSE":
				return false, nil
			}
			return nil, errK8sComponentYAML
		case "!!int", "!!float":
			return json.Number(node.Value), nil
		case "!!null":
			return nil, nil
		}
		return nil, errK8sComponentYAML
	}
	return nil, errK8sComponentYAML
}
