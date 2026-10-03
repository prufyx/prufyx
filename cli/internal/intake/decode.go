// SPDX-License-Identifier: AGPL-3.0-only

package intake

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

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
	documents, err := decodeDocuments(raw, decodeOptions{})
	if err != nil {
		return nil, errK8sComponentYAML
	}
	return documents, nil
}

// decodeOptions tightens or relaxes the base decoder for the manifest path.
type decodeOptions struct {
	// foldKeys rejects two keys in one mapping that differ only in case,
	// as the strict JSON decoder of the preparers does.
	foldKeys bool
	// timestampStrings reads an untagged timestamp scalar such as 2026-01-02
	// as the string it is written as.
	timestampStrings bool
	// maxDocuments bounds the documents of this call; zero means MaxDocuments
	// and a negative value allows none.
	maxDocuments int
	// nodes is the node budget shared with the caller, so one budget can span
	// several files; nil means a fresh MaxNodes budget.
	nodes *int
}

// errLimit and the limit names let Open report which bound was exceeded.
type limitReached struct{ limit string }

func (e limitReached) Error() string { return "limit reached: " + e.limit }

// structuralTokens returns a cheap upper bound on the number of YAML nodes in
// raw, from bytes alone: every flow indicator, comma, colon and line break, and
// every dash that starts a sequence entry, can introduce at most one node, plus
// one for the root. It lets the caller refuse input before the YAML decoder
// allocates a tree that is roughly two hundred bytes per node.
func structuralTokens(raw []byte) int {
	count := 1
	for i, b := range raw {
		switch b {
		case '[', '{', ',', ':', '\n', '\r':
			count++
		case '-':
			if i+1 == len(raw) || raw[i+1] == ' ' || raw[i+1] == '\n' || raw[i+1] == '\r' || raw[i+1] == '\t' {
				count++
			}
		}
	}
	return count
}

func decodeDocuments(raw []byte, opts decodeOptions) ([]any, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	documents := make([]any, 0, 1)
	local := MaxNodes
	budget := &local
	if opts.nodes != nil {
		budget = opts.nodes
	}
	if structuralTokens(raw) > *budget {
		return nil, limitReached{"nodes"}
	}
	maxDocuments := MaxDocuments
	if opts.maxDocuments != 0 {
		maxDocuments = max(opts.maxDocuments, 0)
	}
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
		value, err := opts.yamlValue(node.Content[0], 0, budget)
		if err != nil {
			return nil, err
		}
		documents = append(documents, value)
		if len(documents) > maxDocuments {
			return nil, limitReached{"documents"}
		}
	}
	return documents, nil
}

func (opts decodeOptions) yamlValue(node *yaml.Node, depth int, budget *int) (any, error) {
	*budget--
	if *budget < 0 {
		return nil, limitReached{"nodes"}
	}
	if depth > MaxDepth || node == nil || node.Anchor != "" || node.Alias != nil || node.Kind == yaml.AliasNode {
		return nil, errK8sComponentYAML
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.ShortTag() != "!!map" || len(node.Content)%2 != 0 || len(node.Content)/2 > MaxObjectMembers {
			return nil, errK8sComponentYAML
		}
		object := make(map[string]any, len(node.Content)/2)
		seen := map[string]bool{}
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || key.Anchor != "" || key.Alias != nil || key.Value == "" || key.Value == "<<" {
				return nil, errK8sComponentYAML
			}
			if _, duplicate := object[key.Value]; duplicate {
				return nil, errK8sComponentYAML
			}
			if opts.foldKeys {
				folded := strings.ToLower(key.Value)
				if seen[folded] {
					return nil, errK8sComponentYAML
				}
				seen[folded] = true
			}
			value, err := opts.yamlValue(node.Content[index+1], depth+1, budget)
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
			value, err := opts.yamlValue(child, depth+1, budget)
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
		case "!!timestamp":
			if opts.timestampStrings {
				return node.Value, nil
			}
		}
		return nil, errK8sComponentYAML
	}
	return nil, errK8sComponentYAML
}
