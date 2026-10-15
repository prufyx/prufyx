// SPDX-License-Identifier: AGPL-3.0-only

package helmvaluespath

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// The strict YAML subset Chart.yaml and values files are read in, with the
// bounds of the CRD extractor's decoder. Anchors, aliases, merge keys,
// custom tags, non-string, empty or duplicate keys, and keys holding a NUL
// byte are refused, and so is a key that YAML 1.1 reads as a boolean or
// null: Helm decodes values with a YAML 1.1 reader, which turns "on:" into
// the key "true", so the key path this reader sees would not be the one
// Helm validates.
const (
	maxDecodeDepth     = 128
	maxDecodeNodes     = 4_000_000
	maxDecodeDocuments = 1
	maxObjectMembers   = 8192
	maxArrayItems      = 8192
)

// ErrStrict is the error of a document outside the subset or its bounds.
var ErrStrict = errors.New("outside the strict YAML subset or its bounds")

// yaml11KeyRE matches the plain scalars YAML 1.1 resolves to a boolean or
// null; as keys they mean something else to Helm than to this reader.
var yaml11KeyRE = regexp.MustCompile(`^(y|Y|yes|Yes|YES|n|N|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF|null|Null|NULL|~)$`)

// DecodeYAML returns the root node and the plain value (map[string]any,
// []any, string, bool, json.Number or nil) of a single-document file. An
// empty file or a document holding only null decodes to a nil root.
func DecodeYAML(data []byte) (*yaml.Node, any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	budget := maxDecodeNodes
	var root *yaml.Node
	var value any
	docs := 0
	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if err == io.EOF {
			return root, value, nil
		}
		if err != nil || node.Kind != yaml.DocumentNode || len(node.Content) > 1 {
			return nil, nil, ErrStrict
		}
		docs++
		if docs > maxDecodeDocuments {
			return nil, nil, ErrStrict
		}
		if len(node.Content) == 0 {
			continue
		}
		r := node.Content[0]
		if r.Kind == yaml.ScalarNode && r.ShortTag() == "!!null" && r.Anchor == "" {
			continue
		}
		v, err := strictValue(r, 0, &budget)
		if err != nil {
			return nil, nil, err
		}
		root, value = r, v
	}
}

func strictValue(node *yaml.Node, depth int, budget *int) (any, error) {
	*budget--
	if *budget < 0 || depth > maxDecodeDepth || node == nil || node.Anchor != "" || node.Alias != nil || node.Kind == yaml.AliasNode {
		return nil, ErrStrict
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.ShortTag() != "!!map" || len(node.Content)%2 != 0 || len(node.Content)/2 > maxObjectMembers {
			return nil, ErrStrict
		}
		obj := make(map[string]any, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || key.Anchor != "" || key.Alias != nil || key.Value == "" || key.Value == "<<" || strings.IndexByte(key.Value, 0) >= 0 {
				return nil, ErrStrict
			}
			if key.Style == 0 && yaml11KeyRE.MatchString(key.Value) {
				return nil, ErrStrict
			}
			if _, dup := obj[key.Value]; dup {
				return nil, ErrStrict
			}
			v, err := strictValue(node.Content[i+1], depth+1, budget)
			if err != nil {
				return nil, err
			}
			obj[key.Value] = v
		}
		return obj, nil
	case yaml.SequenceNode:
		if node.ShortTag() != "!!seq" || len(node.Content) > maxArrayItems {
			return nil, ErrStrict
		}
		items := make([]any, 0, len(node.Content))
		for _, c := range node.Content {
			v, err := strictValue(c, depth+1, budget)
			if err != nil {
				return nil, err
			}
			items = append(items, v)
		}
		return items, nil
	case yaml.ScalarNode:
		switch node.ShortTag() {
		case "!!str", "!!timestamp":
			return node.Value, nil
		case "!!bool":
			switch node.Value {
			case "true", "True", "TRUE":
				return true, nil
			case "false", "False", "FALSE":
				return false, nil
			}
		case "!!int", "!!float":
			return json.Number(node.Value), nil
		case "!!null":
			return nil, nil
		}
	}
	return nil, ErrStrict
}

// MappingLine returns the line of key's value in a mapping root, 0 when
// absent.
func MappingLine(root *yaml.Node, key string) int {
	if root == nil || root.Kind != yaml.MappingNode {
		return 0
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			return root.Content[i].Line
		}
	}
	return 0
}
