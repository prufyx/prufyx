// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"gopkg.in/yaml.v3"
)

// The strict YAML subset of the component-configuration route (package
// intake), with bounds sized for CustomResourceDefinition manifests: a
// generated OpenAPI schema nests far deeper than a configuration file
// (Argo CD's ApplicationSet passes 32 levels) and a bundle of definitions
// holds far more nodes. Everything else is the same: anchors, aliases,
// merge keys, custom tags, non-string, empty or duplicate keys are refused,
// because each can make the bytes a reader sees differ from what the API
// server is sent.
const (
	maxDecodeDepth     = 128
	maxDecodeNodes     = 4_000_000
	maxDecodeDocuments = 1024
	maxObjectMembers   = 8192
	maxArrayItems      = 8192
)

var errStrict = errors.New("outside the strict YAML subset or its bounds")

// decodeStrict returns the root node and the plain value (map[string]any,
// []any, string, bool, json.Number or nil) of every non-empty document.
// Empty documents and documents holding only null are skipped.
func decodeStrict(data []byte) ([]*yaml.Node, []any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	budget := maxDecodeNodes
	var roots []*yaml.Node
	var values []any
	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if err == io.EOF {
			return roots, values, nil
		}
		if err != nil || node.Kind != yaml.DocumentNode || len(node.Content) > 1 {
			return nil, nil, errStrict
		}
		if len(node.Content) == 0 {
			continue
		}
		root := node.Content[0]
		if root.Kind == yaml.ScalarNode && root.ShortTag() == "!!null" && root.Anchor == "" {
			continue
		}
		v, err := strictValue(root, 0, &budget)
		if err != nil {
			return nil, nil, err
		}
		roots = append(roots, root)
		values = append(values, v)
		if len(values) > maxDecodeDocuments {
			return nil, nil, errStrict
		}
	}
}

func strictValue(node *yaml.Node, depth int, budget *int) (any, error) {
	*budget--
	if *budget < 0 || depth > maxDecodeDepth || node == nil || node.Anchor != "" || node.Alias != nil || node.Kind == yaml.AliasNode {
		return nil, errStrict
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.ShortTag() != "!!map" || len(node.Content)%2 != 0 || len(node.Content)/2 > maxObjectMembers {
			return nil, errStrict
		}
		obj := make(map[string]any, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || key.Anchor != "" || key.Alias != nil || key.Value == "" || key.Value == "<<" {
				return nil, errStrict
			}
			if _, dup := obj[key.Value]; dup {
				return nil, errStrict
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
			return nil, errStrict
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
			// A timestamp-looking scalar is sent as the string it is
			// written as.
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
	return nil, errStrict
}
