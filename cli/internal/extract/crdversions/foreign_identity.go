// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// foreignIdentityProblem reads identities only, never versions or schemas.
// Exact content pins and the caller's disjoint-group/text checks are required
// before this function runs. Duplicate nonidentity schema fields cannot change
// an unambiguous foreign group; every branch is nevertheless inspected.
func foreignIdentityProblem(b *ForeignBundle, data []byte, groups []string) string {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	budget := maxDecodeNodes
	documents := 0
	definitions := 0
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil || len(doc.Content) != 1 {
			return "foreign identity YAML is malformed"
		}
		documents++
		if documents > maxDecodeDocuments {
			return "too many foreign identity documents"
		}
		root := doc.Content[0]
		if why := foreignIdentityNodes(root, root, groups, 0, &budget); why != "" {
			return why
		}
		if root.Kind != yaml.MappingNode {
			return "foreign identity document is not a mapping"
		}
		kind, err := foreignIdentityKey(root, "kind")
		if err != nil || kind.Kind != yaml.ScalarNode || kind.ShortTag() != "!!str" {
			return "ambiguous foreign kind"
		}
		api, err := foreignIdentityKey(root, "apiVersion")
		if err != nil || api.Kind != yaml.ScalarNode || api.ShortTag() != "!!str" {
			return "ambiguous foreign apiVersion"
		}
		if kind.Value != crdKind {
			if strings.HasPrefix(api.Value, crdAPIGroupPrefix) || strings.HasPrefix(api.Value, "kustomize.config.k8s.io/") || kind.Value == "Kustomization" || kind.Value == "Component" {
				return "foreign identity bundle includes an unsupported install surface"
			}
			v, err := strictValue(root, 0, &budget)
			if err != nil {
				return "non-CRD foreign document is outside the strict subset"
			}
			if why := definitionInside(v); why != "" {
				return why
			}
			continue
		}
		if api.Value != crdAPIGroupPrefix+"v1" && api.Value != crdAPIGroupPrefix+"v1beta1" {
			return "unsupported foreign CRD apiVersion"
		}
		spec, err := foreignIdentityKey(root, "spec")
		if err != nil {
			return "ambiguous foreign spec"
		}
		group, err := foreignIdentityKey(spec, "group")
		if err != nil || group.Kind != yaml.ScalarNode || group.ShortTag() != "!!str" || !slices.Contains(b.Groups, group.Value) {
			return "ambiguous or undeclared foreign group"
		}
		meta, err := foreignIdentityKey(root, "metadata")
		if err != nil {
			return "ambiguous foreign metadata"
		}
		name, err := foreignIdentityKey(meta, "name")
		if err != nil || name.Kind != yaml.ScalarNode || name.ShortTag() != "!!str" || !strings.HasSuffix(name.Value, "."+group.Value) || !pluralRE.MatchString(strings.TrimSuffix(name.Value, "."+group.Value)) {
			return "ambiguous foreign name"
		}
		definitions++
	}
	if definitions == 0 {
		return "foreign identity bundle defines no CRD"
	}
	return ""
}

func foreignIdentityKey(n *yaml.Node, key string) (*yaml.Node, error) {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("identity is not a mapping")
	}
	var out *yaml.Node
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			if out != nil {
				return nil, fmt.Errorf("duplicate identity %s", key)
			}
			out = n.Content[i+1]
		}
	}
	if out == nil {
		return nil, fmt.Errorf("missing identity %s", key)
	}
	return out, nil
}

func foreignIdentityNodes(n, root *yaml.Node, groups []string, depth int, budget *int) string {
	*budget--
	if n == nil || *budget < 0 || depth > maxDecodeDepth || n.Anchor != "" || n.Alias != nil || n.Kind == yaml.AliasNode {
		return "foreign identity aliases, anchors or bounds"
	}
	switch n.Kind {
	case yaml.MappingNode:
		if n.ShortTag() != "!!map" || len(n.Content)%2 != 0 || len(n.Content)/2 > maxObjectMembers {
			return "invalid foreign identity mapping"
		}
		identities := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || key.Value == "" || key.Value == "<<" {
				return "unsupported foreign identity key"
			}
			switch key.Value {
			case "kind", "apiVersion", "metadata", "spec", "group", "name":
				if identities[key.Value] {
					return "duplicate foreign identity key"
				}
				identities[key.Value] = true
			}
			if n != root && key.Value == "kind" && n.Content[i+1].Value == crdKind {
				return "nested foreign definition"
			}
		}
	case yaml.SequenceNode:
		if n.ShortTag() != "!!seq" || len(n.Content) > maxArrayItems {
			return "invalid foreign identity sequence"
		}
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case "!!str", "!!bool", "!!int", "!!float", "!!null", "!!timestamp":
		default:
			return "unsupported foreign identity tag"
		}
		lower := strings.ToLower(n.Value)
		if n.ShortTag() == "!!str" && (strings.Contains(lower, `\u`) || strings.Contains(lower, `\x`)) {
			return "unresolved escape inside foreign scalar"
		}
		for _, g := range groups {
			if strings.Contains(lower, strings.ToLower(g)) {
				return "foreign scalar mentions the target group"
			}
		}
		if strings.Contains(lower, strings.ToLower(crdKind)) {
			top, err := foreignIdentityKey(root, "kind")
			if err != nil || n != top || n.Value != crdKind {
				return "embedded foreign definition text"
			}
		}
	default:
		return "unsupported foreign identity node"
	}
	for _, c := range n.Content {
		if why := foreignIdentityNodes(c, root, groups, depth+1, budget); why != "" {
			return why
		}
	}
	return ""
}
