// SPDX-License-Identifier: AGPL-3.0-only

package helmvalues

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/helmvaluespath"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// maxSchemaDepth bounds the nesting of values.schema.json.
const maxSchemaDepth = 128

// schemaNode is one JSON schema object. A schema may also be a boolean;
// such a property is opaque to the analysis.
type schemaNode map[string]any

// decodeSchema reads values.schema.json: one JSON object with no member
// names that are equal or equal under case folding, at any depth.
func decodeSchema(raw []byte) (schemaNode, error) {
	if err := strictjson.CheckDepth(raw, maxSchemaDepth); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("the schema is not a JSON object")
	}
	return schemaNode(obj), nil
}

// safeKeywords are the keywords a schema object on the path to a required
// key or a closed object may hold. Each either annotates, constrains only
// the object itself (its type, its size), or is one the analysis reads.
// Any other keyword (allOf, anyOf, oneOf, not, if/then/else, $ref,
// dependencies, unevaluatedProperties, propertyNames, const, enum, ...)
// makes the object opaque: what it requires or admits is not derived.
var safeKeywords = map[string]bool{
	"$comment": true, "title": true, "description": true, "default": true, "examples": true,
	"deprecated": true, "readOnly": true, "writeOnly": true,
	"type": true, "properties": true, "required": true, "additionalProperties": true, "patternProperties": true,
	"minProperties": true, "maxProperties": true,
}

// rootKeywords may appear only at the schema root.
var rootKeywords = map[string]bool{"$schema": true, "$id": true, "definitions": true, "$defs": true}

// objectKeywords make a schema describe an object's keys.
var objectKeywords = []string{"properties", "required", "additionalProperties", "patternProperties"}

// hidingKeywords can require or admit keys the analysis does not read.
var hidingKeywords = []string{"$ref", "$dynamicRef", "$recursiveRef", "allOf", "anyOf", "oneOf", "not", "if", "then", "else",
	"dependencies", "dependentRequired", "dependentSchemas", "unevaluatedProperties", "propertyNames"}

// leaf reports a property schema that describes no object keys and holds
// no keyword that could: a string, number, boolean or list value. The walk
// does not descend into it and records nothing for it.
func (n schemaNode) leaf() bool {
	if t, ok := n["type"]; ok && t == "object" {
		return false
	}
	if ts, ok := n["type"].([]any); ok {
		for _, t := range ts {
			if t == "object" {
				return false
			}
		}
	}
	for _, k := range objectKeywords {
		if _, ok := n[k]; ok {
			return false
		}
	}
	for _, k := range hidingKeywords {
		if _, ok := n[k]; ok {
			return false
		}
	}
	return true
}

// opaqueReason returns why a schema object on a walked path is opaque, ""
// when the analysis reads it completely.
func (n schemaNode) opaqueReason(root bool) string {
	var bad []string
	for k := range n {
		if safeKeywords[k] || root && rootKeywords[k] || strings.HasPrefix(k, "x-") {
			continue
		}
		bad = append(bad, k)
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return "keyword " + strings.Join(bad, ", ")
	}
	if t, ok := n["type"]; ok && t != "object" {
		return "type is not the single type object"
	}
	if p, ok := n["properties"]; ok {
		if _, isObj := p.(map[string]any); !isObj {
			return "properties is not an object"
		}
	}
	if r, ok := n["required"]; ok {
		items, isArr := r.([]any)
		if !isArr {
			return "required is not an array"
		}
		for _, it := range items {
			if _, isStr := it.(string); !isStr {
				return "required holds a non-string"
			}
		}
	}
	if a, ok := n["additionalProperties"]; ok {
		switch a.(type) {
		case bool, map[string]any:
		default:
			return "additionalProperties is neither a boolean nor a schema"
		}
	}
	if p, ok := n["patternProperties"]; ok {
		if _, isObj := p.(map[string]any); !isObj {
			return "patternProperties is not an object"
		}
	}
	return ""
}

// property returns the schema of key k under properties: (node, true,
// "") for an object schema, (nil, true, reason) for a boolean or other
// schema, (nil, false, "") when properties does not name k.
func (n schemaNode) property(k string) (schemaNode, bool, string) {
	props, _ := n["properties"].(map[string]any)
	v, ok := props[k]
	if !ok {
		return nil, false, ""
	}
	switch s := v.(type) {
	case map[string]any:
		return schemaNode(s), true, ""
	case bool:
		return nil, true, fmt.Sprintf("the schema of %q is the boolean %v", k, s)
	}
	return nil, true, fmt.Sprintf("the schema of %q is not an object", k)
}

func (n schemaNode) requiredKeys() []string {
	items, _ := n["required"].([]any)
	var out []string
	for _, it := range items {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// closed reports whether the object admits only the keys properties names:
// additionalProperties is false and no patternProperties are declared.
func (n schemaNode) closed() bool {
	if _, ok := n["patternProperties"]; ok {
		return false
	}
	b, ok := n["additionalProperties"].(bool)
	return ok && !b
}

// RequiredKey is one key a schema object requires, found by walking the
// schema from its root through properties only.
type RequiredKey struct {
	Path []string
}

// OpaqueNode is a schema object the walk did not read past.
type OpaqueNode struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// schemaWalk is every required key under readable objects and every object
// the walk could not read, in path order.
type schemaWalk struct {
	Required [][]string
	Opaque   []OpaqueNode
}

// walkSchema enumerates the required keys of every object reachable from
// the root through properties. An opaque object is recorded and not
// descended: nothing under it is derived.
func walkSchema(root schemaNode) schemaWalk {
	var w schemaWalk
	var visit func(n schemaNode, path []string)
	visit = func(n schemaNode, path []string) {
		if reason := n.opaqueReason(len(path) == 0); reason != "" {
			w.Opaque = append(w.Opaque, OpaqueNode{Path: helmvaluespath.DisplayPath(path), Reason: reason})
			return
		}
		for _, k := range n.requiredKeys() {
			w.Required = append(w.Required, helmvaluespath.AppendPath(path, k))
		}
		props, _ := n["properties"].(map[string]any)
		keys := make([]string, 0, len(props))
		for k := range props {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child, _, reason := n.property(k)
			if reason != "" {
				// A boolean property schema constrains nothing below it
				// that the analysis would read; record it only when it
				// forbids the key.
				if b, ok := props[k].(bool); ok && b {
					continue
				}
				w.Opaque = append(w.Opaque, OpaqueNode{Path: helmvaluespath.DisplayPath(helmvaluespath.AppendPath(path, k)), Reason: reason})
				continue
			}
			if child.leaf() {
				continue
			}
			visit(child, helmvaluespath.AppendPath(path, k))
		}
	}
	visit(root, nil)
	sort.Slice(w.Required, func(i, j int) bool { return pathLess(w.Required[i], w.Required[j]) })
	return w
}

// rejection walks the schema along path and returns the shortest prefix
// the schema refuses as an unknown key of a closed object. ok is false
// when no prefix is refused or the walk cannot tell (reason says which).
func rejection(root schemaNode, path []string) (prefix []string, ok bool, reason string) {
	n := root
	for i, k := range path {
		if r := n.opaqueReason(i == 0); r != "" {
			return nil, false, "opaque at " + helmvaluespath.DisplayPath(path[:i]) + ": " + r
		}
		child, named, r := n.property(k)
		if named {
			if r != "" {
				return nil, false, r
			}
			n = child
			continue
		}
		if n.closed() {
			return append([]string(nil), path[:i+1]...), true, ""
		}
		return nil, false, "open object at " + helmvaluespath.DisplayPath(path[:i])
	}
	return nil, false, "every key is declared"
}

func pathLess(a, b []string) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}
