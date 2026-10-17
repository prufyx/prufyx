// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
)

// fieldMaxDepth bounds the path length and the placeholder recursion.
const fieldMaxDepth = 16

// Schema states of a path at the To release.
const (
	schemaPresent    = "present"
	schemaAbsent     = "absent"
	schemaPermissive = "permissive"
)

// errNotBuildable marks a placeholder the schema does not determine.
var errNotBuildable = errors.New("no placeholder")

// crdVersionEntry returns the spec.versions entry named version.
func crdVersionEntry(crd map[string]any, version string) (map[string]any, bool) {
	spec, _ := crd["spec"].(map[string]any)
	versions, _ := spec["versions"].([]any)
	for _, v := range versions {
		m, _ := v.(map[string]any)
		if m != nil && str(m, "name") == version {
			return m, true
		}
	}
	return nil, false
}

// versionSchema returns spec.versions[i].schema.openAPIV3Schema for the
// version named, ok false when the version or its schema is absent.
func versionSchema(crd map[string]any, version string) (map[string]any, bool) {
	v, ok := crdVersionEntry(crd, version)
	if !ok {
		return nil, false
	}
	schema, _ := v["schema"].(map[string]any)
	root, _ := schema["openAPIV3Schema"].(map[string]any)
	return root, root != nil
}

// preservesUnknown reports x-kubernetes-preserve-unknown-fields: true.
func preservesUnknown(schema map[string]any) bool {
	b, _ := schema["x-kubernetes-preserve-unknown-fields"].(bool)
	return b
}

// intOrString reports x-kubernetes-int-or-string: true.
func intOrString(schema map[string]any) bool {
	b, _ := schema["x-kubernetes-int-or-string"].(bool)
	return b
}

// fieldStep is one segment of a walked path: its schema, the object schema
// below it after crossing its arrays (nil for the leaf), and how many arrays
// were crossed.
type fieldStep struct {
	name   string
	schema map[string]any
	object map[string]any
	arrays int
}

// buildFieldObject builds the object for a claim from the From CRD as
// installed (scope "Namespaced" or "Cluster"). On success reason is "" and
// serverPath is the path as the API server names it; otherwise reason is a
// crd-field reason code and detail says why.
func buildFieldObject(crd map[string]any, s Subject, scope string) (obj map[string]any, serverPath, reason, detail string) {
	if _, ok := crdVersionEntry(crd, s.Version); !ok {
		return nil, "", ReasonPathNotInFrom, "the From definition declares no version " + s.Version
	}
	root, ok := versionSchema(crd, s.Version)
	if !ok {
		return nil, "", ReasonSchemaPermissive, "version " + s.Version + " of the From release has no structural schema"
	}
	spec, _ := crd["spec"].(map[string]any)
	names, _ := spec["names"].(map[string]any)
	if str(spec, "group") != s.Group || str(names, "kind") != s.Kind {
		return nil, "", ReasonPathNotInFrom, fmt.Sprintf("the From definition serves %s %s, not %s %s", str(spec, "group"), str(names, "kind"), s.Group, s.Kind)
	}
	segs := strings.Split(s.Path, ".")
	if len(segs) > fieldMaxDepth {
		return nil, "", ReasonObjectNotBuildable, fmt.Sprintf("path %s is longer than %d segments", s.Path, fieldMaxDepth)
	}
	for _, seg := range segs {
		if seg == "" {
			return nil, "", ReasonPathNotInFrom, "path " + s.Path + " has an empty segment"
		}
	}
	switch segs[0] {
	case "apiVersion", "kind", "metadata":
		return nil, segs[0], ReasonObjectNotBuildable, "path " + s.Path + " is under " + segs[0] + ", which the tool sets itself"
	}
	if preservesUnknown(root) {
		return nil, "", ReasonSchemaPermissive, "the From root schema preserves unknown fields"
	}
	if segs[0] == "status" {
		v, _ := crdVersionEntry(crd, s.Version)
		sub, _ := v["subresources"].(map[string]any)
		if _, ok := sub["status"]; ok {
			return nil, "status", ReasonSchemaPermissive, "version " + s.Version + " has a status subresource, so status is dropped on create"
		}
	}
	mapKeysAllowed := s.Change == ChangeTypeChanged || s.Change == ChangeEnumValueRemoved || s.Change == ChangeValidationTightened

	var parts []string
	var steps []fieldStep
	cur := root
	for i, seg := range segs {
		props, _ := cur["properties"].(map[string]any)
		p, ok := props[seg].(map[string]any)
		if !ok {
			ap, isSchema := cur["additionalProperties"].(map[string]any)
			if !isSchema || !mapKeysAllowed {
				return nil, strings.Join(append(parts, seg), "."), ReasonPathNotInFrom, "the From schema declares no property " + seg + " at " + strings.Join(segs[:i+1], ".")
			}
			p = ap
		}
		if preservesUnknown(p) {
			return nil, strings.Join(append(parts, seg), "."), ReasonSchemaPermissive, "the From schema preserves unknown fields at " + strings.Join(segs[:i+1], ".")
		}
		step := fieldStep{name: seg, schema: p}
		part := seg
		if i < len(segs)-1 {
			next := p
			for str(next, "type") == "array" {
				items, _ := next["items"].(map[string]any)
				if items == nil {
					return nil, strings.Join(append(parts, part), "."), ReasonPathNotInFrom, "the From schema declares no items under the array " + strings.Join(segs[:i+1], ".")
				}
				if preservesUnknown(items) {
					return nil, strings.Join(append(parts, part), "."), ReasonSchemaPermissive, "the From schema preserves unknown fields in the items of " + strings.Join(segs[:i+1], ".")
				}
				next, step.arrays, part = items, step.arrays+1, part+"[0]"
			}
			step.object = next
		}
		parts = append(parts, part)
		steps = append(steps, step)
		cur = step.object
	}
	serverPath = strings.Join(parts, ".")
	leaf := steps[len(steps)-1].schema
	if str(leaf, "type") == "" && !intOrString(leaf) {
		return nil, serverPath, ReasonSchemaPermissive, "the From schema gives " + s.Path + " no type"
	}

	var value any
	switch s.Change {
	case ChangeFieldRemoved:
		v, err := fieldPlaceholder(leaf, 0)
		if err != nil {
			return nil, serverPath, ReasonObjectNotBuildable, "no placeholder for " + s.Path + ": " + err.Error()
		}
		value = v
	case ChangeTypeChanged, ChangeEnumValueRemoved, ChangeValidationTightened:
		if len(s.Value) == 0 {
			return nil, serverPath, ReasonValueMissing, "the claim names no value for " + s.Change
		}
		if err := json.Unmarshal(s.Value, &value); err != nil {
			return nil, serverPath, ReasonValueMissing, "the claim's value is not JSON: " + err.Error()
		}
		if value == nil {
			return nil, serverPath, ReasonValueMissing, "the claim's value is null"
		}
		if s.Change == ChangeEnumValueRemoved && !enumHas(leaf, value) {
			return nil, serverPath, ReasonPathNotInFrom, "the From schema declares no enum value " + string(s.Value) + " at " + s.Path
		}
	case ChangeRequiredAdded:
	default:
		return nil, serverPath, ReasonObjectNotBuildable, "unknown change " + s.Change
	}

	meta := map[string]any{"name": fieldObjectName}
	if scope != "Cluster" {
		meta["namespace"] = "default"
	}
	obj = map[string]any{}
	skip := map[string]bool{"apiVersion": true, "kind": true, "metadata": true, segs[0]: true}
	if err := fillRequired(obj, root, skip, 0); err != nil {
		return nil, serverPath, ReasonObjectNotBuildable, "no placeholder for a required field at the root: " + err.Error()
	}
	obj["apiVersion"], obj["kind"], obj["metadata"] = s.Group+"/"+s.Version, s.Kind, meta

	container := obj
	for i, st := range steps {
		if i == len(steps)-1 {
			if s.Change != ChangeRequiredAdded {
				container[st.name] = value
			}
			break
		}
		child := map[string]any{}
		if err := fillRequired(child, st.object, map[string]bool{segs[i+1]: true}, 0); err != nil {
			return nil, serverPath, ReasonObjectNotBuildable, "no placeholder for a required field at " + strings.Join(segs[:i+1], ".") + ": " + err.Error()
		}
		var v any = child
		for n := 0; n < st.arrays; n++ {
			v = []any{v}
		}
		container[st.name] = v
		container = child
	}
	return obj, serverPath, "", ""
}

// requiredNames is the schema's required list followed by the required
// list of the first oneOf and anyOf branch when that branch holds nothing
// else.
func requiredNames(schema map[string]any) []string {
	var out []string
	add := func(list any) {
		l, _ := list.([]any)
		for _, n := range l {
			if s, ok := n.(string); ok {
				out = append(out, s)
			}
		}
	}
	add(schema["required"])
	for _, key := range []string{"oneOf", "anyOf"} {
		branches, _ := schema[key].([]any)
		if len(branches) == 0 {
			continue
		}
		first, _ := branches[0].(map[string]any)
		if _, ok := first["required"]; ok && len(first) == 1 {
			add(first["required"])
		}
	}
	return out
}

// fillRequired sets a placeholder in obj for every required name of schema
// not in skip and not yet set.
func fillRequired(obj, schema map[string]any, skip map[string]bool, depth int) error {
	props, _ := schema["properties"].(map[string]any)
	for _, name := range requiredNames(schema) {
		if skip[name] {
			continue
		}
		if _, set := obj[name]; set {
			continue
		}
		p, ok := props[name].(map[string]any)
		if !ok {
			if p, ok = schema["additionalProperties"].(map[string]any); !ok {
				return fmt.Errorf("required %s is not declared", name)
			}
		}
		v, err := fieldPlaceholder(p, depth+1)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		obj[name] = v
	}
	return nil
}

// fieldPlaceholder is the least value the schema accepts, as far as its
// type, enum and simple bounds tell.
func fieldPlaceholder(schema map[string]any, depth int) (any, error) {
	if depth > fieldMaxDepth {
		return nil, fmt.Errorf("deeper than %d levels: %w", fieldMaxDepth, errNotBuildable)
	}
	if enum, _ := schema["enum"].([]any); len(enum) > 0 {
		return enum[0], nil
	}
	if intOrString(schema) {
		return "x", nil
	}
	switch t := str(schema, "type"); t {
	case "string":
		n, _ := schema["minLength"].(float64)
		return strings.Repeat("x", max(1, int(n))), nil
	case "integer", "number":
		v := 1.0
		if lo, ok := schema["minimum"].(float64); ok {
			if excl, _ := schema["exclusiveMinimum"].(bool); excl {
				lo++
			}
			if t == "integer" {
				lo = math.Ceil(lo)
			}
			if lo > v {
				v = lo
			}
		}
		return v, nil
	case "boolean":
		return true, nil
	case "object":
		m := map[string]any{}
		if err := fillRequired(m, schema, nil, depth); err != nil {
			return nil, err
		}
		return m, nil
	case "array":
		n, _ := schema["minItems"].(float64)
		out := []any{}
		if n <= 0 {
			return out, nil
		}
		items, _ := schema["items"].(map[string]any)
		if items == nil {
			return nil, fmt.Errorf("array of %d items declares no items: %w", int(n), errNotBuildable)
		}
		item, err := fieldPlaceholder(items, depth+1)
		if err != nil {
			return nil, err
		}
		for i := 0; i < int(n); i++ {
			out = append(out, item)
		}
		return out, nil
	case "":
		if preservesUnknown(schema) {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("schema has no type: %w", errNotBuildable)
	default:
		return nil, fmt.Errorf("unknown type %s: %w", t, errNotBuildable)
	}
}

// schemaAt reports the state of path in the CRD as installed at To, version
// named: permissive when the version has no schema or the root, an ancestor
// or the field preserves unknown fields; absent when a segment is not a
// declared property (nor a map key through additionalProperties) or the
// version is absent; else present.
func schemaAt(crd map[string]any, version, path string) string {
	if _, ok := crdVersionEntry(crd, version); !ok {
		return schemaAbsent
	}
	cur, ok := versionSchema(crd, version)
	if !ok || preservesUnknown(cur) {
		return schemaPermissive
	}
	for _, seg := range strings.Split(path, ".") {
		for str(cur, "type") == "array" {
			items, _ := cur["items"].(map[string]any)
			if items == nil {
				return schemaAbsent
			}
			if preservesUnknown(items) {
				return schemaPermissive
			}
			cur = items
		}
		props, _ := cur["properties"].(map[string]any)
		p, ok := props[seg].(map[string]any)
		if !ok {
			// A map key: present through additionalProperties (a crd-field
			// claim names one only for a change of the value's schema).
			switch ap := cur["additionalProperties"].(type) {
			case map[string]any:
				p = ap
			case bool:
				if ap {
					return schemaPermissive
				}
				return schemaAbsent
			default:
				return schemaAbsent
			}
		}
		if preservesUnknown(p) {
			return schemaPermissive
		}
		cur = p
	}
	return schemaPresent
}

// enumHas reports whether the schema's enum lists the value (compared as
// JSON).
func enumHas(schema map[string]any, value any) bool {
	want, _ := json.Marshal(value)
	list, _ := schema["enum"].([]any)
	for _, v := range list {
		if got, _ := json.Marshal(v); string(got) == string(want) {
			return true
		}
	}
	return false
}
