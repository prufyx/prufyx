// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// widgetSchema is the openAPIV3Schema of the fixture definition.
const widgetSchema = `{
  "type": "object",
  "required": ["metadata", "config", "spec"],
  "properties": {
    "apiVersion": {"type": "string"},
    "kind": {"type": "string"},
    "metadata": {"type": "object"},
    "config": {"type": "object", "required": ["level"], "properties": {"level": {"type": "string", "enum": ["low", "high"]}}},
    "spec": {
      "type": "object",
      "required": ["name", "replicas"],
      "properties": {
        "name": {"type": "string", "minLength": 3},
        "replicas": {"type": "integer", "minimum": 2},
        "a": {"type": "object", "required": ["mode"], "properties": {
          "mode": {"type": "string", "enum": ["fast", "slow"]},
          "b": {"type": "object", "required": ["ref"], "properties": {
            "ref": {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}},
            "c": {"type": "string"}
          }}
        }},
        "ports": {"type": "array", "items": {"type": "object", "required": ["port"], "properties": {
          "port": {"type": "integer", "minimum": 1},
          "name": {"type": "string"}
        }}},
        "tags": {"type": "array", "items": {"type": "string"}},
        "hosts": {"type": "array", "minItems": 2, "items": {"type": "string"}},
        "labels": {"type": "object", "additionalProperties": {"type": "string", "enum": ["a", "b"]}},
        "raw": {"type": "object", "x-kubernetes-preserve-unknown-fields": true, "properties": {"x": {"type": "string"}}},
        "opaque": {"x-kubernetes-preserve-unknown-fields": true},
        "untyped": {"description": "no type"},
        "port": {"x-kubernetes-int-or-string": true},
        "choice": {"type": "object", "oneOf": [{"required": ["left"]}, {"required": ["right"]}], "properties": {
          "left": {"type": "boolean"}, "right": {"type": "boolean"}, "extra": {"type": "string"}
        }},
        "broken": {"type": "object", "required": ["nope"], "properties": {"nope": {"description": "no type"}, "v": {"type": "string"}}},
        "matrix": {"type": "array", "items": {"type": "array", "items": {"type": "object", "properties": {"cell": {"type": "string"}}}}}
      }
    },
    "status": {"type": "object", "properties": {"phase": {"type": "string"}}}
  }
}`

// widgetCRD decodes the fixture definition: v1 with the schema and a status
// subresource, v2 without a schema, v3 with the schema and no subresources.
func widgetCRD(t *testing.T, schema string) map[string]any {
	t.Helper()
	doc := `{"kind": "CustomResourceDefinition", "metadata": {"name": "widgets.example.io"}, "spec": {
	  "group": "example.io", "names": {"kind": "Widget"}, "scope": "Namespaced",
	  "versions": [
	    {"name": "v1", "served": true, "storage": true, "schema": {"openAPIV3Schema": SCHEMA}, "subresources": {"status": {}}},
	    {"name": "v2", "served": true, "storage": false},
	    {"name": "v3", "served": true, "storage": false, "schema": {"openAPIV3Schema": SCHEMA}}
	  ]}}`
	var crd map[string]any
	if err := json.Unmarshal([]byte(strings.ReplaceAll(doc, "SCHEMA", schema)), &crd); err != nil {
		t.Fatal(err)
	}
	return crd
}

const (
	widgetHead    = `{"apiVersion":"example.io/v1","config":{"level":"low"},"kind":"Widget","metadata":{"name":"kindval-field","namespace":"default"},`
	widgetCluster = `{"apiVersion":"example.io/v1","config":{"level":"low"},"kind":"Widget","metadata":{"name":"kindval-field"},`
)

func TestBuildFieldObject(t *testing.T) {
	cases := []struct {
		name, version, path, change, value, scope string
		group                                     string
		reason, serverPath, object                string
	}{
		{name: "nested object with required siblings", path: "spec.a.b.c", change: ChangeFieldRemoved,
			serverPath: "spec.a.b.c",
			object:     widgetHead + `"spec":{"a":{"b":{"c":"x","ref":{"id":"x"}},"mode":"fast"},"name":"xxx","replicas":2}}`},
		{name: "array of objects", path: "spec.ports.name", change: ChangeValidationTightened, value: `"http"`,
			serverPath: "spec.ports[0].name",
			object:     widgetHead + `"spec":{"name":"xxx","ports":[{"name":"http","port":1}],"replicas":2}}`},
		{name: "array of arrays", path: "spec.matrix.cell", change: ChangeValidationTightened, value: `"v"`,
			serverPath: "spec.matrix[0][0].cell",
			object:     widgetHead + `"spec":{"matrix":[[{"cell":"v"}]],"name":"xxx","replicas":2}}`},
		{name: "leaf array", path: "spec.tags", change: ChangeFieldRemoved,
			serverPath: "spec.tags",
			object:     widgetHead + `"spec":{"name":"xxx","replicas":2,"tags":[]}}`},
		{name: "leaf array with minItems", path: "spec.hosts", change: ChangeFieldRemoved,
			serverPath: "spec.hosts",
			object:     widgetHead + `"spec":{"hosts":["x","x"],"name":"xxx","replicas":2}}`},
		{name: "oneOf first branch required", path: "spec.choice.extra", change: ChangeFieldRemoved,
			serverPath: "spec.choice.extra",
			object:     widgetHead + `"spec":{"choice":{"extra":"x","left":true},"name":"xxx","replicas":2}}`},
		{name: "cluster scope", path: "spec.tags", change: ChangeFieldRemoved, scope: "Cluster",
			serverPath: "spec.tags",
			object:     widgetCluster + `"spec":{"name":"xxx","replicas":2,"tags":[]}}`},
		{name: "int-or-string leaf", path: "spec.port", change: ChangeFieldRemoved,
			serverPath: "spec.port",
			object:     widgetHead + `"spec":{"name":"xxx","port":"x","replicas":2}}`},
		{name: "type changed takes the value", path: "spec.replicas", change: ChangeTypeChanged, value: `"three"`,
			serverPath: "spec.replicas",
			object:     widgetHead + `"spec":{"name":"xxx","replicas":"three"}}`},
		{name: "required added omits the leaf", path: "spec.a.b.c", change: ChangeRequiredAdded,
			serverPath: "spec.a.b.c",
			object:     widgetHead + `"spec":{"a":{"b":{"ref":{"id":"x"}},"mode":"fast"},"name":"xxx","replicas":2}}`},
		{name: "map key for enum-value-removed", path: "spec.labels.team", change: ChangeEnumValueRemoved, value: `"a"`,
			serverPath: "spec.labels.team",
			object:     widgetHead + `"spec":{"labels":{"team":"a"},"name":"xxx","replicas":2}}`},
		{name: "status without subresource", version: "v3", path: "status.phase", change: ChangeFieldRemoved,
			serverPath: "status.phase",
			object: `{"apiVersion":"example.io/v3","config":{"level":"low"},"kind":"Widget","metadata":{"name":"kindval-field","namespace":"default"},` +
				`"spec":{"name":"xxx","replicas":2},"status":{"phase":"x"}}`},

		{name: "map key for field-removed", path: "spec.labels.team", change: ChangeFieldRemoved, reason: ReasonPathNotInFrom},
		{name: "map key for required-added", path: "spec.labels.team", change: ChangeRequiredAdded, reason: ReasonPathNotInFrom},
		{name: "path absent", path: "spec.missing", change: ChangeFieldRemoved, reason: ReasonPathNotInFrom},
		{name: "version absent", version: "v9", path: "spec.tags", change: ChangeFieldRemoved, reason: ReasonPathNotInFrom},
		{name: "enum value not in From", path: "spec.labels.team", change: ChangeEnumValueRemoved, value: `"zzz"`, reason: ReasonPathNotInFrom},
		{name: "other kind", path: "spec.tags", change: ChangeFieldRemoved, group: "other.io", reason: ReasonPathNotInFrom},
		{name: "preserve-unknown on an ancestor", path: "spec.raw.x", change: ChangeFieldRemoved, reason: ReasonSchemaPermissive},
		{name: "preserve-unknown on the leaf", path: "spec.opaque", change: ChangeFieldRemoved, reason: ReasonSchemaPermissive},
		{name: "version without schema", version: "v2", path: "spec.tags", change: ChangeFieldRemoved, reason: ReasonSchemaPermissive},
		{name: "status with subresource", path: "status.phase", change: ChangeFieldRemoved, reason: ReasonSchemaPermissive},
		{name: "leaf without type", path: "spec.untyped", change: ChangeFieldRemoved, reason: ReasonSchemaPermissive},
		{name: "value missing", path: "spec.a.mode", change: ChangeEnumValueRemoved, reason: ReasonValueMissing},
		{name: "value null", path: "spec.a.mode", change: ChangeEnumValueRemoved, value: "null", reason: ReasonValueMissing},
		{name: "required sibling without type", path: "spec.broken.v", change: ChangeFieldRemoved, reason: ReasonObjectNotBuildable},
		{name: "path too deep", path: "spec" + strings.Repeat(".a", 16), change: ChangeFieldRemoved, reason: ReasonObjectNotBuildable},
		{name: "metadata path", path: "metadata.name", change: ChangeFieldRemoved, reason: ReasonObjectNotBuildable},
	}
	crd := widgetCRD(t, widgetSchema)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := Subject{Group: "example.io", Version: "v1", Kind: "Widget", Path: c.path, Change: c.change}
			if c.version != "" {
				s.Version = c.version
			}
			if c.group != "" {
				s.Group = c.group
			}
			if c.value != "" {
				s.Value = json.RawMessage(c.value)
			}
			scope := c.scope
			if scope == "" {
				scope = "Namespaced"
			}
			obj, serverPath, reason, detail := buildFieldObject(crd, s, scope)
			if reason != c.reason {
				t.Fatalf("reason %q (%s), want %q", reason, detail, c.reason)
			}
			if c.reason != "" {
				if detail == "" || obj != nil {
					t.Fatalf("detail %q, object %v", detail, obj)
				}
				return
			}
			if serverPath != c.serverPath {
				t.Errorf("serverPath %q, want %q", serverPath, c.serverPath)
			}
			got, err := json.Marshal(obj)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.object {
				t.Errorf("object\n got %s\nwant %s", got, c.object)
			}
		})
	}
}

func TestBuildFieldObjectPermissiveRoot(t *testing.T) {
	crd := widgetCRD(t, `{"type": "object", "x-kubernetes-preserve-unknown-fields": true, "properties": {"spec": {"type": "object", "properties": {"a": {"type": "string"}}}}}`)
	s := Subject{Group: "example.io", Version: "v1", Kind: "Widget", Path: "spec.a", Change: ChangeFieldRemoved}
	if _, _, reason, _ := buildFieldObject(crd, s, "Namespaced"); reason != ReasonSchemaPermissive {
		t.Fatalf("reason %q, want %q", reason, ReasonSchemaPermissive)
	}
	if got := schemaAt(crd, "v1", "spec.a"); got != schemaPermissive {
		t.Fatalf("schemaAt %q, want %q", got, schemaPermissive)
	}
}

func TestFieldPlaceholder(t *testing.T) {
	cases := []struct{ schema, want string }{
		{`{"type": "string"}`, `"x"`},
		{`{"type": "string", "minLength": 4}`, `"xxxx"`},
		{`{"type": "string", "enum": ["b", "a"]}`, `"b"`},
		{`{"type": "integer"}`, `1`},
		{`{"type": "integer", "minimum": 0}`, `1`},
		{`{"type": "integer", "minimum": 5}`, `5`},
		{`{"type": "integer", "minimum": 5, "exclusiveMinimum": true}`, `6`},
		{`{"type": "integer", "minimum": 2.5}`, `3`},
		{`{"type": "number", "minimum": 2.5}`, `2.5`},
		{`{"type": "boolean"}`, `true`},
		{`{"type": "object", "x-kubernetes-preserve-unknown-fields": true}`, `{}`},
		{`{"type": "object", "required": ["n"], "anyOf": [{"required": ["m"]}], "properties": {"n": {"type": "integer"}, "m": {"type": "string"}}}`, `{"m":"x","n":1}`},
		{`{"type": "object", "oneOf": [{"required": ["m"], "properties": {}}], "properties": {"m": {"type": "string"}}}`, `{}`},
		{`{"type": "array", "minItems": 1, "items": {"type": "object", "required": ["k"], "properties": {"k": {"type": "boolean"}}}}`, `[{"k":true}]`},
		{`{"x-kubernetes-int-or-string": true}`, `"x"`},
	}
	for _, c := range cases {
		var schema map[string]any
		if err := json.Unmarshal([]byte(c.schema), &schema); err != nil {
			t.Fatal(err)
		}
		v, err := fieldPlaceholder(schema, 0)
		if err != nil {
			t.Errorf("%s: %v", c.schema, err)
			continue
		}
		got, _ := json.Marshal(v)
		if string(got) != c.want {
			t.Errorf("%s: got %s, want %s", c.schema, got, c.want)
		}
	}
	for _, bad := range []string{`{"description": "no type"}`, `{"type": "array", "minItems": 1}`, `{"type": "object", "required": ["z"]}`} {
		var schema map[string]any
		if err := json.Unmarshal([]byte(bad), &schema); err != nil {
			t.Fatal(err)
		}
		if _, err := fieldPlaceholder(schema, 0); err == nil {
			t.Errorf("%s: placeholder built", bad)
		}
	}
}

func TestSchemaAt(t *testing.T) {
	cases := []struct{ version, path, want string }{
		{"v1", "spec.a.b.c", schemaPresent},
		{"v1", "spec.ports.name", schemaPresent},
		{"v1", "spec.tags", schemaPresent},
		{"v1", "spec.missing", schemaAbsent},
		{"v1", "spec.labels.team", schemaPresent},
		{"v1", "spec.raw.x", schemaPermissive},
		{"v1", "spec.raw.undeclared", schemaPermissive},
		{"v1", "spec.opaque", schemaPermissive},
		{"v1", "spec.opaque.deeper", schemaPermissive},
		{"v2", "spec.tags", schemaPermissive},
		{"v9", "spec.tags", schemaAbsent},
	}
	crd := widgetCRD(t, widgetSchema)
	for _, c := range cases {
		if got := schemaAt(crd, c.version, c.path); got != c.want {
			t.Errorf("%s %s: got %q, want %q", c.version, c.path, got, c.want)
		}
	}
}
