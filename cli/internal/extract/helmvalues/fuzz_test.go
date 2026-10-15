// SPDX-License-Identifier: AGPL-3.0-only

package helmvalues

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/helmvaluespath"
)

// The decoders and the analyses never panic, and a decoded document's key
// paths read back through valueAt.
func FuzzValues(f *testing.F) {
	for _, s := range []string{"a: {b: 1}\n", "a: [1, {b: null}]\n", "a: &x 1\n", "\"on\": 1\n", ""} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, v, err := helmvaluespath.DecodeYAML(data)
		if err != nil {
			return
		}
		for _, p := range helmvaluespath.ValuePaths(v) {
			if got, ok := helmvaluespath.ValueAt(v, p); !ok || got == nil {
				t.Fatalf("path %v does not read back", p)
			}
			if m, ok := helmvaluespath.Member(p); ok && !constraintengine.ValidSetMember(m) {
				t.Fatalf("member %q outside the engine grammar", m)
			}
		}
	})
}

func FuzzSchema(f *testing.F) {
	for _, s := range []string{
		`{"properties":{"a":{"type":"object","required":["b"],"additionalProperties":false}}}`,
		`{"required":["a"],"allOf":[{}]}`, `{"properties":{"a":true,"b":false}}`, `{}`,
	} {
		f.Add([]byte(s), "a.b")
	}
	f.Fuzz(func(t *testing.T, raw []byte, path string) {
		s, err := decodeSchema(raw)
		if err != nil {
			return
		}
		w := walkSchema(s)
		for _, p := range w.Required {
			if len(p) == 0 {
				t.Fatal("empty required path")
			}
		}
		_ = schemaPaths(s)
		var keys []string
		for _, k := range []byte(path) {
			if k == '.' {
				continue
			}
			keys = append(keys, string(k))
		}
		if prefix, ok, _ := rejection(s, keys); ok && (len(prefix) == 0 || len(prefix) > len(keys)) {
			t.Fatalf("prefix %v of %v", prefix, keys)
		}
	})
}

func FuzzTemplates(f *testing.F) {
	for _, s := range []string{"{{ .Values.a.b }}", "{{ with .Values.x }}{{ .y }}{{ end }}", "{{ if", "{{ define \"x\" }}{{ $.Values.z }}{{ end }}"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var r TemplateRefs
		r.scanTemplate("t", data)
		r.finish()
		if r.Files != 1 {
			t.Fatal("file count")
		}
	})
}

func FuzzKubeVersion(f *testing.F) {
	for _, s := range []string{">=1.25.0-0", ">= 1.2", "<2", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, c string) {
		k := parseKubeVersion(c)
		if k.Shape == "minimum" {
			if _, ok := normalVersion(k.Minimum); !ok {
				t.Fatalf("minimum %q", k.Minimum)
			}
		}
	})
}
