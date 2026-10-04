// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"bytes"
	"io"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

var structuralSeeds = []string{
	"a: 1\nb: 2\nc: 3\n",
	"a:\n  x: 1\n  # tail\n# next\nb: 2\n",
	"l:\n- a\n- b\n- c\n",
	"args:\n- --a\n- --b\nnext: 1\n",
	"l:\n- k: 1\n  j: 2\n  # t\n- m: 3\n  n: 4\n",
	"a: |\n  text\n  # not\n\n  more\nb: 1\n",
	"a: 1\r\nb:\r\n  x: 1 # c\r\nc: 3\r\n",
	"m: {a: 1, b: 2}\nl: [x, y]\nz: 1\n",
	"a: first\n  second\nb: 'q'\n\"c\": \"d\"\n",
	"x: 1\n---\ny:\n  - 1\n  - 2\nz: 3\n",
	"\uFEFFa: 1\nb: 2\n",
	"top:\n  mid:\n    a: 1\n    b: 2\n  other: 3\n",
}

// plainDocuments decodes every document with the YAML library alone and
// keeps the non-empty ones, as the package's document indexes do. It is the
// independent oracle of the removal fuzzers.
func plainDocuments(src []byte) ([]any, bool) {
	decoder := yaml.NewDecoder(bytes.NewReader(src))
	var docs []any
	for {
		var doc any
		err := decoder.Decode(&doc)
		if err == io.EOF {
			return docs, true
		}
		if err != nil {
			return nil, false
		}
		if doc != nil {
			docs = append(docs, doc)
		}
	}
}

// without returns value with the entry at path removed.
func without(value any, path Path) (any, bool) {
	segment := path[0]
	switch typed := value.(type) {
	case map[string]any:
		child, ok := typed[segment.key]
		if segment.isIndex || !ok {
			return nil, false
		}
		out := map[string]any{}
		for k, v := range typed {
			out[k] = v
		}
		if len(path) == 1 {
			delete(out, segment.key)
			return out, true
		}
		replaced, ok := without(child, path[1:])
		out[segment.key] = replaced
		return out, ok
	case []any:
		if !segment.isIndex || segment.index < 0 || segment.index >= len(typed) {
			return nil, false
		}
		out := append([]any(nil), typed...)
		if len(path) == 1 {
			return append(out[:segment.index], out[segment.index+1:]...), true
		}
		replaced, ok := without(typed[segment.index], path[1:])
		out[segment.index] = replaced
		return out, ok
	}
	return nil, false
}

// entryPaths lists the key and element paths below value, bounded.
func entryPaths(value any, prefix Path, out *[]Path) {
	if len(*out) > 60 || len(prefix) > 6 {
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			path := append(prefix[:len(prefix):len(prefix)], Key(key))
			*out = append(*out, path)
			entryPaths(child, path, out)
		}
	case []any:
		for i, child := range typed {
			path := append(prefix[:len(prefix):len(prefix)], Index(i))
			*out = append(*out, path)
			entryPaths(child, path, out)
		}
	}
}

// FuzzRemovalSpan tries to remove every entry of a parsable file and checks
// each accepted span against a library-only oracle: whole lines, the result
// decodes to the original with exactly that entry gone, and the lines taken
// belong to the entry (the first one is indented like it, the others are
// deeper).
func FuzzRemovalSpan(f *testing.F) {
	for _, seed := range structuralSeeds {
		f.Add([]byte(seed))
	}
	addSeeds(f)
	f.Fuzz(func(t *testing.T, src []byte) {
		file, r := parseFile(src)
		if r != nil {
			return
		}
		before, ok := plainDocuments(src)
		if !ok || len(before) != len(file.docs) {
			return
		}
		for document := range file.docs {
			var paths []Path
			entryPaths(before[document], nil, &paths)
			for _, path := range paths {
				element := path[len(path)-1].isIndex
				span, r := file.removalSpan(document, path, element)
				if r != nil {
					if !knownReasons[r.Reason] || len(r.Detail) > maxDetail {
						t.Fatalf("refusal outside the vocabulary: %v", r)
					}
					continue
				}
				if span.Start < 0 || span.Start >= span.End || span.End > len(src) || !file.lineAligned(span.Start) || !file.lineAligned(span.End) {
					t.Fatalf("span %+v is not whole lines of %q", span, src)
				}
				after := splice(src, []Edit{{StartByte: span.Start, EndByte: span.End}})
				got, ok := plainDocuments(after)
				if !ok {
					t.Fatalf("removing %+v from %q gives undecodable %q", path, src, after)
				}
				want := append([]any(nil), before...)
				replaced, found := without(want[document], path)
				if !found {
					t.Fatalf("oracle cannot remove %+v", path)
				}
				want[document] = replaced
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("removing %+v from %q gives %q: %v, want %v", path, src, after, got, want)
				}
				// The lines taken belong to the entry.
				lines := bytes.Split(bytes.TrimSuffix(src[span.Start:span.End], []byte("\n")), []byte("\n"))
				indent := func(line []byte) int {
					line = bytes.TrimSuffix(line, []byte("\r"))
					return len(line) - len(bytes.TrimLeft(line, " "))
				}
				base := indent(lines[0])
				for i, line := range lines {
					trimmed := bytes.TrimSpace(line)
					if i == 0 && len(trimmed) == 0 {
						t.Fatalf("empty first line in %q", src[span.Start:span.End])
					}
					if i > 0 && len(trimmed) > 0 && indent(line) <= base && !(trimmed[0] == '-' && indent(line) == base) {
						t.Fatalf("line %q is not part of the entry %+v in %q", line, path, src)
					}
				}
				if last := bytes.TrimSpace(lines[len(lines)-1]); len(last) == 0 {
					t.Fatalf("trailing blank line taken from %q", src)
				}
			}
		}
	})
}

// fuzzKind plans one request on fuzzed bytes: only bounded refusals, plans
// that apply, a stable second plan, and a source that is left alone outside
// the edits.
func fuzzKind(t *testing.T, src []byte, request Request) {
	plan, err := Plan(display, src, []Request{request}, Options{})
	if err != nil {
		r, ok := err.(*Refusal)
		if !ok || !knownReasons[r.Reason] || len(r.Detail) > maxDetail {
			t.Fatalf("not a bounded refusal: %v", err)
		}
		return
	}
	after, err := ApplyInMemory(src, plan, Options{})
	if err != nil {
		t.Fatalf("a plan does not apply: %v", err)
	}
	var rebuilt []byte
	cursor := 0
	for _, e := range plan.Edits {
		rebuilt = append(rebuilt, src[cursor:e.StartByte]...)
		rebuilt = append(rebuilt, e.Replacement...)
		cursor = e.EndByte
	}
	rebuilt = append(rebuilt, src[cursor:]...)
	if !bytes.Equal(rebuilt, after) {
		t.Fatal("bytes outside the edits changed")
	}
	again, err := Plan(display, after, []Request{request}, Options{})
	if err != nil || len(again.Edits) != 0 {
		t.Fatalf("not idempotent: %v %+v", err, again.Edits)
	}
}

func fuzzKindSeeds(f *testing.F) {
	for _, seed := range structuralSeeds {
		f.Add([]byte(seed))
	}
	addSeeds(f)
}

var removeKeyFuzzParams = []string{
	`{"path":["a"]}`, `{"path":["b"]}`, `{"path":["a","x"]}`, `{"path":["top","mid","b"]}`, `{"path":["l",1,"j"]}`,
	`{"path":["m","a"]}`, `{"path":["args"]}`, `{"path":["c"]}`, `{"path":["y"]}`,
}

func FuzzRemoveKey(f *testing.F) {
	fuzzKindSeeds(f)
	f.Fuzz(func(t *testing.T, src []byte) {
		for _, params := range removeKeyFuzzParams {
			fuzzKind(t, src, Request{Kind: "remove_key", Params: Params(params)})
		}
		fuzzKind(t, src, Request{Kind: "remove_feature_gate", Params: Params(`{"component":"pkg:oci/cert-manager/cert-manager","gate":"A"}`)})
	})
}

func FuzzRemoveElement(f *testing.F) {
	fuzzKindSeeds(f)
	gate := "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - image: quay.io/jetstack/cert-manager-controller:v1\n        args:\n        - --v=2\n        - --feature-gates=ServerSideApply=true\n"
	f.Add([]byte(gate))
	f.Add([]byte(gate + "        - --feature-gates\n        - A=true\n"))
	f.Add([]byte("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - image: quay.io/jetstack/cert-manager-controller:v1\n        args: [--v=2, --feature-gates=A=true]\n"))
	f.Fuzz(func(t *testing.T, src []byte) {
		for _, gate := range []string{"A", "ServerSideApply"} {
			fuzzKind(t, src, Request{Kind: "remove_feature_gate", Params: Params(`{"component":"pkg:oci/cert-manager/cert-manager","gate":"` + gate + `"}`)})
		}
	})
}

var renameKeyFuzzParams = []string{
	`{"path":["a"],"newKey":"alpha"}`, `{"path":["b"],"newKey":"B"}`, `{"path":["a"],"newKey":"on"}`, `{"path":["l",0,"k"],"newKey":"kk"}`,
	`{"path":["top","mid","a"],"newKey":"z z"}`, `{"path":["m","a"],"newKey":"b"}`, `{"path":["\"c\""],"newKey":"it's"}`, `{"path":["c"],"newKey":"d"}`,
}

func FuzzRenameKey(f *testing.F) {
	fuzzKindSeeds(f)
	f.Fuzz(func(t *testing.T, src []byte) {
		for _, params := range renameKeyFuzzParams {
			fuzzKind(t, src, Request{Kind: "rename_key", Params: Params(params)})
		}
	})
}

var setValueFuzzParams = []string{
	`{"path":["a"],"value":"s"}`, `{"path":["b"],"value":5}`, `{"path":["a"],"value":true}`, `{"path":["b"],"value":null}`,
	`{"path":["l",0,"k"],"value":"it's"}`, `{"path":["top","mid","a"],"value":-1.5}`, `{"path":["m","a"],"value":"on"}`, `{"path":["c"],"value":"q\"b"}`,
}

func FuzzSetValue(f *testing.F) {
	fuzzKindSeeds(f)
	f.Fuzz(func(t *testing.T, src []byte) {
		for _, params := range setValueFuzzParams {
			fuzzKind(t, src, Request{Kind: "set_value", Params: Params(params)})
		}
	})
}

// FuzzStructuralKindValidate feeds arbitrary parameters to the structural
// kinds.
func FuzzStructuralKindValidate(f *testing.F) {
	for _, seed := range append(append(append([]string{}, removeKeyFuzzParams...), renameKeyFuzzParams...), setValueFuzzParams...) {
		f.Add([]byte(seed))
	}
	f.Add([]byte(`{"apiVersion":"v1","kind":"ConfigMap","path":["data","a"],"value":1}`))
	src := []byte("apiVersion: v1\nkind: ConfigMap\ndata:\n  a: 1\n  b: 2\n")
	f.Fuzz(func(t *testing.T, params []byte) {
		for _, id := range []string{"rename_key", "remove_key", "set_value"} {
			plan, err := Plan(display, src, []Request{{Kind: id, Params: params}}, Options{})
			if err != nil {
				r, ok := err.(*Refusal)
				if !ok || !knownReasons[r.Reason] || len(r.Detail) > maxDetail {
					t.Fatalf("not a bounded refusal: %v", err)
				}
				continue
			}
			if after, err := ApplyInMemory(src, plan, Options{}); err != nil || len(after) == 0 {
				t.Fatalf("a plan does not apply: %v", err)
			}
		}
	})
}
