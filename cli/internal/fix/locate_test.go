// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"strings"
	"testing"
)

func path(segments ...any) Path {
	var out Path
	for _, segment := range segments {
		switch s := segment.(type) {
		case string:
			out = append(out, Key(s))
		case int:
			out = append(out, Index(s))
		}
	}
	return out
}

const deployment = `# leading comment
apiVersion: apps/v1   # trailing comment
kind: Deployment
metadata:
  name: web
  labels: {app: web, "tier": 'front'}
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: app
          image: "registry.example/app:1.2"
          args: [--port=8080, '--mode=fast']
        - name: 'side car'
          image: side
`

func TestLocateSpans(t *testing.T) {
	cases := []struct {
		name string
		src  string
		doc  int
		path Path
		part Part
		want string
		// at, when set, is the byte offset the span must start at.
		at int
	}{
		{name: "plain value", src: deployment, path: path("apiVersion"), want: "apps/v1"},
		{name: "plain key", src: deployment, path: path("apiVersion"), part: PartKey, want: "apiVersion"},
		{name: "plain value before comment", src: deployment, path: path("kind"), want: "Deployment"},
		{name: "nested plain value", src: deployment, path: path("metadata", "name"), want: "web"},
		{name: "nested key", src: deployment, path: path("metadata", "name"), part: PartKey, want: "name"},
		{name: "number", src: deployment, path: path("spec", "replicas"), want: "3"},
		{name: "flow map plain value", src: deployment, path: path("metadata", "labels", "app"), want: "web"},
		{name: "flow map quoted key", src: deployment, path: path("metadata", "labels", "tier"), part: PartKey, want: `"tier"`},
		{name: "flow map single quoted value", src: deployment, path: path("metadata", "labels", "tier"), want: `'front'`},
		{name: "sequence item key", src: deployment, path: path("spec", "template", "spec", "containers", 0, "name"), part: PartKey, want: "name"},
		{name: "double quoted value", src: deployment, path: path("spec", "template", "spec", "containers", 0, "image"), want: `"registry.example/app:1.2"`},
		{name: "flow sequence plain", src: deployment, path: path("spec", "template", "spec", "containers", 0, "args", 0), want: "--port=8080"},
		{name: "flow sequence quoted", src: deployment, path: path("spec", "template", "spec", "containers", 0, "args", 1), want: `'--mode=fast'`},
		{name: "single quoted with space", src: deployment, path: path("spec", "template", "spec", "containers", 1, "name"), want: `'side car'`},
		{name: "second item plain", src: deployment, path: path("spec", "template", "spec", "containers", 1, "image"), want: "side"},
		{name: "block sequence scalar", src: "items:\n- a\n- bb\n", path: path("items", 1), want: "bb"},
		{name: "second document", src: "a: 1\n---\nb: two\n", doc: 1, path: path("b"), want: "two", at: 12},
		{name: "third document after empty", src: "a: 1\n---\n---\nc: x\n---\nd: y\n", doc: 2, path: path("d"), want: "y"},
		{name: "null document skipped", src: "---\n~\n---\nk: v\n", doc: 0, path: path("k"), want: "v"},
		{name: "document end marker", src: "a: 1\n...\n---\nb: 2\n", doc: 1, path: path("b"), want: "2"},
		{name: "crlf value", src: "a: 1\r\nb: two\r\nc: 3\r\n", path: path("b"), want: "two", at: 9},
		{name: "crlf key", src: "a: 1\r\nb: two\r\n", path: path("b"), part: PartKey, want: "b"},
		{name: "crlf second document", src: "a: 1\r\n---\r\nb: \"x\"\r\n", doc: 1, path: path("b"), want: `"x"`},
		{name: "tab before comment", src: "a: x\t# c\nb: y\n", path: path("a"), want: "x"},
		{name: "tab in flow", src: "a: [\tx,\ty]\n", path: path("a", 1), want: "y"},
		{name: "tab inside quoted", src: "a: \"x\ty\"\n", path: path("a"), want: "\"x\ty\""},
		{name: "utf8 before target on line", src: "\"ключ\": значение\nb: c\n", path: path("ключ"), want: "значение", at: 12},
		{name: "utf8 key quoted", src: "\"ключ\": значение\n", path: path("ключ"), part: PartKey, want: "\"ключ\""},
		{name: "emoji in flow before target", src: "a: {\"😀\": x, y: z}\n", path: path("a", "y"), want: "z"},
		{name: "utf8 lines before", src: "# résumé ünïcödé\nmetadata:\n  name: ök\n  ns: dev\n", path: path("metadata", "ns"), want: "dev"},
		{name: "cjk value then next", src: "a: 漢字\nb: 漢字2\n", path: path("b"), want: "漢字2"},
		{name: "leading byte order mark", src: "\uFEFFa: x\nb: y\n", path: path("a"), want: "x", at: 6},
		{name: "byte order mark key", src: "\uFEFFa: x\n", path: path("a"), part: PartKey, want: "a", at: 3},
		{name: "escaped quote", src: `a: "x\"y" # c` + "\n", path: path("a"), want: `"x\"y"`},
		{name: "escaped backslash end", src: `a: "x\\"` + "\n", path: path("a"), want: `"x\\"`},
		{name: "doubled single quote", src: "a: 'it''s'\n", path: path("a"), want: "'it''s'"},
		{name: "empty double quoted", src: "a: \"\"\n", path: path("a"), want: `""`},
		{name: "plain with colon inside", src: "a: http://x:80/y\n", path: path("a"), want: "http://x:80/y"},
		{name: "plain with hash inside", src: "a: x#y\n", path: path("a"), want: "x#y"},
		{name: "boolean", src: "a: true\n", path: path("a"), want: "true"},
		{name: "json document", src: `{"apiVersion": "v1", "kind": "ConfigMap"}`, path: path("kind"), want: `"ConfigMap"`},
		{name: "json key", src: `{"apiVersion":"v1"}`, path: path("apiVersion"), part: PartKey, want: `"apiVersion"`},
		{name: "root scalar document", src: "--- hello\n", path: path(), want: "hello"},
		{name: "deep indent with tabs in comment", src: "a:\n  b:\n    c: d #\tnote\n", path: path("a", "b", "c"), want: "d"},
		{name: "no trailing newline", src: "a: b", path: path("a"), want: "b"},
		{name: "explicit document start with comment", src: "--- # head\na: b\n", path: path("a"), want: "b"},
		{name: "sequence of maps compact", src: "- a: 1\n  b: 2\n- a: 3\n", path: path(1, "a"), want: "3"},
		{name: "trailing spaces after plain", src: "a: b   \nc: d\n", path: path("a"), want: "b"},
	}
	if len(cases) < 30 {
		t.Fatalf("table has %d rows, want at least 30", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := []byte(tc.src)
			span, err := Locate(src, tc.doc, tc.path, tc.part)
			if err != nil {
				t.Fatalf("Locate: %v", err)
			}
			if got := string(src[span.Start:span.End]); got != tc.want {
				t.Fatalf("span %d..%d = %q, want %q", span.Start, span.End, got, tc.want)
			}
			if tc.at != 0 && span.Start != tc.at {
				t.Fatalf("span starts at %d, want %d", span.Start, tc.at)
			}
			if n := strings.Count(tc.src, tc.want); n == 1 && strings.Index(tc.src, tc.want) != span.Start {
				t.Fatalf("span starts at %d, want %d", span.Start, strings.Index(tc.src, tc.want))
			}
			assertSentinel(t, src, tc.doc, tc.path, tc.part, span)
		})
	}
}

// assertSentinel proves a span by replacing it with a fresh token: the file
// must decode to the original values with only the target changed.
func assertSentinel(t testing.TB, src []byte, doc int, p Path, part Part, span Span) {
	t.Helper()
	assertSpanShape(t, src, span)
	file, r := parseFile(src)
	if r != nil {
		t.Fatalf("parse: %v", r)
	}
	sentinel := "zqsentinel"
	for strings.Contains(strings.ToLower(string(src)), sentinel) {
		sentinel += "q"
	}
	expected := make([]any, len(file.docs))
	for i, d := range file.docs {
		expected[i] = copyValue(d.value)
	}
	if !substitute(&expected[doc], p, part, sentinel) {
		t.Fatalf("substitute failed")
	}
	token := sentinel
	if src[span.Start] == '"' || src[span.Start] == '\'' {
		// A quoted token may sit where a plain one would read differently,
		// as in {"a":1}; keep the quoting.
		token = `"` + sentinel + `"`
	}
	edited := splice(src, []Edit{{StartByte: span.Start, EndByte: span.End, Replacement: token}})
	after, r := parseFile(edited)
	if r != nil {
		t.Fatalf("edited file does not parse: %v\n%s", r, edited)
	}
	if len(after.docs) != len(expected) {
		t.Fatalf("document count changed")
	}
	for i := range expected {
		if !deepEqual(after.docs[i].value, expected[i]) {
			t.Fatalf("document %d differs after sentinel substitution:\n%s", i, edited)
		}
	}
}

func TestLocateRefusals(t *testing.T) {
	cases := []struct {
		name string
		src  string
		doc  int
		path Path
		part Part
		want Reason
	}{
		{name: "literal block scalar", src: "a: |\n  x\n", path: path("a"), want: ReasonBlockScalar},
		{name: "folded block scalar", src: "a: >-\n  x\n  y\n", path: path("a"), want: ReasonBlockScalar},
		{name: "anchor", src: "a: &x b\nc: d\n", path: path("c"), want: ReasonUnsupportedYAML},
		{name: "alias", src: "a: &x b\nc: *x\n", path: path("a"), want: ReasonUnsupportedYAML},
		{name: "merge key", src: "a: {x: 1}\nb:\n  <<: {y: 2}\n", path: path("a"), want: ReasonUnsupportedYAML},
		{name: "duplicate key", src: "a: 1\na: 2\n", path: path("a"), want: ReasonUnsupportedYAML},
		{name: "duplicate key differing in case", src: "a: 1\nA: 2\n", path: path("a"), want: ReasonUnsupportedYAML},
		{name: "custom tag", src: "a: !thing b\n", path: path("a"), want: ReasonUnsupportedYAML},
		{name: "non-string key", src: "1: a\n", path: path("1"), want: ReasonUnsupportedYAML},
		{name: "templated value", src: "a: \"{{ .Values.x }}\"\n", path: path("a"), want: ReasonTemplated},
		{name: "templated comment", src: "# ${X}\na: b\n", path: path("a"), want: ReasonTemplated},
		{name: "raw template", src: "{{- if .x }}\na: b\n{{- end }}\n", path: path("a"), want: ReasonTemplated},
		{name: "multi-line plain scalar", src: "a: one\n  two\nb: c\n", path: path("a"), want: ReasonMultiLineScalar},
		{name: "multi-line plain scalar blank line", src: "a: one\n\n  two\n", path: path("a"), want: ReasonMultiLineScalar},
		{name: "multi-line double quoted", src: "a: \"one\n  two\"\n", path: path("a"), want: ReasonMultiLineScalar},
		{name: "multi-line single quoted", src: "a: 'one\n  two'\n", path: path("a"), want: ReasonMultiLineScalar},
		{name: "escaped line break", src: "a: \"one\\\n  two\"\n", path: path("a"), want: ReasonMultiLineScalar},
		{name: "secret document", src: "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n", path: path("metadata", "name"), want: ReasonSecretDocument},
		{name: "secret list item", src: "apiVersion: v1\nkind: List\nitems:\n- apiVersion: v1\n  kind: Secret\n", path: path("kind"), want: ReasonSecretDocument},
		{name: "secret list kind", src: "apiVersion: v1\nkind: SecretList\nitems: []\n", path: path("kind"), want: ReasonSecretDocument},
		{name: "explicit str tag", src: "a: !!str b\n", path: path("a"), want: ReasonSpanNotIsolated},
		{name: "implicit null", src: "a:\nb: c\n", path: path("a"), want: ReasonSpanNotIsolated},
		{name: "collection target", src: "a:\n  b: c\n", path: path("a"), want: ReasonSpanNotIsolated},
		{name: "explicit key", src: "? a\n: b\n", path: path("a"), part: PartKey, want: ReasonSpanNotIsolated},
		{name: "missing path", src: "a: b\n", path: path("x"), want: ReasonPathNotFound},
		{name: "index into map", src: "a: b\n", path: path(0), want: ReasonPathNotFound},
		{name: "missing document", src: "a: b\n", doc: 1, path: path("a"), want: ReasonPathNotFound},
		{name: "key part on index", src: "- a\n", path: path(0), part: PartKey, want: ReasonPathNotFound},
		{name: "inner byte order mark", src: "a: b\n\uFEFFc: d\n", path: path("a"), want: ReasonUnsupportedEncoding},
		{name: "bare carriage return", src: "a: b\rc: d\n", path: path("a"), want: ReasonUnsupportedEncoding},
		{name: "next line character", src: "a: b\u0085\n", path: path("a"), want: ReasonUnsupportedEncoding},
		{name: "line separator", src: "a: \"b\u2028\"\n", path: path("a"), want: ReasonUnsupportedEncoding},
		{name: "invalid utf8", src: "a: \xff\n", path: path("a"), want: ReasonUnsupportedEncoding},
		{name: "empty file", src: "", path: path("a"), want: ReasonUnsupportedYAML},
		{name: "too many segments", src: "a: b\n", path: make(Path, MaxPathSegments+1), want: ReasonLimit},
		{name: "unparseable", src: "a: [b\n", path: path("a"), want: ReasonUnsupportedYAML},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Locate([]byte(tc.src), tc.doc, tc.path, tc.part)
			if got := ReasonOf(err); got != tc.want {
				t.Fatalf("reason %q (%v), want %q", got, err, tc.want)
			}
		})
	}
}
