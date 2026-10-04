// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"strings"
	"testing"
)

func rkParams(path string) Params { return Params(`{"path":` + path + `}`) }

// ---- remove_key ----

func TestRemoveKey(t *testing.T) {
	cases := []kindCase{
		{name: "last key of a mapping", params: rkParams(`["c"]`),
			src: "a: 1\nb: 2\nc: 3\n", want: "a: 1\nb: 2\n", edits: 1},
		{name: "middle key", params: rkParams(`["b"]`),
			src: "a: 1\nb: 2\nc: 3\n", want: "a: 1\nc: 3\n", edits: 1},
		{name: "first key", params: rkParams(`["a"]`),
			src: "a: 1\nb: 2\nc: 3\n", want: "b: 2\nc: 3\n", edits: 1},
		{name: "key with a block value", params: rkParams(`["b"]`),
			src:  "a: 1\nb:\n  x:\n    deep: 1\n  y:\n  - one\n  - two: 2\n    three: 3\nc: 3\n",
			want: "a: 1\nc: 3\n", edits: 1},
		{name: "key with a trailing comment", params: rkParams(`["b"]`),
			src: "a: 1\nb: 2 # about b\nc: 3\n", want: "a: 1\nc: 3\n", edits: 1},
		{name: "comment of the next key stays", params: rkParams(`["a"]`),
			src: "a: 1\n# about b\nb: 2\n", want: "# about b\nb: 2\n", edits: 1},
		{name: "comment of the next key stays below a block value", params: rkParams(`["a"]`),
			src: "a:\n  x: 1\n# about b\nb: 2\n", want: "# about b\nb: 2\n", edits: 1},
		{name: "deeper comment after the value goes with the entry", params: rkParams(`["a"]`),
			src: "a:\n  x: 1\n  # end of a\n# about b\nb: 2\n", want: "# about b\nb: 2\n", edits: 1},
		{name: "comment above the key stays", params: rkParams(`["b"]`),
			src: "a: 1\n# about b\nb: 2\nc: 3\n", want: "a: 1\n# about b\nc: 3\n", edits: 1},
		{name: "blank lines stay", params: rkParams(`["b"]`),
			src: "a: 1\n\nb:\n  x: 1\n\nc: 3\n", want: "a: 1\n\n\nc: 3\n", edits: 1},
		{name: "crlf", params: rkParams(`["b"]`),
			src: "a: 1\r\nb:\r\n  x: 1 # c\r\n  # tail\r\nc: 3\r\n", want: "a: 1\r\nc: 3\r\n", edits: 1},
		{name: "last line without a final newline", params: rkParams(`["b"]`),
			src: "a: 1\nb: 2", want: "a: 1\n", edits: 1},
		{name: "quoted key", params: rkParams(`["a b"]`),
			src: "\"a b\": 1\n'c': 2\n", want: "'c': 2\n", edits: 1},
		{name: "nested path", params: rkParams(`["top","mid","b"]`),
			src: "top:\n  mid:\n    a: 1\n    b: 2\n  other: 3\n", want: "top:\n  mid:\n    a: 1\n  other: 3\n", edits: 1},
		{name: "key inside a sequence item", params: rkParams(`["items",1,"w"]`),
			src:  "items:\n- name: x\n  w: 0\n- name: y\n  v: 1\n  w: 2\n  # tail\n- name: z\n",
			want: "items:\n- name: x\n  w: 0\n- name: y\n  v: 1\n  # tail\n- name: z\n", edits: 1},
		{name: "block sequence at the key's indentation", params: rkParams(`["args"]`),
			src:  "args:\n- --a\n- --b\nnext: 1\n",
			want: "next: 1\n", edits: 1},
		{name: "block sequence at the key's indentation in a mapping", params: rkParams(`["spec","args"]`),
			src:  "spec:\n  args:\n  - --a\n  - --b\n  other: 1\n",
			want: "spec:\n  other: 1\n", edits: 1},
		{name: "block scalar value with hash lines", params: rkParams(`["a"]`),
			src: "a: |\n  text\n  # not a comment\n\n  more\nb: 1\n", want: "b: 1\n", edits: 1},
		{name: "single-line flow value", params: rkParams(`["a"]`),
			src: "a: {x: 1, y: [2, 3]}\nb: 1\n", want: "b: 1\n", edits: 1},
		{name: "key with an empty value", params: rkParams(`["a"]`),
			src: "a:\nb: 1\n", want: "b: 1\n", edits: 1},
		{name: "the end of a document", params: rkParams(`["b"]`),
			src: "a: 1\nb: 2\n---\nc: 3\nd: 4\n", want: "a: 1\n---\nc: 3\nd: 4\n", edits: 1},
		{name: "ends before a document marker", params: rkParams(`["a"]`),
			src: "z: 0\na:\n  x: 1\n--- # next\nb: 1\n", want: "z: 0\n--- # next\nb: 1\n", edits: 1},
		{name: "missing key", params: rkParams(`["z"]`), src: "a: 1\nb: 2\n"},
		{name: "missing parent", params: rkParams(`["z","y"]`), src: "a: 1\nb: 2\n"},
		{name: "index out of range", params: rkParams(`["l",5,"y"]`), src: "l:\n- {y: 1, z: 2}\n"},
		{name: "selected by apiVersion and kind", params: Params(`{"apiVersion":"v1","kind":"ConfigMap","path":["data","b"]}`),
			src:  "apiVersion: v1\nkind: ConfigMap\ndata:\n  a: 1\n  b: 2\n---\nkind: Pod\ndata:\n  a: 1\n  b: 2\n",
			want: "apiVersion: v1\nkind: ConfigMap\ndata:\n  a: 1\n---\nkind: Pod\ndata:\n  a: 1\n  b: 2\n", edits: 1},
		{name: "values file is not selected by a kind", params: Params(`{"apiVersion":"v1","kind":"ConfigMap","path":["b"]}`),
			src: "a: 1\nb: 2\n"},
		{name: "kind is not selected by a values file selector", params: rkParams(`["data","b"]`),
			src: "apiVersion: v1\nkind: ConfigMap\ndata:\n  a: 1\n  b: 2\n"},
	}
	runPositive(t, "remove_key", cases)
}

func TestRemoveKeyRefusals(t *testing.T) {
	type refusal struct {
		src    string
		path   string
		reason Reason
	}
	cases := map[string]refusal{
		"parent would become empty":                                   {"a: 1\n", `["a"]`, ReasonInvalidEdit},
		"nested parent would become empty":                            {"top:\n  only: 1\nother: 2\n", `["top","only"]`, ReasonInvalidEdit},
		"sequence item would become empty":                            {"l:\n- k: 1\n- z\n", `["l",0,"k"]`, ReasonInvalidEdit},
		"tab in the indentation of a comment":                         {"a:\n  x: 1\n\t# tab\nb: 1\n", `["a"]`, ReasonUnsupportedYAML},
		"tab in the indentation of a comment below a nested key":      {"t:\n  a: 1\n\t# tab\n  b: 1\n", `["t","a"]`, ReasonUnsupportedYAML},
		"tab in the indentation of block scalar text":                 {"a: |\n  \ttext\nb: 1\n", `["a"]`, ReasonUnsupportedYAML},
		"tab in the indentation of block scalar text in a nested key": {"t:\n  a: |\n    \ttext\n  b: 1\n", `["t","a"]`, ReasonUnsupportedYAML},
		"flow mapping parent":                                         {"{a: 1, b: 2}\n", `["a"]`, ReasonSpanNotIsolated},
		"flow mapping parent on several lines":                        {"top: {a: 1,\n  b: 2}\n", `["top","a"]`, ReasonSpanNotIsolated},
		"flow sequence parent":                                        {"l: [{a: 1, b: 2}, 3]\n", `["l",0,"a"]`, ReasonSpanNotIsolated},
		"json document":                                               {"{\"a\": 1, \"b\": 2}", `["a"]`, ReasonSpanNotIsolated},
		"first key of a sequence item":                                {"l:\n- a: 1\n  b: 2\n", `["l",0,"a"]`, ReasonSpanNotIsolated},
		"anchor on the entry":                                         {"a: &x 1\nb: 2\n", `["a"]`, ReasonUnsupportedYAML},
		"alias in the file":                                           {"a: &x 1\nb: *x\nc: 2\n", `["c"]`, ReasonUnsupportedYAML},
		"merge key in the file":                                       {"a: &x {k: 1}\nb:\n  <<: *x\nc: 1\n", `["c"]`, ReasonUnsupportedYAML},
		"explicit key":                                                {"? a\n: 1\nb: 2\n", `["a"]`, ReasonSpanNotIsolated},
		"key on the line of a document marker":                        {"--- a: 1\n", `["a"]`, ReasonUnsupportedYAML},
		"templated":                                                   {"a: 1\nb: {{ .x }}\n", `["a"]`, ReasonTemplated},
		"secret file":                                                 {"kind: Secret\nstringData: {a: 1}\n---\nx: 1\ny: 2\n", `["x"]`, ReasonSecretDocument},
		"multi-line plain value":                                      {"a: first\n  second\nb: 1\n", `["a"]`, ReasonMultiLineScalar},
		"multi-line quoted value":                                     {"a: \"first\n  second\"\nb: 1\n", `["a"]`, ReasonMultiLineScalar},
		"quoted value continuing at column zero":                      {"A: \nB: '00\n'", `["B"]`, ReasonMultiLineScalar},
		"quoted value with comment-like text":                         {"A: 1\nB: \"x\n# y\"\n", `["B"]`, ReasonMultiLineScalar},
		"multi-line scalar deep in the value":                         {"b:\n  c: 'x\n    y'\nd: 1\n", `["b"]`, ReasonMultiLineScalar},
		"multi-line flow closing at column zero":                      {"a: [1,\n2\n]\nb: 1\n", `["a"]`, ReasonSpanNotIsolated},
		"value is a multi-line flow collection":                       {"a: [1,\n2]\nb: 1\n", `["a"]`, ReasonSpanNotIsolated},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := planKind(t, tc.src, "remove_key", rkParams(tc.path))
			if ReasonOf(err) != tc.reason {
				t.Fatalf("got %v, want %s", err, tc.reason)
			}
		})
	}
	t.Run("a List holding a matching document", func(t *testing.T) {
		_, _, err := planKind(t, "apiVersion: v1\nkind: List\nitems:\n- apiVersion: v1\n  kind: ConfigMap\n  data: {a: 1}\n",
			"remove_key", Params(`{"apiVersion":"v1","kind":"ConfigMap","path":["data","a"]}`))
		wantReason(t, err, ReasonKindRefused)
	})
	runInvalidParams(t, "remove_key", []string{
		``, `{}`, `{"path":[]}`, `{"path":"a"}`, `{"path":[1]}`, `{"path":["a",-1]}`, `{"path":["a",1.5]}`, `{"path":["a",true]}`,
		`{"path":["a",null]}`, `{"path":[""]}`, `{"path":["<<"]}`, `{"path":["a\nb"]}`, `{"path":["{{x}}"]}`,
		`{"path":["a","b","c","d","e","f","g","h","i","j","k","l","m"]}`, `{"path":[1,2]}`,
		`{"path":["a"],"extra":1}`, `{"kind":"ConfigMap","path":["a"]}`, `{"apiVersion":"v1","path":["a"]}`,
		`{"apiVersion":"v1","kind":"Secret","path":["a"]}`, `{"apiVersion":"v1","kind":"List","path":["a"]}`,
		`{"apiVersion":"V1","kind":"ConfigMap","path":["a"]}`, `{"path":["a"],"path":["b"]}`,
	})
}

// The removal span against hand-written whole-line expectations, at the
// locator level.
func TestRemovalSpans(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		path    Path
		element bool
		want    string // the removed text
	}{
		{"key", "a: 1\nb: 2\n", Path{Key("a")}, false, "a: 1\n"},
		{"key with comment", "a: 1 # c\nb: 2\n", Path{Key("a")}, false, "a: 1 # c\n"},
		{"block", "a:\n  x: 1\nb: 2\n", Path{Key("a")}, false, "a:\n  x: 1\n"},
		{"deeper tail comment", "a:\n  x: 1\n    # t\nb: 2\n", Path{Key("a")}, false, "a:\n  x: 1\n    # t\n"},
		{"same indent comment is the next entry's", "a:\n  x: 1\n# n\nb: 2\n", Path{Key("a")}, false, "a:\n  x: 1\n"},
		{"blank lines inside the block are removed with it", "a:\n  x: 1\n\n  y: 2\nb: 2\n", Path{Key("a")}, false, "a:\n  x: 1\n\n  y: 2\n"},
		{"trailing blank lines stay", "a:\n  x: 1\n\n\nb: 2\n", Path{Key("a")}, false, "a:\n  x: 1\n"},
		{"element", "l:\n- a\n- b\n- c\n", Path{Key("l"), Index(1)}, true, "- b\n"},
		{"element with a mapping", "l:\n- k: 1\n  j: 2\n- c\n", Path{Key("l"), Index(0)}, true, "- k: 1\n  j: 2\n"},
		{"indented element", "s:\n  l:\n    - a # x\n    - b\n", Path{Key("s"), Key("l"), Index(0)}, true, "    - a # x\n"},
		{"element with a nested sequence", "l:\n- - 1\n  - 2\n- c\n", Path{Key("l"), Index(0)}, true, "- - 1\n  - 2\n"},
		{"last element at the end of the file", "l:\n- a\n- b", Path{Key("l"), Index(1)}, true, "- b"},
		{"element with a deeper tail comment", "l:\n- a\n  # tail\n- b\n", Path{Key("l"), Index(0)}, true, "- a\n  # tail\n"},
		{"wide dash spacing", "l:\n-   a\n-   b\n", Path{Key("l"), Index(0)}, true, "-   a\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			locator, err := NewLocator([]byte(tc.src))
			if err != nil {
				t.Fatal(err)
			}
			var edit Edit
			if tc.element {
				edit, err = locator.RemoveElementEdit(display, 0, tc.path)
			} else {
				edit, err = locator.RemoveKeyEdit(display, 0, tc.path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := tc.src[edit.StartByte:edit.EndByte]; got != tc.want || edit.Replacement != "" || edit.File != display {
				t.Fatalf("removed %q, want %q (%+v)", got, tc.want, edit)
			}
		})
	}
	t.Run("refusals", func(t *testing.T) {
		locator, err := NewLocator([]byte("l: [a, b]\nm: {x: 1, y: 2}\nn:\n- k: 1\n  j: 2\no: 1\n"))
		if err != nil {
			t.Fatal(err)
		}
		for name, tc := range map[string]struct {
			path    Path
			element bool
			reason  Reason
		}{
			"flow element":      {Path{Key("l"), Index(0)}, true, ReasonSpanNotIsolated},
			"flow key":          {Path{Key("m"), Key("x")}, false, ReasonSpanNotIsolated},
			"key as element":    {Path{Key("o")}, true, ReasonPathNotFound},
			"element as key":    {Path{Key("n"), Index(0)}, false, ReasonPathNotFound},
			"empty path":        {Path{}, false, ReasonPathNotFound},
			"first key of item": {Path{Key("n"), Index(0), Key("k")}, false, ReasonSpanNotIsolated},
			"missing":           {Path{Key("zz")}, false, ReasonPathNotFound},
		} {
			var err error
			if tc.element {
				_, err = locator.RemoveElementEdit(display, 0, tc.path)
			} else {
				_, err = locator.RemoveKeyEdit(display, 0, tc.path)
			}
			if ReasonOf(err) != tc.reason {
				t.Errorf("%s: got %v, want %s", name, err, tc.reason)
			}
		}
		if _, err := locator.RemoveKeyEdit(display, 3, Path{Key("o")}); ReasonOf(err) != ReasonPathNotFound {
			t.Errorf("missing document: %v", err)
		}
	})
}

// ---- rename_key ----

func renParams(path, newKey string) Params {
	return Params(`{"path":` + path + `,"newKey":"` + newKey + `"}`)
}

func TestRenameKey(t *testing.T) {
	cases := []kindCase{
		{name: "plain", params: renParams(`["a"]`, "alpha"),
			src: "a: 1\nb: 2\n", want: "alpha: 1\nb: 2\n", edits: 1},
		{name: "only the case changes", params: renParams(`["prometheus","servicemonitor"]`, "serviceMonitor"),
			src: "prometheus:\n  servicemonitor:\n    enabled: true\n", want: "prometheus:\n  serviceMonitor:\n    enabled: true\n", edits: 1},
		{name: "double quoted key keeps its quotes", params: renParams(`["a"]`, "alpha"),
			src: "\"a\": 1\n", want: "\"alpha\": 1\n", edits: 1},
		{name: "single quoted key keeps its quotes", params: renParams(`["a"]`, "alpha"),
			src: "'a': 1\nb: 2\n", want: "'alpha': 1\nb: 2\n", edits: 1},
		{name: "quote characters in the new key", params: renParams(`["a"]`, `it's`),
			src: "'a': 1\nb: 2\n", want: "'it''s': 1\nb: 2\n", edits: 1},
		{name: "plain key becomes quoted when it must", params: renParams(`["a"]`, "x y"),
			src: "a: 1\n", want: "\"x y\": 1\n", edits: 1},
		{name: "yaml 1.1 words are quoted", params: renParams(`["a"]`, "on"),
			src: "a: 1\nb: 2\n", want: "\"on\": 1\nb: 2\n", edits: 1},
		{name: "a number looking key is quoted", params: renParams(`["a"]`, "123"),
			src: "a: 1\nb: 2\n", want: "\"123\": 1\nb: 2\n", edits: 1},
		{name: "a boolean looking key is quoted", params: renParams(`["a"]`, "true"),
			src: "a: 1\nb: 2\n", want: "\"true\": 1\nb: 2\n", edits: 1},
		{name: "a colon in the new key", params: renParams(`["a"]`, "a: b"),
			src: "a: 1\nb: 2\n", want: "\"a: b\": 1\nb: 2\n", edits: 1},
		{name: "a hash in the new key", params: renParams(`["a"]`, "a #b"),
			src: "a: 1\nb: 2\n", want: "\"a #b\": 1\nb: 2\n", edits: 1},
		{name: "unicode", params: renParams(`["a"]`, "ключ"),
			src: "a: 1\nb: 2\n", want: "\"ключ\": 1\nb: 2\n", edits: 1},
		{name: "dots and slashes stay plain", params: renParams(`["a"]`, "app.kubernetes.io/name"),
			src: "a: 1\nb: 2\n", want: "app.kubernetes.io/name: 1\nb: 2\n", edits: 1},
		{name: "key in a flow mapping", params: renParams(`["m","a"]`, "alpha"),
			src: "m: {a: 1, b: 2}\n", want: "m: {alpha: 1, b: 2}\n", edits: 1},
		{name: "key in a sequence item", params: renParams(`["l",1,"b"]`, "bee"),
			src: "l:\n- b: 1\n- b: 2 # c\n", want: "l:\n- b: 1\n- bee: 2 # c\n", edits: 1},
		{name: "value stays whatever it is", params: renParams(`["a"]`, "alpha"),
			src: "a:\n  x: [1, 2]\n  y: |\n    text\n", want: "alpha:\n  x: [1, 2]\n  y: |\n    text\n", edits: 1},
		{name: "crlf", params: renParams(`["a"]`, "alpha"),
			src: "a: 1\r\nb: 2\r\n", want: "alpha: 1\r\nb: 2\r\n", edits: 1},
		{name: "key already renamed", params: renParams(`["a"]`, "alpha"), src: "alpha: 1\nb: 2\n"},
		{name: "missing key", params: renParams(`["z"]`, "alpha"), src: "a: 1\n"},
		{name: "rename to the same name", params: renParams(`["a"]`, "a"), src: "a: 1\nb: 2\n"},
		{name: "path through a missing parent", params: renParams(`["z","a"]`, "alpha"), src: "a: 1\n"},
		{name: "selected by apiVersion and kind", params: Params(`{"apiVersion":"v1","kind":"ConfigMap","path":["data","a"],"newKey":"alpha"}`),
			src:  "apiVersion: v1\nkind: ConfigMap\ndata:\n  a: 1\n---\nkind: Pod\ndata:\n  a: 1\n",
			want: "apiVersion: v1\nkind: ConfigMap\ndata:\n  alpha: 1\n---\nkind: Pod\ndata:\n  a: 1\n", edits: 1},
	}
	runPositive(t, "rename_key", cases)
}

func TestRenameKeyRefusals(t *testing.T) {
	refused := map[string]struct {
		src    string
		path   string
		newKey string
		reason Reason
	}{
		"existing sibling":                {"a: 1\nb: 2\n", `["a"]`, "b", ReasonKindRefused},
		"existing sibling, other case":    {"a: 1\nb: 2\n", `["a"]`, "B", ReasonKindRefused},
		"existing sibling, upper case":    {"a: 1\nBeta: 2\n", `["a"]`, "bETA", ReasonKindRefused},
		"existing quoted sibling":         {"a: 1\n\"b\": 2\n", `["a"]`, "b", ReasonKindRefused},
		"existing sibling in a flow map":  {"m: {a: 1, b: 2}\n", `["m","a"]`, "b", ReasonKindRefused},
		"existing sibling in a list item": {"l:\n- a: 1\n  b: 2\n", `["l",0,"a"]`, "B", ReasonKindRefused},
		"key in a block scalar parent":    {"a: |\n  b: 2\n", `["a","b"]`, "c", Reason("none")},
		"templated file":                  {"a: 1\nb: {{ x }}\n", `["a"]`, "z", ReasonTemplated},
		"secret file":                     {"kind: Secret\nstringData: {a: 1}\n---\nx: 1\n", `["x"]`, "z", ReasonSecretDocument},
		"anchor":                          {"a: &x 1\nb: *x\n", `["a"]`, "z", ReasonUnsupportedYAML},
		"merge key":                       {"a: &x {k: 1}\nb:\n  <<: *x\n", `["a"]`, "z", ReasonUnsupportedYAML},
	}
	for name, tc := range refused {
		t.Run(name, func(t *testing.T) {
			_, _, err := planKind(t, tc.src, "rename_key", renParams(tc.path, tc.newKey))
			if tc.reason == Reason("none") {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if ReasonOf(err) != tc.reason {
				t.Fatalf("got %v, want %s", err, tc.reason)
			}
		})
	}
	runInvalidParams(t, "rename_key", []string{
		``, `{}`, `{"path":["a"]}`, `{"newKey":"b"}`, `{"path":["a"],"newKey":""}`, `{"path":["a"],"newKey":"<<"}`,
		`{"path":["a"],"newKey":"x\ny"}`, `{"path":["a"],"newKey":"{{x}}"}`, `{"path":["a"],"newKey":1}`,
		`{"path":["a",0],"newKey":"b"}`, `{"path":[],"newKey":"b"}`, `{"path":["a"],"newKey":"b","to":"c"}`,
		`{"apiVersion":"v1","path":["a"],"newKey":"b"}`, `{"apiVersion":"v1","kind":"Secret","path":["a"],"newKey":"b"}`,
	})
}

// ---- set_value ----

func svParams(path, value string) Params {
	return Params(`{"path":` + path + `,"value":` + value + `}`)
}

func TestSetValue(t *testing.T) {
	cases := []kindCase{
		{name: "string is quoted", params: svParams(`["a"]`, `"hello"`),
			src: "a: old\nb: 2\n", want: "a: \"hello\"\nb: 2\n", edits: 1},
		{name: "string replaces a number", params: svParams(`["a"]`, `"7"`),
			src: "a: 7\n", want: "a: \"7\"\n", edits: 1},
		{name: "string true stays a string", params: svParams(`["a"]`, `"true"`),
			src: "a: true\n", want: "a: \"true\"\n", edits: 1},
		{name: "string on stays a string", params: svParams(`["a"]`, `"on"`),
			src: "a: x\n", want: "a: \"on\"\n", edits: 1},
		{name: "single quoted token keeps its quote style", params: svParams(`["a"]`, `"it's"`),
			src: "a: 'old' # c\n", want: "a: 'it''s' # c\n", edits: 1},
		{name: "double quoted token with escapes in the value", params: svParams(`["a"]`, `"q\"b\\s"`),
			src: "a: \"old\"\n", want: "a: \"q\\\"b\\\\s\"\n", edits: 1},
		{name: "unicode", params: svParams(`["a"]`, `"日本語 ключ"`),
			src: "a: x\n", want: "a: \"日本語 ключ\"\n", edits: 1},
		{name: "integer", params: svParams(`["a"]`, `5`),
			src: "a: \"x\"\nb: 1\n", want: "a: 5\nb: 1\n", edits: 1},
		{name: "negative decimal", params: svParams(`["a"]`, `-1.5`),
			src: "a: 3\n", want: "a: -1.5\n", edits: 1},
		{name: "zero", params: svParams(`["a"]`, `0`),
			src: "a: 3\n", want: "a: 0\n", edits: 1},
		{name: "true", params: svParams(`["a"]`, `true`),
			src: "a: \"yes\"\n", want: "a: true\n", edits: 1},
		{name: "false", params: svParams(`["a"]`, `false`),
			src: "a: true\n", want: "a: false\n", edits: 1},
		{name: "null", params: svParams(`["a"]`, `null`),
			src: "a: 3 # c\n", want: "a: null # c\n", edits: 1},
		{name: "nested in a sequence item", params: svParams(`["l",1,"v"]`, `10`),
			src: "l:\n- v: 1\n- v: 2\n", want: "l:\n- v: 1\n- v: 10\n", edits: 1},
		{name: "in a flow mapping", params: svParams(`["m","a"]`, `"z"`),
			src: "m: {a: x, b: y}\n", want: "m: {a: \"z\", b: y}\n", edits: 1},
		{name: "crlf", params: svParams(`["a"]`, `1`),
			src: "a: 0\r\nb: 2\r\n", want: "a: 1\r\nb: 2\r\n", edits: 1},
		{name: "already the string", params: svParams(`["a"]`, `"x"`), src: "a: x\n"},
		{name: "already the string, quoted", params: svParams(`["a"]`, `"x"`), src: "a: 'x'\n"},
		{name: "already the number", params: svParams(`["a"]`, `5`), src: "a: 5\n"},
		{name: "already true", params: svParams(`["a"]`, `true`), src: "a: true\n"},
		{name: "already null", params: svParams(`["a"]`, `null`), src: "a: null\n"},
		{name: "missing key", params: svParams(`["z"]`, `1`), src: "a: 1\n"},
		{name: "missing parent", params: svParams(`["z","y"]`, `1`), src: "a: 1\n"},
		{name: "selected by apiVersion and kind", params: Params(`{"apiVersion":"v1","kind":"ConfigMap","path":["data","a"],"value":"n"}`),
			src:  "apiVersion: v1\nkind: ConfigMap\ndata:\n  a: o\n---\nkind: Pod\ndata:\n  a: o\n",
			want: "apiVersion: v1\nkind: ConfigMap\ndata:\n  a: \"n\"\n---\nkind: Pod\ndata:\n  a: o\n", edits: 1},
	}
	runPositive(t, "set_value", cases)
}

func TestSetValueRefusals(t *testing.T) {
	cases := map[string]struct {
		src    string
		path   string
		value  string
		reason Reason
	}{
		"block scalar target":      {"a: |\n  text\n", `["a"]`, `"x"`, ReasonBlockScalar},
		"folded scalar target":     {"a: >\n  text\n", `["a"]`, `"x"`, ReasonBlockScalar},
		"multi-line plain target":  {"a: first\n  second\n", `["a"]`, `"x"`, ReasonMultiLineScalar},
		"multi-line quoted target": {"a: \"first\n  second\"\n", `["a"]`, `"x"`, ReasonMultiLineScalar},
		"mapping target":           {"a:\n  b: 1\n", `["a"]`, `"x"`, ReasonKindRefused},
		"sequence target":          {"a:\n- 1\n", `["a"]`, `"x"`, ReasonKindRefused},
		"flow collection target":   {"a: {b: 1}\n", `["a"]`, `1`, ReasonKindRefused},
		"empty target":             {"a:\nb: 1\n", `["a"]`, `1`, ReasonSpanNotIsolated},
		"templated":                {"a: 1\nb: {{ x }}\n", `["a"]`, `2`, ReasonTemplated},
		"secret file":              {"kind: Secret\nstringData: {a: 1}\n---\nx: 1\n", `["x"]`, `2`, ReasonSecretDocument},
		"tagged target":            {"a: !!str 1\n", `["a"]`, `2`, ReasonSpanNotIsolated},
		"anchored target":          {"a: &x 1\nb: *x\n", `["a"]`, `2`, ReasonUnsupportedYAML},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := planKind(t, tc.src, "set_value", svParams(tc.path, tc.value))
			if ReasonOf(err) != tc.reason {
				t.Fatalf("got %v, want %s", err, tc.reason)
			}
		})
	}
	runInvalidParams(t, "set_value", []string{
		``, `{}`, `{"path":["a"]}`, `{"value":1}`, `{"path":[],"value":1}`,
		`{"path":["a"],"value":[1]}`, `{"path":["a"],"value":{"b":1}}`, `{"path":["a"],"value":1e3}`, `{"path":["a"],"value":1E3}`,
		`{"path":["a"],"value":-2.5e-1}`, `{"path":["a"],"value":"a\nb"}`, `{"path":["a"],"value":"a\u0000"}`,
		`{"path":["a"],"value":"{{x}}"}`, `{"path":["a"],"value":"${x}"}`, `{"path":["a"],"value":"a\u2028b"}`,
		`{"path":["a"],"value":1,"extra":2}`, `{"path":["a"],"value":1,"value":2}`, `{"path":["a"],"value":nul}`,
		`{"apiVersion":"v1","kind":"Secret","path":["a"],"value":1}`, `{"kind":"Pod","path":["a"],"value":1}`,
	})
}

// A value that the YAML 1.1 reading would take for something else is never
// written plain.
func TestSetValueNeverWritesAmbiguousPlainText(t *testing.T) {
	for _, text := range []string{"on", "off", "yes", "no", "y", "n", "True", "NULL", "~", "0x10", "1_000", "0b11", "012", "1e3", "2001-01-02", "1:30", "true", "null", "5", ".inf"} {
		_, after, err := planKind(t, "a: old\nb: 1\n", "set_value", svParams(`["a"]`, `"`+text+`"`))
		if err != nil || after != "a: \""+text+"\"\nb: 1\n" {
			t.Fatalf("%s: %v %q", text, err, after)
		}
	}
}

// ---- remove_feature_gate: structural cases ----

func TestRemoveFeatureGateStructural(t *testing.T) {
	params := kindParams(t, map[string]string{"component": cmID, "gate": "ServerSideApply"})
	img := "quay.io/jetstack/cert-manager-controller:v1.16.2"
	args := func(list string) string { return container(img, "        args:\n"+list) }
	runPositive(t, "remove_feature_gate", []kindCase{
		{name: "last gate removes the argument", params: params,
			src:  workload("Deployment", args("        - --v=2\n        - --feature-gates=ServerSideApply=true\n        - --other\n")),
			want: workload("Deployment", args("        - --v=2\n        - --other\n")), edits: 1},
		{name: "last gate as the final argument", params: params,
			src:  workload("Deployment", args("        - --v=2\n        - \"--feature-gates=ServerSideApply=false\" # gates\n")),
			want: workload("Deployment", args("        - --v=2\n")), edits: 1},
		{name: "last gate in the first argument", params: params,
			src:  workload("Deployment", args("        - --feature-gates=ServerSideApply=true\n        - --v=2\n")),
			want: workload("Deployment", args("        - --v=2\n")), edits: 1},
		{name: "last gate in the separate form removes both elements", params: params,
			src:  workload("Deployment", args("        - --v=2\n        - --feature-gates\n        - ServerSideApply=true\n        - --other\n")),
			want: workload("Deployment", args("        - --v=2\n        - --other\n")), edits: 2},
		{name: "last gate in the separate form with quotes", params: params,
			src:  workload("Deployment", args("        - --v=2\n        - '--feature-gates'\n        - 'ServerSideApply=true' # c\n")),
			want: workload("Deployment", args("        - --v=2\n")), edits: 2},
		{name: "last gate in a list at the key's indentation", params: params,
			src:  workload("Deployment", container(img, "        args:\n        - --feature-gates=ServerSideApply=true\n        - --v=2\n")),
			want: workload("Deployment", container(img, "        args:\n        - --v=2\n")), edits: 1},
		{name: "last gate in command", params: params,
			src:  workload("Deployment", container(img, "        command:\n        - /app\n        - --feature-gates=ServerSideApply=true\n")),
			want: workload("Deployment", container(img, "        command:\n        - /app\n")), edits: 1},
		{name: "gate in the second of two flags is the last gate", params: params,
			src:  workload("Deployment", args("        - --feature-gates=A=true\n        - --feature-gates=ServerSideApply=true\n")),
			want: workload("Deployment", args("        - --feature-gates=A=true\n")), edits: 1},
		{name: "map entry", params: params,
			src:  "apiVersion: config.cert-manager.io/v1alpha1\nkind: ControllerConfiguration\nfeatureGates:\n  A: true\n  ServerSideApply: true\n  B: false\nother: 1\n",
			want: "apiVersion: config.cert-manager.io/v1alpha1\nkind: ControllerConfiguration\nfeatureGates:\n  A: true\n  B: false\nother: 1\n", edits: 1},
		{name: "map entry with a comment", params: params,
			src:  "featureGates:\n  # the gate\n  ServerSideApply: true # on\n  A: true\n",
			want: "featureGates:\n  # the gate\n  A: true\n", edits: 1},
		{name: "map entry nested in a list", params: params,
			src:  "components:\n- name: x\n  featureGates:\n    A: true\n    ServerSideApply: false\n",
			want: "components:\n- name: x\n  featureGates:\n    A: true\n", edits: 1},
		{name: "a map in each of two documents", params: params,
			src:  "featureGates:\n  ServerSideApply: true\n  X: 1\n---\nfeatureGates:\n  ServerSideApply: false\n  Y: 1\n",
			want: "featureGates:\n  X: 1\n---\nfeatureGates:\n  Y: 1\n", edits: 2},
		{name: "map entry and the argument of a workload in one file", params: params,
			src: "featureGates:\n  A: true\n  ServerSideApply: true\n---\n" +
				workload("Deployment", args("        - --feature-gates=ServerSideApply=true\n        - --v=2\n")),
			want: "featureGates:\n  A: true\n---\n" +
				workload("Deployment", args("        - --v=2\n")), edits: 2},
		{name: "map entry and a list rewrite in one file", params: params,
			src: "featureGates:\n  A: true\n  ServerSideApply: true\n---\n" +
				workload("Deployment", args("        - --feature-gates=A=true,ServerSideApply=true\n")),
			want: "featureGates:\n  A: true\n---\n" +
				workload("Deployment", args("        - --feature-gates=A=true\n")), edits: 2},
	})
}

func TestRemoveFeatureGateStructuralRefusals(t *testing.T) {
	params := kindParams(t, map[string]string{"component": cmID, "gate": "ServerSideApply"})
	img := "quay.io/jetstack/cert-manager-controller:v1.16.2"
	reasons := map[string]struct {
		src    string
		reason Reason
	}{
		"only argument of args would leave it empty": {workload("Deployment", container(img, "        args:\n        - --feature-gates=ServerSideApply=true\n")), ReasonInvalidEdit},
		"separate form that is all of args":          {workload("Deployment", container(img, "        args:\n        - --feature-gates\n        - ServerSideApply=true\n")), ReasonInvalidEdit},
		"flow list":                                  {workload("Deployment", container(img, "        args: [--v=2, --feature-gates=ServerSideApply=true]\n")), ReasonSpanNotIsolated},
		"flow list, separate form":                   {workload("Deployment", container(img, "        args: [--v=2, --feature-gates, ServerSideApply=true]\n")), ReasonSpanNotIsolated},
		"only map entry would leave the map empty":   {"featureGates:\n  ServerSideApply: true\nother: 1\n", ReasonInvalidEdit},
		"flow map":                                            {"featureGates: {ServerSideApply: true, A: true}\n", ReasonSpanNotIsolated},
		"map in a flow parent":                                {"top: {featureGates: {ServerSideApply: true, A: true}, b: 1}\n", ReasonSpanNotIsolated},
		"gate maps in two places":                             {"a:\n  featureGates:\n    ServerSideApply: true\n    X: 1\nb:\n  featureGates:\n    ServerSideApply: false\n    Y: 1\n", ReasonKindRefused},
		"unknown image with the last gate":                    {workload("Deployment", container("example.com/x:1", "        args:\n        - --v=2\n        - --feature-gates=ServerSideApply=true\n")), ReasonKindRefused},
		"gate twice, one of them the last":                    {workload("Deployment", container(img, "        args:\n        - --feature-gates=ServerSideApply=true\n        - --feature-gates=ServerSideApply=true\n        - --v=2\n")), ReasonKindRefused},
		"malformed entry beside the last gate":                {workload("Deployment", container(img, "        args:\n        - --feature-gates=ServerSideApply=true,A\n        - --v=2\n")), ReasonKindRefused},
		"templated":                                           {"featureGates:\n  ServerSideApply: true\n  A: {{ .x }}\n", ReasonTemplated},
		"anchored map entry":                                  {"featureGates:\n  ServerSideApply: &g true\n  A: *g\n", ReasonUnsupportedYAML},
		"tab in a comment below the entry":                    {"featureGates:\n  ServerSideApply: true\n\t# tab\n  A: 1\n", ReasonUnsupportedYAML},
		"separate form in a different place than the element": {workload("Deployment", container(img, "        args:\n        - --feature-gates\n        - ServerSideApply=true # c\n")), ReasonInvalidEdit},
	}
	for name, tc := range reasons {
		t.Run(name, func(t *testing.T) {
			_, _, err := planKind(t, tc.src, "remove_feature_gate", params)
			if ReasonOf(err) != tc.reason {
				t.Fatalf("got %v, want %s", err, tc.reason)
			}
		})
	}
}

func TestStructuralKindsAreRegistered(t *testing.T) {
	ids := strings.Join(Kinds(), ",")
	for _, want := range []string{"rename_key", "remove_key", "set_value"} {
		if !strings.Contains(ids, want) {
			t.Fatalf("%s missing from %s", want, ids)
		}
	}
	for _, id := range []string{"rename_key", "remove_key", "set_value", "remove_feature_gate"} {
		kind, _ := Lookup(id)
		if _, ok := kind.(OperationKind); !ok {
			t.Fatalf("%s does not implement OperationKind", id)
		}
	}
}

// Every positive row is also a stable plan: the same bytes plan the same
// edits every time (map iteration order must not decide).
func TestStructuralKindsArePlannedDeterministically(t *testing.T) {
	src := "featureGates:\n  A: 1\n  ServerSideApply: true\n  B: 2\nrest:\n  one: 1\n  two: 2\n  three: 3\n"
	requests := []Request{
		{Kind: "remove_feature_gate", Params: kindParams(t, map[string]string{"component": cmID, "gate": "ServerSideApply"})},
		{Kind: "remove_key", Params: rkParams(`["rest","two"]`)},
		{Kind: "rename_key", Params: renParams(`["rest","one"]`, "uno")},
		{Kind: "set_value", Params: svParams(`["rest","three"]`, `"tres"`)},
	}
	first, err := Plan(display, []byte(src), requests, Options{})
	if err != nil || len(first.Edits) != 4 {
		t.Fatalf("%v %+v", err, first.Edits)
	}
	for i := 0; i < 30; i++ {
		again, err := Plan(display, []byte(src), requests, Options{})
		if err != nil || again.Diff != first.Diff {
			t.Fatalf("plans differ: %v", err)
		}
	}
	after, err := ApplyInMemory([]byte(src), first, Options{})
	want := "featureGates:\n  A: 1\n  B: 2\nrest:\n  uno: 1\n  three: \"tres\"\n"
	if err != nil || string(after) != want {
		t.Fatalf("%v\n%s", err, after)
	}
}
