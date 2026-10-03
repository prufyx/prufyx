// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"bytes"
	"strings"
	"testing"
)

const display = "deploy/app.yaml"

// fixtures are small files covering the handled YAML forms.
var fixtures = map[string]string{
	"deployment": deployment,
	"multi":      "# one\napiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: a}\n---\n# two\napiVersion: batch/v1beta1 # old\nkind: CronJob\nmetadata:\n  name: 'b'\n",
	"crlf":       "apiVersion: v1\r\nkind: ConfigMap\r\ndata:\r\n  key: \"value\"\r\n  other: x # note\r\n",
	"utf8":       "# ünïcödé\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: ök\ndata:\n  \"ключ\": значение\n  b: 漢字\n",
	"tabs":       "apiVersion: v1\t# api\nkind: ConfigMap\ndata: {a: x,\tb: y}\n",
	"json":       `{"apiVersion": "v1", "kind": "ConfigMap", "data": {"a": "1", "b": "2"}}`,
	"values":     "image:\n  repository: app\n  tag: \"1.0\"\nreplicas: 2\nlist:\n- one\n- two\n",
	"nonewline":  "a: b\nc: d",
	"bom":        "\uFEFFapiVersion: v1\nkind: ConfigMap\n",
}

func TestApplyPreservesFormat(t *testing.T) {
	src := []byte(fixtures["multi"])
	requests := []Request{setRequest("value", "batch/v1beta1", "batch/v1", "apiVersion")}
	plan, err := Plan(display, src, requests, Options{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Edits) != 2 {
		t.Fatalf("got %d edits, want 2", len(plan.Edits))
	}
	after, err := ApplyInMemory(src, plan, Options{})
	if err != nil {
		t.Fatalf("ApplyInMemory: %v", err)
	}
	want := strings.ReplaceAll(fixtures["multi"], "batch/v1beta1", "batch/v1")
	if string(after) != want {
		t.Fatalf("after:\n%s\nwant:\n%s", after, want)
	}
	// Every fixture, every scalar value and every key: the bytes outside the
	// edited token are unchanged.
	for name, text := range fixtures {
		src := []byte(text)
		file, r := parseFile(src)
		if r != nil {
			t.Fatalf("%s: %v", name, r)
		}
		for _, token := range file.tokenIndex() {
			span, r := file.tokenSpan(token.node, token.part)
			if r != nil {
				continue
			}
			replacement := `"zq-new"`
			plan, err := Plan(display, src, []Request{rawRequest(rawEdit{span.Start, span.End, replacement})}, Options{SkipIdempotenceCheck: true})
			if token.document != 0 {
				plan, err = Plan(display, src, []Request{{Kind: "test_set", Params: mustParams(t, token, replacement), Documents: []int{token.document}}}, Options{})
			}
			if err != nil {
				t.Fatalf("%s %v: %v", name, token.path, err)
			}
			after, err := ApplyInMemory(src, plan, Options{SkipIdempotenceCheck: true})
			if err != nil {
				t.Fatalf("%s %v: %v", name, token.path, err)
			}
			if !bytes.Equal(after[:span.Start], src[:span.Start]) || !bytes.Equal(after[span.Start+len(replacement):], src[span.End:]) ||
				string(after[span.Start:span.Start+len(replacement)]) != replacement {
				t.Fatalf("%s %v: bytes outside the span changed", name, token.path)
			}
		}
	}
}

// mustParams builds set-kind parameters that target one token of a document.
func mustParams(t *testing.T, token tokenRef, replacement string) Params {
	t.Helper()
	var segments []any
	for _, s := range token.path {
		if s.isIndex {
			segments = append(segments, s.index)
		} else {
			segments = append(segments, s.key)
		}
	}
	part := "value"
	if token.part == PartKey {
		part = "key"
	}
	request := setRequest(part, token.node.Value, replacement, segments...)
	return request.Params
}

func TestPlanConflicts(t *testing.T) {
	src := []byte("apiVersion: v1\nkind: ConfigMap\ndata:\n  a: x\n")
	// The key "a" is at 39..40 and the value "x" at 42..43.
	cases := []struct {
		name  string
		edits []rawEdit
		want  Reason
	}{
		{name: "same token different replacements", edits: []rawEdit{{41, 42, "y"}, {41, 42, "z"}}, want: ReasonConflictingEdits},
		{name: "overlapping spans", edits: []rawEdit{{38, 42, "q"}, {41, 42, "z"}}, want: ReasonConflictingEdits},
		{name: "nested span", edits: []rawEdit{{30, 42, "q"}, {38, 39, "b"}}, want: ReasonConflictingEdits},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Plan(display, src, []Request{rawRequest(tc.edits...)}, Options{SkipIdempotenceCheck: true})
			if got := ReasonOf(err); got != tc.want {
				t.Fatalf("reason %q (%v), want %q", got, err, tc.want)
			}
		})
	}
	t.Run("two kinds conflict", func(t *testing.T) {
		requests := []Request{setRequest("value", "x", "y", "data", "a"), setRequest("value", "x", "z", "data", "a")}
		_, err := Plan(display, src, requests, Options{})
		if ReasonOf(err) != ReasonConflictingEdits {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("identical edits merge", func(t *testing.T) {
		requests := []Request{setRequest("value", "x", "y", "data", "a"), setRequest("value", "x", "y", "data", "a")}
		plan, err := Plan(display, src, requests, Options{})
		if err != nil || len(plan.Edits) != 1 {
			t.Fatalf("plan %+v, err %v", plan, err)
		}
	})
	t.Run("altered plan refused at apply", func(t *testing.T) {
		plan, err := Plan(display, src, []Request{setRequest("value", "x", "y", "data", "a")}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		plan.Edits = append(plan.Edits, Edit{File: display, StartByte: 42, EndByte: 43, Replacement: "w"})
		if _, err := ApplyInMemory(src, plan, Options{}); ReasonOf(err) != ReasonConflictingEdits {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("key and value edits on one pair", func(t *testing.T) {
		plan, err := Plan(display, src, []Request{rawRequest(rawEdit{39, 40, "b"}, rawEdit{42, 43, "y"})}, Options{SkipIdempotenceCheck: true})
		if err != nil {
			t.Fatal(err)
		}
		after, err := ApplyInMemory(src, plan, Options{SkipIdempotenceCheck: true})
		if err != nil || !strings.HasSuffix(string(after), "  b: y\n") {
			t.Fatalf("after %q err %v", after, err)
		}
	})
}

func TestPlanEditValidation(t *testing.T) {
	src := []byte("apiVersion: v1\nkind: ConfigMap\ndata:\n  a: x\n  b: [p, q]\n")
	cases := []struct {
		name string
		edit rawEdit
		want Reason
	}{
		{name: "out of bounds", edit: rawEdit{42, 400, "y"}, want: ReasonInvalidEdit},
		{name: "negative", edit: rawEdit{-1, 2, "y"}, want: ReasonInvalidEdit},
		{name: "empty span", edit: rawEdit{42, 42, "y"}, want: ReasonInvalidEdit},
		{name: "off by one end", edit: rawEdit{42, 44, "y"}, want: ReasonSpanNotIsolated},
		{name: "off by one start", edit: rawEdit{41, 43, "y"}, want: ReasonSpanNotIsolated},
		{name: "part of token", edit: rawEdit{0, 3, "api"}, want: ReasonSpanNotIsolated},
		{name: "newline in replacement", edit: rawEdit{42, 43, "y\nz: 1"}, want: ReasonInvalidEdit},
		{name: "document marker", edit: rawEdit{0, 10, "---"}, want: ReasonInvalidEdit},
		{name: "control character", edit: rawEdit{42, 43, "y\x00"}, want: ReasonInvalidEdit},
		{name: "template syntax", edit: rawEdit{42, 43, "${y}"}, want: ReasonInvalidEdit},
		{name: "empty replacement", edit: rawEdit{42, 43, ""}, want: ReasonInvalidEdit},
		{name: "too long", edit: rawEdit{42, 43, strings.Repeat("y", MaxReplacementBytes+1)}, want: ReasonLimit},
		{name: "mapping replacement", edit: rawEdit{42, 43, "y: z"}, want: ReasonInvalidEdit},
		{name: "replacement with comment", edit: rawEdit{42, 43, "y # c"}, want: ReasonInvalidEdit},
		{name: "replacement with anchor", edit: rawEdit{42, 43, "&a y"}, want: ReasonInvalidEdit},
		{name: "replacement with tag", edit: rawEdit{42, 43, "!!str y"}, want: ReasonInvalidEdit},
		{name: "non-string key", edit: rawEdit{39, 40, "12"}, want: ReasonInvalidEdit},
		{name: "merge key", edit: rawEdit{39, 40, "<<"}, want: ReasonInvalidEdit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Plan(display, src, []Request{rawRequest(tc.edit)}, Options{SkipIdempotenceCheck: true})
			if got := ReasonOf(err); got != tc.want {
				t.Fatalf("reason %q (%v), want %q", got, err, tc.want)
			}
		})
	}
	t.Run("wrong file", func(t *testing.T) {
		plan, err := Plan(display, src, []Request{setRequest("value", "x", "y", "data", "a")}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		plan.Edits[0].File = "other.yaml"
		if _, err := ApplyInMemory(src, plan, Options{}); ReasonOf(err) != ReasonInvalidEdit {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("too many edits", func(t *testing.T) {
		edits := make([]rawEdit, MaxEditsPerFile+1)
		for i := range edits {
			edits[i] = rawEdit{42, 43, "y"}
		}
		_, err := Plan(display, src, []Request{rawRequest(edits...)}, Options{SkipIdempotenceCheck: true})
		if ReasonOf(err) != ReasonLimit {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("unknown kind", func(t *testing.T) {
		_, err := Plan(display, src, []Request{{Kind: "nope"}}, Options{})
		if ReasonOf(err) != ReasonUnknownKind {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("invalid params", func(t *testing.T) {
		_, err := Plan(display, src, []Request{{Kind: "test_set", Params: Params(`{"bogus":1}`)}}, Options{})
		if ReasonOf(err) != ReasonInvalidParams {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad display", func(t *testing.T) {
		_, err := Plan("a\nb", src, nil, Options{})
		if ReasonOf(err) != ReasonInvalidEdit {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("missing document", func(t *testing.T) {
		request := setRequest("value", "x", "y", "data", "a")
		request.Documents = []int{3}
		_, err := Plan(display, src, []Request{request}, Options{})
		if ReasonOf(err) != ReasonPathNotFound {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("secret file", func(t *testing.T) {
		secret := []byte("apiVersion: v1\nkind: ConfigMap\ndata:\n  a: x\n---\napiVersion: v1\nkind: Secret\nstringData:\n  p: hunter2\n")
		request := setRequest("value", "x", "y", "data", "a")
		request.Documents = []int{0}
		_, err := Plan(display, secret, []Request{request}, Options{})
		if ReasonOf(err) != ReasonSecretDocument || strings.Contains(err.Error(), "hunter2") {
			t.Fatalf("got %v", err)
		}
		// Even with nothing to change the file is refused, so no diff
		// context can ever show Secret bytes.
		if _, err := Plan(display, secret, nil, Options{}); ReasonOf(err) != ReasonSecretDocument {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("edit turns document into secret", func(t *testing.T) {
		_, err := Plan(display, src, []Request{setRequest("value", "ConfigMap", "Secret", "kind")}, Options{})
		if ReasonOf(err) != ReasonSecretDocument {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("digest mismatch in memory", func(t *testing.T) {
		plan, err := Plan(display, src, []Request{setRequest("value", "x", "y", "data", "a")}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		changed := append(bytes.Clone(src), '\n')
		if _, err := ApplyInMemory(changed, plan, Options{}); ReasonOf(err) != ReasonFileChanged {
			t.Fatalf("got %v", err)
		}
	})
}

func TestIdempotent(t *testing.T) {
	plans := 0
	for name, text := range fixtures {
		src := []byte(text)
		file, r := parseFile(src)
		if r != nil {
			t.Fatalf("%s: %v", name, r)
		}
		for _, token := range file.tokenIndex() {
			if _, r := file.tokenSpan(token.node, token.part); r != nil {
				continue
			}
			request := Request{Kind: "test_set", Params: mustParams(t, token, `"zq-new"`), Documents: []int{token.document}}
			plan, err := Plan(display, src, []Request{request}, Options{})
			if err != nil {
				t.Fatalf("%s %v: %v", name, token.path, err)
			}
			if len(plan.Edits) != 1 {
				t.Fatalf("%s %v: %d edits", name, token.path, len(plan.Edits))
			}
			after, err := ApplyInMemory(src, plan, Options{})
			if err != nil {
				t.Fatalf("%s %v: %v", name, token.path, err)
			}
			again, err := Plan(display, after, []Request{request}, Options{})
			if err != nil || len(again.Edits) != 0 || again.Diff != "" {
				t.Fatalf("%s %v: second plan %+v err %v", name, token.path, again, err)
			}
			plans++
		}
	}
	if plans < 50 {
		t.Fatalf("only %d plans exercised", plans)
	}
	t.Run("non-idempotent kind refused", func(t *testing.T) {
		src := []byte("a: x\n")
		params := setRequest("value", "", "", "a").Params
		_, err := Plan(display, src, []Request{{Kind: "test_grow", Params: params}}, Options{})
		if ReasonOf(err) != ReasonNotIdempotent {
			t.Fatalf("got %v", err)
		}
		plan, err := Plan(display, src, []Request{{Kind: "test_grow", Params: params}}, Options{SkipIdempotenceCheck: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ApplyInMemory(src, plan, Options{}); ReasonOf(err) != ReasonNotIdempotent {
			t.Fatalf("apply got %v", err)
		}
	})
}

func TestApplyDecodeVerification(t *testing.T) {
	cases := []struct {
		name string
		src  string
		edit rawEdit
		want Reason
	}{
		// "x" in the flow sequence becomes two items.
		{name: "flow comma splits item", src: "a: [x, y]\n", edit: rawEdit{4, 5, "p, q"}, want: ReasonDecodeMismatch},
		{name: "flow brace closes early", src: "a: {k: x}\nb: c\n", edit: rawEdit{7, 8, "v}"}, want: ReasonDecodeMismatch},
		{name: "plain key followed by colon in flow", src: "{\"a\":1}\n", edit: rawEdit{1, 4, "b"}, want: ReasonDecodeMismatch},
		{name: "rename onto sibling", src: "a: 1\nb: 2\n", edit: rawEdit{0, 1, "b"}, want: ReasonDecodeMismatch},
		{name: "rename onto sibling by case", src: "a: 1\nb: 2\n", edit: rawEdit{0, 1, "B"}, want: ReasonDecodeMismatch},
		{name: "root document becomes null", src: "a: b\n--- x\n", edit: rawEdit{9, 10, "null"}, want: ReasonDecodeMismatch},
		{name: "value becomes timestamp text kept", src: "a: x\n", edit: rawEdit{3, 4, "2026-01-02"}, want: ""},
		{name: "quoted value", src: "a: x\n", edit: rawEdit{3, 4, `"y z"`}, want: ""},
		{name: "number", src: "a: x\n", edit: rawEdit{3, 4, "12"}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Plan(display, []byte(tc.src), []Request{rawRequest(tc.edit)}, Options{SkipIdempotenceCheck: true})
			if got := ReasonOf(err); got != tc.want {
				t.Fatalf("reason %q (%v), want %q", got, err, tc.want)
			}
		})
	}
	// The check also runs on a plan that was altered after planning.
	t.Run("altered replacement refused at apply", func(t *testing.T) {
		src := []byte("a: [x, y]\n")
		plan, err := Plan(display, src, []Request{rawRequest(rawEdit{4, 5, "p"})}, Options{SkipIdempotenceCheck: true})
		if err != nil {
			t.Fatal(err)
		}
		plan.Edits[0].Replacement = "p, q"
		if _, err := ApplyInMemory(src, plan, Options{SkipIdempotenceCheck: true}); ReasonOf(err) != ReasonDecodeMismatch {
			t.Fatalf("got %v", err)
		}
	})
}

func TestRegistry(t *testing.T) {
	ids := Kinds()
	if strings.Join(ids, ",") != "test_grow,test_raw,test_set" {
		t.Fatalf("kinds %v", ids)
	}
	if _, ok := Lookup("test_set"); !ok {
		t.Fatal("lookup failed")
	}
	mustPanic := func(name string, f func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Fatalf("%s: no panic", name)
			}
		}()
		f()
	}
	mustPanic("register after use", func() { Register(setKind{}) })
	registry.Lock()
	registry.sealed = false
	registry.Unlock()
	defer func() {
		registry.Lock()
		registry.sealed = true
		registry.Unlock()
	}()
	mustPanic("duplicate", func() { Register(setKind{}) })
	mustPanic("invalid id", func() { Register(badIDKind{}) })
	mustPanic("nil", func() { Register(nil) })
}

type badIDKind struct{ growKind }

func (badIDKind) ID() string { return "Bad-ID" }
