// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"bytes"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The tests in this file pin the checks that keep a plan, a replacement, a
// parameter set or a kind from changing what a user approved.

func TestForgedPlanRefused(t *testing.T) {
	src := []byte("apiVersion: v1\nkind: Pod\nimage: good\n")
	start := bytes.Index(src, []byte("good"))
	forged := Edit{File: display, StartByte: start, EndByte: start + 4, Replacement: "evil"}

	t.Run("edits that no request produces", func(t *testing.T) {
		plan, err := Plan(display, src, nil, Options{})
		if err != nil {
			t.Fatal(err)
		}
		plan.Edits = []Edit{forged}
		plan.Diff = "(benign)"
		if after, err := ApplyInMemory(src, plan, Options{}); err == nil || after != nil {
			t.Fatalf("forged plan applied: %q, %v", after, err)
		}
		// A diff that matches the forged edits does not help either.
		diff, err := UnifiedDiff(display, src, []Edit{forged})
		if err != nil {
			t.Fatal(err)
		}
		plan.Diff = diff
		if _, err := ApplyInMemory(src, plan, Options{}); ReasonOf(err) != ReasonInvalidEdit {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("real edits with a benign diff", func(t *testing.T) {
		plan, err := Plan(display, src, []Request{setRequest("value", "good", "better", "image")}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		plan.Diff = "(benign)"
		if _, err := ApplyInMemory(src, plan, Options{}); ReasonOf(err) != ReasonInvalidEdit {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("edits that differ from the requested ones", func(t *testing.T) {
		plan, err := Plan(display, src, []Request{setRequest("value", "good", "better", "image")}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		plan.Edits[0].Replacement = "evil"
		if _, err := ApplyInMemory(src, plan, Options{}); ReasonOf(err) != ReasonInvalidEdit {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("an empty plan with a diff", func(t *testing.T) {
		plan, err := Plan(display, src, nil, Options{})
		if err != nil {
			t.Fatal(err)
		}
		plan.Diff = "--- a/x\n"
		if _, err := ApplyInMemory(src, plan, Options{}); ReasonOf(err) != ReasonInvalidEdit {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a genuine plan applies", func(t *testing.T) {
		plan, err := Plan(display, src, []Request{setRequest("value", "good", "better", "image")}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		after, diff, err := applyPlan(src, plan, Options{})
		if err != nil || string(after) != "apiVersion: v1\nkind: Pod\nimage: better\n" || diff != plan.Diff || diff == "" {
			t.Fatalf("after %q diff %q err %v", after, diff, err)
		}
	})
}

func TestSecretDetectionAtAnyDepth(t *testing.T) {
	cases := map[string]string{
		"root sequence then a ConfigMap": "- {kind: Secret, stringData: {password: hunter2}}\n---\napiVersion: v1\nkind: ConfigMap\n",
		"template objects":               "apiVersion: template.openshift.io/v1\nkind: Template\nmetadata:\n  name: t\nobjects:\n- kind: Secret\n  stringData:\n    password: hunter2\n",
		"list item":                      "apiVersion: v1\nkind: List\nitems:\n- kind: Secret\n",
		"list in a list":                 "kind: List\nitems:\n- kind: List\n  items:\n  - kind: Secret\n",
		"secret list":                    "kind: List\nitems:\n- kind: SecretList\n",
		"custom resource wrapper":        "apiVersion: v1\nkind: ConfigMap\nspec:\n  resources:\n  - metadata: {name: x}\n    deep:\n      kind: Secret\n",
		"json":                           "{\"kind\":\"List\",\"items\":[[{\"kind\":\"Secret\"}]]}",
		"root document":                  "kind: Secret\n",
		"second document":                "kind: ConfigMap\n---\nkind: SecretList\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			src := []byte(text)
			if _, err := Plan(display, src, []Request{setRequest("value", "v1", "v2", "apiVersion")}, Options{}); ReasonOf(err) != ReasonSecretDocument {
				t.Fatalf("Plan: %v", err)
			}
			plan := FilePlan{Display: display, Digest: digestOf(src)}
			if _, err := ApplyInMemory(src, plan, Options{}); ReasonOf(err) != ReasonSecretDocument {
				t.Fatalf("ApplyInMemory: %v", err)
			}
		})
	}
	for name, text := range map[string]string{
		"lower case kind": "kind: ConfigMap\ndata:\n  kind: secret\n  other: Secrets\n",
		"kind in a list":  "kind: List\nitems:\n- kind: ConfigMap\n- {kind: Pod}\n",
		"not a string":    "kind: ConfigMap\ndata: {kind: 1}\n",
	} {
		t.Run("not a secret: "+name, func(t *testing.T) {
			if _, err := Plan(display, []byte(text), nil, Options{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestYAML11AmbiguousReplacements(t *testing.T) {
	refused := []string{
		"y", "Y", "n", "N", "yes", "Yes", "YES", "yEs", "no", "No", "NO", "on", "On", "ON", "oN", "off", "Off", "OFF",
		"true", "True", "TRUE", "false", "False", "FALSE", "~", "null", "Null", "NULL",
		"1_000", "0b101", "0B101", "0o17", "0x1F", "0xff", "1:20", "190:20:30", "1:20.5", ".inf", ".Inf", ".INF", "-.inf", "+.inf",
		".nan", ".NaN", ".NAN", "0777", "017", "1e3", "1E3", "1.5e3", "+1_0", "-0b1", ".5", "1.",
		"2001-12-14", "2001-12-14t21:59:43.10-05:00", "2001-12-14 21:59:43.10 -5", "2001-12-14T21:59:43Z",
	}
	for _, token := range refused {
		for _, part := range []string{"value", "key"} {
			t.Run(part+" "+token, func(t *testing.T) {
				from := "x"
				if part == "key" {
					from = ""
				}
				_, err := Plan(display, []byte("a: x\n"), []Request{setRequest(part, from, token, "a")}, Options{})
				if ReasonOf(err) != ReasonInvalidEdit {
					t.Fatalf("plain %q: %v", token, err)
				}
			})
		}
	}
	for _, token := range append(refused, "text with spaces", "a: b") {
		quoted := []string{`"` + token + `"`, `'` + token + `'`}
		if strings.Contains(token, ": ") {
			continue
		}
		for _, replacement := range quoted {
			t.Run("quoted "+replacement, func(t *testing.T) {
				for _, part := range []string{"value", "key"} {
					from := "x"
					if part == "key" {
						from = ""
					}
					plan, err := Plan(display, []byte("a: x\n"), []Request{setRequest(part, from, replacement, "a")}, Options{})
					if err != nil || len(plan.Edits) != 1 {
						t.Fatalf("quoted %s %s: %+v %v", part, replacement, plan, err)
					}
				}
			})
		}
	}
	for _, token := range []string{"12", "-3", "+4", "0", "1.5", "0.25", "ab", "v1", "1.2.3", "yy", "nope", "online", "batch/v1", "x-1", "3xlarge"} {
		t.Run("allowed "+token, func(t *testing.T) {
			if _, err := Plan(display, []byte("a: x\n"), []Request{setRequest("value", "x", token, "a")}, Options{}); err != nil {
				t.Fatalf("plain %q: %v", token, err)
			}
		})
	}
}

func TestDecodedReplacementChecks(t *testing.T) {
	for name, replacement := range map[string]string{
		"escape":          `"\e[31mX"`,
		"nul":             `"\0"`,
		"line feed":       `"a\nb"`,
		"carriage return": `"a\rb"`,
		"hex control":     `"\x1b"`,
		"tab escape":      `"a\tb"`,
		"delete":          `"\x7f"`,
		"next line":       `"\N"`,
		"line separator":  `"\L"`,
		"paragraph":       `"\P"`,
		"unicode escape":  `"\u2028"`,
		"byte order mark": `"\ufeff"`,
		"template braces": `"\x7b\x7b"`,
		"template dollar": `"\x24\x7b"`,
		"raw tab":         "\"a\tb\"",
		"single raw tab":  "'a\tb'",
	} {
		for _, part := range []string{"value", "key"} {
			t.Run(name+" "+part, func(t *testing.T) {
				from := "x"
				if part == "key" {
					from = ""
				}
				_, err := Plan(display, []byte("a: x\n"), []Request{setRequest(part, from, replacement, "a")}, Options{})
				if ReasonOf(err) != ReasonInvalidEdit {
					t.Fatalf("%s: %v", replacement, err)
				}
			})
		}
	}
	for _, replacement := range []string{`"a b"`, `"\u00e9\xe9"`, `"quote \" inside"`, `'it''s'`, `"back\\slash"`} {
		t.Run("allowed "+replacement, func(t *testing.T) {
			if _, err := Plan(display, []byte("a: x\n"), []Request{setRequest("value", "x", replacement, "a")}, Options{}); err != nil {
				t.Fatalf("%s: %v", replacement, err)
			}
		})
	}
}

func TestKindRefusalsAreBounded(t *testing.T) {
	src := []byte("a: x\n")
	content := "password: hunter2"
	cases := []struct {
		name    string
		request Request
		want    Reason
		detail  string
	}{
		{"closed reason passes", refuseRequest("refusal", "PATH_NOT_FOUND", "no such path"), ReasonPathNotFound, "no such path"},
		{"wrapped refusal passes", refuseRequest("wrapped", "LIMIT", "too big"), ReasonLimit, "too big"},
		{"reason outside the list", refuseRequest("refusal", "X", "fine"), ReasonKindRefused, ""},
		{"empty reason", refuseRequest("refusal", "", "fine"), ReasonKindRefused, ""},
		{"long detail", refuseRequest("refusal", "LIMIT", strings.Repeat("a", maxDetail+1)), ReasonKindRefused, ""},
		{"detail at the bound", refuseRequest("refusal", "LIMIT", strings.Repeat("a", maxDetail)), ReasonLimit, strings.Repeat("a", maxDetail)},
		{"detail with a line break", refuseRequest("refusal", "LIMIT", "a\n"+content), ReasonKindRefused, ""},
		{"detail with non-ASCII", refuseRequest("refusal", "LIMIT", "caf\u00e9"), ReasonKindRefused, ""},
		{"plain error", refuseRequest("plain", "", content), ReasonKindRefused, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Plan(display, src, []Request{tc.request}, Options{})
			var refusal *Refusal
			if ReasonOf(err) != tc.want || !asRefusal(err, &refusal) {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
			if tc.detail != "" && refusal.Detail != tc.detail {
				t.Fatalf("detail %q", refusal.Detail)
			}
			if strings.Contains(refusal.Error(), "hunter2") || len(refusal.Detail) > maxDetail {
				t.Fatalf("unbounded refusal: %v", refusal)
			}
		})
	}
}

func asRefusal(err error, target **Refusal) bool {
	refusal, ok := err.(*Refusal)
	*target = refusal
	return ok
}

func TestKindGetsACopyOfTheSource(t *testing.T) {
	src := []byte("a: x\n")
	original := string(src)
	_, err := Plan(display, src, []Request{{Kind: "test_mutate"}}, Options{})
	if ReasonOf(err) != ReasonKindRefused {
		t.Fatalf("got %v", err)
	}
	if string(src) != original {
		t.Fatalf("the caller's bytes changed: %q", src)
	}
	// A kind that does not write is unaffected, also on later calls.
	if _, err := Plan(display, src, []Request{setRequest("value", "x", "zz", "a")}, Options{}); err != nil {
		t.Fatal(err)
	}
	// The same holds when applying a plan.
	plan, err := Plan(display, src, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	plan.Requests = []Request{{Kind: "test_mutate"}}
	if _, err := ApplyInMemory(src, plan, Options{}); ReasonOf(err) != ReasonKindRefused || string(src) != original {
		t.Fatalf("got %v, bytes %q", err, src)
	}
}

func TestPlanDoesNotAliasTheCallersBytes(t *testing.T) {
	src := []byte("a: x\n")
	plan, err := Plan(display, src, []Request{setRequest("value", "x", "zz", "a")}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	after, err := ApplyInMemory(src, plan, Options{})
	if err != nil || string(after) != "a: zz\n" || string(src) != "a: x\n" {
		t.Fatalf("after %q src %q err %v", after, src, err)
	}
	after[0] = 'Z'
	if string(src) != "a: x\n" {
		t.Fatal("result aliases the source")
	}
}

func TestParamsAreBoundedAndParsedOnce(t *testing.T) {
	src := []byte("a: x\n")
	bad := map[string]struct {
		params string
		want   Reason
	}{
		"too large":        {`{"a":"` + strings.Repeat("x", MaxParamsBytes) + `"}`, ReasonLimit},
		"not JSON":         {`{"a":`, ReasonInvalidParams},
		"trailing data":    {`{} {}`, ReasonInvalidParams},
		"duplicate key":    {`{"a":1,"a":2}`, ReasonInvalidParams},
		"case-folded dup":  {`{"path":[],"Path":[]}`, ReasonInvalidParams},
		"escaped dup":      {`{"a":1,"a":2}`, ReasonInvalidParams},
		"nested duplicate": {`{"o":[{"k":1,"k":2}]}`, ReasonInvalidParams},
		"too deep":         {strings.Repeat("[", maxParamsDepth+1) + strings.Repeat("]", maxParamsDepth+1), ReasonInvalidParams},
	}
	for name, tc := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := Plan(display, src, []Request{{Kind: "test_once", Params: Params(tc.params)}}, Options{})
			if ReasonOf(err) != tc.want {
				t.Fatalf("got %v", err)
			}
		})
	}
	for name, params := range map[string]string{
		"empty":           "",
		"same key in two": `{"a":{"k":1},"b":{"k":2}}`,
		"sibling arrays":  `{"a":[{"k":1},{"k":2}]}`,
		"at the bound":    `{"a":"` + strings.Repeat("x", MaxParamsBytes-9) + `"}`,
		"deep enough":     strings.Repeat("[", maxParamsDepth) + strings.Repeat("]", maxParamsDepth),
	} {
		t.Run("ok "+name, func(t *testing.T) {
			if _, err := Plan(display, src, []Request{{Kind: "test_once", Params: Params(params)}}, Options{}); err != nil {
				t.Fatal(err)
			}
		})
	}

	// Validate runs once per request, and every Plan call (the plan and the
	// idempotence re-plan) receives the value it returned.
	t.Run("parsed once", func(t *testing.T) {
		onceLog.validated, onceLog.planned = nil, nil
		plan, err := Plan(display, src, []Request{{Kind: "test_once", Params: Params(`{}`)}}, Options{})
		if err != nil || len(plan.Edits) != 1 {
			t.Fatalf("%+v %v", plan, err)
		}
		if len(onceLog.validated) != 1 || len(onceLog.planned) != 2 {
			t.Fatalf("validated %d, planned %d", len(onceLog.validated), len(onceLog.planned))
		}
		for _, parsed := range onceLog.planned {
			if parsed != any(onceLog.validated[0]) {
				t.Fatal("Plan did not receive the validated value")
			}
		}
		onceLog.validated, onceLog.planned = nil, nil
		if _, err := ApplyInMemory(src, plan, Options{}); err != nil {
			t.Fatal(err)
		}
		if len(onceLog.validated) != 1 || len(onceLog.planned) != 2 {
			t.Fatalf("apply: validated %d, planned %d", len(onceLog.validated), len(onceLog.planned))
		}
	})
}

// The quoted-token proof decodes the token alone and compares value and
// style. The byte scanner makes it redundant for real input, so it is tested
// directly.
func TestQuotedTokenProof(t *testing.T) {
	double := yaml.DoubleQuotedStyle
	single := yaml.SingleQuotedStyle
	cases := []struct {
		name  string
		token string
		node  yaml.Node
		ok    bool
	}{
		{"matches", `"abc"`, yaml.Node{Value: "abc", Style: double}, true},
		{"escape matches", `"a\tb"`, yaml.Node{Value: "a\tb", Style: double}, true},
		{"single matches", `'it''s'`, yaml.Node{Value: "it's", Style: single}, true},
		{"flow style ignored", `"abc"`, yaml.Node{Value: "abc", Style: double | yaml.FlowStyle}, true},
		{"different value", `"abc"`, yaml.Node{Value: "abd", Style: double}, false},
		{"different style", `'abc'`, yaml.Node{Value: "abc", Style: double}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			end, r := quotedEnd([]byte(tc.token), 0, len(tc.token), &tc.node)
			if (r == nil) != tc.ok || (r == nil && end != len(tc.token)) {
				t.Fatalf("end %d, refusal %v", end, r)
			}
		})
	}
}

func TestSameDocuments(t *testing.T) {
	file, r := parseFile([]byte("a: 1\n---\nb: 2\n"))
	if r != nil {
		t.Fatal(r)
	}
	values := []any{copyValue(file.docs[0].value), copyValue(file.docs[1].value)}
	if r := sameDocuments(file, values); r != nil {
		t.Fatal(r)
	}
	if r := sameDocuments(file, values[:1]); ReasonOf(r) != ReasonDecodeMismatch {
		t.Fatalf("fewer expected documents: %v", r)
	}
	if r := sameDocuments(file, append(values, map[string]any{})); ReasonOf(r) != ReasonDecodeMismatch {
		t.Fatalf("more expected documents: %v", r)
	}
	values[1].(map[string]any)["b"] = "other"
	if r := sameDocuments(file, values); ReasonOf(r) != ReasonDecodeMismatch {
		t.Fatalf("different value: %v", r)
	}
}

// assertSpanShape is an oracle that does not use the sentinel substitution:
// a plain span is exactly the decoded text, and a quoted span starts and
// ends with its quote and decodes alone to the value. A span that swallowed
// trailing blanks or a comment would fail both.
func assertSpanShape(t testing.TB, src []byte, span Span) {
	t.Helper()
	file, r := parseFile(src)
	if r != nil {
		t.Fatalf("parse: %v", r)
	}
	token, ok := file.tokenIndex()[span.Start]
	if !ok {
		t.Fatalf("no token starts at %d", span.Start)
	}
	text := src[span.Start:span.End]
	switch first := text[0]; {
	case first == '"' || first == '\'':
		if len(text) < 2 || text[len(text)-1] != first {
			t.Fatalf("quoted span %q does not end with its quote", text)
		}
		alone, ok := decodeLoneScalar(text)
		if !ok || alone.Value != token.node.Value {
			t.Fatalf("quoted span %q does not decode alone to %q", text, token.node.Value)
		}
	default:
		if string(text) != token.node.Value {
			t.Fatalf("plain span %q is not the decoded text %q", text, token.node.Value)
		}
		if text[0] == ' ' || text[0] == '\t' || text[len(text)-1] == ' ' || text[len(text)-1] == '\t' {
			t.Fatalf("plain span %q has blanks at an end", text)
		}
	}
}

func TestSpanShapeOracle(t *testing.T) {
	src := []byte("a:   plain value   # comment\nb: \"quoted\"   \nc: 'single'  # x\n")
	file, r := parseFile(src)
	if r != nil {
		t.Fatal(r)
	}
	for start, token := range file.tokenIndex() {
		span, err := Locate(src, token.document, token.path, token.part)
		if err != nil {
			t.Fatal(err)
		}
		if span.Start != start {
			t.Fatalf("span %+v at token %d", span, start)
		}
		assertSpanShape(t, src, span)
	}
	// The oracle itself must see a span that swallows what follows.
	fails := func(span Span) (failed bool) {
		defer func() {
			if recover() != nil {
				failed = true
			}
		}()
		assertSpanShape(&recordingT{}, src, span)
		return false
	}
	plain := bytes.Index(src, []byte("plain value"))
	quoted := bytes.Index(src, []byte(`"quoted"`))
	single := bytes.Index(src, []byte(`'single'`))
	for name, span := range map[string]Span{
		"plain with blanks and comment": {plain, plain + len("plain value   # comment")},
		"plain with blanks":             {plain, plain + len("plain value   ")},
		"plain with a leading blank":    {plain - 1, plain + len("plain value")},
		"quoted with blanks":            {quoted, quoted + len(`"quoted"   `)},
		"quoted without its end":        {quoted, quoted + len(`"quoted`)},
		"single with a comment":         {single, single + len(`'single'  # x`)},
	} {
		if !fails(span) {
			t.Errorf("the oracle accepted: %s", name)
		}
	}
}

// recordingT turns a failing oracle into a panic that the test recovers.
type recordingT struct{ testing.TB }

func (recordingT) Helper()                  {}
func (r *recordingT) Fatalf(string, ...any) { panic(r) }
