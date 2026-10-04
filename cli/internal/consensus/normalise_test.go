// SPDX-License-Identifier: AGPL-3.0-only

package consensus

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

var k8sSpec = SectionSpec{Repo: KubernetesRepo, Path: "CHANGELOG/CHANGELOG-1.41.md", Version: "v1.41.0"}

// doc wraps body as the "## Changes by Kind" subsection of the v1.41.0
// section, between a newer and an older section. body starts on line 9.
func doc(body string) string {
	return "# v1.41.1\n\n- newer patch item\n\n# v1.41.0\n\n## Changes by Kind\n\n" + body + "\n\n# v1.41.0-rc.1\n\n- older item\n"
}

func mustNormalise(t *testing.T, src string) Normalised {
	t.Helper()
	n, err := Normalise([]byte(src), k8sSpec)
	if err != nil {
		t.Fatalf("normalise: %v", err)
	}
	return n
}

func texts(n Normalised) []string {
	out := make([]string, len(n.Lines))
	for i, l := range n.Lines {
		out[i] = l.Text
	}
	return out
}

func hasFlag(l Line, f string) bool {
	for _, x := range l.Flags {
		if x == f {
			return true
		}
	}
	return false
}

func refusalCode(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	return ""
}

func TestNormaliseSectionSelection(t *testing.T) {
	src := "# v1.41.0\n\n[Documentation](https://docs.example.invalid)\n\n## Downloads for v1.41.0\n\n| file | hash |\n| --- | --- |\n\n" +
		"## Changelog since v1.40.0\n\n## Urgent Upgrade Notes\n\n### (Read this)\n\n- a\n\n## Changes by Kind\n\n### Feature\n\n- b\n  more\n\n" +
		"## Dependencies\n\n- github.com/x: v1 → v2\n\n # v1.41.0-rc.1\n\n- rc\n"
	n := mustNormalise(t, src)
	want := []string{"## Urgent Upgrade Notes", "", "### (Read this)", "", "- a", "", "## Changes by Kind", "", "### Feature", "", "- b", "  more", ""}
	if !reflect.DeepEqual(texts(n), want) {
		t.Fatalf("section %q, want %q", texts(n), want)
	}
	if n.Lines[0].Original != 12 || n.Lines[6].Original != 18 || !n.Parsed() {
		t.Fatalf("original lines %d %d, problems %v", n.Lines[0].Original, n.Lines[6].Original, n.Problems)
	}
	// One subsection is enough; the release section ends at a level-1
	// heading with up to three leading spaces.
	// An indented level-1 heading does not end the section for the
	// verifier (it may sit in a list item), but it is a problem and a
	// barrier: what follows it renders in another section.
	n = mustNormalise(t, "# v1.41.0\n\n## Urgent Upgrade Notes\n\n- x\n\n   # v1.41.0-rc.1\n\n## Changes by Kind\n\n- rc\n")
	if len(n.Barriers) != 1 || n.Barriers[0].Original != 7 || n.Parsed() {
		t.Fatalf("barriers %v problems %v", n.Barriers, n.Problems)
	}
}

func TestNormaliseSectionRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec SectionSpec
		src  string
		code string
	}{
		{"other repository", SectionSpec{Repo: "github.com/example/other", Path: k8sSpec.Path, Version: "v1.41.0"}, doc("- x"), "no-section-rule"},
		{"other path", SectionSpec{Repo: KubernetesRepo, Path: "CHANGELOG.md", Version: "v1.41.0"}, doc("- x"), "no-section-rule"},
		{"minor mismatch", SectionSpec{Repo: KubernetesRepo, Path: "CHANGELOG/CHANGELOG-1.40.md", Version: "v1.41.0"}, doc("- x"), "no-section-rule"},
		{"patch release", SectionSpec{Repo: KubernetesRepo, Path: k8sSpec.Path, Version: "v1.41.1"}, doc("- x"), "no-section-rule"},
		{"no heading", k8sSpec, "# v1.40.0\n## Changes by Kind\n- x\n", "no-section"},
		{"two headings", k8sSpec, doc("- x\n# v1.41.0\n## Changes by Kind\n- y"), "section-ambiguous"},
		{"no citable subsection", k8sSpec, "# v1.41.0\n\n## Downloads\n\n- x\n", "no-section"},
		{"subsection twice", k8sSpec, doc("- x\n\n## Changes by Kind\n\n- y"), "section-ambiguous"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Normalise([]byte(tc.src), tc.spec)
			if refusalCode(err) != tc.code {
				t.Fatalf("err %v, want %s", err, tc.code)
			}
		})
	}
}

// Lines in the shape of real release notes are inside the grammar.
func TestNormaliseGrammarAccepts(t *testing.T) {
	body := strings.Join([]string{
		"### Deprecation",
		"",
		"- Removed the `RetiredKnob` feature gate. ([#140001](https://github.com/kubernetes/kubernetes/pull/140001), [@dev-c](https://github.com/dev-c)) [SIG Node and Apps]",
		"- Fixed `<none>` and `a | b` and `<!--` in code, a < b, R&amp;D, *emphasis* and __strong__. ([#7](https://github.com/kubernetes/kubernetes/issues/7))",
		"  See [the guide](https://kubernetes.io/docs/concepts/) and [docs](https://k8s.io/x#y).",
		"  - nested item",
		"    - deeper item",
		"      - deepest item",
		"        continued",
		"* star item",
		"Paragraph text, with a bracket [SIG Node] and #140001.",
		"",
		"#### Heading four",
		"",
		"- last",
	}, "\n")
	n := mustNormalise(t, doc(body))
	if !n.Parsed() {
		t.Fatalf("problems %v", n.Problems)
	}
}

func TestNormaliseGrammarProblems(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"<div>", "raw HTML"},
		{"- text </span> more", "raw HTML"},
		{"<!-- comment -->", "raw HTML"},
		{"- a <!--", "raw HTML"},
		{"<?php ?>", "raw HTML"},
		{"<![CDATA[ x ]]>", "raw HTML"},
		{"- see <https://github.com/kubernetes/kubernetes/pull/1>", "raw HTML"},
		{"- <podname> path", "raw HTML"},
		{"- end -->", "comment marker"},
		{"- ![alt](https://kubernetes.io/a.png)", "image"},
		{"- ![alt]", "image"},
		{"[ref]: https://kubernetes.io/x", "link reference definition"},
		{"[^1]: footnote", "link reference definition"},
		{"- see[^1]", "footnote"},
		{"- a [link][ref]", "reference link"},
		{"    - indented code", "list item indentation"},
		{"    plain indented", "indented code or unaligned indentation"},
		{"```", "fenced code"},
		{"~~~", "fenced code"},
		{"===", "setext underline or thematic break"},
		{"---", "setext underline or thematic break"},
		{"* * *", "setext underline or thematic break"},
		{"| a | b |", "table cell"},
		{"- ~~struck~~", "strikethrough"},
		{"- a\tb", "tab"},
		{"1. ordered", "ordered list"},
		{"+ plus", "list marker +"},
		{"> quote", "block quote"},
		{"- [x](https://kubernetes.io/a \"title\")", "link form"},
		{"- [x](https://example.invalid/a)", "link target"},
		{"- [#1](https://github.com/example/kubernetes/pull/1)", "link target"},
		{"- [#1](http://github.com/kubernetes/kubernetes/pull/1)", "link target"},
		{"- [someone](https://github.com/dev-x)", "link target"},
		{"- [x](https://github.com/example/kubernetes)", "link target"},
		{"- [x](https://gitlab.com/kubernetes/kubernetes)", "link target"},
		{"- a \\`b` c", "unmatched or escaped backtick"},
		{"- a `b", "unmatched or escaped backtick"},
		{"-     code after the marker", "item text indentation"},
		{" - one space", "list item indentation"},
		{" ### heading", "indented heading"},
		{"#Heading", "heading form"},
		{"-", "setext underline or thematic break"},
	} {
		n := mustNormalise(t, doc(tc.line))
		if n.Parsed() || !strings.Contains(n.Problems[0].Reason, tc.want) || n.Problems[0].Original != 9 {
			t.Errorf("%q: problems %v, want %q on line 9", tc.line, n.Problems, tc.want)
		}
	}
	// Nesting: under an open item, at most MaxListDepth deep; continuation
	// lines at most five columns past their item's marker.
	for _, body := range []string{"- a\n  - b\n    - c\n      - d\n        - e", "Paragraph\n  - nested under nothing", "- a\n      six columns", "### H\n  - after a heading", "- a\n - odd", "- a\n   - three", "- a\n    - jump", "- a\n\n      - jump after blank"} {
		if mustNormalise(t, doc(body)).Parsed() {
			t.Errorf("%q parsed", body)
		}
	}
}

// A construct opened before a subsection and still open at its heading
// swallows the heading when rendered.
func TestNormaliseOpenConstructBeforeSubsection(t *testing.T) {
	for _, opener := range []string{"<!--", "```", "<pre>", "<?", "<![CDATA[", "<!DOCTYPE"} {
		src := "# v1.41.0\n\n" + opener + "\n\n## Changes by Kind\n\n- Removed the SilentDial feature gate.\n\n# v1.41.0-rc.1\n"
		n := mustNormalise(t, src)
		if n.Parsed() || !strings.Contains(n.Problems[0].Reason, "left open before the heading") {
			t.Errorf("%q: problems %v", opener, n.Problems)
		}
	}
	// Closed constructs before the subsection are fine.
	for _, closed := range []string{"<!-- x -->", "<!-->", "```\nx\n```", "<pre>\nx\n</pre>", "<div>\nx"} {
		src := "# v1.41.0\n\n" + closed + "\n\n## Changes by Kind\n\n- y\n"
		if n := mustNormalise(t, src); !n.Parsed() {
			t.Errorf("%q: problems %v", closed, n.Problems)
		}
	}
}

func TestNormaliseInvisibleCharacters(t *testing.T) {
	for _, r := range []rune{0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2060, 0x2061, 0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF, 0x00AD, 0xFE0F, 0xE0041, 0x2028} {
		n := mustNormalise(t, doc("- Silent"+string(r)+"Dial"))
		l := n.Lines[2]
		if l.Text != "- SilentDial" || !hasFlag(l, FlagInvisibleCharacter) || !l.Hidden() {
			t.Fatalf("U+%04X: %q %v", r, l.Text, l.Flags)
		}
	}
}

func TestNormaliseControlCharacters(t *testing.T) {
	for _, c := range []string{"\x00", "\x1b", "\r", "\x7f", "\u0085", "\x08"} {
		n := mustNormalise(t, doc("- a"+c+"b"))
		l := n.Lines[2]
		if l.Text != "- ab" || !hasFlag(l, FlagControlCharacter) || !l.Hidden() {
			t.Fatalf("%q: %q %v", c, l.Text, l.Flags)
		}
	}
}

func TestNormaliseLineEndings(t *testing.T) {
	lf := mustNormalise(t, doc("- one\n- two"))
	crlf := mustNormalise(t, strings.ReplaceAll(doc("- one\n- two"), "\n", "\r\n"))
	if !bytes.Equal(lf.Text(), crlf.Text()) || lf.Digest() != crlf.Digest() {
		t.Fatalf("CRLF differs:\n%q\n%q", lf.Text(), crlf.Text())
	}
	for _, l := range crlf.Lines {
		if len(l.Flags) != 0 {
			t.Fatalf("CRLF flagged: %+v", l)
		}
	}
}

func TestNormaliseLineMap(t *testing.T) {
	n := mustNormalise(t, doc("- a\n<div>\n- b"))
	for i, l := range n.Lines {
		if l.Original != 7+i {
			t.Fatalf("normalised line %d maps to %d, want %d", i+1, l.Original, 7+i)
		}
	}
	raw, err := LineMapJSON(n)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"normaliserVersion": "` + NormaliserVersion + `"`, `"original": 11`, `"problem": "raw HTML"`, `"reason": "raw HTML"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("line map lacks %s:\n%s", want, raw)
		}
	}
}

func TestNormaliseDeterministic(t *testing.T) {
	src := doc("- a `x` b\n- ![i](u) <b>y</b>\n  ```\n  z\n  ```\n- Silent\u200bDial")
	a, b := mustNormalise(t, src), mustNormalise(t, src)
	if !reflect.DeepEqual(a, b) || a.Digest() != b.Digest() {
		t.Fatal("two runs differ")
	}
	ma, _ := LineMapJSON(a)
	mb, _ := LineMapJSON(b)
	if !bytes.Equal(ma, mb) {
		t.Fatal("line maps differ")
	}
}

func TestNormaliseBounds(t *testing.T) {
	big := doc("- x") + strings.Repeat("a\n", MaxSourceBytes/2+1)
	if _, err := Normalise([]byte(big), k8sSpec); refusalCode(err) != "too-large" {
		t.Fatalf("large file: %v", err)
	}
	long := doc("- " + strings.Repeat("x", MaxLineBytes))
	if _, err := Normalise([]byte(long), k8sSpec); refusalCode(err) != "line-too-long" {
		t.Fatalf("long line: %v", err)
	}
	if _, err := Normalise([]byte(doc("- "+strings.Repeat("x", MaxLineBytes-2))), k8sSpec); err != nil {
		t.Fatalf("line at the bound: %v", err)
	}
	if _, err := Normalise([]byte(doc("- \xff")), k8sSpec); refusalCode(err) != "invalid-utf8" {
		t.Fatalf("invalid UTF-8: %v", err)
	}
}

func FuzzNormalise(f *testing.F) {
	f.Add(doc("- Removed the X feature gate. (#1)"))
	f.Add(doc("- a <!-- b\n- c --> d\n```\ne\n```"))
	f.Add(doc("- \u202ex\u202c <b>y</b> ![z](w) [r]: s"))
	f.Fuzz(func(t *testing.T, src string) {
		a, errA := Normalise([]byte(src), k8sSpec)
		b, errB := Normalise([]byte(src), k8sSpec)
		if (errA == nil) != (errB == nil) || (errA == nil && (!bytes.Equal(a.Text(), b.Text()) || len(a.Problems) != len(b.Problems))) {
			t.Fatal("not deterministic")
		}
		if errA != nil {
			return
		}
		for _, l := range a.Lines {
			if strings.Contains(l.Text, "\n") {
				t.Fatalf("line %q", l.Text)
			}
			for _, r := range l.Text {
				if invisible(r) || control(r) {
					t.Fatalf("line %q keeps U+%04X", l.Text, r)
				}
			}
		}
		// A parsed section has no raw HTML, image, fence or comment
		// marker outside code spans.
		if a.Parsed() {
			for _, l := range a.Lines {
				plain := codeSpans(l.Text)
				for _, bad := range []string{"<!", "<?", "![", "-->", "\t"} {
					if strings.Contains(plain, bad) {
						t.Fatalf("parsed line %q holds %q", l.Text, bad)
					}
				}
			}
		}
	})
}

// Barriers: what can hide later text when rendered, anywhere in the
// release section or left open before it.
func TestNormaliseBarriers(t *testing.T) {
	tail := "## Changes by Kind\n\n- x\n\n# v1.41.0-rc.1\n"
	for _, tc := range []struct {
		name, src, want string
	}{
		{"raw HTML outside the read subsections", "# v1.41.0\n\n## Changelog since v1.40.0\n\n<details>\n\n" + tail, "raw HTML"},
		{"inside a comment", "# v1.41.0\n\n## Changelog since v1.40.0\n\n<!--\nnote\n-->\n\n" + tail, "inside HTML block"},
		{"release heading inside a comment", "<!--\n# v1.41.0\n-->\n\n" + tail, "the release heading is inside HTML block"},
		{"element left open before the release heading", "# v1.41.1\n\n<details>\n\n- newer\n\n# v1.41.0\n\n" + tail, "HTML element <details> left open"},
		{"indented level-2 heading", "# v1.41.0\n\n  ## Changes by Kind\n\n" + tail, "indented level-1 or level-2 heading"},
	} {
		n := mustNormalise(t, tc.src)
		found := false
		for _, b := range n.Barriers {
			found = found || strings.Contains(b.Reason, tc.want)
		}
		if !found {
			t.Errorf("%s: barriers %v, want %q", tc.name, n.Barriers, tc.want)
		}
	}
	for _, tc := range []struct{ name, src string }{
		{"closed elements and unknown tags before the release", "# v1.41.1\n\n- [<code>x</code>](#x) /api/<version>/watch\n\n# v1.41.0\n\n" + tail},
		{"HTML in a code span or fenced code", "# v1.41.0\n\n## Changelog since v1.40.0\n\n- `<div>`\n\n```\n<div>\n```\n\n" + tail},
	} {
		if n := mustNormalise(t, tc.src); len(n.Barriers) != 0 {
			t.Errorf("%s: barriers %v", tc.name, n.Barriers)
		}
	}
}
