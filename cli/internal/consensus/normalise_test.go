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

// doc wraps body as the v1.41.0 section between a newer and an older
// section.
func doc(body string) string {
	return "# v1.41.1\n\n- newer patch item\n\n# v1.41.0\n\n" + body + "\n# v1.41.0-rc.1\n\n- older item\n"
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

func lineWith(t *testing.T, n Normalised, original int) Line {
	t.Helper()
	for _, l := range n.Lines {
		if l.Original == original {
			return l
		}
	}
	t.Fatalf("no normalised line for original line %d", original)
	return Line{}
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
	n := mustNormalise(t, doc("- one\n- two"))
	want := []string{"# v1.41.0", "", "- one", "- two"}
	if !reflect.DeepEqual(texts(n), want) {
		t.Fatalf("section %q, want %q", texts(n), want)
	}
	if n.Lines[0].Original != 5 || n.Lines[3].Original != 8 {
		t.Fatalf("original lines %d..%d", n.Lines[0].Original, n.Lines[3].Original)
	}
	// The last section of a file runs to its end; trailing spaces after the
	// heading are allowed; "# v1.41.0-rc.1" is not "# v1.41.0".
	n = mustNormalise(t, "# v1.41.0-rc.1\n- rc\n# v1.41.0  \n- last\n")
	if want := []string{"# v1.41.0", "- last"}; !reflect.DeepEqual(texts(n), want) {
		t.Fatalf("section %q, want %q", texts(n), want)
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
		{"no heading", k8sSpec, "# v1.40.0\n- x\n", "no-section"},
		{"two headings", k8sSpec, doc("- x\n# v1.41.0\n- y"), "section-ambiguous"},
		{"heading only in a comment", k8sSpec, "<!--\n# v1.41.0\n-->\n- x\n", "no-section"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Normalise([]byte(tc.src), tc.spec)
			if refusalCode(err) != tc.code {
				t.Fatalf("err %v, want %s", err, tc.code)
			}
		})
	}
}

func TestNormaliseHTMLComments(t *testing.T) {
	n := mustNormalise(t, doc("- kept <!-- hidden --> text\n<!--\n- hidden item\n-->\n- after"))
	want := []string{"# v1.41.0", "", "- kept  text", "", "", "", "- after"}
	if !reflect.DeepEqual(texts(n), want) {
		t.Fatalf("lines %q, want %q", texts(n), want)
	}
	for _, orig := range []int{7, 8, 9, 10} {
		if !hasFlag(lineWith(t, n, orig), FlagHTMLComment) {
			t.Fatalf("line %d not flagged: %v", orig, lineWith(t, n, orig).Flags)
		}
	}
	if hasFlag(lineWith(t, n, 11), FlagHTMLComment) || n.Truncated {
		t.Fatal("a line after the comment is flagged")
	}
	if !lineWith(t, n, 7).Hidden() {
		t.Fatal("a comment is hidden content")
	}
}

func TestNormaliseUnterminatedComment(t *testing.T) {
	n := mustNormalise(t, doc("- before\n- cut <!-- never closed\n- hidden item"))
	if !n.Truncated {
		t.Fatal("not truncated")
	}
	if !hasFlag(lineWith(t, n, 8), FlagUnterminatedComment) {
		t.Fatalf("start line flags %v", lineWith(t, n, 8).Flags)
	}
	got := strings.Join(texts(n), "\n")
	if strings.Contains(got, "hidden item") || strings.Contains(got, "older item") || !strings.Contains(got, "- before") {
		t.Fatalf("section after an unterminated comment:\n%s", got)
	}
}

func TestNormaliseHTMLTags(t *testing.T) {
	n := mustNormalise(t, doc("- a <span hidden>b</span> c </release_notes>\n- link <https://github.com/kubernetes/kubernetes/pull/1>\n- code `<none>` stays\n- open <div\n- plain a < b"))
	got := texts(n)
	if got[2] != "- a b c" {
		t.Fatalf("tags: %q", got[2])
	}
	if !hasFlag(n.Lines[2], FlagHTMLTag) {
		t.Fatal("tags not flagged")
	}
	if got[3] != "- link https://github.com/kubernetes/kubernetes/pull/1" || hasFlag(n.Lines[3], FlagHTMLTag) {
		t.Fatalf("autolink: %q %v", got[3], n.Lines[3].Flags)
	}
	if got[4] != "- code `<none>` stays" || hasFlag(n.Lines[4], FlagHTMLTag) {
		t.Fatalf("code span: %q %v", got[4], n.Lines[4].Flags)
	}
	if !hasFlag(n.Lines[5], FlagHTMLTag) {
		t.Fatal("a tag continued on the next line is not flagged")
	}
	if hasFlag(n.Lines[6], FlagHTMLTag) || got[6] != "- plain a < b" {
		t.Fatalf("a comparison is not a tag: %q %v", got[6], n.Lines[6].Flags)
	}
}

func TestNormaliseLinkReferences(t *testing.T) {
	n := mustNormalise(t, doc("- item\n  [ref]: https://example.invalid \"Removed X\"\n[other]: https://example.invalid"))
	got := texts(n)
	if got[3] != "" || got[4] != "" || !hasFlag(n.Lines[3], FlagLinkReference) {
		t.Fatalf("link references: %q", got)
	}
}

func TestNormaliseImages(t *testing.T) {
	n := mustNormalise(t, doc("- ![Removed X](https://example.invalid/a.png) shown ![alt][ref]"))
	if got := texts(n)[2]; got != "-  shown" || !hasFlag(n.Lines[2], FlagImage) {
		t.Fatalf("images: %q %v", got, n.Lines[2].Flags)
	}
}

func TestNormaliseFencedCode(t *testing.T) {
	n := mustNormalise(t, doc("- item\n  ```yaml\n  removed: X\n  ``` not a close\n  ```\n- after\n~~~~\nx\n~~~\n~~~~\n- end"))
	got := texts(n)
	for _, i := range []int{3, 4, 5, 6, 8, 9, 10, 11} {
		if got[i] != "" || !hasFlag(n.Lines[i], FlagCodeBlock) {
			t.Fatalf("line %d %q %v", i, got[i], n.Lines[i].Flags)
		}
	}
	if got[7] != "- after" || got[12] != "- end" || n.Truncated {
		t.Fatalf("lines %q", got)
	}
	n = mustNormalise(t, doc("- item\n```\nremoved: X\n- hidden"))
	if !n.Truncated || !hasFlag(n.Lines[3], FlagUnterminatedCodeBlock) || strings.Contains(string(n.Text()), "hidden") {
		t.Fatalf("unterminated code block: %q", texts(n))
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
	// A tab is ordinary text.
	if l := mustNormalise(t, doc("- a\tb")).Lines[2]; l.Text != "- a\tb" || len(l.Flags) != 0 {
		t.Fatalf("tab: %q %v", l.Text, l.Flags)
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
	n := mustNormalise(t, doc("- a\n<!--\nx\n-->\n- b"))
	for i, l := range n.Lines {
		if l.Original != 5+i {
			t.Fatalf("normalised line %d maps to %d, want %d", i+1, l.Original, 5+i)
		}
	}
	raw, err := LineMapJSON(n)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"normaliserVersion": "`+NormaliserVersion+`"`) || !strings.Contains(string(raw), `"original": 9`) {
		t.Fatalf("line map:\n%s", raw)
	}
}

func TestNormaliseDeterministic(t *testing.T) {
	src := doc("- a <!-- c --> b\n- ![i](u) `x` <b>y</b>\n  ```\n  z\n  ```\n- Silent​Dial")
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
	f.Add(doc("- ‮x‬ <b>y</b> ![z](w) [r]: s"))
	f.Fuzz(func(t *testing.T, src string) {
		a, errA := Normalise([]byte(src), k8sSpec)
		b, errB := Normalise([]byte(src), k8sSpec)
		if (errA == nil) != (errB == nil) || (errA == nil && !bytes.Equal(a.Text(), b.Text())) {
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
	})
}
