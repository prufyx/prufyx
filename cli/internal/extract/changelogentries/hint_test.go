// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func hintCode(t *testing.T, err error, code string) {
	t.Helper()
	var he *HintError
	if !errors.As(err, &he) || he.Code != code {
		t.Fatalf("want hint refusal %s, got %v", code, err)
	}
}

const hintDocs = "# v1.1.0\n\n- c\n\n# v1.0.1\n\n- b\n\n# v1.0.0\n\n- a\n"

func hintFixtureTree(t *testing.T) map[string]string {
	t.Helper()
	// docs/CHANGELOG.md has every version; CHANGELOG.md only the newest one.
	return map[string]string{"a|docs/CHANGELOG.md": hintDocs, "a|CHANGELOG.md": "# v1.1.0\n\n- c\n"}
}

func TestHintDecodeStrict(t *testing.T) {
	ok := `{"source":"path","path":"docs/CHANGELOG.md","style":"version-v-prefixed"}`
	if _, err := DecodeHint([]byte(ok)); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ raw, code string }{
		"unknown field":   {`{"source":"path","path":"CHANGELOG.md","style":"version-plain","extra":1}`, HintMalformed},
		"repeated key":    {`{"source":"path","path":"CHANGELOG.md","path":"x.md","style":"version-plain"}`, HintMalformed},
		"trailing":        {ok + ` {}`, HintMalformed},
		"not an object":   {`[]`, HintMalformed},
		"empty":           {``, HintMalformed},
		"oversized":       {`{"source":"path","path":"` + strings.Repeat("a", MaxHintBytes) + `.md","style":"version-plain"}`, HintMalformed},
		"unknown style":   {`{"source":"path","path":"CHANGELOG.md","style":"version-made-up"}`, HintStyleUnknown},
		"boundary style":  {`{"source":"path","path":"CHANGELOG.md","style":"unreleased"}`, HintStyleUnknown},
		"release body":    {`{"source":"release-body","style":"version-plain"}`, HintSourceUnsupport},
		"traversal":       {`{"source":"path","path":"../etc/passwd.md","style":"version-plain"}`, HintPathInvalid},
		"inner traversal": {`{"source":"path","path":"docs/../CHANGELOG.md","style":"version-plain"}`, HintPathInvalid},
		"absolute":        {`{"source":"path","path":"/CHANGELOG.md","style":"version-plain"}`, HintPathInvalid},
		"backslash":       {`{"source":"path","path":"docs\\CHANGELOG.md","style":"version-plain"}`, HintPathInvalid},
		"not markdown":    {`{"source":"path","path":"CHANGELOG.toml","style":"version-plain"}`, HintPathInvalid},
		"no path":         {`{"source":"path","style":"version-plain"}`, HintPathInvalid},
	} {
		_, err := DecodeHint([]byte(c.raw))
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		hintCode(t, err, c.code)
	}
}

func TestHintedRowEqualsUnhintedRow(t *testing.T) {
	src := rcFixture(t, threeTags, hintFixtureTree(t))
	plain, err := ProposeRow(src, "notes", rcRepo, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plain.Row.Path != "docs/CHANGELOG.md" {
		t.Fatalf("fixture does not find the docs file: %+v", plain.Row)
	}
	h := Hint{Source: "path", Path: "docs/CHANGELOG.md", Style: "version-v-prefixed"}
	hinted, err := ProposeRowHint(src, nil, "notes", rcRepo, nil, &h)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(plain)
	b, _ := json.Marshal(hinted)
	da, _ := plain.RowDigest()
	db, _ := hinted.RowDigest()
	if string(a) != string(b) || da != db {
		t.Fatalf("hinted row differs:\n%s\n%s", a, b)
	}
}

func TestHintToWrongFileYieldsNoRowFromTheBar(t *testing.T) {
	src := rcFixture(t, threeTags, hintFixtureTree(t))
	h := Hint{Source: "path", Path: "CHANGELOG.md", Style: "version-v-prefixed"}
	p, err := ProposeRowHint(src, nil, "notes", rcRepo, nil, &h)
	if p != nil {
		t.Fatalf("a row from a misleading hint: %+v", p)
	}
	wantNoRow(t, err, NoRowPartialCoverage)
	// A wrong style on the right file locates nothing: no row either.
	h = Hint{Source: "path", Path: "docs/CHANGELOG.md", Style: "version-bracketed"}
	p, err = ProposeRowHint(src, nil, "notes", rcRepo, nil, &h)
	if p != nil {
		t.Fatalf("a row from a wrong style: %+v", p)
	}
	wantNoRow(t, err, NoRowNoCandidate)
}

func TestHintMissingOrUnreadFile(t *testing.T) {
	src := rcFixture(t, threeTags, hintFixtureTree(t))
	_, err := ProposeRowHint(src, nil, "notes", rcRepo, nil, &Hint{Source: "path", Path: "docs/NOPE.md", Style: "version-plain"})
	hintCode(t, err, HintPathMissing)
	// A file that exists but is no place the closed candidates read.
	tree := hintFixtureTree(t)
	tree["a|elsewhere/NOTES.md"] = hintDocs
	src = rcFixture(t, threeTags, tree)
	_, err = ProposeRowHint(src, nil, "notes", rcRepo, nil, &Hint{Source: "path", Path: "elsewhere/NOTES.md", Style: "version-v-prefixed"})
	hintCode(t, err, HintNoCandidate)
	// An invalid hint object is refused before anything is read.
	_, err = ProposeRowHint(src, nil, "notes", rcRepo, nil, &Hint{Source: "path", Path: "../x.md", Style: "version-plain"})
	hintCode(t, err, HintPathInvalid)
}

func TestHintNarrowsToTemplatePath(t *testing.T) {
	src := rcFixture(t, threeTags, map[string]string{
		"a|docs/releases/v1.0.0.md": pvBody, "a|docs/releases/v1.0.1.md": pvBody, "a|docs/releases/v1.1.0.md": pvBody,
	})
	plain, err := ProposeRow(src, "notes", rcRepo, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := Hint{Source: "path", Path: "docs/releases/v1.1.0.md", Style: "version-plain"}
	hinted, err := ProposeRowHint(src, nil, "notes", rcRepo, nil, &h)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(plain)
	b, _ := json.Marshal(hinted)
	if string(a) != string(b) {
		t.Fatalf("%s\n%s", a, b)
	}
}

func TestHintKeysAreExactLowercase(t *testing.T) {
	for name, raw := range map[string]string{
		"Path":         `{"source":"path","Path":"CHANGELOG.md","style":"version-plain"}`,
		"PATH":         `{"source":"path","PATH":"CHANGELOG.md","style":"version-plain"}`,
		"Source":       `{"Source":"path","path":"CHANGELOG.md","style":"version-plain"}`,
		"Style":        `{"source":"path","path":"CHANGELOG.md","Style":"version-plain"}`,
		"case repeat":  `{"source":"path","path":"a.md","Path":"b.md","style":"version-plain"}`,
		"case repeat2": `{"source":"path","PATH":"a.md","path":"b.md","style":"version-plain"}`,
	} {
		_, err := DecodeHint([]byte(raw))
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		hintCode(t, err, HintMalformed)
	}
}

func TestHintSuffixIsCaseExact(t *testing.T) {
	_, err := DecodeHint([]byte(`{"source":"path","path":"CHANGELOG.MD","style":"version-plain"}`))
	hintCode(t, err, HintPathInvalid)
}

// A hint may pick a different valid candidate than the unhinted run, but the
// bar applies to it in full: a weaker source passes only with the bar written
// into the row, and a source below the bar is no row.
func TestHintedCandidateStillFacesTheBar(t *testing.T) {
	tags := map[string]byte{}
	var all, newest6, newest4 strings.Builder
	for i := 7; i >= 0; i-- {
		v := "1." + string(rune('0'+i)) + ".0"
		tags["v"+v] = 'a'
		h := "# v" + v + "\n\n- c\n\n"
		all.WriteString(h)
		if i >= 2 {
			newest6.WriteString(h)
		}
		if i >= 4 {
			newest4.WriteString(h)
		}
	}
	src := rcFixture(t, tags, map[string]string{"a|docs/CHANGELOG.md": all.String(), "a|CHANGELOG.md": newest6.String()})
	plain, err := ProposeRow(src, "notes", rcRepo, nil)
	if err != nil || plain.Row.Path != "docs/CHANGELOG.md" || plain.Row.MinLocatedNewest != nil {
		t.Fatalf("%v %+v", err, plain)
	}
	weak, err := ProposeRowHint(src, nil, "notes", rcRepo, nil, &Hint{Source: "path", Path: "CHANGELOG.md", Style: "version-v-prefixed"})
	if err != nil {
		t.Fatal(err)
	}
	if weak.Row.Path != "CHANGELOG.md" || weak.Row.MinLocatedNewest == nil || *weak.Row.MinLocatedNewest != 6 {
		t.Fatalf("the weaker hinted candidate must carry its bar: %+v", weak.Row)
	}
	src = rcFixture(t, tags, map[string]string{"a|docs/CHANGELOG.md": all.String(), "a|CHANGELOG.md": newest4.String()})
	p, err := ProposeRowHint(src, nil, "notes", rcRepo, nil, &Hint{Source: "path", Path: "CHANGELOG.md", Style: "version-v-prefixed"})
	if p != nil {
		t.Fatalf("a row below the bar: %+v", p)
	}
	wantNoRow(t, err, NoRowPartialCoverage)
}

func TestHintStyleIgnoredForPerVersionCandidate(t *testing.T) {
	src := rcFixture(t, threeTags, map[string]string{
		"a|docs/releases/v1.0.0.md": pvBody, "a|docs/releases/v1.0.1.md": pvBody, "a|docs/releases/v1.1.0.md": pvBody,
	})
	var out [2]string
	for i, st := range []string{"version-plain", "version-bracketed"} {
		p, err := ProposeRowHint(src, nil, "notes", rcRepo, nil, &Hint{Source: "path", Path: "docs/releases/v1.0.1.md", Style: st})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(p)
		out[i] = string(b)
	}
	if out[0] != out[1] || strings.Contains(out[0], "version-plain") {
		t.Fatalf("%s\n%s", out[0], out[1])
	}
}
