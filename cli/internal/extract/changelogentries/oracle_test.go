// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// oracleIsLinkDef is an independent, regexp-free reading of a link reference
// definition: label, colon, exactly one link-looking destination, then
// nothing or one quoted title.
// oracleBlank is CommonMark blank: ASCII spaces and tabs only.
func oracleBlank(l string) bool { return strings.Trim(l, " \t") == "" }

func oracleIsLinkDef(l string) bool {
	trim := strings.TrimLeft(l, " ")
	if len(l)-len(trim) > 3 || !strings.HasPrefix(trim, "[") {
		return false
	}
	end := strings.Index(trim, "]:")
	if end < 2 || strings.ContainsAny(trim[1:end], "[]\\") {
		return false
	}
	if first := trim[1]; first == ' ' || first == '\t' || first == '^' {
		return false // a blank label or a footnote is not a definition
	}
	rest := strings.TrimLeft(trim[end+2:], " \t")
	if rest == "" {
		return false
	}
	var dest string
	if strings.HasPrefix(rest, "<") {
		c := strings.Index(rest, ">")
		if c < 0 {
			return false
		}
		dest, rest = rest[1:c], rest[c+1:]
	} else {
		f := strings.IndexAny(rest, " \t")
		if f < 0 {
			f = len(rest)
		}
		dest, rest = rest[:f], rest[f:]
	}
	ok := false
	for _, p := range []string{"http://", "https://", "/", "./", "../", "#"} {
		if strings.HasPrefix(dest, p) {
			ok = true
		}
	}
	if !ok || strings.ContainsAny(dest, " \t<>") {
		return false
	}
	if !strings.HasPrefix(strings.TrimLeft(trim[end+2:], " \t"), "<") && strings.ContainsAny(dest, "()") {
		return false // a bare destination holds no parenthesis
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return true
	}
	if len(rest) < 2 {
		return false
	}
	open, closing := rest[0], rest[len(rest)-1]
	body := rest[1 : len(rest)-1]
	switch {
	case open == '"' && closing == '"':
		return !strings.Contains(body, `"`)
	case open == '\'' && closing == '\'':
		return !strings.Contains(body, "'")
	case open == '(' && closing == ')':
		return !strings.ContainsAny(body, "()")
	}
	return false
}

// oracleAccount is an independent line accounting of an entry. It does not
// call the scanner: it takes the raw lines and the entry's own spans and
// requires every non-blank line of the section to lie in exactly one of a
// heading span, an item span, or be a link reference definition.
func oracleAccount(t *testing.T, raw []byte, e *Entry) {
	t.Helper()
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	start, end := e.Section.StartLine, e.Section.EndLine
	if start < 1 || end > len(lines) || start > end {
		t.Fatalf("span %d..%d outside the file (%d lines)", start, end, len(lines))
	}
	if oracleBlank(lines[end-1]) {
		t.Fatal("section ends on a blank line")
	}
	owner := make([]string, len(lines)+2)
	claim := func(from, to int, who string) {
		for n := from; n <= to; n++ {
			if n < start || n > end {
				t.Fatalf("%s line %d lies outside the section %d..%d", who, n, start, end)
			}
			if owner[n] != "" {
				t.Fatalf("line %d claimed twice: %s and %s", n, owner[n], who)
			}
			owner[n] = who
		}
	}
	for _, h := range e.Structure {
		claim(h.Line, h.EndLine, "heading")
	}
	prevEnd := 0
	for _, it := range e.Items {
		if it.StartLine <= prevEnd {
			t.Fatalf("items overlap or are out of order at line %d", it.StartLine)
		}
		prevEnd = it.EndLine
		if oracleBlank(lines[it.StartLine-1]) || oracleBlank(lines[it.EndLine-1]) {
			t.Fatalf("item %d..%d starts or ends on a blank line", it.StartLine, it.EndLine)
		}
		for n := it.StartLine; n <= it.EndLine; n++ {
			if oracleBlank(lines[n-1]) {
				continue // interior blank of an item
			}
			claim(n, n, "item")
		}
	}
	var heads, blanks, defs, itemLines int
	for n := start; n <= end; n++ {
		l := lines[n-1]
		inItem := false
		for _, it := range e.Items {
			if n >= it.StartLine && n <= it.EndLine {
				inItem = true
			}
		}
		switch {
		case owner[n] == "heading":
			heads++
		case owner[n] == "item":
			itemLines++
		case oracleBlank(l):
			blanks++
		case oracleIsLinkDef(l) && !inItem:
			defs++
		default:
			t.Fatalf("line %d is not accounted for: %q", n, l)
		}
	}
	if heads+blanks+defs+itemLines != end-start+1 {
		t.Fatal("tiling does not add up")
	}
	got := e.Tiling
	if got.Lines != end-start+1 || got.Headings != heads || got.LinkDefs != defs || got.ItemLines != itemLines || got.Blanks != blanks {
		t.Fatalf("tiling %+v differs from the oracle {lines %d headings %d blanks %d defs %d items %d}", got, end-start+1, heads, blanks, defs, itemLines)
	}
	if e.ResidueLines != 0 {
		t.Fatal("residue in a returned entry")
	}
}

// oracleListItems counts column-zero list bullets in the section, the way a
// reader would count them by eye.
func oracleListItems(raw []byte, e *Entry) int {
	lines := strings.Split(strings.TrimSuffix(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n"), "\n")
	n, fence := 0, false
	for _, l := range lines[e.Section.StartLine-1 : e.Section.EndLine] {
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			fence = !fence
			continue
		}
		if !fence && (strings.HasPrefix(l, "* ") || strings.HasPrefix(l, "- ")) {
			n++
		}
	}
	return n
}

type fixtureCase struct {
	target Target
	tag    string
	items  int
	marks  map[string]int // marker -> count
}

func TestFixtureEntriesAndOracle(t *testing.T) {
	r := fixtureRoot(t)
	for _, c := range []fixtureCase{
		{promTarget, "v3.5.0", -1, nil},
		{promTarget, "v3.4.0", -1, nil},
		{cortexTarget, "v1.18.0", -1, nil},
		{thanosTarget, "v0.38.0", -1, nil},
		{thanosTarget, "v0.37.0", -1, nil},
	} {
		t.Run(c.target.Component+"/"+c.tag, func(t *testing.T) {
			tag := fixtureTag(t, r, c.target, c.tag)
			e, err := Locate(r, c.target, tag)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := r.Read(c.target.Repo, tag.Commit, c.target.Path)
			if err != nil {
				t.Fatal(err)
			}
			oracleAccount(t, raw, e)
			if n := oracleListItems(raw, e); n != len(e.Items) {
				t.Fatalf("oracle counts %d list bullets, the entry has %d items", n, len(e.Items))
			}
			for _, it := range e.Items {
				if it.Kind != "list" {
					t.Fatalf("unexpected block item %+v", it)
				}
			}
			if e.Version != strings.TrimPrefix(c.tag, "v") {
				t.Fatalf("version %s", e.Version)
			}
		})
	}
}

// TestFixturePinnedCounts pins what the real excerpts hold, so a parser
// change that drops or merges an item shows up as a number.
func TestFixturePinnedCounts(t *testing.T) {
	r := fixtureRoot(t)
	want := map[string]struct{ items, start, end int }{
		"prometheus/v3.5.0": {39, 5, 45},
		"prometheus/v3.4.0": {18, 3, 22},
		"cortex/v1.18.0":    {53, 6, 60},
		"thanos/v0.38.0":    {19, 21, 50},
		"thanos/v0.37.0":    {42, 11, 65},
	}
	targets := map[string]Target{"prometheus": promTarget, "cortex": cortexTarget, "thanos": thanosTarget}
	for k, w := range want {
		parts := strings.SplitN(k, "/", 2)
		tg := targets[parts[0]]
		e, err := Locate(r, tg, fixtureTag(t, r, tg, parts[1]))
		if err != nil {
			t.Fatal(err)
		}
		if len(e.Items) != w.items || e.Section.StartLine != w.start || e.Section.EndLine != w.end {
			t.Errorf("%s: items %d span %d..%d", k, len(e.Items), e.Section.StartLine, e.Section.EndLine)
		}
	}
}

// TestInjectedResidueIsAlwaysCaught puts a thematic break into every blank
// line of a real entry in turn; each must withhold the entry.
func TestInjectedResidueIsAlwaysCaught(t *testing.T) {
	r := fixtureRoot(t)
	tag := fixtureTag(t, r, promTarget, "v3.5.0")
	raw, err := r.Read(promTarget.Repo, tag.Commit, promTarget.Path)
	if err != nil {
		t.Fatal(err)
	}
	e, err := Locate(r, promTarget, tag)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	n := 0
	for i := e.Section.StartLine; i <= e.Section.EndLine; i++ { // 1-based line i+1 follows line i
		if !oracleBlank(lines[i-1]) {
			continue
		}
		mut := append(append(append([]string{}, lines[:i]...), "---"), lines[i:]...)
		_, err := locateBytes(promTarget, "v3.5.0", []byte(strings.Join(mut, "\n")+"\n"))
		if c, _ := CodeOf(err); c != EntryParseResidue {
			t.Fatalf("break after line %d: %v", i, err)
		}
		n++
	}
	if n == 0 {
		t.Skip("no blank line in the section")
	}
}

// TestRealNegatives reads real excerpts the wrong way.
func TestRealNegatives(t *testing.T) {
	r := fixtureRoot(t)
	// Cortex v1.19.0: the file at the tag still says "in progress".
	tag := fixtureTag(t, r, cortexTarget, "v1.19.0")
	_, err := Locate(r, cortexTarget, tag)
	wantCode(t, err, EntryNotFinal)
	// A tag whose own file lacks its entry is missing; the neighbour is not used.
	prom := fixtureTag(t, r, promTarget, "v3.4.0")
	_, err = Locate(r, promTarget, extract.Tag{Name: "v3.5.0", Commit: prom.Commit})
	wantCode(t, err, EntryMissing)
	// The wrong repository's commit is not in the mirror.
	if _, err = Locate(r, thanosTarget, extract.Tag{Name: "v0.38.0", Commit: prom.Commit}); err == nil {
		t.Fatal("a commit of another repository resolved")
	}
	if _, ok := CodeOf(err); ok {
		t.Fatalf("a mirror error became a reason: %v", err)
	}
	// A patch version below the window: 3.4.2 sits in the 3.5.0 file as a
	// separate entry and is read on its own.
	p35 := fixtureTag(t, r, promTarget, "v3.5.0")
	e, err := Locate(r, promTarget, extract.Tag{Name: "v3.4.2", Commit: p35.Commit})
	if err != nil || len(e.Items) == 0 {
		t.Fatalf("3.4.2: %v", err)
	}
}
