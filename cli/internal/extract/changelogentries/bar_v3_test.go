// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// barRow is the per-version row with a per-row coverage bar.
func barRow(n int) Target {
	r := pvRow
	r.MinLocatedNewest = n
	return r
}

// eightFiles gives entries for the listed versions of eightTags (v1.0.0..v1.0.7).
func eightFiles(have ...int) map[string]string {
	f := map[string]string{}
	for _, i := range have {
		f[fmt.Sprintf("a|docs/releases/v1.0.%d.md", i)] = pvBody
	}
	return f
}

func TestRowBarCountsLocatedOfNewestEight(t *testing.T) {
	// The newest version has no entry (it was never written upstream), the
	// seven below it have.
	src := rcFixture(t, eightTags(), eightFiles(0, 1, 2, 3, 4, 5, 6))
	r := CheckRow(src, barRow(7), "d")
	if r.Status != RowPass || r.Window != 8 || r.WindowLocated != 7 || r.Bar != 7 || r.MinLocatedNewest != 7 {
		t.Fatalf("%+v", r)
	}
	// The default bar is 8: the same source fails.
	if r := CheckRow(src, pvRow, "d"); r.Status != RowFail || r.Bar != 8 || r.MinLocatedNewest != 8 || len(r.Reasons) == 0 {
		t.Fatalf("%+v", r)
	}
	if r := CheckRow(src, barRow(8), "d"); r.Status != RowFail {
		t.Fatalf("%+v", r)
	}
	// Six of eight: bar 7 fails, bars 6 and 5 pass.
	six := rcFixture(t, eightTags(), eightFiles(0, 1, 2, 3, 4, 6))
	if r := CheckRow(six, barRow(7), "d"); r.Status != RowFail || r.WindowLocated != 6 {
		t.Fatalf("%+v", r)
	}
	for _, n := range []int{6, 5} {
		if r := CheckRow(six, barRow(n), "d"); r.Status != RowPass {
			t.Fatalf("bar %d: %+v", n, r)
		}
	}
	// Four of eight fails every allowed bar.
	four := rcFixture(t, eightTags(), eightFiles(0, 1, 2, 3))
	for n := 5; n <= 8; n++ {
		if r := CheckRow(four, barRow(n), "d"); r.Status != RowFail || r.WindowLocated != 4 {
			t.Fatalf("bar %d: %+v", n, r)
		}
	}
}

func TestRowBarNeverLooserThanTheTagsAllow(t *testing.T) {
	// Fewer than a bar's worth of versions: every one must be located.
	few := rcFixture(t, map[string]byte{"v1.0.0": 'a', "v1.0.1": 'a', "v1.0.2": 'a'},
		map[string]string{"a|docs/releases/v1.0.0.md": pvBody, "a|docs/releases/v1.0.1.md": pvBody})
	if r := CheckRow(few, barRow(5), "d"); r.Status != RowFail || r.Window != 3 || r.Bar != 3 || r.WindowLocated != 2 {
		t.Fatalf("%+v", r)
	}
	// A version counts only when every one of its tags is located.
	tags := eightTags()
	tags["1.0.7"] = 'b' // a second tag of v1.0.7 whose commit has no file
	src := rcFixture(t, tags, eightFiles(0, 1, 2, 3, 4, 5, 6, 7), 'b')
	if r := CheckRow(src, barRow(8), "d"); r.Status != RowFail || r.WindowLocated != 7 {
		t.Fatalf("a version with an unlocated tag counted: %+v", r)
	}
	if r := CheckRow(src, barRow(7), "d"); r.Status != RowPass || r.WindowLocated != 7 {
		t.Fatalf("%+v", r)
	}
	// A row that locates nothing fails whatever the bar is.
	none := rcFixture(t, eightTags(), nil)
	if r := CheckRow(none, barRow(5), "d"); r.Status != RowFail {
		t.Fatalf("%+v", r)
	}
	// A typed reason that is the row's own defect still fails the row.
	bad := pvRow
	bad.Path = "docs/releases/v{version}.toml"
	bad.MinLocatedNewest = 5
	if r := CheckRow(rcFixture(t, eightTags(), eightFiles(0, 1, 2, 3, 4, 5, 6, 7)), bad, "d"); r.Status != RowFail {
		t.Fatalf("%+v", r)
	}
	// The explicit override replaces the row bar and keeps its own, stricter
	// reading: the newest N versions must all be located.
	src7 := rcFixture(t, eightTags(), eightFiles(0, 1, 2, 3, 4, 5, 6))
	if r := CheckRowMin(src7, barRow(5), "d", 7); r.Status != RowFail || r.WindowLocated != 6 {
		t.Fatalf("override: %+v", r)
	}
	if r := CheckRowMin(src7, barRow(5), "d", 0); r.Status != RowFail {
		t.Fatalf("override 0: %+v", r)
	}
	// An older source whose newest five lack entries fails a bar of five.
	old := rcFixture(t, eightTags(), eightFiles(0, 1, 2))
	if r := CheckRow(old, barRow(5), "d"); r.Status != RowFail {
		t.Fatalf("%+v", r)
	}
}

// A lower row bar never creates an entry: the version without one is still
// withheld by the one reader, so no pair can be counted for it.
func TestLowerBarCreatesNoEntry(t *testing.T) {
	src := rcFixture(t, eightTags(), eightFiles(0, 1, 2, 3, 4, 5, 6))
	tags, err := src.Tags(pvRow.Repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range tags {
		for _, row := range []Target{pvRow, barRow(5), barRow(7)} {
			m, err := BuildManifest(src, row, tag, "d")
			if err != nil {
				t.Fatal(err)
			}
			if got := tag.Name != "v1.0.7"; got != (m.Entry != nil) {
				t.Fatalf("%s with bar %d: entry %v", tag.Name, row.MinLocatedNewest, m.Entry != nil)
			}
			if m.Entry == nil && m.Withheld == nil {
				t.Fatal("neither entry nor reason")
			}
		}
	}
}

func TestRowsOfDifferentBarsInOneTable(t *testing.T) {
	src := rcFixture(t, eightTags(), eightFiles(0, 1, 2, 3, 4, 5, 6))
	a, b := barRow(7), pvRow
	a.Component, b.Component = "a-row", "b-row"
	// two rows, one repository: the table check is by component
	rs, err := CheckRows(src, []Target{a, b}, "", "d")
	if err != nil || len(rs) != 2 {
		t.Fatal(rs, err)
	}
	if rs[0].Status != RowPass || rs[0].MinLocatedNewest != 7 || rs[1].Status != RowFail || rs[1].MinLocatedNewest != 8 {
		t.Fatalf("%+v", rs)
	}
	rs, err = CheckRowsMin(src, []Target{a, b}, "", "d", 7)
	if err != nil || rs[0].Status != RowFail || rs[1].Status != RowFail || rs[0].MinLocatedNewest != 7 {
		t.Fatalf("override ignored the strict reading: %+v %v", rs, err)
	}
}

// ---- propose-rows --------------------------------------------------------

func TestProposeWritesTheBarForAMissingVersion(t *testing.T) {
	src := rcFixture(t, eightTags(), eightFiles(0, 1, 2, 3, 4, 5, 6))
	p, err := propose(t, src)
	if err != nil {
		t.Fatal(err)
	}
	if p.Row.MinLocatedNewest == nil || *p.Row.MinLocatedNewest != 7 || p.Versions != 7 || p.Window != 8 {
		t.Fatalf("%+v", p)
	}
	// The emitted row passes the loader and the row check as written.
	doc, _ := json.Marshal(struct {
		Schema string    `json:"schema"`
		Rows   []rowData `json:"rows"`
	}{TargetsSchema, []rowData{p.Row}})
	rows, err := parseTargets(doc)
	if err != nil {
		t.Fatal(err)
	}
	if r := CheckRow(src, rows[0], "d"); r.Status != RowPass || r.MinLocatedNewest != 7 {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(string(doc), `"minLocatedNewest":7`) {
		t.Fatalf("%s", doc)
	}
	// All eight located: no field.
	full := rcFixture(t, eightTags(), eightFiles(0, 1, 2, 3, 4, 5, 6, 7))
	p, err = propose(t, full)
	if err != nil || p.Row.MinLocatedNewest != nil {
		t.Fatalf("%+v %v", p, err)
	}
	// Five of eight is the lowest bar the proposal writes.
	five := rcFixture(t, eightTags(), eightFiles(1, 3, 4, 5, 6))
	p, err = propose(t, five)
	if err != nil || p.Row.MinLocatedNewest == nil || *p.Row.MinLocatedNewest != 5 {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestProposeRefusesBelowTheLowestBar(t *testing.T) {
	four := rcFixture(t, eightTags(), eightFiles(4, 5, 6, 7))
	_, err := propose(t, four)
	wantNoRow(t, err, NoRowPartialCoverage)
	// A scan of explicit tags never writes a bar: all of them must locate.
	src := rcFixture(t, eightTags(), eightFiles(0, 1, 2, 3, 4, 5, 6))
	_, err = propose(t, src, "v1.0.7", "v1.0.6")
	wantNoRow(t, err, NoRowPartialCoverage)
	p, err := propose(t, src, "v1.0.6", "v1.0.5")
	if err != nil || p.Row.MinLocatedNewest != nil {
		t.Fatalf("%+v %v", p, err)
	}
}

// ksmEight is a file of eight releases, each with a "## Note" right under its
// heading, at one commit for every tag.
func ksmEight() (map[string]byte, map[string]string) {
	var b strings.Builder
	tags := map[string]byte{}
	for i := 7; i >= 0; i-- {
		fmt.Fprintf(&b, "## v2.%d.0 / 2025-01-0%d\n\n## Note\n\n* This release builds with Go\n\n* [BUGFIX] fix %d\n\n", i, i+1, i)
		tags[fmt.Sprintf("v2.%d.0", i)] = 'a'
	}
	return tags, map[string]string{"a|CHANGELOG.md": b.String()}
}

func TestProposeTriesInnerStylesOnlyWhenNeeded(t *testing.T) {
	tags, files := ksmEight()
	p, err := propose(t, rcFixture(t, tags, files))
	if err != nil {
		t.Fatal(err)
	}
	if p.Row.HeadingStyle != "version-v-slash-date" || len(p.Row.InnerHeadingStyles) != 1 || p.Row.InnerHeadingStyles[0] != "note-first" || p.Versions != 8 {
		t.Fatalf("%+v", p.Row)
	}
	// A file that needs none gets none.
	file := "## v1.0.1\n\n- b\n\n## v1.0.0\n\n- a\n"
	p, err = propose(t, rcFixture(t, map[string]byte{"v1.0.0": 'a', "v1.0.1": 'a'}, map[string]string{"a|CHANGELOG.md": file}))
	if err != nil || p.Row.InnerHeadingStyles != nil {
		t.Fatalf("%+v %v", p, err)
	}
	// Sections one level deeper need no inner style either.
	deep := "## v1.0.1\n\n### Fixed\n\n- b\n\n## v1.0.0\n\n### Fixed\n\n- a\n"
	p, err = propose(t, rcFixture(t, map[string]byte{"v1.0.0": 'a', "v1.0.1": 'a'}, map[string]string{"a|CHANGELOG.md": deep}))
	if err != nil || p.Row.InnerHeadingStyles != nil {
		t.Fatalf("%+v %v", p, err)
	}
}

// The proposal JSON names the versions scored.
func TestProposalJSONHoldsVersionCounts(t *testing.T) {
	src := rcFixture(t, eightTags(), eightFiles(0, 1, 2, 3, 4, 5, 6))
	p, err := propose(t, src)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(p)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["versionsLocated"] != float64(7) || m["versions"] != float64(8) {
		t.Fatalf("%s", raw)
	}
}
