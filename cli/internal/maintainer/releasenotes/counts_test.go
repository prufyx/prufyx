// SPDX-License-Identifier: AGPL-3.0-only

package releasenotes

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fixtureCounts(t *testing.T, name string) *Counts {
	t.Helper()
	c, err := LoadCounts(fixture(t, name), nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// testOptions are Options carrying the two fixture counts.
func testOptions(t *testing.T, o Options) Options {
	o.Prev, o.Cur = fixtureCounts(t, "counts-prev.json"), fixtureCounts(t, "counts-cur.json")
	o.Previous = PreviousPin{Tag: "v1", Commit: "aaa", CountsSha256: o.Prev.Sha256}
	return o
}

func mustRender(t *testing.T, a, b *Snapshot, o Options) string {
	t.Helper()
	out, err := Render(a, b, testOptions(t, o))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mutate(t *testing.T, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(fixture(t, "counts-cur.json"), &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLoadCountsRefuses(t *testing.T) {
	block := "\nblock\n"
	readme := []byte("# x\n<!-- coverage:begin -->" + block + "<!-- coverage:end -->\n")
	good := Sum256Hex([]byte("block\n"))
	for _, tc := range []struct {
		name   string
		data   []byte
		readme []byte
	}{
		{"empty", nil, nil},
		{"not json", []byte("{"), nil},
		{"wrong schema", mutate(t, func(m map[string]any) { m["schema"] = "prufyx.io/coverage-readme-counts/v9" }), nil},
		{"v2 without forms", mutate(t, func(m map[string]any) { m["schema"] = CountsSchemaV2 }), nil},
		{"v1 with forms", mutate(t, func(m map[string]any) { m["forms"] = formsJSON(t) }), nil},
		{"v2 with tampered forms", v2Counts(t, func(f map[string]any) { f["fleet"].(map[string]any)["ab"] = 999 }), nil},
		{"v2 with a row removed", v2Counts(t, func(f map[string]any) { f["rows"] = f["rows"].([]any)[1:] }), nil},
		{"missing schema", mutate(t, func(m map[string]any) { delete(m, "schema") }), nil},
		{"extra top-level field", mutate(t, func(m map[string]any) { m["extra"] = 1 }), nil},
		{"extra report field", mutate(t, func(m map[string]any) { m["report"].(map[string]any)["extra"] = 1 }), nil},
		{"wrong report schema", mutate(t, func(m map[string]any) { m["report"].(map[string]any)["schema"] = "x" }), nil},
		{"no inventory counts", mutate(t, func(m map[string]any) { delete(m, "inventoryCounts") }), nil},
		{"trailing data", append(fixture(t, "counts-cur.json"), []byte("{}")...), nil},
		{"bad status", mutate(t, func(m map[string]any) {
			m["report"].(map[string]any)["projects"].([]any)[0].(map[string]any)["pairs"].([]any)[0].(map[string]any)["status"] = "Z"
		}), nil},
		{"duplicate project", mutate(t, func(m map[string]any) {
			r := m["report"].(map[string]any)
			ps := r["projects"].([]any)
			r["projects"] = append(ps, ps[0])
		}), nil},
		{"duplicate pair", mutate(t, func(m map[string]any) {
			p := m["report"].(map[string]any)["projects"].([]any)[0].(map[string]any)
			ps := p["pairs"].([]any)
			p["pairs"] = append(ps, ps[0])
		}), nil},
		{"malformed block hash", mutate(t, func(m map[string]any) { m["readmeBlockSha256"] = "ABC" }), nil},
		{"block hash mismatch", mutate(t, func(m map[string]any) { m["readmeBlockSha256"] = strings.Repeat("0", 64) }), readme},
		{"readme markers missing", mutate(t, func(m map[string]any) { m["readmeBlockSha256"] = good }), []byte("# x\n")},
		{"readme markers duplicated", mutate(t, func(m map[string]any) { m["readmeBlockSha256"] = good }), append(readme, readme...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadCounts(tc.data, tc.readme); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	ok := mutate(t, func(m map[string]any) { m["readmeBlockSha256"] = good })
	c, err := LoadCounts(ok, readme)
	if err != nil {
		t.Fatal(err)
	}
	if c.Sha256 != Sum256Hex(ok) {
		t.Error("sha256 is not the digest of the file bytes")
	}
}

func TestReadPreviousCountsPin(t *testing.T) {
	prev := fixture(t, "counts-prev.json")
	dir := func(files map[string]string) Tree { return DirTree{writeTree(t, files)} }
	cur := dir(map[string]string{})
	has := dir(map[string]string{CountsPath: string(prev)})
	for _, tc := range []struct {
		name string
		tree Tree
		sha  string
		tag  string
	}{
		{"file missing", dir(map[string]string{"x": "y"}), Sum256Hex(prev), "v1"},
		{"hash mismatch", has, strings.Repeat("0", 64), "v1"},
		{"no pin", has, "", "v1"},
		{"malformed pin", has, "abc", "v1"},
		{"bootstrap without pin constant", cur, Sum256Hex(prev), BootstrapTag},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ReadPreviousCounts(tc.tree, cur, tc.tag, tc.sha); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	c, err := ReadPreviousCounts(has, cur, "v1", Sum256Hex(prev))
	if err != nil || c.Sha256 != Sum256Hex(prev) {
		t.Fatalf("err = %v", err)
	}
}

func TestRenderNeedsCounts(t *testing.T) {
	s := &Snapshot{}
	for _, o := range []Options{{}, {Prev: fixtureCounts(t, "counts-prev.json")}, {Cur: fixtureCounts(t, "counts-cur.json")}} {
		if _, err := Render(s, s, o); err == nil {
			t.Error("rendered without both counts")
		}
	}
}

func TestDiffCounts(t *testing.T) {
	d := DiffCounts(fixtureCounts(t, "counts-prev.json"), fixtureCounts(t, "counts-cur.json"))
	if got := strings.Join(d.Added, ","); got != "newone,zcomm (community)" {
		t.Errorf("added = %s", got)
	}
	if got := strings.Join(d.Removed, ","); got != "gone" {
		t.Errorf("removed = %s", got)
	}
	if len(d.Projects) != 2 || d.Projects[0].Name != "alpha" || d.Projects[1].Name != "beta" {
		t.Fatalf("projects = %+v", d.Projects)
	}
	a := d.Projects[0]
	if a.PairsAdded != 1 || len(a.Gained) != 1 || a.Gained[0] != (pairChange{"1.0", "1.1", "G", "B"}) || a.RulesFrom != 1 || a.RulesTo != 2 {
		t.Errorf("alpha = %+v", a)
	}
	if b := d.Projects[1]; len(b.Lost) != 1 || b.Lost[0].Was != "B" {
		t.Errorf("beta = %+v", b)
	}
}

func TestDiffUnsortedInputIsDeterministic(t *testing.T) {
	prev, cur := fixtureCounts(t, "counts-prev.json"), fixtureCounts(t, "counts-cur.json")
	var want strings.Builder
	renderCountsDiff(&want, prev, cur, PreviousPin{Tag: "v1", Commit: "aaa", CountsSha256: prev.Sha256})
	rev := *cur
	rev.Report.Projects = append(rev.Report.Projects[:0:0], cur.Report.Projects...)
	for i, j := 0, len(rev.Report.Projects)-1; i < j; i, j = i+1, j-1 {
		rev.Report.Projects[i], rev.Report.Projects[j] = rev.Report.Projects[j], rev.Report.Projects[i]
	}
	for k := range rev.Report.Projects {
		p := rev.Report.Projects[k]
		p.Pairs = append(p.Pairs[:0:0], p.Pairs...)
		for i, j := 0, len(p.Pairs)-1; i < j; i, j = i+1, j-1 {
			p.Pairs[i], p.Pairs[j] = p.Pairs[j], p.Pairs[i]
		}
		rev.Report.Projects[k] = p
	}
	var got strings.Builder
	renderCountsDiff(&got, prev, &rev, PreviousPin{Tag: "v1", Commit: "aaa", CountsSha256: prev.Sha256})
	if got.String() != want.String() {
		t.Errorf("order changed the output:\n%s\n---\n%s", got.String(), want.String())
	}
}

func TestCountsDiffGolden(t *testing.T) {
	prev, cur := fixtureCounts(t, "counts-prev.json"), fixtureCounts(t, "counts-cur.json")
	var b strings.Builder
	renderCountsDiff(&b, prev, cur, PreviousPin{Tag: "v0.1.0-beta.0", Commit: "0123456789ab", CountsSha256: prev.Sha256})
	path := "testdata/counts-diff.golden.md"
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if b.String() != string(want) {
		t.Errorf("golden mismatch:\n%s", b.String())
	}
	if strings.Contains(b.String(), "n/a") || strings.Contains(b.String(), "4"+"35") {
		t.Error("forbidden text in the block")
	}
}

func TestRenderBootstrapApproximationNote(t *testing.T) {
	s := &Snapshot{}
	prev, cur := fixtureCounts(t, "counts-prev.json"), fixtureCounts(t, "counts-cur.json")
	want := "The figures for `v0.1.0-beta.0` in this section are approximate: that release has no counts file, so they were recomputed from its rules with the current pinned release lines."
	got, err := Render(s, s, Options{FromLabel: "v0.1.0-beta.0", ToLabel: "v1", Prev: prev, Cur: cur, Previous: PreviousPin{Tag: BootstrapTag, Commit: "abc", CountsSha256: prev.Sha256}, OmitMergedPRs: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(got, want+"\n\n") != 1 {
		t.Errorf("bootstrap note missing or repeated:\n%s", got)
	}
	got, err = Render(s, s, Options{FromLabel: "v1", ToLabel: "v2", Prev: prev, Cur: cur, Previous: PreviousPin{Tag: "v1", Commit: "abc", CountsSha256: prev.Sha256}, OmitMergedPRs: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "approximate") {
		t.Error("note printed for a release with real counts")
	}
}

// formsJSON is the forms table of the v1 fixture, as a generic JSON value.
func formsJSON(t *testing.T) any {
	t.Helper()
	tab, err := coveragereport.FormsOfV2(fixtureCounts(t, "counts-cur.json").Report)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(tab)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// v2Counts is the fixture as a v2 file with its forms table, after edit.
func v2Counts(t *testing.T, edit func(forms map[string]any)) []byte {
	t.Helper()
	return mutate(t, func(m map[string]any) {
		m["schema"] = CountsSchemaV2
		f := formsJSON(t).(map[string]any)
		edit(f)
		m["forms"] = f
	})
}

// A v1 file loads as before; a v2 file loads with a matching forms table.
func TestLoadCountsV1AndV2(t *testing.T) {
	if c := fixtureCounts(t, "counts-cur.json"); c.Forms != nil {
		t.Error("a v1 file has forms")
	}
	c, err := LoadCounts(v2Counts(t, func(map[string]any) {}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Forms == nil || len(c.Forms.Rows) != len(c.Report.Projects) {
		t.Errorf("v2 forms: %+v", c.Forms)
	}
}

// A pair decided by the served-API family alone is in its own row, never in
// the A/B row; a v2 file without forms is refused.
func TestSummarySplitsServedAPIOnlyPairs(t *testing.T) {
	cur := fixtureCounts(t, "counts-cur.json")
	var fleet *coveragereport.Project
	for i := range cur.Report.Projects {
		if cur.Report.Projects[i].Catalog == "" && len(cur.Report.Projects[i].Pairs) > 0 {
			fleet = &cur.Report.Projects[i]
			break
		}
	}
	if fleet == nil {
		t.Fatal("no fleet project in the fixture")
	}
	fleet.Pairs = append(fleet.Pairs, coveragereport.Pair{From: "9.0", To: "9.1", Status: coveragereport.StatusA, Families: []string{coveragereport.FamilyServedAPI}})
	cur.Report.Fleet.Pairs++
	cur.Report.Fleet.A++
	cur.Schema = CountsSchemaV2
	forms, err := coveragereport.FormsOfV2(cur.Report)
	if err != nil {
		t.Fatal(err)
	}
	cur.Forms = &forms
	prev := fixtureCounts(t, "counts-prev.json")
	out, err := Render(&Snapshot{}, &Snapshot{}, Options{Prev: prev, Cur: cur, Previous: PreviousPin{Tag: "v1", Commit: "aaa", CountsSha256: prev.Sha256}})
	if err != nil {
		t.Fatal(err)
	}
	if forms.Fleet.K8s != 1 || !strings.Contains(out, "| Kubernetes served-API (decided) | 0 | 1 | +1 |") || !strings.Contains(out, "excluded) | 2 | 2 | 0 |") {
		t.Fatalf("forms %+v\n%s", forms.Fleet, out)
	}
	if strings.Contains(out, "(A+B)") {
		t.Error("a summed A+B row is still printed")
	}
	cur.Forms = nil
	if _, err := Render(&Snapshot{}, &Snapshot{}, Options{Prev: prev, Cur: cur, Previous: PreviousPin{Tag: "v1", Commit: "aaa", CountsSha256: prev.Sha256}}); err == nil {
		t.Error("a v2 counts file without forms was rendered")
	}
}

// v3Counts is the fixture as a v3 file with its forms table, after edit.
func v3Counts(t *testing.T, edit func(forms map[string]any)) []byte {
	t.Helper()
	tab, err := coveragereport.FormsOf(fixtureCounts(t, "counts-cur.json").Report)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(tab)
	var f map[string]any
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	edit(f)
	return mutate(t, func(m map[string]any) {
		m["schema"] = CountsSchemaV3
		m["forms"] = f
	})
}

func TestLoadCountsV3Families(t *testing.T) {
	c, err := LoadCounts(v3Counts(t, func(map[string]any) {}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Forms.Families) == 0 {
		t.Fatal("a v3 file has no family rows")
	}
	if _, err := LoadCounts(v3Counts(t, func(f map[string]any) { delete(f, "families") }), nil); err == nil {
		t.Error("a v3 file without family rows loaded")
	}
	if _, err := LoadCounts(v3Counts(t, func(f map[string]any) {
		f["families"].([]any)[0].(map[string]any)["fleet"].(map[string]any)["pairs"] = 99
	}), nil); err == nil {
		t.Error("a v3 file with tampered family rows loaded")
	}
	// A v2 file may not carry family rows; one without them still loads.
	tab, _ := coveragereport.FormsOf(fixtureCounts(t, "counts-cur.json").Report)
	b, _ := json.Marshal(tab)
	var f map[string]any
	_ = json.Unmarshal(b, &f)
	if _, err := LoadCounts(mutate(t, func(m map[string]any) { m["schema"] = CountsSchemaV2; m["forms"] = f }), nil); err == nil {
		t.Error("a v2 file with family rows loaded")
	}
}

// The notes carry one row per family, none summed, for old and new files.
func TestRenderFamilyRows(t *testing.T) {
	prev := fixtureCounts(t, "counts-prev.json")
	cur := fixtureCounts(t, "counts-cur.json")
	out, err := Render(&Snapshot{}, &Snapshot{}, Options{Prev: prev, Cur: cur, Previous: PreviousPin{Tag: "v1", Commit: "aaa", CountsSha256: prev.Sha256}})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"Decided by CRD versions (fleet; family rows are not summed)", "Decided by Chart install API surface (fleet; family rows are not summed) | 0 | 0 | 0 |"} {
		if !strings.Contains(out, l) {
			t.Errorf("missing row %q", l)
		}
	}
}
