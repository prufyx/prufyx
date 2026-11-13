// SPDX-License-Identifier: AGPL-3.0-only

package helmvalues

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/chartrun"
)

const (
	mappedRoot = "testdata/mapped"
	sha13      = "56ebb942e2461ea18605a3b37c4dc1b8b1d4b565"
	sha14      = "452f9d9939a51bfad1c7d82cb32033ed17e72c26"
	sha15      = "c9fb3c73528ebee3170789b86b2abc173fe0d37f"
)

func openfga(t *testing.T) Target {
	t.Helper()
	return target(t, "openfga")
}

func mappedIndex(t *testing.T, root string, tg Target) extract.ReleaseIndex {
	t.Helper()
	repo, err := extract.ParseRepo(tg.Repo)
	must(t, err)
	tags, err := extract.FixtureReader{Root: root}.Tags(repo)
	must(t, err)
	return extract.ReleaseIndex{Repo: repo, Tags: tags}
}

func runMapped(t *testing.T, root string, tg Target) (*chartrun.Output, error) {
	t.Helper()
	repo, err := extract.ParseRepo(tg.Repo)
	must(t, err)
	fr := extract.FixtureReader{Root: root}
	return chartrun.Run(context.Background(), New(tg), fr, fr, extract.Options{Repo: repo, DerivedAt: derivedAt})
}

// testTarget builds a target with the shape of the shipped one and the given
// mapping JSON, through the strict loader.
func testTarget(mapping string) (Target, error) {
	doc := `{"schema":"` + TargetsSchema + `","targets":[{"project":"openfga","name":"OpenFGA","repo":"github.com/openfga/helm-charts","component":"pkg:github/openfga/openfga","factProject":"openfga","chart":{"source":"https://openfga.github.io/helm-charts","name":"openfga","path":"charts/openfga"},"tagPrefix":"openfga-","minFrom":"0.3","anchorMapping":` + mapping + `}]}`
	ts, err := LoadTargets([]byte(doc))
	if err != nil {
		return Target{}, err
	}
	return ts[0], nil
}

func row(line, chart, sha, app string) string {
	return fmt.Sprintf(`{"line":%q,"chart":%q,"chartCommit":%q,"appVersion":%q}`, line, chart, sha, app)
}

func lines(ls ...string) string {
	b, _ := json.Marshal(ls)
	return string(b)
}

func mappingDoc(window string, rows ...string) string {
	return `{"lines":` + window + `,"rows":[` + strings.Join(rows, ",") + `]}`
}

func TestShippedMappingRows(t *testing.T) {
	m := openfga(t).AnchorMapping
	if m == nil {
		t.Fatal("no anchorMapping")
	}
	want := []MappingRow{
		{Line: "1.19", Chart: "0.3.13", ChartCommit: sha13, AppVersion: "v1.19.0"},
		{Line: "1.20", Chart: "0.3.14", ChartCommit: sha14, AppVersion: "v1.20.0"},
		{Line: "1.21", Chart: "0.3.15", ChartCommit: sha15, AppVersion: "v1.21.0"},
	}
	if !reflect.DeepEqual(m.Rows, want) {
		t.Fatalf("rows %+v", m.Rows)
	}
	if !slices.Equal(m.Lines, []string{"1.17", "1.18", "1.19", "1.20", "1.21", "1.22"}) {
		t.Fatalf("window %v", m.Lines)
	}
	// Only this target maps anchors; every other target is untouched.
	for _, tg := range Targets {
		if (tg.AnchorMapping != nil) != (tg.Project == "openfga") {
			t.Fatalf("%s: anchorMapping %v", tg.Project, tg.AnchorMapping != nil)
		}
	}
}

func TestMappingResolution(t *testing.T) {
	r := func(line, chart, app string) MappingRow {
		return MappingRow{Line: line, Chart: chart, ChartCommit: sha13, AppVersion: app}
	}
	for _, tc := range []struct {
		name       string
		rows       []MappingRow
		line       string
		want       string
		wantReason string
		candidates int
	}{
		{"zero", nil, "1.19", "", ReasonMappingMissing, 0},
		{"other line only", []MappingRow{r("1.20", "0.3.14", "v1.20.0")}, "1.19", "", ReasonMappingMissing, 0},
		{"one", []MappingRow{r("1.19", "0.3.13", "1.19.0")}, "1.19", "0.3.13", "", 1},
		{"v prefix is normalised", []MappingRow{r("1.19", "0.3.13", "v1.19.2")}, "1.19", "0.3.13", "", 1},
		{"many is withheld, newest never wins", []MappingRow{r("1.18", "0.3.9", "v1.18.0"), r("1.18", "0.3.12", "v1.18.3")}, "1.18", "", ReasonMappingAmbiguous, 2},
		{"a pre-release is not a candidate", []MappingRow{r("1.20", "0.3.14", "v1.20.0"), r("1.20", "0.3.20", "1.20.0-rc1")}, "1.20", "0.3.14", "", 1},
		{"only a pre-release is zero", []MappingRow{r("1.20", "0.3.20", "v1.20.0-rc1")}, "1.20", "", ReasonMappingMissing, 0},
		{"two finals and a pre-release", []MappingRow{r("1.20", "0.3.14", "1.20.0"), r("1.20", "0.3.16", "v1.20.1"), r("1.20", "0.3.20", "1.20.2-rc1")}, "1.20", "", ReasonMappingAmbiguous, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &AnchorMapping{Rows: tc.rows}
			row, n, reason := m.resolveLine(tc.line)
			if row.Chart != tc.want || reason != tc.wantReason || n != tc.candidates {
				t.Fatalf("got %q %d %q", row.Chart, n, reason)
			}
		})
	}
}

func TestMappingLoadRefusals(t *testing.T) {
	win := lines("1.19", "1.20")
	good := []string{row("1.19", "0.3.13", sha13, "v1.19.0")}
	if _, err := testTarget(mappingDoc(win, good...)); err != nil {
		t.Fatalf("baseline refused: %v", err)
	}
	for name, doc := range map[string]string{
		"unpinned: no commit":         mappingDoc(win, row("1.19", "0.3.13", "", "v1.19.0")),
		"unpinned: short commit":      mappingDoc(win, row("1.19", "0.3.13", sha13[:12], "v1.19.0")),
		"unpinned: upper case":        mappingDoc(win, row("1.19", "0.3.13", strings.ToUpper(sha13), "v1.19.0")),
		"no rows":                     mappingDoc(win),
		"one line window":             mappingDoc(lines("1.19"), good...),
		"unsorted window":             mappingDoc(lines("1.20", "1.19"), good...),
		"duplicate window line":       mappingDoc(lines("1.19", "1.19"), good...),
		"bad window line":             mappingDoc(lines("1.19", "1.x"), good...),
		"row off the window":          mappingDoc(win, row("1.22", "0.3.16", sha13, "v1.22.0")),
		"app version on another line": mappingDoc(win, row("1.19", "0.3.13", sha13, "v1.20.0")),
		"app version not a version":   mappingDoc(win, row("1.19", "0.3.13", sha13, "latest")),
		"chart not a version":         mappingDoc(win, row("1.19", "0.3", sha13, "v1.19.0")),
		"same chart twice":            mappingDoc(win, row("1.19", "0.3.13", sha13, "v1.19.0"), row("1.19", "0.3.13", sha14, "v1.19.0")),
		"unknown field":               `{"lines":` + win + `,"rows":[` + good[0] + `],"newest":true}`,
		"unknown row field":           `{"lines":` + win + `,"rows":[{"line":"1.19","chart":"0.3.13","chartCommit":"` + sha13 + `","appVersion":"v1.19.0","imageTag":"1.19.5"}]}`,
	} {
		if _, err := testTarget(doc); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// With the shipped rows the window has 5 pairs: two resolve, three are
// withheld by the mapping with a named reason, and nothing is guessed.
func TestMappedPairs(t *testing.T) {
	tg := openfga(t)
	idx := mappedIndex(t, mappedRoot, tg)
	x := New(tg)
	got := x.MappedPairs(idx)
	type view struct{ from, to, reason string }
	var vs []view
	for _, mp := range got {
		vs = append(vs, view{mp.FromLine, mp.ToLine, mp.Reason})
	}
	want := []view{
		{"1.17", "1.18", "mapping-missing: line 1.17"},
		{"1.18", "1.19", "mapping-missing: line 1.18"},
		{"1.19", "1.20", ""},
		{"1.20", "1.21", ""},
		{"1.21", "1.22", "mapping-missing: line 1.22"},
	}
	if !reflect.DeepEqual(vs, want) {
		t.Fatalf("pairs %+v", vs)
	}
	var keys []string
	for _, p := range x.Pairs(idx) {
		keys = append(keys, p.FromTag+"->"+p.ToTag)
	}
	if !slices.Equal(keys, []string{"openfga-0.3.13->openfga-0.3.14", "openfga-0.3.14->openfga-0.3.15"}) {
		t.Fatalf("Pairs %v", keys)
	}
	p := x.Pairs(idx)[0]
	if p.FromCommit != sha13 || p.ToCommit != sha14 || p.From != "0.3.13" || p.To != "0.3.14" {
		t.Fatalf("pair %+v", p)
	}
}

// The index holds benchmark-0.0.x, openfga-operator-0.1.0 and a later
// openfga tag: none of them takes part, and a tag that moved or vanished
// withholds its pairs.
func TestMappedPairsAgainstTheIndex(t *testing.T) {
	tg := openfga(t)
	idx := mappedIndex(t, mappedRoot, tg)
	reasons := func(idx extract.ReleaseIndex) []string {
		var out []string
		for _, mp := range New(tg).MappedPairs(idx) {
			out = append(out, mp.Reason)
		}
		return out
	}
	moved := extract.ReleaseIndex{Repo: idx.Repo}
	for _, tag := range idx.Tags {
		if tag.Name == "openfga-0.3.14" {
			tag.Commit = "0000000000000000000000000000000000e00014"
		}
		moved.Tags = append(moved.Tags, tag)
	}
	if got := reasons(moved); got[2] == "" || !strings.HasPrefix(got[2], ReasonMappingCommit) || !strings.HasPrefix(got[3], ReasonMappingCommit) {
		t.Fatalf("moved tag: %v", got)
	}
	gone := extract.ReleaseIndex{Repo: idx.Repo}
	for _, tag := range idx.Tags {
		if tag.Name != "openfga-0.3.14" {
			gone.Tags = append(gone.Tags, tag)
		}
	}
	if got := reasons(gone); !strings.HasPrefix(got[2], ReasonMappingTagMissing) || !strings.HasPrefix(got[3], ReasonMappingTagMissing) {
		t.Fatalf("missing tag: %v", got)
	}
	// An index of other tags only: every pair is withheld.
	other := extract.ReleaseIndex{Repo: idx.Repo, Tags: []extract.Tag{{Name: "benchmark-0.0.1", Commit: sha13}, {Name: "openfga-operator-0.1.0", Commit: sha14}}}
	if ps := New(tg).Pairs(other); len(ps) != 0 {
		t.Fatalf("pairs from foreign tags: %v", ps)
	}
	// A mapping with two candidates for a line withholds it: never newest wins.
	amb, err := testTarget(mappingDoc(lines("1.19", "1.20", "1.21"),
		row("1.19", "0.3.12", sha13, "v1.19.0"), row("1.19", "0.3.13", sha13, "v1.19.1"),
		row("1.20", "0.3.14", sha14, "v1.20.0"), row("1.21", "0.3.15", sha15, "v1.21.0")))
	must(t, err)
	got := New(amb).MappedPairs(idx)
	if !strings.HasPrefix(got[0].Reason, ReasonMappingAmbiguous) || got[1].Reason != "" {
		t.Fatalf("ambiguous: %+v", got)
	}
	if ps := New(amb).Pairs(idx); len(ps) != 1 || ps[0].FromTag != "openfga-0.3.14" {
		t.Fatalf("ambiguous line kept a pair: %+v", ps)
	}
}

// refusedMismatch compares the keys a derivation refused with the keys a
// person listed by hand; "" means equal.
func refusedMismatch(got, want []string) string {
	g, w := slices.Clone(got), slices.Clone(want)
	sort.Strings(g)
	sort.Strings(w)
	if slices.Equal(g, w) {
		return ""
	}
	return fmt.Sprintf("refused %v, oracle %v", g, w)
}

type oracleFile struct {
	Pair       string   `json:"pair"`
	Refused    []string `json:"refused"`
	NotRefused []string `json:"notRefused"`
}

func readOracle(t *testing.T) oracleFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(mappedRoot, "oracle.json"))
	must(t, err)
	var o oracleFile
	must(t, json.Unmarshal(raw, &o))
	return o
}

// proofOf runs one mapped pair and returns the proof of its withheld
// result.
func proofOf(t *testing.T, root string, tg Target, from, to string) (*PairProof, string) {
	t.Helper()
	idx := mappedIndex(t, root, tg)
	x := New(tg)
	for _, p := range x.Pairs(idx) {
		if p.From == from && p.To == to {
			fr := extract.FixtureReader{Root: root}
			_, err := x.Extract(context.Background(), fr, p)
			w, ok := extract.IsWithheld(err)
			if !ok {
				t.Fatalf("a mapped pair must be withheld, got %v", err)
			}
			proof, _ := w.Proof.(*PairProof)
			return proof, w.Reason
		}
	}
	t.Fatalf("no pair %s->%s", from, to)
	return nil, ""
}

func refusedKeys(p *PairProof) []string {
	var out []string
	for _, k := range p.Removed.Keys {
		if k.Class == ClassRejected {
			out = append(out, k.Detail)
		}
	}
	return out
}

// The oracle is hand-written: the refused keys are listed by a person in
// oracle.json, not by the reader under test.
func TestHandWrittenOracle(t *testing.T) {
	o := readOracle(t)
	proof, reason := proofOf(t, mappedRoot, openfga(t), "0.3.13", "0.3.14")
	if !strings.HasPrefix(reason, ReasonMappedInert) {
		t.Fatalf("reason %q", reason)
	}
	if o.Pair != "0.3.13->0.3.14" || proof.Removed == nil {
		t.Fatalf("oracle %+v, removed %v", o, proof.Removed)
	}
	got := refusedKeys(proof)
	if msg := refusedMismatch(got, o.Refused); msg != "" {
		t.Fatal(msg)
	}
	// The opaque map and the kept keys are never refused.
	for _, k := range o.NotRefused {
		if slices.Contains(got, k) {
			t.Fatalf("%s refused", k)
		}
	}
	if len(proof.Rules) != 0 {
		t.Fatalf("rules %v", proof.Rules)
	}
	// Seeded wrong oracles: dropping the removed key, dropping the moved
	// key, or adding the opaque key must each fail the comparison.
	for name, wrong := range map[string][]string{
		"removed key dropped": {"moved"},
		"moved key dropped":   {"legacy.flag"},
		"opaque key added":    {"legacy.flag", "moved", "annotations.tier"},
		"empty":               nil,
	} {
		if refusedMismatch(got, wrong) == "" {
			t.Errorf("%s: the seeded oracle passed", name)
		}
	}
	if refusedMismatch(got, slices.DeleteFunc(slices.Clone(o.Refused), func(k string) bool { return k == "legacy.flag" })) == "" {
		t.Error("oracle without the removed key passed")
	}
}

// The whole run: no rule, no vector, no decided pair reaches any output.
func TestMappedTargetIsInert(t *testing.T) {
	if mappedTargetsEmitRules {
		t.Fatal("a mapped target may not emit rules before the attestation family exists")
	}
	tg := openfga(t)
	out, err := runMapped(t, mappedRoot, tg)
	must(t, err)
	m := out.Manifest
	if m.Totals.Pairs != 2 || m.Totals.Derived != 0 || m.Totals.Withheld != 2 || m.Totals.Rules != 0 || m.Totals.Vectors != 0 {
		t.Fatalf("totals %+v", m.Totals)
	}
	if len(out.Entries) != 0 || len(out.Vectors) != 0 {
		t.Fatalf("entries %d vectors %d", len(out.Entries), len(out.Vectors))
	}
	for _, p := range m.Pairs {
		if p.Status != extract.PairWithheld || len(p.Rules) != 0 || !strings.HasPrefix(p.Reason, ReasonMappedInert) {
			t.Fatalf("pair %+v", p)
		}
	}
	files, err := out.Files()
	must(t, err)
	var cand []json.RawMessage
	must(t, json.Unmarshal(files["candidates.json"], &cand))
	if len(cand) != 0 {
		t.Fatalf("candidates.json holds %d entries", len(cand))
	}
	// Whatever the fixture holds, an unmapped keda run is unchanged: it
	// still derives its three rules.
	if k := fixtureOutput(t); k.Manifest.Totals.Rules != 3 {
		t.Fatalf("keda totals %+v", k.Manifest.Totals)
	}
}

// copyMapped copies the mapped fixture and lets edit change the copy.
func copyMapped(t *testing.T, edit func(root string)) string {
	t.Helper()
	dst := t.TempDir()
	must(t, filepath.WalkDir(mappedRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(mappedRoot, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), raw, 0o644)
	}))
	edit(dst)
	return dst
}

func chartFile(root, sha, name string) string {
	return filepath.Join(root, "github.com/openfga/helm-charts/commits", sha, "charts/openfga", name)
}

// A side without a schema, or with an open one, is withheld by name before
// anything is derived: the empty rule list of such a pair is never an A.
func TestSchemaGates(t *testing.T) {
	tg := openfga(t)
	for _, tc := range []struct {
		name   string
		edit   func(root string)
		reason string
	}{
		// The loki shape: the earlier side has no schema, the later one has.
		{"earlier side has no schema", func(r string) { must(t, os.Remove(chartFile(r, sha13, "values.schema.json"))) }, ReasonNoSchemaEarlier},
		{"later side has no schema", func(r string) { must(t, os.Remove(chartFile(r, sha14, "values.schema.json"))) }, ReasonNoSchemaLater},
		{"both have none: the earlier one is named", func(r string) {
			must(t, os.Remove(chartFile(r, sha13, "values.schema.json")))
			must(t, os.Remove(chartFile(r, sha14, "values.schema.json")))
		}, ReasonNoSchemaEarlier},
		{"open root, later", func(r string) {
			f := chartFile(r, sha14, "values.schema.json")
			raw, err := os.ReadFile(f)
			must(t, err)
			must(t, os.WriteFile(f, []byte(strings.Replace(string(raw), `"additionalProperties": false,`, "", 1)), 0o644))
		}, ReasonSchemaOpen},
		{"open root, earlier", func(r string) {
			f := chartFile(r, sha13, "values.schema.json")
			raw, err := os.ReadFile(f)
			must(t, err)
			must(t, os.WriteFile(f, []byte(strings.Replace(string(raw), `"additionalProperties": false,`, `"additionalProperties": true,`, 1)), 0o644))
		}, ReasonSchemaOpen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := copyMapped(t, tc.edit)
			proof, reason := proofOf(t, root, tg, "0.3.13", "0.3.14")
			if !strings.HasPrefix(reason, tc.reason+":") {
				t.Fatalf("reason %q, want %s", reason, tc.reason)
			}
			if proof.Removed != nil || proof.Required != nil || len(proof.Rules) != 0 {
				t.Fatalf("derivation ran before the gate: %+v", proof)
			}
			out, err := runMapped(t, root, tg)
			must(t, err)
			if out.Manifest.Totals.Derived != 0 || out.Manifest.Totals.Rules != 0 {
				t.Fatalf("totals %+v", out.Manifest.Totals)
			}
		})
	}
}

func TestMappedRunIsDeterministic(t *testing.T) {
	tg := openfga(t)
	var first map[string][]byte
	for i := 0; i < 3; i++ {
		out, err := runMapped(t, mappedRoot, tg)
		must(t, err)
		files, err := out.Files()
		must(t, err)
		if first == nil {
			first = files
			continue
		}
		if !reflect.DeepEqual(first, files) {
			t.Fatal("two runs differ")
		}
	}
}

// The proof names every line of the window and why a line is withheld.
func TestMappedProofNamesTheWithheldLines(t *testing.T) {
	proof, _ := proofOf(t, mappedRoot, openfga(t), "0.3.14", "0.3.15")
	if proof.Mapping == nil || proof.Mapping.Mode != "appVersion" || len(proof.Mapping.Lines) != 6 {
		t.Fatalf("mapping %+v", proof.Mapping)
	}
	want := []string{"1.17>1.18: mapping-missing", "1.18>1.19: mapping-missing", "1.21>1.22: mapping-missing"}
	if !slices.Equal(proof.Mapping.Withheld, want) {
		t.Fatalf("withheld %v", proof.Mapping.Withheld)
	}
}
