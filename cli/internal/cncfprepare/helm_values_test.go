// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

func TestParseHelmSetAccepted(t *testing.T) {
	for text, want := range map[string]HelmSet{
		"a=1":                {Path: []string{"a"}},
		"a.b.c=x":            {Path: []string{"a", "b", "c"}},
		`a\.b=1`:             {Path: []string{"a.b"}},
		`ann.x\.io/y=v`:      {Path: []string{"ann", "x.io/y"}},
		`k\=y=v`:             {Path: []string{"k=y"}},
		`k\,y=v`:             {Path: []string{"k,y"}},
		`k\\y=v`:             {Path: []string{`k\y`}},
		"a=":                 {Path: []string{"a"}},
		"a=null":             {Path: []string{"a"}, Null: true},
		"a=NuLL":             {Path: []string{"a"}, Null: true},
		`a=nu\ll`:            {Path: []string{"a"}, Null: true},
		"a=x=y":              {Path: []string{"a"}},
		`a=1\,2`:             {Path: []string{"a"}},
		"a=}{":               {Path: []string{"a"}},
		"a b.c=d":            {Path: []string{"a b", "c"}},
		"image.tag=v1.2.3-0": {Path: []string{"image", "tag"}},
	} {
		got, err := ParseHelmSet(text)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %+v %v, want %+v", text, got, err, want)
		}
	}
}

// TestParseHelmSetRefused: anything Helm would read differently, or that
// is not the restricted grammar, is refused, never read partly.
func TestParseHelmSetRefused(t *testing.T) {
	for _, text := range []string{
		"", "a", "=1", ".a=1", "a.=1", "a..b=1", "a[0]=x", "a[0].b=x", "a]=x",
		"a=1,b=2", "a=1,", "a,b=1", "a={x,y}", "a={x}", `a\x=1`, `a\`, `a=1\`,
		"a=\x00", "a\x00=1", string([]byte{'a', '=', 0xff}), strings.Repeat("a", 5000) + "=1",
	} {
		if got, err := ParseHelmSet(text); !errors.Is(err, ErrHelmSet) {
			t.Errorf("%q accepted: %+v", text, got)
		}
	}
}

// TestDecodeHelmValuesStrict: a file outside the strict subset is refused
// as a whole; JSON and an empty file are accepted.
func TestDecodeHelmValuesStrict(t *testing.T) {
	for name, text := range map[string]string{
		"yaml11 key":     "on: 1\n",
		"yaml11 nested":  "a:\n  yes: 1\n",
		"alias":          "a: &x {b: 1}\nc: *x\n",
		"merge key":      "a: {b: 1}\nc:\n  <<: {d: 1}\n",
		"duplicate":      "a: 1\na: 2\n",
		"two documents":  "a: 1\n---\nb: 2\n",
		"custom tag":     "a: !foo 1\n",
		"non-string key": "1: a\n",
		"list root":      "- a\n",
		"scalar root":    "a\n",
		"bad yaml":       "a: [\n",
	} {
		if _, err := DecodeHelmValues([]byte(text)); !errors.Is(err, ErrHelmValuesFile) {
			t.Errorf("%s accepted", name)
		}
	}
	for name, text := range map[string]string{"empty": "", "null": "null\n", "json": `{"a":{"b":1},"c":null}`, "quoted on": "'on': 1\n"} {
		if _, err := DecodeHelmValues([]byte(text)); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
}

func decoded(t *testing.T, texts ...string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, text := range texts {
		m, err := DecodeHelmValues([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func mustSet(t *testing.T, texts ...string) []HelmSet {
	t.Helper()
	var out []HelmSet
	for _, text := range texts {
		s, err := ParseHelmSet(text)
		if err != nil {
			t.Fatal(text, err)
		}
		out = append(out, s)
	}
	return out
}

// TestMergeHelmValues follows Helm's merge of a release's own values: maps
// merge key by key, anything else (null too) replaces, a null is kept, and
// assignments apply after every file.
func TestMergeHelmValues(t *testing.T) {
	files := decoded(t, "a: {x: 1, w: {z: 1}}\nb: 1\nnn: null\n", "a: {w: 2}\nb: {c: 1}\nnn: {k: 1}\nd: null\n")
	got := merged(t, files, mustSet(t, "a.y.deep=1", "e=null", `f\.g=1`))
	want := map[string]any{
		"a":  map[string]any{"x": json.Number("1"), "y": map[string]any{"deep": "set"}, "w": json.Number("2")},
		"b":  map[string]any{"c": json.Number("1")},
		"nn": map[string]any{"k": json.Number("1")},
		"d":  nil, "e": nil, "f.g": "set",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merge\n%#v\nwant\n%#v", got, want)
	}
	if !reflect.DeepEqual(files[0]["a"], map[string]any{"x": json.Number("1"), "w": map[string]any{"z": json.Number("1")}}) {
		t.Fatal("merge changed its input")
	}
	if nulls := HelmNullPaths(got); !reflect.DeepEqual(nulls, [][]string{{"d"}, {"e"}}) {
		t.Fatalf("nulls %v", nulls)
	}
}

var testChart = constraintengine.ChartRef{Source: "https://kedacore.github.io/charts", Name: "keda"}

const testFact = "component.keda.chart_keda_values_paths_set"

func hop() HelmChartHop {
	return HelmChartHop{Component: "pkg:github/kedacore/keda", Chart: testChart, From: "2.15.0", To: "2.16.0"}
}

type inputDoc struct {
	Current, Proposed struct {
		Components []struct {
			Component string                     `json:"component"`
			Version   string                     `json:"version"`
			Chart     *constraintengine.ChartRef `json:"chart"`
			Facts     []struct {
				ID       string `json:"id"`
				State    string `json:"state"`
				SetValue *struct {
					Members  []string `json:"members"`
					Complete bool     `json:"complete"`
				} `json:"setValue"`
			} `json:"facts"`
		} `json:"components"`
	}
}

func parseInput(t *testing.T, raw []byte) inputDoc {
	t.Helper()
	var doc inputDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// TestPrepareHelmValuesUniverse: the declared set is the merged paths the
// rules name, so a values file with far more than 256 paths still declares
// a complete set; a universe over 256 members, or one that is not
// resolved, makes the fact unsupported.
func TestPrepareHelmValuesUniverse(t *testing.T) {
	var big strings.Builder
	big.WriteString("auth: {token: x}\n")
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&big, "k%03d: {a: 1}\n", i)
	}
	values := merged(t, decoded(t, big.String()), mustSet(t, `ann.x\.io/y=1`))
	universe := HelmUniverse{Members: []string{"auth.token", "k..ann..x_2Eio/y", "missing.key", "k007.a"}, Resolved: true}
	scan, err := PrepareHelmValues(hop(), testFact, values, universe, true)
	if err != nil {
		t.Fatal(err)
	}
	if scan.Prepared.Reason != ReasonHelmValuesComplete || scan.PathsRead != 604 || scan.UniverseSize != 4 || !reflect.DeepEqual(scan.Members, []string{"auth.token", "k..ann..x_2Eio/y", "k007.a"}) {
		t.Fatalf("scan %+v", scan)
	}
	doc := parseInput(t, scan.Prepared.CanonicalInputJSON)
	proposed := doc.Proposed.Components[0]
	if len(doc.Current.Components) != 1 || len(doc.Current.Components[0].Facts) != 0 || *doc.Current.Components[0].Chart != testChart || *proposed.Chart != testChart ||
		proposed.Version != "2.16.0" || len(proposed.Facts) != 1 || proposed.Facts[0].ID != testFact || !proposed.Facts[0].SetValue.Complete {
		t.Fatalf("input %s", scan.Prepared.CanonicalInputJSON)
	}

	var many []string
	for i := 0; i <= constraintengine.MaxSetMembers; i++ {
		many = append(many, fmt.Sprintf("m%03d", i))
	}
	for name, u := range map[string]HelmUniverse{"too large": {Members: many, Resolved: true}, "unresolved": {Members: []string{"auth.token"}}} {
		scan, err := PrepareHelmValues(hop(), testFact, values, u, true)
		if err != nil {
			t.Fatal(err)
		}
		fact := parseInput(t, scan.Prepared.CanonicalInputJSON).Proposed.Components[0].Facts[0]
		if scan.Prepared.State != StateUnknown || fact.State != "unsupported" || fact.SetValue != nil || scan.Members != nil {
			t.Fatalf("%s: %+v %s", name, scan, scan.Prepared.CanonicalInputJSON)
		}
	}
}

// TestPrepareHelmValuesComplete: the set is complete only when declared
// complete and no null is left; otherwise it is declared incomplete.
func TestPrepareHelmValuesComplete(t *testing.T) {
	universe := HelmUniverse{Members: []string{"a.b"}, Resolved: true}
	for _, tc := range []struct {
		files    []string
		sets     []string
		complete bool
		reason   Reason
	}{
		{[]string{"a: {b: 1}\n"}, nil, true, ReasonHelmValuesComplete},
		{[]string{"a: {b: 1}\n"}, nil, false, ReasonHelmValuesNotDeclaredComplete},
		{[]string{"a: {b: 1}\n", "a: null\n"}, nil, true, ReasonHelmValuesNullOverride},
		{[]string{"a: null\n", "a: {b: 1}\n"}, nil, true, ReasonHelmValuesComplete},
		{[]string{"a: {b: 1}\n"}, []string{"c.d=null"}, true, ReasonHelmValuesNullOverride},
		{[]string{"a: {b: 1}\n"}, []string{"a.b=null", "a.b=1"}, true, ReasonHelmValuesComplete},
	} {
		values := merged(t, decoded(t, tc.files...), mustSet(t, tc.sets...))
		scan, err := PrepareHelmValues(hop(), testFact, values, universe, tc.complete)
		if err != nil {
			t.Fatal(err)
		}
		fact := parseInput(t, scan.Prepared.CanonicalInputJSON).Proposed.Components[0].Facts[0]
		if scan.Prepared.Reason != tc.reason || fact.SetValue.Complete != (tc.reason == ReasonHelmValuesComplete) {
			t.Errorf("%v %v %t: %s complete=%t", tc.files, tc.sets, tc.complete, scan.Prepared.Reason, fact.SetValue.Complete)
		}
	}
}

// TestPrepareHelmValuesDeterministic: the same values give the same bytes,
// whatever order the maps were built in, and the Kubernetes versions are
// declared only when given.
func TestPrepareHelmValuesDeterministic(t *testing.T) {
	universe := HelmUniverse{Members: []string{"a.b", "c"}, Resolved: true}
	first, _ := PrepareHelmValues(hop(), testFact, merged(t, decoded(t, "c: 1\na: {b: 1}\n"), nil), universe, true)
	second, _ := PrepareHelmValues(hop(), testFact, merged(t, decoded(t, "a: {b: 1}\nc: 1\n"), nil), universe, true)
	if string(first.Prepared.CanonicalInputJSON) != string(second.Prepared.CanonicalInputJSON) {
		t.Fatal("not deterministic")
	}
	if strings.Contains(string(first.Prepared.CanonicalInputJSON), "kubernetes") {
		t.Fatal("Kubernetes declared without being given")
	}
	h := hop()
	h.Kubernetes, h.KubernetesTo = "pkg:github/kubernetes/kubernetes", "1.31.0"
	withKube, err := PrepareHelmValues(h, testFact, nil, universe, true)
	if err != nil {
		t.Fatal(err)
	}
	doc := parseInput(t, withKube.Prepared.CanonicalInputJSON)
	if len(doc.Current.Components) != 1 || len(doc.Proposed.Components) != 2 || doc.Proposed.Components[1].Version != "1.31.0" || doc.Proposed.Components[1].Chart != nil {
		t.Fatalf("input %s", withKube.Prepared.CanonicalInputJSON)
	}
	for _, bad := range []HelmChartHop{
		{Component: h.Component, Chart: h.Chart, From: "2.16.0", To: "2.16.0"},
		{Component: h.Component, Chart: constraintengine.ChartRef{Source: "http://x", Name: "keda"}, From: "2.15.0", To: "2.16.0"},
		{Component: h.Component, Chart: h.Chart, From: "2.15.0", To: "2.16.0", KubernetesTo: "1.31.0"},
	} {
		if _, err := PrepareHelmValues(bad, testFact, nil, universe, true); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func merged(t *testing.T, files []map[string]any, sets []HelmSet) map[string]any {
	t.Helper()
	out, err := MergeHelmValues(files, sets)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestMergeHelmValuesRefusesSetThroughValue: Helm refuses an assignment
// whose key passes through a value that is not a mapping (null included);
// it is never turned into a mapping.
func TestMergeHelmValuesRefusesSetThroughValue(t *testing.T) {
	for _, tc := range []struct {
		files []string
		sets  []string
		index int
	}{
		{[]string{"a: 1\n"}, []string{"a.b=2"}, 0},
		{[]string{"a: [x]\n"}, []string{"a.b=2"}, 0},
		{[]string{"a: null\n"}, []string{"a.b=2"}, 0},
		{[]string{"a: {b: s}\n"}, []string{"x=1", "a.b.c=2"}, 1},
		{nil, []string{"a=1", "a.b=2"}, 1},
		{nil, []string{"a=null", "a.b=2"}, 1},
	} {
		_, err := MergeHelmValues(decoded(t, tc.files...), mustSet(t, tc.sets...))
		var path HelmSetPathError
		if !errors.Is(err, ErrHelmSetPath) || !errors.As(err, &path) || path.Index != tc.index {
			t.Errorf("%v %v: %v", tc.files, tc.sets, err)
		}
	}
	if _, err := MergeHelmValues(decoded(t, "a: {b: 1}\n"), mustSet(t, "a.c.d=2", "e.f=1")); err != nil {
		t.Fatal(err)
	}
}

// TestPrepareHelmValuesNoFact: with no values fact the input declares no
// fact at all (no invented id), and a universe for a missing fact is
// refused.
func TestPrepareHelmValuesNoFact(t *testing.T) {
	values := merged(t, decoded(t, "a: {b: 1}\n"), nil)
	scan, err := PrepareHelmValues(hop(), "", values, HelmUniverse{Resolved: true}, true)
	if err != nil {
		t.Fatal(err)
	}
	doc := parseInput(t, scan.Prepared.CanonicalInputJSON)
	if scan.Prepared.Reason != ReasonHelmValuesNoFact || scan.Prepared.State != StatePrepared || len(doc.Proposed.Components[0].Facts) != 0 || scan.PathsRead != 2 || scan.Members != nil {
		t.Fatalf("scan %+v %s", scan, scan.Prepared.CanonicalInputJSON)
	}
	for _, u := range []HelmUniverse{{Members: []string{"a.b"}, Resolved: true}, {}} {
		if _, err := PrepareHelmValues(hop(), "", values, u, true); !errors.Is(err, ErrInvalid) {
			t.Fatalf("universe %+v without a fact: %v", u, err)
		}
	}
}
