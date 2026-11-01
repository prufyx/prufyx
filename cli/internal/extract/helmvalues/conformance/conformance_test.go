// SPDX-License-Identifier: AGPL-3.0-only

package conformance

// The scan reads the values a user supplies through its own flags only:
// --helm-values FILE (repeatable, in order) and --helm-set KEY=VALUE
// (repeatable, applied after the files). Helm's own spellings are refused by
// name. What the collector reports for a key is read from the declared set
// fact it hands to the engine:
//
//   - present: the key path is a member of the declared set;
//   - absent:  the set is declared complete and the key path is not a member;
//   - UNKNOWN: anything else, including every input the collector refuses
//     (the scan stops with a usage error and reports nothing for the key).
//
// "absent" means absent from the supplied values; chart defaults are not
// evaluated here (the extractor derives rules that account for them).

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/helmvaluespath"
	"github.com/prufyx/prufyx/cli/internal/scanrun"
)

type state string

const (
	present state = "present"
	absent  state = "absent"
	unknown state = "UNKNOWN"
)

const fact = "component.keda.chart_keda_values_paths_set"

var chart = constraintengine.ChartRef{Source: "https://kedacore.github.io/charts", Name: "keda"}

// supplied is what a user hands the scan.
type supplied struct {
	files    []string // contents of the values files, in order
	sets     []string // --helm-set texts, in order
	complete bool     // --helm-values-complete
}

// report runs the collector's own steps (the ones scan runs in
// scanrun/helmchart.go) and reads the declared fact for one key path.
func report(t *testing.T, in supplied, path ...string) state {
	t.Helper()
	var files []map[string]any
	for _, f := range in.files {
		v, err := cncfprepare.DecodeHelmValues([]byte(f))
		if err != nil {
			return unknown
		}
		files = append(files, v)
	}
	var sets []cncfprepare.HelmSet
	for _, s := range in.sets {
		set, err := cncfprepare.ParseHelmSet(s)
		if err != nil {
			return unknown
		}
		sets = append(sets, set)
	}
	values, err := cncfprepare.MergeHelmValues(files, sets)
	if err != nil {
		return unknown
	}
	member, ok := helmvaluespath.Member(path)
	if !ok {
		return unknown // no rule can name this key, so nothing is asked of it
	}
	hop := cncfprepare.HelmChartHop{Component: "pkg:github/kedacore/keda", Chart: chart, From: "2.15.0", To: "2.16.0"}
	scan, err := cncfprepare.PrepareHelmValues(hop, fact, values, cncfprepare.HelmUniverse{Members: []string{member}, Resolved: true}, in.complete)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Proposed struct {
			Components []struct {
				Facts []struct {
					State    string `json:"state"`
					SetValue *struct {
						Members  []string `json:"members"`
						Complete bool     `json:"complete"`
					} `json:"setValue"`
				} `json:"facts"`
			} `json:"components"`
		} `json:"proposed"`
	}
	if err := json.Unmarshal(scan.Prepared.CanonicalInputJSON, &doc); err != nil {
		t.Fatal(err)
	}
	f := doc.Proposed.Components[0].Facts[0]
	if f.State != "declared" || f.SetValue == nil {
		return unknown
	}
	switch {
	case slices.Contains(f.SetValue.Members, member):
		return present
	case f.SetValue.Complete:
		return absent
	}
	return unknown
}

func p(dotted string) []string { return strings.Split(dotted, ".") }

func TestKeyStates(t *testing.T) {
	longPath := strings.Split(strings.Repeat("g.", 64)+"g", ".") // its member would exceed the bound
	type probe struct {
		path []string
		want state
	}
	tests := []struct {
		name   string
		in     supplied
		probes []probe
	}{
		// --- values files and their order ---
		{"later file adds a sibling", supplied{files: []string{"a: {b: 1}\n", "a: {c: 2}\n"}, complete: true},
			[]probe{{p("a.b"), present}, {p("a.c"), present}, {p("a.d"), absent}}},
		{"later scalar replaces an earlier mapping", supplied{files: []string{"a: {b: 1}\n", "a: 5\n"}, complete: true},
			[]probe{{p("a.b"), absent}, {p("a"), present}}},
		{"later mapping replaces an earlier scalar", supplied{files: []string{"a: 5\n", "a: {b: 1}\n"}, complete: true},
			[]probe{{p("a.b"), present}}},
		{"later list replaces an earlier mapping", supplied{files: []string{"a: {b: 1}\n", "a: [1]\n"}, complete: true},
			[]probe{{p("a.b"), absent}, {p("a"), present}}},
		{"a key inside a list is not a key path", supplied{files: []string{"a: [{b: 1}]\n"}, complete: true},
			[]probe{{p("a.b"), absent}, {p("a"), present}}},
		{"empty file adds nothing", supplied{files: []string{"", "a: {b: 1}\n"}, complete: true},
			[]probe{{p("a.b"), present}, {p("a.c"), absent}}},
		{"no source at all, declared complete", supplied{complete: true},
			[]probe{{p("a.b"), absent}}},
		{"a dotted key is one key, not a path", supplied{files: []string{"\"a.b\": 1\n"}, complete: true},
			[]probe{{[]string{"a.b"}, present}, {p("a.b"), absent}}},
		// --- null ---
		{"a later null removes the default mapping under it", supplied{files: []string{"a: {b: 1}\n", "a: null\n"}, complete: true},
			[]probe{{p("a.b"), unknown}, {p("a.c"), unknown}, {p("x"), unknown}}},
		{"a null replaced by a later mapping leaves no null", supplied{files: []string{"a: null\n", "a: {b: 1}\n"}, complete: true},
			[]probe{{p("a.b"), present}, {p("a.c"), absent}}},
		{"a null leaf makes the whole set incomplete", supplied{files: []string{"a: {b: null, c: 1}\n"}, complete: true},
			[]probe{{p("a.c"), present}, {p("a.b"), unknown}, {p("a.d"), unknown}}},
		{"an empty YAML value is null, not an empty string", supplied{files: []string{"a:\n"}, complete: true},
			[]probe{{p("a"), unknown}}},
		{"a tilde is null", supplied{files: []string{"a: ~\n"}, complete: true},
			[]probe{{p("a"), unknown}}},
		{"an empty string is a value", supplied{files: []string{"a: {b: \"\"}\n"}, complete: true},
			[]probe{{p("a.b"), present}, {p("a.c"), absent}}},
		// --- --helm-set ---
		{"set creates the mapping on the way", supplied{sets: []string{"a.b=c"}, complete: true},
			[]probe{{p("a.b"), present}, {p("a"), present}, {p("a.x"), absent}}},
		{"set with an empty value is an empty string, present", supplied{sets: []string{"a.b="}, complete: true},
			[]probe{{p("a.b"), present}, {p("a.c"), absent}}},
		{"set replaces a file mapping with a scalar", supplied{files: []string{"a: {b: 1}\n"}, sets: []string{"a=1"}, complete: true},
			[]probe{{p("a.b"), absent}, {p("a"), present}}},
		{"set keeps the file's other keys", supplied{files: []string{"a: {b: 1}\n"}, sets: []string{"a.c=2"}, complete: true},
			[]probe{{p("a.b"), present}, {p("a.c"), present}}},
		{"sets apply in order: scalar last wins", supplied{sets: []string{"a.b=2", "a=1"}, complete: true},
			[]probe{{p("a.b"), absent}, {p("a"), present}}},
		{"sets apply in order: a key through an earlier scalar is refused", supplied{sets: []string{"a=1", "a.b=2"}, complete: true},
			[]probe{{p("a.b"), unknown}, {p("x"), unknown}}},
		{"set through a file scalar is refused", supplied{files: []string{"a: 5\n"}, sets: []string{"a.b=c"}, complete: true},
			[]probe{{p("a.b"), unknown}}},
		{"set through a file null is refused", supplied{files: []string{"a: null\n"}, sets: []string{"a.b=c"}, complete: true},
			[]probe{{p("a.b"), unknown}}},
		{"set null removes the key: unknown, never absent", supplied{files: []string{"a: {b: 1}\n"}, sets: []string{"a.b=null"}, complete: true},
			[]probe{{p("a.b"), unknown}}},
		{"set null in any letter case", supplied{files: []string{"a: {b: 1}\n"}, sets: []string{"a.b=NuLl"}, complete: true},
			[]probe{{p("a.b"), unknown}}},
		{"a value that only starts with null is a value", supplied{sets: []string{"a.b=nullx"}, complete: true},
			[]probe{{p("a.b"), present}}},
		{"escaped dot in a key is one key", supplied{sets: []string{`a\.b=c`}, complete: true},
			[]probe{{[]string{"a.b"}, present}, {p("a.b"), absent}}},
		{"escaped dot after a path", supplied{sets: []string{`a.b\.c=1`}, complete: true},
			[]probe{{[]string{"a", "b.c"}, present}, {p("a.b"), absent}}},
		{"escaped dot is the same key as the same key in a file", supplied{files: []string{"\"a.b\": 1\n"}, sets: []string{`a\.b=2`}, complete: true},
			[]probe{{[]string{"a.b"}, present}}},
		{"escaped comma and equals in a value", supplied{sets: []string{`a.b=x\,y\=z`}, complete: true},
			[]probe{{p("a.b"), present}}},
		// --- refused spellings: the whole input is refused, so every key is unknown ---
		{"list index in a key", supplied{sets: []string{"a[0].b=c"}, complete: true},
			[]probe{{p("a.b"), unknown}, {p("x"), unknown}}},
		{"comma splits assignments in Helm", supplied{sets: []string{"a.b=1,c=2"}, complete: true},
			[]probe{{p("a.b"), unknown}, {p("c"), unknown}}},
		{"leading brace is a list in Helm", supplied{sets: []string{"a.b={x}"}, complete: true},
			[]probe{{p("a.b"), unknown}}},
		{"an escape the collector does not know", supplied{sets: []string{`a\x.b=c`}, complete: true},
			[]probe{{p("a.b"), unknown}}},
		{"empty key part", supplied{sets: []string{"a..b=c"}, complete: true},
			[]probe{{p("a.b"), unknown}}},
		{"no equals sign", supplied{sets: []string{"a.b"}, complete: true},
			[]probe{{p("a.b"), unknown}}},
		{"values file with an anchor", supplied{files: []string{"a: &x {b: 1}\nc: *x\n"}, complete: true},
			[]probe{{p("a.b"), unknown}}},
		{"values file with an anchor and no alias", supplied{files: []string{"a: &x {b: 1}\n"}, complete: true},
			[]probe{{p("a.b"), unknown}}},
		{"values file with a YAML 1.1 boolean key", supplied{files: []string{"on: 1\n"}, complete: true},
			[]probe{{p("a"), unknown}}},
		{"values file with a duplicate key", supplied{files: []string{"a: 1\na: 2\n"}, complete: true},
			[]probe{{p("a"), unknown}}},
		{"values file with a merge key", supplied{files: []string{"a: {<<: {b: 1}}\n"}, complete: true},
			[]probe{{p("a.b"), unknown}}},
		{"values file that is a list", supplied{files: []string{"- a\n"}, complete: true},
			[]probe{{p("a"), unknown}}},
		{"values file of two documents", supplied{files: []string{"a: 1\n---\nb: 2\n"}, complete: true},
			[]probe{{p("a"), unknown}}},
		{"a refused second file refuses the first too", supplied{files: []string{"a: 1\n", "a: &x 1\nb: *x\n"}, complete: true},
			[]probe{{p("a"), unknown}}},
		// --- completeness ---
		{"not declared complete: present is known, absent is not", supplied{files: []string{"a: {b: 1}\n"}},
			[]probe{{p("a.b"), present}, {p("a.c"), unknown}}},
		{"a key no rule can name is never asked", supplied{files: []string{"a: 1\n"}, complete: true},
			[]probe{{longPath, unknown}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, pr := range tc.probes {
				if got := report(t, tc.in, pr.path...); got != pr.want {
					t.Errorf("%s: reported %s, want %s", strings.Join(pr.path, "."), got, pr.want)
				}
			}
		})
	}
}

// Files are applied in the order given: reversing them changes what is
// reported, so the order the collector keeps is part of the contract.
func TestFileOrderIsKept(t *testing.T) {
	forward := supplied{files: []string{"a: {b: 1}\n", "a: 5\n"}, complete: true}
	reverse := supplied{files: []string{"a: 5\n", "a: {b: 1}\n"}, complete: true}
	if f, r := report(t, forward, "a", "b"), report(t, reverse, "a", "b"); f != absent || r != present {
		t.Fatalf("forward %s reverse %s", f, r)
	}
}

// Helm's own spellings are refused by name, never read in part.
func TestHelmSpellingsAreRefused(t *testing.T) {
	for _, flag := range []string{"--set", "--set-string", "--set-json", "--set-file", "--set-literal", "--values", "-f"} {
		for _, args := range [][]string{{flag, "a.b=c"}, {flag + "=a.b=c"}} {
			_, err := scanrun.ParseArgs(args)
			var u *scanrun.UsageError
			if !errors.As(err, &u) || !strings.Contains(u.Message, "unknown flag") {
				t.Errorf("%v: %v", args, err)
			}
		}
	}
	req, err := scanrun.ParseArgs([]string{"--helm-values", "one.yaml", "--helm-values=two.yaml", "--helm-set", "a.b=c", "--helm-set=d=e"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(req.HelmValues, []string{"one.yaml", "two.yaml"}) || !slices.Equal(req.HelmSet, []string{"a.b=c", "d=e"}) {
		t.Fatalf("files %v sets %v", req.HelmValues, req.HelmSet)
	}
	if _, err := scanrun.ParseArgs([]string{"--helm-values", "-"}); err == nil {
		t.Fatal("standard input accepted as a values file")
	}
}

// The prepared input says what was not evaluated, so a reader of a report
// never mistakes supplied values for the deployed release.
func TestOmissionsAreStated(t *testing.T) {
	values, err := cncfprepare.MergeHelmValues(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	hop := cncfprepare.HelmChartHop{Component: "pkg:github/kedacore/keda", Chart: chart, From: "2.15.0", To: "2.16.0"}
	scan, err := cncfprepare.PrepareHelmValues(hop, fact, values, cncfprepare.HelmUniverse{Resolved: true}, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"HELM_VALUES_ARE_CALLER_SUPPLIED_NOT_THE_DEPLOYED_RELEASE", "CHART_TEMPLATES_DEFAULTS_AND_APPLICATION_UPGRADE_NOT_EVALUATED"} {
		if !slices.Contains(scan.Prepared.Omissions, want) {
			t.Errorf("omission %s missing from %v", want, scan.Prepared.Omissions)
		}
	}
}
