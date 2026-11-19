// SPDX-License-Identifier: AGPL-3.0-only

package bundlechart

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSplitLabel(t *testing.T) {
	for label, want := range map[string][2]string{
		"widget-1.4.2":                 {"widget", "1.4.2"},
		"kube-prometheus-stack-55.0.0": {"kube-prometheus-stack", "55.0.0"},
		"widget-1.4.2-rc.1":            {"widget", "1.4.2-rc.1"},
		"app2-v3.0.1":                  {"app2", "v3.0.1"},
		"ingress-nginx-4.11.2":         {"ingress-nginx", "4.11.2"},
	} {
		n, v, ok := SplitLabel(label)
		if !ok || n != want[0] || v != want[1] {
			t.Errorf("SplitLabel(%q) = %q %q %v", label, n, v, ok)
		}
	}
	for _, label := range []string{"", "widget", "widget-", "-1.0.0", "widget-1.0", "Widget-1.0.0", "widget-1.0.0-1.2.3", "widget 1.0.0", "widget-1.0.0\n", "widget-01.0.0", strings.Repeat("a", 300) + "-1.0.0"} {
		if n, v, ok := SplitLabel(label); ok {
			t.Errorf("SplitLabel(%q) accepted as %q %q", label, n, v)
		}
	}
}

func TestParseDeclarationIsStrict(t *testing.T) {
	good := `{"apiVersion":"prufyx.io/chart-declaration/v1alpha1","kind":"ChartDeclaration","charts":[{"name":"widget","version":"1.4.2"}]}`
	got, err := ParseDeclaration([]byte(good))
	if err != nil || len(got) != 1 || got[0] != (Declared{"widget", "1.4.2"}) {
		t.Fatalf("good declaration: %v %v", got, err)
	}
	for name, doc := range map[string]string{
		"empty":         ``,
		"unknown field": `{"apiVersion":"prufyx.io/chart-declaration/v1alpha1","kind":"ChartDeclaration","charts":[{"name":"widget","version":"1.4.2","values":"x"}]}`,
		"no charts":     `{"apiVersion":"prufyx.io/chart-declaration/v1alpha1","kind":"ChartDeclaration","charts":[]}`,
		"wrong kind":    `{"apiVersion":"prufyx.io/chart-declaration/v1alpha1","kind":"Other","charts":[{"name":"widget","version":"1.4.2"}]}`,
		"bad version":   `{"apiVersion":"prufyx.io/chart-declaration/v1alpha1","kind":"ChartDeclaration","charts":[{"name":"widget","version":"latest"}]}`,
		"bad name":      `{"apiVersion":"prufyx.io/chart-declaration/v1alpha1","kind":"ChartDeclaration","charts":[{"name":"Wid get","version":"1.0.0"}]}`,
		"trailing":      good + `{}`,
		"oversize":      good + strings.Repeat(" ", MaxDeclarationBytes),
	} {
		if _, err := ParseDeclaration([]byte(doc)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func lab(kind, ns, name, label string) LabelObservation {
	return LabelObservation{Kind: kind, Namespace: ns, Name: name, Label: label}
}

func TestBuildStates(t *testing.T) {
	d := func(n, v string) Declared { return Declared{n, v} }
	cases := []struct {
		name     string
		declared []Declared
		labels   []LabelObservation
		unread   int
		status   string
	}{
		{"nothing", nil, nil, 0, StatusNotDeclared},
		{"declared only", []Declared{d("w", "1.0.0")}, nil, 0, StatusIdentified},
		{"label only", nil, []LabelObservation{lab("Deployment", "a", "x", "w-1.0.0")}, 0, StatusIdentified},
		{"agree", []Declared{d("w", "1.0.0")}, []LabelObservation{lab("Deployment", "a", "x", "w-1.0.0")}, 0, StatusIdentified},
		{"conflict", []Declared{d("w", "1.0.0")}, []LabelObservation{lab("Deployment", "a", "x", "w-1.1.0")}, 0, StatusAmbiguous},
		{"two declared", []Declared{d("w", "1.0.0"), d("w", "1.1.0")}, nil, 0, StatusAmbiguous},
		{"same ns two versions", nil, []LabelObservation{lab("Deployment", "a", "x", "w-1.0.0"), lab("Deployment", "a", "y", "w-1.1.0")}, 0, StatusAmbiguous},
		{"other ns two versions", nil, []LabelObservation{lab("Deployment", "a", "x", "w-1.0.0"), lab("Deployment", "b", "y", "w-1.1.0")}, 0, StatusIdentified},
		{"unrelated chart does not conflict", []Declared{d("w", "1.0.0")}, []LabelObservation{lab("Deployment", "a", "x", "z-9.0.0")}, 0, StatusIdentified},
		{"malformed only", nil, []LabelObservation{lab("Deployment", "a", "x", "junk")}, 0, StatusNotDeclared},
		{"unread source", []Declared{d("w", "1.0.0")}, nil, 1, StatusAmbiguous},
	}
	for _, c := range cases {
		set := Build(c.declared, c.labels, c.unread)
		if set.Status != c.status {
			t.Errorf("%s: status %s, want %s (%+v)", c.name, set.Status, c.status, set)
		}
		if (set.Status == StatusIdentified) != (set.NextAction == "") {
			t.Errorf("%s: next action %q with status %s", c.name, set.NextAction, set.Status)
		}
		if err := Validate(set); err != nil {
			t.Errorf("%s: built set does not validate: %v", c.name, err)
		}
	}
}

func TestBuildDeduplicatesAndBounds(t *testing.T) {
	set := Build(nil, []LabelObservation{lab("ReplicaSet", "a", "x-1", "w-1.0.0"), lab("Deployment", "a", "x", "w-1.0.0")}, 0)
	if len(set.Entries) != 1 || set.Entries[0].SourceKind != "Deployment" {
		t.Fatalf("dedup: %+v", set.Entries)
	}
	var many []LabelObservation
	for i := 0; i < MaxEntries+5; i++ {
		many = append(many, lab("Deployment", "ns"+strings.Repeat("a", i%50), "n"+strings.Repeat("b", i/50), "w-1.0."+strings.Repeat("1", 1+i%9)))
	}
	set = Build(nil, many, 0)
	if len(set.Entries) > MaxEntries {
		t.Fatalf("entries not bounded: %d", len(set.Entries))
	}
}

func TestDecodeRejectsTamperAndExtraFields(t *testing.T) {
	set := Build([]Declared{{"w", "1.0.0"}}, []LabelObservation{lab("Deployment", "a", "x", "w-1.1.0")}, 0)
	raw, _ := json.Marshal(set)
	if _, err := Decode(raw); err != nil {
		t.Fatalf("valid set rejected: %v", err)
	}
	mutations := map[string]func(*Set){
		"state resolved on a conflict":  func(s *Set) { s.Entries[0].State = StateResolved },
		"status identified on conflict": func(s *Set) { s.Status, s.NextAction = StatusIdentified, "" },
		"next action dropped":           func(s *Set) { s.NextAction = "" },
		"declared with object":          func(s *Set) { s.Entries[0].SourceName = "x" },
		"bad version":                   func(s *Set) { s.Entries[0].ChartVersion = "x" },
		"bad source":                    func(s *Set) { s.Entries[0].Source = "release" },
		"unknown omission":              func(s *Set) { s.Omissions = append(s.Omissions, Omission{Code: "ANYTHING", Count: 1}) },
		"nil entries":                   func(s *Set) { s.Entries = nil },
	}
	for name, mutate := range mutations {
		s := set
		s.Entries = append([]Entry(nil), set.Entries...)
		s.Omissions = append([]Omission(nil), set.Omissions...)
		mutate(&s)
		raw, _ := json.Marshal(s)
		if _, err := Decode(raw); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := Decode([]byte(strings.Replace(string(raw), `"status"`, `"extra":"x","status"`, 1))); err == nil {
		t.Error("extra field accepted")
	}
}

func TestSummaryNamesNothing(t *testing.T) {
	set := Build([]Declared{{"secret-chart", "1.0.0"}}, nil, 0)
	if s := Summary(set); strings.Contains(s, "secret-chart") || strings.Contains(s, "1.0.0") {
		t.Fatalf("summary leaks identity: %q", s)
	}
}
