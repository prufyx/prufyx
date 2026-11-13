// SPDX-License-Identifier: AGPL-3.0-only

package crdbatchids

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The batch statement itself: 13 rules over three projects, every id naming
// its kind and project, five quiet Strimzi lines.
func TestBatchStatement(t *testing.T) {
	perProject := map[string]int{}
	seen := map[string]bool{}
	for _, r := range Rules() {
		if seen[r.ID] || !strings.HasPrefix(r.ID, r.Project+Marker) || len(r.Members) == 0 {
			t.Fatalf("rule %+v", r)
		}
		seen[r.ID] = true
		perProject[r.Project]++
	}
	if len(IDs()) != 13 || perProject["crossplane"] != 2 || perProject["kyverno"] != 1 || perProject["strimzi"] != 10 || len(perProject) != 3 {
		t.Fatalf("batch %d rules %v", len(IDs()), perProject)
	}
	if len(Lines()) != 5 {
		t.Fatalf("%d lines", len(Lines()))
	}
}

// The shipped pack holds the whole batch or none of it, as Holds reads it.
func TestShippedPackHoldsAllOrNone(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "cncfcheck", "data", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	held, err := Holds(raw)
	if err != nil {
		t.Fatal(err)
	}
	if held != Shipped() {
		t.Fatalf("Holds = %v, Shipped() = %v", held, Shipped())
	}
	for _, project := range []string{"crossplane", "kyverno", "strimzi", "argo-cd"} {
		if want := len(ProjectRules(project)); held && Count(project) != want || !held && Count(project) != 0 {
			t.Fatalf("Count(%s) = %d", project, Count(project))
		}
	}
}

func entryOf(r Rule, members []string) string {
	quoted, _ := json.Marshal(members)
	return fmt.Sprintf(`{"project":%q,"rule":{"id":%q,"operator":"forbid_set_member","subject":{"component":%q,"from":%q,"to":%q},"setCondition":{"side":"proposed","component":%q,"factId":%q,"members":%s}}}`,
		r.Project, r.ID, r.Component, r.From, r.To, r.Component, r.FactID(), quoted)
}

func lineOf(l Line, ruleIDs string) string {
	return fmt.Sprintf(`{"component":%q,"line":%q,"factFamily":%q,"ruleIds":%s}`, l.Component, l.Line, FactFamily, ruleIDs)
}

func packOf(entries, lines []string) []byte {
	return []byte(`{"entries":[` + strings.Join(entries, ",") + `],"lineAttestations":[` + strings.Join(lines, ",") + `]}`)
}

// Holds accepts exactly the empty and the complete batch, and refuses every
// partial or altered one.
func TestHoldsRefusesPartialAndAlteredBatches(t *testing.T) {
	var all, quiet []string
	for _, r := range Rules() {
		all = append(all, entryOf(r, r.Members))
	}
	for _, l := range Lines() {
		quiet = append(quiet, lineOf(l, "[]"))
	}
	other := `{"project":"argo-cd","rule":{"id":"argo-cd.other-rule","operator":"forbid_enum_value"}}`
	if held, err := Holds(packOf([]string{other}, nil)); err != nil || held {
		t.Fatalf("no batch: %v %v", held, err)
	}
	if held, err := Holds(packOf(append([]string{other}, all...), quiet)); err != nil || !held {
		t.Fatalf("whole batch: %v %v", held, err)
	}
	first := Rules()[0]
	altered := append([]string{entryOf(first, append(first.Members, "x.example/v1/Extra"))}, all[1:]...)
	for name, pack := range map[string][]byte{
		"rules without lines":                      packOf(all, nil),
		"lines without rules":                      packOf(nil, quiet),
		"one rule missing":                         packOf(all[1:], quiet),
		"one line missing":                         packOf(all, quiet[1:]),
		"altered members":                          packOf(altered, quiet),
		"foreign crd rule shapeless":               packOf(append(all, `{"project":"keda","rule":{"id":"keda.crd-version-removal.x"}}`), quiet),
		"foreign crd rule of another project's id": packOf(append(all, foreignEntry("keda", "cilium.crd-version-removal.x", "pkg:github/keda/keda", "component.keda.custom_resource_versions_set", "proposed")), quiet),
		"foreign crd rule on the current side":     packOf(append(all, foreignEntry("keda", "keda.crd-version-removal.x", "pkg:github/keda/keda", "component.keda.custom_resource_versions_set", "current")), quiet),
		"foreign crd rule over another fact":       packOf(append(all, foreignEntry("keda", "keda.crd-version-removal.x", "pkg:github/keda/keda", "component.other.custom_resource_versions_set", "proposed")), quiet),
		"line with a rule":                         packOf(all, append(quiet[1:], lineOf(Lines()[0], `["`+first.ID+`"]`))),
		"line without ids":                         packOf(all, append(quiet[1:], lineOf(Lines()[0], "null"))),
		"repeated line":                            packOf(all, append(quiet, quiet[0])),
		"foreign line with a rule":                 packOf(all, append(quiet, lineOf(Line{Component: "pkg:github/dapr/dapr", Line: "1.14"}, `["`+first.ID+`"]`))),
		"foreign repeated line":                    packOf(all, append(quiet, lineOf(Line{Component: "pkg:github/dapr/dapr", Line: "1.14"}, "[]"), lineOf(Line{Component: "pkg:github/dapr/dapr", Line: "1.14"}, "[]"))),
	} {
		if _, err := Holds(pack); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Quiet lines of other projects are accepted whatever they are (the factory's
// onboarding ships new ones), with the batch whole and with none of it; they
// never count towards the batch.
func TestHoldsAcceptsForeignQuietLines(t *testing.T) {
	var all, quiet []string
	for _, r := range Rules() {
		all = append(all, entryOf(r, r.Members))
	}
	for _, l := range Lines() {
		quiet = append(quiet, lineOf(l, "[]"))
	}
	foreign := []Line{{"pkg:github/dapr/dapr", "1.14"}, {"pkg:github/tektoncd/pipeline", "1.13"}, {"pkg:github/strimzi/strimzi-kafka-operator", "0.49"}}
	var extra []string
	for _, l := range foreign {
		extra = append(extra, lineOf(l, "[]"))
	}
	held, others, err := holds(packOf(all, append(append([]string(nil), quiet...), extra...)))
	if err != nil || !held || len(others) != len(foreign) {
		t.Fatalf("whole batch with foreign lines: %v %v %v", held, others, err)
	}
	held, others, err = holds(packOf(nil, extra))
	if err != nil || held || len(others) != len(foreign) {
		t.Fatalf("no batch with foreign lines: %v %v %v", held, others, err)
	}
	// Foreign lines alone never make a partial batch.
	if _, err := Holds(packOf(all, extra)); err == nil {
		t.Fatal("rules and foreign lines without the batch's lines accepted")
	}
}

func foreignEntry(project, id, component, factID, side string) string {
	return fmt.Sprintf(`{"project":%q,"rule":{"id":%q,"operator":"forbid_set_member","subject":{"component":%q,"from":"1.0.0","to":"2.0.0"},"setCondition":{"side":%q,"component":%q,"factId":%q,"members":["x.example/v1/X"]}}}`,
		project, id, component, side, component, factID)
}

// A mechanical custom-resource version-removal rule of another project (the
// factory's daily export adds them) is accepted beside the whole batch and
// beside none of it, and never counts towards the batch.
func TestHoldsAcceptsForeignMechanicalRules(t *testing.T) {
	var all, quiet []string
	for _, r := range Rules() {
		all = append(all, entryOf(r, r.Members))
	}
	for _, l := range Lines() {
		quiet = append(quiet, lineOf(l, "[]"))
	}
	foreign := foreignEntry("cilium", "cilium.crd-version-removal.ciliumnodeconfigs-cilium-io.1-19-0-to-1-20-0", "pkg:github/cilium/cilium", "component.cilium.custom_resource_versions_set", "proposed")
	if held, err := Holds(packOf(append([]string{foreign}, all...), quiet)); err != nil || !held {
		t.Fatalf("whole batch with a foreign rule: %v %v", held, err)
	}
	if held, err := Holds(packOf([]string{foreign}, nil)); err != nil || held {
		t.Fatalf("no batch with a foreign rule: %v %v", held, err)
	}
	// A foreign rule never completes a partial batch.
	if _, err := Holds(packOf(append([]string{foreign}, all[1:]...), quiet)); err == nil {
		t.Fatal("a foreign rule made up for a missing batch rule")
	}
}

// mechEntry is a mechanical rule of another project with its evidence, as the
// factory ships it: from 1.5.0 to 1.6.0 of the project.
func mechEntry(project, slug, basis, extractor string) string {
	return mechEntryState(project, slug, basis, extractor, "active")
}

func mechEntryState(project, slug, basis, extractor, state string) string {
	component := "pkg:github/" + project + "/" + project
	id := project + Marker + slug + ".1-5-0-to-1-6-0"
	return fmt.Sprintf(`{"project":%q,"rule":{"id":%q,"operator":"forbid_set_member","subject":{"component":%q,"from":"1.5.0","to":"1.6.0"},"evidence":{"basis":%q,"state":%q,"extractor":{"id":%q}},"setCondition":{"side":"proposed","component":%q,"factId":"component.%s.custom_resource_versions_set","members":["x.example/v1/X"]}}}`,
		project, id, component, basis, state, extractor, component, project)
}

// A foreign line may list rules only when they are known mechanical rules of
// the line, exactly; the batch's lines stay quiet; the batch stays all or none.
func TestHoldsForeignLinesWithKnownMechanicalRules(t *testing.T) {
	var all, quiet []string
	for _, r := range Rules() {
		all = append(all, entryOf(r, r.Members))
	}
	for _, l := range Lines() {
		quiet = append(quiet, lineOf(l, "[]"))
	}
	const comp = "pkg:github/openyurt/openyurt"
	idA := "openyurt" + Marker + "a.1-5-0-to-1-6-0"
	idB := "openyurt" + Marker + "b.1-5-0-to-1-6-0"
	mech := func(slug string) string {
		return mechEntry("openyurt", slug, "mechanical", "crd.version-removal.openyurt")
	}
	line := func(l string, ids ...string) string {
		if ids == nil {
			ids = []string{}
		}
		quoted, _ := json.Marshal(ids)
		return lineOf(Line{comp, l}, string(quoted))
	}
	type tc struct {
		name    string
		entries []string
		lines   []string
		ok      bool
	}
	cases := []tc{
		{"quiet foreign line", []string{mech("a")}, []string{line("1.4")}, true},
		{"known rule", []string{mech("a")}, []string{line("1.6", idA)}, true},
		{"known rules, complete list", []string{mech("a"), mech("b")}, []string{line("1.6", idA, idB)}, true},
		{"incomplete list", []string{mech("a"), mech("b")}, []string{line("1.6", idA)}, false},
		{"rule listed twice", []string{mech("a")}, []string{line("1.6", idA, idA)}, false},
		{"unknown rule id", []string{mech("a")}, []string{line("1.6", "openyurt"+Marker+"zzz.1-5-0-to-1-6-0")}, false},
		{"id of a non-crd rule", []string{mech("a"), `{"project":"openyurt","rule":{"id":"openyurt.other","operator":"forbid_enum_value"}}`}, []string{line("1.6", "openyurt.other")}, false},
		{"no rule in the pack", nil, []string{line("1.6", idA)}, false},
		{"another line of the same project", []string{mech("a")}, []string{line("1.7", idA)}, false},
		{"rule of another project", []string{mechEntry("keda", "a", "mechanical", "crd.version-removal.keda")}, []string{line("1.6", "keda"+Marker+"a.1-5-0-to-1-6-0")}, false},
		{"rule of another component", []string{mech("a"), mechEntry("keda", "a", "mechanical", "crd.version-removal.keda")}, []string{line("1.6", idA, "keda"+Marker+"a.1-5-0-to-1-6-0")}, false},
		{"rule not mechanical", []string{mechEntry("openyurt", "a", "reviewed", "crd.version-removal.openyurt")}, []string{line("1.6", idA)}, false},
		{"rule of another extractor", []string{mechEntry("openyurt", "a", "mechanical", "crd.version-removal.keda")}, []string{line("1.6", idA)}, false},
		{"rule without extractor", []string{`{"project":"openyurt","rule":{"id":"` + idA + `","operator":"forbid_set_member","subject":{"component":"` + comp + `","from":"1.5.0","to":"1.6.0"},"setCondition":{"side":"proposed","component":"` + comp + `","factId":"component.openyurt.custom_resource_versions_set","members":["x.example/v1/X"]}}}`}, []string{line("1.6", idA)}, false},
		{"line without ids", []string{mech("a")}, []string{lineOf(Line{comp, "1.6"}, "null")}, false},
		{"withdrawn rule listed", []string{mechEntryState("openyurt", "a", "mechanical", "crd.version-removal.openyurt", "withdrawn")}, []string{line("1.6", idA)}, true},
		{"withdrawn rule left out", []string{mechEntryState("openyurt", "a", "mechanical", "crd.version-removal.openyurt", "withdrawn")}, []string{line("1.6")}, false},
		{"rule id repeated in the pack", []string{mech("a"), mech("a")}, []string{line("1.6", idA)}, false},
		{"quiet line but a rule of the line exists", []string{mech("a")}, []string{line("1.6")}, false},
	}
	for _, c := range cases {
		// Without the batch, and with the whole batch beside it: the same
		// verdict; a foreign line never changes which of the two the pack is.
		held, err := Holds(packOf(c.entries, c.lines))
		if (err == nil) != c.ok || held {
			t.Errorf("%s (no batch): held=%v err=%v, want ok=%v", c.name, held, err, c.ok)
		}
		held, err = Holds(packOf(append(append([]string(nil), all...), c.entries...), append(append([]string(nil), quiet...), c.lines...)))
		if (err == nil) != c.ok || (c.ok && !held) {
			t.Errorf("%s (whole batch): held=%v err=%v, want ok=%v", c.name, held, err, c.ok)
		}
	}
	// The batch's own lines never carry rules, known or not.
	known := mech("a")
	if _, err := Holds(packOf(append([]string{known}, all...), append(append([]string(nil), quiet[1:]...), lineOf(Lines()[0], `["`+idA+`"]`)))); err == nil {
		t.Error("a batch line listing a known rule accepted")
	}
	// All or none still holds with a foreign line with rules in the pack.
	if _, err := Holds(packOf(append([]string{known}, all[1:]...), append(append([]string(nil), quiet...), line("1.6", idA)))); err == nil {
		t.Error("partial batch beside a foreign rule line accepted")
	}
	if _, err := Holds(packOf(append([]string{known}, all...), append(append([]string(nil), quiet[1:]...), line("1.6", idA)))); err == nil {
		t.Error("batch with a line missing beside a foreign rule line accepted")
	}
	// The line is counted among the other lines, not the batch's.
	held, others, err := holds(packOf([]string{known}, []string{line("1.6", idA)}))
	if err != nil || held || len(others) != 1 {
		t.Errorf("foreign line with a rule: %v %v %v", held, others, err)
	}
}
