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
