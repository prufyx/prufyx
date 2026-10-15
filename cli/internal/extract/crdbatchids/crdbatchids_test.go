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

// The batch statement itself: 28 rules over four projects, every id naming
// its kind and project, four quiet Strimzi lines.
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
	if len(IDs()) != 28 || perProject["crossplane"] != 2 || perProject["kyverno"] != 1 || perProject["longhorn"] != 15 || perProject["strimzi"] != 10 || len(perProject) != 4 {
		t.Fatalf("batch %d rules %v", len(IDs()), perProject)
	}
	if len(Lines()) != 4 {
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
	for _, project := range []string{"crossplane", "kyverno", "longhorn", "strimzi", "argo-cd"} {
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
		"rules without lines": packOf(all, nil),
		"lines without rules": packOf(nil, quiet),
		"one rule missing":    packOf(all[1:], quiet),
		"one line missing":    packOf(all, quiet[1:]),
		"altered members":     packOf(altered, quiet),
		"foreign crd rule":    packOf(append(all, `{"project":"keda","rule":{"id":"keda.crd-version-removal.x"}}`), quiet),
		"line with a rule":    packOf(all, append(quiet[1:], lineOf(Lines()[0], `["`+first.ID+`"]`))),
		"line without ids":    packOf(all, append(quiet[1:], lineOf(Lines()[0], "null"))),
		"unknown line":        packOf(all, append(quiet, lineOf(Line{Component: "pkg:github/strimzi/strimzi-kafka-operator", Line: "0.49"}, "[]"))),
	} {
		if _, err := Holds(pack); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
