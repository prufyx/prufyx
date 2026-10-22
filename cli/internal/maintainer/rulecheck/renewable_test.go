// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func hasCollision(r Result) bool {
	for _, f := range r.Findings {
		if f.Check == "rule-id-collision" {
			return true
		}
	}
	return false
}

// RenewableIDs lifts the published-id collision for the listed ids only.
func TestValidate_RenewableIDsSkipOnlyTheListedIDs(t *testing.T) {
	packPath := filepath.Join("..", "..", "projectcheck", "data", "rules.json")
	first := firstRealEntry(t)
	id, _ := rule(first)["id"].(string)
	entries := realEntries(t, packPath)
	if len(entries) < 2 {
		t.Fatal("need two published entries")
	}
	second := entries[1]
	otherID, _ := rule(second)["id"].(string)
	raw, err := json.Marshal([]map[string]any{first, second})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name      string
		renewable map[string]bool
		collides  bool
	}{
		{"none listed", nil, true},
		{"one of two listed", map[string]bool{id: true}, true},
		{"unrelated id listed", map[string]bool{"x.y": true}, true},
		{"both listed", map[string]bool{id: true, otherID: true}, false},
	} {
		res, err := Validate(raw, Options{AllowRange: true, ExistingRulesPaths: []string{packPath}, RenewableIDs: c.renewable})
		if err != nil {
			t.Fatal(err)
		}
		if got := hasCollision(res); got != c.collides {
			t.Errorf("%s: collision = %v, want %v: %+v", c.name, got, c.collides, res.Findings)
		}
	}
}

// A listed id is still refused when the candidate file repeats it.
func TestValidate_RenewableIDsStillRefuseARepeatInTheFile(t *testing.T) {
	packPath := filepath.Join("..", "..", "projectcheck", "data", "rules.json")
	e := firstRealEntry(t)
	id, _ := rule(e)["id"].(string)
	raw, _ := json.Marshal([]map[string]any{e, e})
	res, err := Validate(raw, Options{AllowRange: true, ExistingRulesPaths: []string{packPath}, RenewableIDs: map[string]bool{id: true}})
	if err != nil || !hasCollision(res) {
		t.Fatalf("%v %+v", err, res.Findings)
	}
}

func TestRenewableIn(t *testing.T) {
	mk := func(id, state, basis, ext string) map[string]any {
		ev := map[string]any{"state": state, "basis": basis}
		if ext != "" {
			ev["extractor"] = map[string]any{"id": ext}
		}
		return map[string]any{"rule": map[string]any{"id": id, "evidence": ev}}
	}
	dir := t.TempDir()
	write := func(name string, entries ...map[string]any) string {
		raw, _ := json.Marshal(map[string]any{"entries": entries})
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	a := write("a.json",
		mk("ok", "active", "mechanical", "x.y"),
		mk("withdrawn", "withdrawn", "mechanical", "x.y"),
		mk("reviewed", "active", "reviewed", ""),
		mk("foreign", "active", "mechanical", "other"),
		mk("twice", "active", "mechanical", "x.y"))
	b := write("b.json", mk("twice", "active", "reviewed", ""))
	got, err := RenewableIn([]string{a, b, " "}, "x.y")
	if err != nil || len(got) != 1 || !got["ok"] {
		t.Fatalf("%v %v", got, err)
	}
	if got, _ := RenewableIn([]string{a}, ""); len(got) != 0 {
		t.Fatalf("empty extractor id matched %v", got)
	}
}
