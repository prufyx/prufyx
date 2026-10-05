// SPDX-License-Identifier: AGPL-3.0-only

package extractpack_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
)

const reviewedSuffix = "-reviewed"

func supersede(t *testing.T, pack, run string) (*extractpack.SupersedeReport, error) {
	t.Helper()
	return extractpack.Supersede(extractpack.Options{PackPath: pack, RunDir: run, Admit: admitAll})
}

func deepCopy(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// reviewedTwin is the run's entry as a reviewed rule: another id, no
// extractor, the same constraint and region. edit may change it.
func reviewedTwin(t *testing.T, e map[string]any, edit func(rule map[string]any)) map[string]any {
	t.Helper()
	twin := deepCopy(t, e)
	rule := twin["rule"].(map[string]any)
	rule["id"] = rule["id"].(string) + reviewedSuffix
	rule["evidence"] = map[string]any{"state": "active", "reviewedAt": "2026-09-23T13:55:00Z", "validUntil": "2026-12-22T13:55:00Z", "sources": []any{}}
	if edit != nil {
		edit(rule)
	}
	return twin
}

func runEntries(t *testing.T, run string) []map[string]any {
	t.Helper()
	var es []map[string]any
	readJSON(t, filepath.Join(run, "candidates.json"), &es)
	return es
}

// reviewedBase is the pruned shipped pack plus a reviewed twin of every rule
// of the run (edit may change one, by index, or drop it by returning nil).
func reviewedBase(t *testing.T, c kase, run string, edit func(i int, rule map[string]any)) string {
	t.Helper()
	pack := prunedPack(t, "cncf", run)
	es := runEntries(t, run)
	mustModifyPack(t, pack, func(base []map[string]any) []map[string]any {
		for i, e := range es {
			i := i
			base = append(base, reviewedTwin(t, e, func(r map[string]any) {
				if edit != nil {
					edit(i, r)
				}
			}))
		}
		return base
	})
	return pack
}

func packIDs(t *testing.T, pack string) map[string]bool {
	t.Helper()
	var doc struct {
		Entries []struct {
			Rule struct {
				ID string `json:"id"`
			} `json:"rule"`
		} `json:"entries"`
	}
	readJSON(t, pack, &doc)
	out := map[string]bool{}
	for _, e := range doc.Entries {
		out[e.Rule.ID] = true
	}
	return out
}

func refused(t *testing.T, pack, run string, want error) {
	t.Helper()
	pre, _ := os.ReadFile(pack)
	_, err := supersede(t, pack, run)
	if !errors.Is(err, want) {
		t.Fatalf("want %v, got %v", want, err)
	}
	assertUnchanged(t, pack, pre)
}

// Golden: the map and the result on every extractor's fixture. Reviewed
// twins of the run's rules go, the run's rules come, everything else keeps
// its bytes.
func TestSupersedeGoldenPerExtractor(t *testing.T) {
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			run := runDir(t, c, derivedAt)
			pack := reviewedBase(t, c, run, nil)
			before := packIDs(t, pack)
			rep, err := supersede(t, pack, run)
			if err != nil {
				t.Fatal(err)
			}
			ids := ruleIDs(t, run)
			doc, err := rep.Map()
			if err != nil {
				t.Fatal(err)
			}
			golden := filepath.Join("testdata", "golden", "supersede-"+c.name+".json")
			if os.Getenv("UPDATE_GOLDEN") != "" {
				if err := os.WriteFile(golden, doc, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if string(want) != string(doc) {
				t.Fatalf("map differs from %s:\n%s", golden, doc)
			}
			if len(rep.Pairs) != len(ids) || !equalStrings(rep.Added, ids) || !rep.Changed {
				t.Fatalf("report %+v", rep)
			}
			after := packIDs(t, pack)
			for _, id := range ids {
				if !after[id] || after[id+reviewedSuffix] || !before[id+reviewedSuffix] {
					t.Fatalf("rule %s not swapped", id)
				}
			}
			if len(after) != len(before) {
				t.Fatalf("%d rules before, %d after", len(before), len(after))
			}
			// Idempotent: the same run again changes nothing and prints an empty map.
			now, _ := os.ReadFile(pack)
			again, err := supersede(t, pack, run)
			if err != nil || again.Changed || len(again.Pairs) != 0 || len(again.Unchanged) != len(ids) {
				t.Fatalf("second supersede: %+v %v", again, err)
			}
			assertUnchanged(t, pack, now)
		})
	}
}

func TestSupersedeIsDeterministic(t *testing.T) {
	for _, c := range cases {
		run := runDir(t, c, derivedAt)
		var outs [][]byte
		var packs [][]byte
		for i := 0; i < 2; i++ {
			pack := reviewedBase(t, c, run, nil)
			rep, err := supersede(t, pack, run)
			if err != nil {
				t.Fatal(err)
			}
			doc, _ := rep.Map()
			outs = append(outs, doc)
			raw, _ := os.ReadFile(pack)
			packs = append(packs, raw)
		}
		if string(outs[0]) != string(outs[1]) || string(packs[0]) != string(packs[1]) {
			t.Fatalf("%s: two supersedes differ", c.name)
		}
	}
}

// A wider reviewed rule is covered by nothing smaller: partial coverage.
func TestSupersedeRefusesPartialCoverage(t *testing.T) {
	c := cases[1] // served APIs: ranged rules
	run := runDir(t, c, derivedAt)
	for name, edit := range map[string]func(r map[string]any){
		"wider from": func(r map[string]any) {
			r["range"].(map[string]any)["from"].(map[string]any)["lt"] = "1.99.0"
		},
		"wider to": func(r map[string]any) {
			r["range"].(map[string]any)["to"].(map[string]any)["gte"] = "1.0.0"
		},
		"reviewed range where the run has an anchor-narrow region": func(r map[string]any) {
			r["range"].(map[string]any)["from"].(map[string]any)["gte"] = "1.0.0"
		},
	} {
		t.Run(name, func(t *testing.T) {
			pack := reviewedBase(t, c, run, func(i int, r map[string]any) {
				if i == 0 {
					edit(r)
				}
			})
			refused(t, pack, run, extractpack.ErrSupersede)
		})
	}
	t.Run("set members not covered", func(t *testing.T) {
		fc := cases[0]
		frun := runDir(t, fc, derivedAt)
		pack := reviewedBase(t, fc, frun, func(i int, r map[string]any) {
			if i == 0 {
				sc := r["setCondition"].(map[string]any)
				sc["members"] = append(sc["members"].([]any), "ZZNotInTheRun")
			}
		})
		refused(t, pack, frun, extractpack.ErrSupersede)
	})
	t.Run("a reviewed rule overlapping two rules of the run", func(t *testing.T) {
		fc := cases[0]
		frun := runDir(t, fc, derivedAt)
		es := runEntries(t, frun)
		// Two rules of one key over different transitions, and a reviewed rule with a wide range and both member sets.
		var a, b map[string]any
	find:
		for i := range es {
			for j := i + 1; j < len(es); j++ {
				x, y := es[i]["rule"].(map[string]any), es[j]["rule"].(map[string]any)
				if x["setCondition"].(map[string]any)["factId"] == y["setCondition"].(map[string]any)["factId"] &&
					x["subject"].(map[string]any)["to"] != y["subject"].(map[string]any)["to"] {
					a, b = es[i], es[j]
					break find
				}
			}
		}
		if a == nil {
			t.Skip("no two rules of one key in this fixture")
		}
		pack := prunedPack(t, "cncf", frun)
		mustModifyPack(t, pack, func(base []map[string]any) []map[string]any {
			tw := reviewedTwin(t, a, nil)
			sc := tw["rule"].(map[string]any)["setCondition"].(map[string]any)
			sc["members"] = append(sc["members"].([]any), b["rule"].(map[string]any)["setCondition"].(map[string]any)["members"].([]any)...)
			tw["rule"].(map[string]any)["range"] = map[string]any{
				"from":   map[string]any{"gte": "1.0.0", "lt": "9.0.0"},
				"to":     map[string]any{"gte": "1.0.0", "lt": "9.0.0"},
				"bounds": []any{},
			}
			return append(base, tw)
		})
		refused(t, pack, frun, extractpack.ErrSupersede)
		if _, err := supersede(t, pack, frun); err == nil || !strings.Contains(err.Error(), "overlaps 2 rules") {
			t.Fatalf("got %v", err)
		}
	})
}

// A run that matches no reviewed rule is an apply, not a supersede.
func TestSupersedeRefusesWhenNoReviewedRuleMatches(t *testing.T) {
	c := cases[1]
	run := runDir(t, c, derivedAt)
	pack := prunedPack(t, "cncf", run)
	refused(t, pack, run, extractpack.ErrSupersede)

	// A reviewed rule of another fact, or another component, does not match.
	pack = reviewedBase(t, c, run, func(i int, r map[string]any) {
		r["condition"].(map[string]any)["factId"] = "component.kubernetes.some_other_fact"
	})
	refused(t, pack, run, extractpack.ErrSupersede)
	pack = reviewedBase(t, c, run, func(i int, r map[string]any) {
		r["subject"].(map[string]any)["component"] = "pkg:github/other/other"
	})
	refused(t, pack, run, extractpack.ErrSupersede)
}

// Only reviewed rules can be replaced; a mechanical rule in the way is a refusal.
func TestSupersedeRefusesAMechanicalRuleInTheWay(t *testing.T) {
	c := cases[1]
	run := runDir(t, c, derivedAt)
	pack := reviewedBase(t, c, run, nil)
	es := runEntries(t, run)
	mustModifyPack(t, pack, func(base []map[string]any) []map[string]any {
		tw := deepCopy(t, es[0])
		tw["rule"].(map[string]any)["id"] = "foreign-mechanical-rule"
		return append(base, tw)
	})
	refused(t, pack, run, extractpack.ErrSupersede)
}

func TestSupersedeRefusesACollision(t *testing.T) {
	c := cases[1]
	run := runDir(t, c, derivedAt)
	pack := reviewedBase(t, c, run, nil)
	es := runEntries(t, run)
	mustModifyPack(t, pack, func(base []map[string]any) []map[string]any {
		tw := deepCopy(t, es[0])
		tw["description"] = "someone else's"
		return append(base, tw)
	})
	refused(t, pack, run, extractpack.ErrCollision)
}

func TestSupersedeRefusesDamagedRunsAndPacks(t *testing.T) {
	c := cases[1]
	run := runDir(t, c, derivedAt)
	pack := reviewedBase(t, c, run, nil)
	pre, _ := os.ReadFile(pack)
	if err := os.WriteFile(filepath.Join(run, "candidates.json"), []byte("[]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := supersede(t, pack, run); !errors.Is(err, extractpack.ErrRun) {
		t.Fatalf("damaged run: %v", err)
	}
	assertUnchanged(t, pack, pre)
	run = runDir(t, c, derivedAt)
	if _, err := supersede(t, filepath.Join(t.TempDir(), "none.json"), run); !errors.Is(err, extractpack.ErrPack) {
		t.Fatalf("missing pack: %v", err)
	}
}

func TestSupersedeLeavesTheAdmissionToTheLoader(t *testing.T) {
	c := cases[1]
	run := runDir(t, c, derivedAt)
	pack := reviewedBase(t, c, run, nil)
	pre, _ := os.ReadFile(pack)
	_, err := extractpack.Supersede(extractpack.Options{PackPath: pack, RunDir: run, Admit: func(string, []byte) error { return errors.New("no") }})
	if !errors.Is(err, extractpack.ErrAdmission) {
		t.Fatalf("got %v", err)
	}
	assertUnchanged(t, pack, pre)
}

// The final audit is wired in: a planning step that removes a rule it did
// not plan to, edits one, adds one, or moves a pack member is refused, and
// nothing is written. Removing the audit call makes this test fail.
func TestSupersedeAuditsTheResult(t *testing.T) {
	c := cases[1]
	run := runDir(t, c, derivedAt)
	for name, fault := range map[string]func(head *extractpack.Pack, removed, added map[string]bool){
		"extra removal": func(h *extractpack.Pack, _, _ map[string]bool) { h.Entries = h.Entries[1:] },
		"foreign edit": func(h *extractpack.Pack, _, _ map[string]bool) {
			var m map[string]any
			_ = json.Unmarshal(h.Entries[0], &m)
			m["description"] = "edited"
			h.Entries[0], _ = json.Marshal(m)
		},
		"unplanned add": func(h *extractpack.Pack, _, _ map[string]bool) {
			var m map[string]any
			_ = json.Unmarshal(h.Entries[0], &m)
			m["rule"].(map[string]any)["id"] = "smuggled"
			raw, _ := json.Marshal(m)
			h.Entries = append(h.Entries, raw)
		},
		"schema moved": func(h *extractpack.Pack, _, _ map[string]bool) {
			var s string
			_ = json.Unmarshal(h.Members["schema"], &s)
			h.Members["schema"], _ = json.Marshal(s + "9")
		},
		"member changed": func(h *extractpack.Pack, _, _ map[string]bool) {
			h.Members["revision"] = json.RawMessage(`"cncf-9999-01-01.1"`)
		},
		"removed rule was never in the pack": func(_ *extractpack.Pack, removed, _ map[string]bool) { removed["ghost"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			pack := reviewedBase(t, c, run, nil)
			pre, _ := os.ReadFile(pack)
			restore := extractpack.SetSupersedeStep(func(b *extractpack.Pack, r *extractpack.Run, rep *extractpack.SupersedeReport) (*extractpack.Pack, map[string]bool, map[string]bool, error) {
				head, removed, added, err := extractpack.RealSupersede(b, r, rep)
				if err == nil {
					fault(head, removed, added)
				}
				return head, removed, added, err
			})
			defer restore()
			_, err := supersede(t, pack, run)
			if !errors.Is(err, extractpack.ErrForeignChange) {
				t.Fatalf("got %v", err)
			}
			assertUnchanged(t, pack, pre)
		})
	}
	// The real step passes the same audit.
	pack := reviewedBase(t, c, run, nil)
	if _, err := supersede(t, pack, run); err != nil {
		t.Fatal(err)
	}
}

// ---- apply --rules-only ----------------------------------------------------

func TestApplyRulesOnlyAddsNoAttestationsAndKeepsTheSchema(t *testing.T) {
	c := cases[1] // served APIs: the run carries attestations
	run := runDir(t, c, derivedAt)
	full := prunedPack(t, "cncf", run)
	only := prunedPack(t, "cncf", run)
	base, _ := os.ReadFile(only)
	if _, err := apply(t, full, run, false); err != nil {
		t.Fatal(err)
	}
	rep, err := extractpack.Apply(extractpack.Options{PackPath: only, RunDir: run, RulesOnly: true, Admit: admitAll})
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(rep.Added, ruleIDs(t, run)) || len(rep.AttAdded) != 0 || rep.SchemaFrom != rep.SchemaTo {
		t.Fatalf("report %+v", rep)
	}
	var fullDoc, onlyDoc, baseDoc map[string]json.RawMessage
	got, _ := os.ReadFile(only)
	fullRaw, _ := os.ReadFile(full)
	for raw, doc := range map[*[]byte]*map[string]json.RawMessage{&got: &onlyDoc, &fullRaw: &fullDoc, &base: &baseDoc} {
		if err := json.Unmarshal(*raw, doc); err != nil {
			t.Fatal(err)
		}
	}
	if string(onlyDoc["lineAttestations"]) != string(baseDoc["lineAttestations"]) || string(onlyDoc["schema"]) != string(baseDoc["schema"]) {
		t.Fatal("rules-only changed the attestations or the schema")
	}
	if string(onlyDoc["entries"]) != string(fullDoc["entries"]) {
		t.Fatal("rules-only entries differ from the full apply's")
	}
	if string(fullDoc["lineAttestations"]) == string(baseDoc["lineAttestations"]) {
		t.Skip("the fixture run adds no attestations; nothing to tell the modes apart")
	}
}

func TestApplyRulesOnlyRefusals(t *testing.T) {
	c := cases[1]
	run := runDir(t, c, derivedAt)
	pack := prunedPack(t, "cncf", run)
	pre, _ := os.ReadFile(pack)
	if _, err := extractpack.Apply(extractpack.Options{PackPath: pack, RunDir: run, RulesOnly: true, Withdraw: true, Admit: admitAll}); err == nil || !strings.Contains(err.Error(), "rules-only") {
		t.Fatalf("withdraw + rules-only: %v", err)
	}
	// A loader that admits the pack only at another schema: rules-only never moves it.
	_, err := extractpack.Apply(extractpack.Options{PackPath: pack, RunDir: run, RulesOnly: true, Admit: func(_ string, raw []byte) error {
		if strings.Contains(string(raw), "v1alpha2") {
			return errors.New("needs a higher schema")
		}
		return nil
	}})
	if !errors.Is(err, extractpack.ErrAdmission) {
		t.Fatalf("got %v", err)
	}
	assertUnchanged(t, pack, pre)
}
