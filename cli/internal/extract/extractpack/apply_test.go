// SPDX-License-Identifier: AGPL-3.0-only

package extractpack_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
)

func apply(t *testing.T, pack, run string, withdraw bool) (*extractpack.Report, error) {
	t.Helper()
	return extractpack.Apply(extractpack.Options{PackPath: pack, RunDir: run, Withdraw: withdraw, Admit: admitAll})
}

// addedView is the part of a result pack a golden file pins: the entries
// the run added in pack order, and the attestation section.
func addedView(t *testing.T, pack string, added []string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(pack)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Entries          []map[string]any `json:"entries"`
		LineAttestations json.RawMessage  `json:"lineAttestations"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, id := range added {
		want[id] = true
	}
	out := map[string]any{"entries": []map[string]any{}}
	for _, e := range doc.Entries {
		if want[e["rule"].(map[string]any)["id"].(string)] {
			out["entries"] = append(out["entries"].([]map[string]any), e)
		}
	}
	if doc.LineAttestations != nil {
		var a any
		if err := json.Unmarshal(doc.LineAttestations, &a); err != nil {
			t.Fatal(err)
		}
		out["lineAttestations"] = a
	}
	return out
}

// Acceptance 1: for every extractor's fixture run, the merged pack is the
// base plus exactly the run's rules, sorted and canonical; untouched entries
// keep their bytes; merging the same run again changes nothing.
func TestApplyGoldenPerExtractor(t *testing.T) {
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			run := runDir(t, c, derivedAt)
			pack := prunedPack(t, "cncf", run)
			base, _ := os.ReadFile(pack)
			rep, err := apply(t, pack, run, false)
			if err != nil {
				t.Fatal(err)
			}
			if !equalStrings(rep.Added, ruleIDs(t, run)) || len(rep.Unchanged) != 0 || !rep.Changed {
				t.Fatalf("report %+v", rep)
			}
			got, _ := os.ReadFile(pack)
			parsed, err := extractpack.ParsePack(got)
			if err != nil {
				t.Fatal(err)
			}
			again, err := parsed.Render()
			if err != nil || !bytes.Equal(again, got) {
				t.Fatalf("the result is not canonical: %v", err)
			}
			// Sorted by project and rule id; the base's entries are verbatim.
			var doc struct {
				Entries []struct {
					Project string `json:"project"`
					Rule    struct {
						ID string `json:"id"`
					} `json:"rule"`
				} `json:"entries"`
			}
			if err := json.Unmarshal(got, &doc); err != nil {
				t.Fatal(err)
			}
			for i := 1; i < len(doc.Entries); i++ {
				a, b := doc.Entries[i-1], doc.Entries[i]
				if a.Project > b.Project || (a.Project == b.Project && a.Rule.ID >= b.Rule.ID) {
					t.Fatalf("entries out of order at %d: %s %s", i, a.Rule.ID, b.Rule.ID)
				}
			}
			bp, _ := extractpack.ParsePack(base)
			for _, e := range bp.Entries {
				var one []byte
				one, _ = compactRaw(e)
				if !bytes.Contains(compactAll(t, got), one) {
					t.Fatal("a base entry changed")
				}
			}
			golden := filepath.Join("testdata", "golden", c.name+".json")
			want, _ := extractCanon(addedView(t, pack, rep.Added))
			if os.Getenv("UPDATE_GOLDEN") != "" {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, want, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			have, err := os.ReadFile(golden)
			if err != nil || !bytes.Equal(have, want) {
				t.Fatalf("the added entries differ from %s (UPDATE_GOLDEN=1 rewrites it)", golden)
			}
			// Idempotent.
			rep2, err := apply(t, pack, run, false)
			if err != nil || rep2.Changed || len(rep2.Added) != 0 || !equalStrings(rep2.Unchanged, rep.Added) {
				t.Fatalf("second apply: %+v %v", rep2, err)
			}
			if after, _ := os.ReadFile(pack); !bytes.Equal(after, got) {
				t.Fatal("a second apply rewrote the pack")
			}
		})
	}
}

func compactRaw(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	err := json.Compact(&buf, raw)
	return buf.Bytes(), err
}

func compactAll(t *testing.T, raw []byte) []byte {
	t.Helper()
	b, err := compactRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func extractCanon(v any) ([]byte, error) {
	return canonical(v)
}

// The merged pack lists only runs it was given: a rule that is in the pack
// with different content, whether foreign or an earlier derivation, refuses
// the whole apply and leaves the file alone.
func TestApplyRefusesCollisions(t *testing.T) {
	c := cases[0]
	run := runDir(t, c, derivedAt)
	id := ruleIDs(t, run)[0]

	// 1. A foreign rule already holds the id.
	pack := prunedPack(t, "cncf", run)
	pre := mustModifyPack(t, pack, func(entries []map[string]any) []map[string]any {
		foreign := map[string]any{"project": "kubernetes", "description": "reviewed", "requiredFacts": []any{}, "rule": map[string]any{"id": id, "operator": "forbid_predicate_value", "evidence": map[string]any{"state": "active", "basis": "reviewed"}}}
		return append(entries, foreign)
	})
	if _, err := apply(t, pack, run, false); !errors.Is(err, extractpack.ErrCollision) {
		t.Fatalf("foreign id: %v", err)
	}
	assertUnchanged(t, pack, pre)

	// 2. The same extractor derived the rule earlier (a renewal is not an apply).
	pack = prunedPack(t, "cncf", run)
	if _, err := apply(t, pack, runDir(t, c, derivedAt.Add(-48*time.Hour)), false); err != nil {
		t.Fatal(err)
	}
	pre, _ = os.ReadFile(pack)
	if _, err := apply(t, pack, run, false); !errors.Is(err, extractpack.ErrCollision) {
		t.Fatalf("earlier derivation: %v", err)
	}
	assertUnchanged(t, pack, pre)

	// 3. An attestation with the same scope but different content.
	c = cases[1]
	run = runDir(t, c, derivedAt)
	pack = prunedPack(t, "cncf", run)
	if _, err := apply(t, pack, runDir(t, c, derivedAt.Add(-48*time.Hour)), false); err != nil {
		t.Fatal(err)
	}
	pre, _ = os.ReadFile(pack)
	if _, err := apply(t, pack, run, false); !errors.Is(err, extractpack.ErrCollision) {
		t.Fatalf("attestation: %v", err)
	}
	assertUnchanged(t, pack, pre)
}

// An attestation that is in the pack with different content refuses the merge
// even when every rule of the run is already there unchanged.
func TestApplyRefusesAttestationCollision(t *testing.T) {
	run := runDir(t, cases[1], derivedAt)
	pack := prunedPack(t, "cncf", run)
	if _, err := apply(t, pack, run, false); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(pack)
	p, err := extractpack.ParsePack(raw)
	if err != nil {
		t.Fatal(err)
	}
	var atts []map[string]any
	if err := json.Unmarshal(p.Members["lineAttestations"], &atts); err != nil || len(atts) == 0 {
		t.Fatalf("no attestations in the pack: %v", err)
	}
	atts[0]["evidence"].(map[string]any)["validUntil"] = "2027-01-01T00:00:00Z"
	p.Members["lineAttestations"], _ = json.Marshal(atts)
	pre, _ := p.Render()
	if err := os.WriteFile(pack, pre, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := apply(t, pack, run, false); !errors.Is(err, extractpack.ErrCollision) || !strings.Contains(err.Error(), "attestation") {
		t.Fatalf("%v", err)
	}
	assertUnchanged(t, pack, pre)
}

func assertUnchanged(t *testing.T, pack string, before []byte) {
	t.Helper()
	if after, _ := os.ReadFile(pack); !bytes.Equal(after, before) {
		t.Fatal("a refused apply changed the pack file")
	}
}

// mustModifyPack rewrites the pack's entries through edit, keeping its order
// and everything else, and returns the new bytes.
func mustModifyPack(t *testing.T, pack string, edit func([]map[string]any) []map[string]any) []byte {
	t.Helper()
	raw, _ := os.ReadFile(pack)
	p, err := extractpack.ParsePack(raw)
	if err != nil {
		t.Fatal(err)
	}
	var entries []map[string]any
	for _, e := range p.Entries {
		var m map[string]any
		if err := json.Unmarshal(e, &m); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, m)
	}
	p.Entries = nil
	for _, m := range edit(entries) {
		b, _ := json.Marshal(m)
		p.Entries = append(p.Entries, b)
	}
	out, err := p.Render()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pack, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return out
}

// An intact run is required: a changed file, a file the manifest does not
// list, or a rule the manifest's pairs do not list each refuse the apply.
func TestApplyRefusesDamagedRuns(t *testing.T) {
	c := cases[1]
	mutate := map[string]func(t *testing.T, dir string){
		"candidates edited": func(t *testing.T, dir string) {
			p := filepath.Join(dir, "candidates.json")
			b, _ := os.ReadFile(p)
			os.WriteFile(p, bytes.Replace(b, []byte("CronJob"), []byte("CronJoX"), 1), 0o644)
		},
		"vectors edited": func(t *testing.T, dir string) {
			p := filepath.Join(dir, "vectors.json")
			b, _ := os.ReadFile(p)
			os.WriteFile(p, append(b, ' '), 0o644)
		},
		"attestations edited": func(t *testing.T, dir string) {
			p := filepath.Join(dir, "attestations.json")
			b, _ := os.ReadFile(p)
			os.WriteFile(p, append(b, ' '), 0o644)
		},
		"attestations unlisted": func(t *testing.T, dir string) {
			var m map[string]any
			readJSON(t, filepath.Join(dir, "manifest.json"), &m)
			delete(m["outputs"].(map[string]any), "attestations.json")
			writeCanon(t, filepath.Join(dir, "manifest.json"), m)
		},
		"rule not in manifest": func(t *testing.T, dir string) {
			var m map[string]any
			readJSON(t, filepath.Join(dir, "manifest.json"), &m)
			for _, p := range m["pairs"].([]any) {
				pair := p.(map[string]any)
				if r := pair["rules"].([]any); len(r) > 0 {
					pair["rules"] = r[1:]
					break
				}
			}
			writeCanon(t, filepath.Join(dir, "manifest.json"), m)
		},
		"pair lists another id": func(t *testing.T, dir string) {
			var m map[string]any
			readJSON(t, filepath.Join(dir, "manifest.json"), &m)
			for _, p := range m["pairs"].([]any) {
				pair := p.(map[string]any)
				if r := pair["rules"].([]any); len(r) > 0 {
					r[0] = "kubernetes.some-other-rule"
					break
				}
			}
			writeCanon(t, filepath.Join(dir, "manifest.json"), m)
		},
		"no manifest": func(t *testing.T, dir string) { os.Remove(filepath.Join(dir, "manifest.json")) },
	}
	names := make([]string, 0, len(mutate))
	for n := range mutate {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		run := runDir(t, c, derivedAt)
		mutate[name](t, run)
		pack := packDir(t, "cncf")
		pre, _ := os.ReadFile(pack)
		if _, err := apply(t, pack, run, false); !errors.Is(err, extractpack.ErrRun) {
			t.Fatalf("%s: %v", name, err)
		}
		assertUnchanged(t, pack, pre)
	}
}

// --withdraw changes only evidence.state, only on rules of the run's
// extractor that its derived pairs cover and no longer produce.
func TestWithdrawOnlyActiveToWithdrawn(t *testing.T) {
	c := cases[0]
	first := runDir(t, c, derivedAt.Add(-24*time.Hour))
	pack := prunedPack(t, "cncf", first)
	if _, err := apply(t, pack, first, false); err != nil {
		t.Fatal(err)
	}
	pre, _ := os.ReadFile(pack)
	ids := ruleIDs(t, first)
	dropped := map[string]bool{ids[0]: true, ids[len(ids)-1]: true}

	// The extractor now derives the same pairs without those rules.
	later := runDir(t, c, derivedAt)
	trimRun(t, later, dropped, false)
	rep, err := apply(t, pack, later, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{ids[0], ids[len(ids)-1]}
	sort.Strings(want)
	if !equalStrings(rep.Withdrawn, want) || len(rep.Added) != 0 {
		t.Fatalf("report %+v", rep)
	}
	post, _ := os.ReadFile(pack)
	// The only difference between the files is the two state lines.
	a, b := strings.Split(string(pre), "\n"), strings.Split(string(post), "\n")
	if len(a) != len(b) {
		t.Fatalf("line count changed: %d -> %d", len(a), len(b))
	}
	changed := 0
	for i := range a {
		if a[i] != b[i] {
			changed++
			if !strings.Contains(a[i], `"state": "active"`) || !strings.Contains(b[i], `"state": "withdrawn"`) || strings.Replace(a[i], "active", "withdrawn", 1) != b[i] {
				t.Fatalf("line %d: %q -> %q", i, a[i], b[i])
			}
		}
	}
	if changed != 2 {
		t.Fatalf("%d lines changed, want 2", changed)
	}
	// Withdrawing again changes nothing (a withdrawn rule is not active).
	rep, err = apply(t, pack, later, true)
	if err != nil || rep.Changed || len(rep.Withdrawn) != 0 {
		t.Fatalf("second withdraw: %+v %v", rep, err)
	}
	// A run that derives everything again withdraws nothing.
	pack2 := prunedPack(t, "cncf", first)
	if _, err := apply(t, pack2, first, false); err != nil {
		t.Fatal(err)
	}
	rep, err = apply(t, pack2, runDir(t, c, derivedAt), true)
	if err != nil || rep.Changed {
		t.Fatalf("full run withdrew: %+v %v", rep, err)
	}
}

// A pair the run withheld proves nothing about its rules, and a rule of
// another extractor is never touched.
func TestWithdrawScope(t *testing.T) {
	c := cases[0]
	first := runDir(t, c, derivedAt.Add(-24*time.Hour))
	pack := prunedPack(t, "cncf", first)
	if _, err := apply(t, pack, first, false); err != nil {
		t.Fatal(err)
	}

	// Later run: the first pair is withheld (its rules are not produced),
	// every other pair still produces its rules.
	later := runDir(t, c, derivedAt)
	var m map[string]any
	readJSON(t, filepath.Join(later, "manifest.json"), &m)
	pair := m["pairs"].([]any)[0].(map[string]any)
	drop := map[string]bool{}
	for _, r := range pair["rules"].([]any) {
		drop[r.(string)] = true
	}
	if len(drop) == 0 {
		t.Fatal("the first pair derives nothing; the test needs a pair with rules")
	}
	pair["status"], pair["reason"], pair["rules"] = "withheld", "a blob was missing", []any{}
	writeCanon(t, filepath.Join(later, "manifest.json"), m)
	trimRun(t, later, drop, false)
	pre, _ := os.ReadFile(pack)
	rep, err := apply(t, pack, later, true)
	if err != nil || rep.Changed || len(rep.Withdrawn) != 0 {
		t.Fatalf("a withheld pair withdrew rules: %+v %v", rep, err)
	}
	assertUnchanged(t, pack, pre)

	// A different extractor's run cannot withdraw this extractor's rules.
	other := runDir(t, cases[1], derivedAt)
	rep, err = apply(t, pack, other, true)
	if err != nil || rep.Changed || len(rep.Withdrawn) != 0 {
		t.Fatalf("foreign extractor: %+v %v", rep, err)
	}
	assertUnchanged(t, pack, pre)
}

// The rule checks apply to what a merge adds: an id another published pack
// already uses is refused (the pack file itself is checked as well), and so
// is a merge that leaves a line attestation not listing every rule of its
// scope - here because the unpruned base holds reviewed rules for the same
// scope the run's attestations do not list.
func TestApplyRuleChecks(t *testing.T) {
	c := cases[0]
	run := runDir(t, c, derivedAt)
	id := ruleIDs(t, run)[0]
	other := filepath.Join(t.TempDir(), "other.json")
	doc := `{"entries":[{"project":"p","description":"d","requiredFacts":[],"rule":{"id":"` + id + `"}}]}`
	if err := os.WriteFile(other, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	pack := prunedPack(t, "cncf", run)
	pre, _ := os.ReadFile(pack)
	_, err := extractpack.Apply(extractpack.Options{PackPath: pack, RunDir: run, Admit: admitAll, ExistingRules: []string{other}})
	if !errors.Is(err, extractpack.ErrAdmission) || !strings.Contains(err.Error(), "rule-id-collision") {
		t.Fatalf("id used by another pack: %v", err)
	}
	assertUnchanged(t, pack, pre)

	served := runDir(t, cases[1], derivedAt)
	pack = packDir(t, "cncf") // reviewed rules of the same scope stay
	dropPublishedDerivations(t, pack)
	pre, _ = os.ReadFile(pack)
	_, err = apply(t, pack, served, false)
	if !errors.Is(err, extractpack.ErrAdmission) || !strings.Contains(err.Error(), "attestation-missing-rule") {
		t.Fatalf("attestation not listing every rule of its scope: %v", err)
	}
	assertUnchanged(t, pack, pre)
}
