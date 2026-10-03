// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGateUnchangedPasses(t *testing.T) {
	base, head := trees(t)
	r := runGate(t, Options{Base: base, Head: head})
	requirePass(t, r)
	if len(r.Changes) != 0 || len(r.ChangedPaths) != 0 {
		t.Fatalf("changes %v paths %v", r.Changes, r.ChangedPaths)
	}
	for _, name := range []string{"admit/cncf", "rulecheck/cncf", "size/cncf", "registry/cncf", "stagger/cncf", "attestation/cncf", "block-only/cncf", "admit/community", "attestation/community", "generated/" + inventoryJSON, "limits"} {
		if c, ok := check(r, name); !ok || !c.OK {
			t.Fatalf("check %s missing or failed: %+v", name, c)
		}
	}
	if r.AutoMerge.Eligible {
		t.Fatal("a change without knowledge changes must not be eligible for automatic merging")
	}
}

// A tightening-only change (withdraw one rule, expire another) passes with
// no proof, and a bot-authored one is eligible for automatic merging.
func TestGateTighteningOnlyPasses(t *testing.T) {
	base, head := trees(t)
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		evidenceOf(p.find(t, ids[0]))["state"] = "withdrawn"
		ev := evidenceOf(p.find(t, ids[1]))
		ev["validUntil"] = shiftTime(t, ev["validUntil"], -24*time.Hour)
	})
	r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
	requirePass(t, r)
	if r.Totals.Tightening != 2 || r.Totals.Loosening != 0 {
		t.Fatalf("totals %+v", r.Totals)
	}
	for _, c := range r.Changes {
		if c.Proof != ProofNoneRequired {
			t.Fatalf("%s proof %q", c.RuleID, c.Proof)
		}
	}
	if !r.AutoMerge.Eligible {
		t.Fatalf("not eligible: %v", r.AutoMerge.Reasons)
	}
	// The same change by a person is not eligible, and neither is one
	// that also touches a file outside the knowledge files.
	if r := runGate(t, Options{Base: base, Head: head, Author: "someone"}); !r.Passed() || r.AutoMerge.Eligible {
		t.Fatalf("person-authored change: pass=%v eligible=%v", r.Passed(), r.AutoMerge.Eligible)
	}
	writeFile(t, filepath.Join(head.Root, "cli/internal/constraintengine/x.go"), []byte("package constraintengine\n"))
	if r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin}); !r.Passed() || r.AutoMerge.Eligible || !strings.Contains(strings.Join(r.AutoMerge.Reasons, " "), "outside the knowledge files") {
		t.Fatalf("code change: pass=%v eligible=%v %v", r.Passed(), r.AutoMerge.Eligible, r.AutoMerge.Reasons)
	}
}

// Loosening a reviewed rule without a proof fails: a renewal, a re-pin, a
// text change and a new rule.
func TestGateLooseningWithoutProofFails(t *testing.T) {
	cases := map[string]func(t *testing.T, p *packDoc, ids []string){
		"renew": func(t *testing.T, p *packDoc, ids []string) {
			ev := evidenceOf(p.find(t, ids[0]))
			ev["reviewedAt"] = shiftTime(t, ev["reviewedAt"], 24*time.Hour)
			ev["validUntil"] = shiftTime(t, ev["validUntil"], 24*time.Hour)
		},
		"text": func(t *testing.T, p *packDoc, ids []string) {
			ruleOf(p.find(t, ids[0]))["nextAction"] = "Upgrade without checking anything."
		},
		"new rule": func(t *testing.T, p *packDoc, ids []string) {
			added := deepCopy(p.find(t, ids[0])).(map[string]any)
			ruleOf(added)["id"] = ids[0] + "-x"
			p.entries = append(p.entries, added)
			p.sortByID()
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			base, head := trees(t)
			ids := readPack(t, base, cncfRulesPath).activeReviewed()
			editPack(t, head, cncfRulesPath, func(p *packDoc) { edit(t, p, ids) })
			r := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
			requireFail(t, r, "a reviewed rule may loosen only with")
			if r.AutoMerge.Eligible {
				t.Fatal("a failing change must not be eligible")
			}
		})
	}
}

func TestGateRemovalFails(t *testing.T) {
	base, head := trees(t)
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		var kept []map[string]any
		for _, e := range p.entries {
			if ruleID(e) != ids[0] {
				kept = append(kept, e)
			}
		}
		p.entries = kept
	})
	r := runGate(t, Options{Base: base, Head: head})
	requireFail(t, r, "withdraw it instead")
}

func TestGateStaleGeneratedFilesFail(t *testing.T) {
	base, head := trees(t)
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	p := readPack(t, head, cncfRulesPath)
	evidenceOf(p.find(t, ids[0]))["state"] = "withdrawn"
	p.write(t, head, cncfRulesPath) // no regeneration
	r := runGate(t, Options{Base: base, Head: head})
	requireFail(t, r, "attestation/cncf")
	requireFail(t, r, "generated/"+inventoryJSON)
}

// The kill switch blocks every loosening change and lets tightening pass.
func TestGateKillSwitch(t *testing.T) {
	for _, where := range []string{"base", "head"} {
		t.Run(where, func(t *testing.T) {
			base, head := trees(t)
			pauseIn := base
			if where == "head" {
				pauseIn = head
			}
			writeFile(t, filepath.Join(pauseIn.Root, "factory", "PAUSE"), []byte("paused\n"))
			ids := readPack(t, base, cncfRulesPath).activeReviewed()
			editPack(t, head, cncfRulesPath, func(p *packDoc) { evidenceOf(p.find(t, ids[0]))["state"] = "withdrawn" })
			r := runGate(t, Options{Base: base, Head: head})
			requirePass(t, r)
			if !r.Paused {
				t.Fatal("pause not reported")
			}
			editPack(t, head, cncfRulesPath, func(p *packDoc) { ruleOf(p.find(t, ids[1]))["nextAction"] = "Changed." })
			r = runGate(t, Options{Base: base, Head: head})
			requireFail(t, r, "kill switch")
			if c, ok := check(r, "kill-switch"); !ok || c.OK {
				t.Fatalf("kill-switch check %+v", c)
			}
			lr, err := Limits(Options{Layout: DefaultLayout(), Base: base, Head: head})
			if err != nil || lr.Passed() {
				t.Fatalf("limits with the kill switch: %v %v", lr.Result, err)
			}
		})
	}
}

// More loosening changes than the cap fail, in verify and in limits.
func TestGateLooseningLimit(t *testing.T) {
	base, head := trees(t)
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		for _, id := range ids[:3] {
			ruleOf(p.find(t, id))["nextAction"] = "Changed."
		}
	})
	for _, max := range []int{2, 3} {
		lr, err := Limits(Options{Layout: DefaultLayout(), Base: base, Head: head, MaxLoosening: max})
		if err != nil {
			t.Fatal(err)
		}
		if lr.Passed() != (max == 3) || lr.Limits.Loosening != 3 {
			t.Fatalf("max %d: pass=%v loosening=%d", max, lr.Passed(), lr.Limits.Loosening)
		}
	}
	r := runGate(t, Options{Base: base, Head: head, MaxLoosening: 2})
	requireFail(t, r, "limits: 3 loosening changes, cap 2")
	if len(r.Alarms) == 0 {
		t.Fatal("no alarm for the exceeded cap")
	}
}

func TestGateSizeAlarm(t *testing.T) {
	r := &Report{}
	spec := PackSpec{Name: "x"}
	stats := PackStats{TargetBytes: 85, MaxTargetBytes: 100}
	r.sizeCheck(spec, stats, 80, 90, true)
	r.sizeCheck(spec, stats, 80, 90, false)
	r.sizeCheck(spec, stats, 95, 90, true)
	r.sizeCheck(spec, PackStats{TargetBytes: 101, MaxTargetBytes: 100}, 80, 70, false)
	r.sizeCheck(spec, PackStats{TargetBytes: 50, MaxTargetBytes: 100}, 40, 50, true)
	got := []bool{}
	for _, c := range r.Checks {
		got = append(got, c.OK)
	}
	want := []bool{false, true, true, false, true}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("size checks %v, want %v", got, want)
		}
	}
	if len(r.Alarms) != 4 {
		t.Fatalf("alarms %v", r.Alarms)
	}
}

// A consensus rule may only block: the gate never admits one as loosening
// and fails any active one while the engine cannot evaluate it as
// block-only.
func TestGateConsensusBlockOnly(t *testing.T) {
	base, head := trees(t)
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	// The engine of this revision does not know the basis, so nothing
	// derived from the pack can be regenerated; the gate must still fail
	// it cleanly.
	p := readPack(t, head, cncfRulesPath)
	added := deepCopy(p.find(t, ids[0])).(map[string]any)
	ruleOf(added)["id"] = ids[0] + "-c"
	evidenceOf(added)["basis"] = "consensus"
	p.entries = append(p.entries, added)
	p.sortByID()
	p.write(t, head, cncfRulesPath)
	r := runGate(t, Options{Base: base, Head: head})
	requireFail(t, r, "consensus evidence may only block")
	requireFail(t, r, "block-only/cncf")
	requireFail(t, r, "admit/cncf")
}

func TestGateStaggerCap(t *testing.T) {
	base, head := trees(t)
	p := readPack(t, base, cncfRulesPath)
	h := &loadedPack{Entries: map[string]*entry{}}
	until := "2027-03-03T00:00:00Z"
	for i, id := range p.activeReviewed() {
		v := "2027-06-01T00:00:00Z"
		if i < 40 {
			v = until
		}
		h.Entries[id] = &entry{RuleID: id, Evidence: evidenceView{ValidUntil: v}}
	}
	r := &Report{}
	week := "2027-W09"
	r.staggerCheck(PackSpec{Name: "x"}, h, map[string]bool{week: true})
	if r.Checks[0].OK || !strings.Contains(r.Checks[0].Detail, week+" holds 40") {
		t.Fatalf("stagger %+v", r.Checks[0])
	}
	_ = head
}

func TestTreeRefusesLinks(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "outside", "secret.json"), []byte("{}"))
	root := filepath.Join(dir, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "outside"), filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "outside", "secret.json"), filepath.Join(root, "file.json")); err != nil {
		t.Fatal(err)
	}
	tr := Tree{Root: root}
	for _, rel := range []string{"linked/secret.json", "file.json", "../outside/secret.json", "/etc/passwd"} {
		if _, err := tr.Read(rel, 1<<10); err == nil {
			t.Fatalf("%s read through a link or outside the tree", rel)
		}
	}
	if _, err := tr.Dir("linked", 1<<10, 10); err == nil {
		t.Fatal("directory read through a link")
	}
}
