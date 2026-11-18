// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
)

// pinnableIDs are the active reviewed rules of the pack that meet the
// structural clauses of the fixed-version predicate and carry a condition, so
// a test can edit them freely.
func pinnableIDs(t *testing.T, p *packDoc) []string {
	t.Helper()
	var out []string
	for _, id := range p.activeReviewed() {
		e := p.find(t, id)
		rule := ruleOf(e)
		if rule["operator"] != "forbid_predicate_value" || rule["condition"] == nil || rule["severity"] != nil {
			continue
		}
		raw, err := entryRuleJSON(entryFrom(t, e))
		if err != nil {
			t.Fatal(err)
		}
		if reasons, err := constraintengine.PinnedRuleReasons(raw); err == nil && len(reasons) == 0 {
			out = append(out, id)
		}
	}
	if len(out) < 60 {
		t.Fatalf("setup: only %d pinnable rules in the shipped pack", len(out))
	}
	return out
}

// pinRule gives a rule the pinned lease: reviewedAt as given and validUntil
// exactly ten years later.
func pinRule(t *testing.T, e map[string]any, reviewedAt string) {
	t.Helper()
	until, err := constraintengine.PinnedValidUntil(reviewedAt)
	if err != nil {
		t.Fatal(err)
	}
	ev := evidenceOf(e)
	ev["reviewedAt"], ev["validUntil"], ev["lease"] = reviewedAt, until, constraintengine.LeasePinned
}

func pinInTree(t *testing.T, tr Tree, ids []string, edit func(e map[string]any)) {
	t.Helper()
	editPack(t, tr, cncfRulesPath, func(p *packDoc) {
		for _, id := range ids {
			e := p.find(t, id)
			pinRule(t, e, evidenceOf(e)["reviewedAt"].(string))
			if edit != nil {
				edit(e)
			}
		}
	})
}

func requireRefusedAsPinned(t *testing.T, c *Change, want string) {
	t.Helper()
	if c.OK || c.Proof != "" || !strings.Contains(c.Detail, LeasePinnedNotEligible) || !strings.Contains(c.Detail, want) {
		t.Fatalf("change %s: ok=%v proof=%q detail=%q, want a %s refusal naming %q", c.RuleID, c.OK, c.Proof, c.Detail, LeasePinnedNotEligible, want)
	}
}

// Time -> pinned is a loosening change of its own kind, and without a verified
// human statement row for the rule nothing admits it.
func TestPinWithoutAStatementRowIsRefused(t *testing.T) {
	base, head := trees(t)
	ids := pinnableIDs(t, readPack(t, base, cncfRulesPath))
	pinInTree(t, head, ids[:1], nil)
	r := runGate(t, Options{Base: base, Head: head})
	c := change(t, r, ids[0])
	if c.Class != ClassLoosening || !containsKind(c.Kinds, KindPin) {
		t.Fatalf("a pin is a loosening change: %s %v", c.Class, c.Kinds)
	}
	requireRefusedAsPinned(t, c, "signed human reattestation row")
	if r.Passed() {
		t.Fatal("the gate passed a pin no statement covers")
	}
	if got, ok := check(r, "pinned/cncf"); !ok || !got.OK {
		t.Fatalf("a rule that meets the predicate must pass the per-pack pinned check: %+v", got)
	}
}

// A rule is never created pinned.
func TestPinnedRuleCannotBeCreated(t *testing.T) {
	base, head := trees(t)
	ids := pinnableIDs(t, readPack(t, base, cncfRulesPath))
	editPack(t, base, cncfRulesPath, func(p *packDoc) {
		kept := p.entries[:0]
		for _, e := range p.entries {
			if ruleID(e) != ids[0] {
				kept = append(kept, e)
			}
		}
		p.entries = kept
	})
	pinInTree(t, head, ids[:1], nil)
	r := runGate(t, Options{Base: base, Head: head})
	requireRefusedAsPinned(t, change(t, r, ids[0]), "never created pinned")
}

// Every edit of a pinned rule is refused, all fields counted, its dates
// included; dropping the lease or withdrawing the rule is tightening.
func TestPinnedRuleEditsAreRefused(t *testing.T) {
	for name, edit := range map[string]func(e map[string]any){
		"remediation text": func(e map[string]any) { ruleOf(e)["nextAction"] = "Changed text." },
		"applicability":    func(e map[string]any) { ruleOf(e)["appliesWhen"] = []any{ruleOf(e)["condition"]} },
		"source span": func(e map[string]any) {
			evidenceOf(e)["sources"].([]any)[0].(map[string]any)["endLine"] = 9999
		},
		"description": func(e map[string]any) { e["description"] = "Other." },
		"dates": func(e map[string]any) {
			pinRule(t, e, shiftTime(t, evidenceOf(e)["reviewedAt"], 24*time.Hour))
		},
	} {
		t.Run(name, func(t *testing.T) {
			base, head := trees(t)
			ids := pinnableIDs(t, readPack(t, base, cncfRulesPath))
			pinInTree(t, base, ids[:1], nil)
			// The head is written without regenerating the derived files: the
			// edit need not be one the engine admits for the change to be refused.
			p := readPack(t, head, cncfRulesPath)
			e := p.find(t, ids[0])
			pinRule(t, e, evidenceOf(e)["reviewedAt"].(string))
			edit(e)
			p.write(t, head, cncfRulesPath)
			r := runGate(t, Options{Base: base, Head: head})
			requireRefusedAsPinned(t, change(t, r, ids[0]), "may change only by dropping its lease or being withdrawn")
			if r.Passed() {
				t.Fatal("the gate passed an edit of a pinned rule")
			}
		})
	}
}

func TestPinnedRuleMayBeUnpinnedOrWithdrawn(t *testing.T) {
	base, _ := trees(t)
	ids := pinnableIDs(t, readPack(t, base, cncfRulesPath))
	pinInTree(t, base, ids[:2], nil)

	_, unpinned := trees(t)
	pinInTree(t, unpinned, ids[:2], nil)
	editPack(t, unpinned, cncfRulesPath, func(p *packDoc) {
		e := p.find(t, ids[0])
		ev := evidenceOf(e)
		delete(ev, "lease")
		ev["validUntil"] = shiftTime(t, ev["reviewedAt"], 90*24*time.Hour)
	})
	r := runGate(t, Options{Base: base, Head: unpinned})
	c := change(t, r, ids[0])
	if c.Class != ClassTightening || !c.OK || len(c.Kinds) != 2 || c.Kinds[0] != KindUnpin || c.Kinds[1] != KindExpire {
		t.Fatalf("dropping the lease with an earlier end is tightening: %+v", c)
	}

	_, withdrawn := trees(t)
	pinInTree(t, withdrawn, ids[:2], nil)
	editPack(t, withdrawn, cncfRulesPath, func(p *packDoc) { evidenceOf(p.find(t, ids[1]))["state"] = "withdrawn" })
	r = runGate(t, Options{Base: base, Head: withdrawn})
	c = change(t, r, ids[1])
	if c.Class != ClassTightening || !c.OK || len(c.Kinds) != 1 || c.Kinds[0] != KindWithdraw {
		t.Fatalf("withdrawing a pinned rule is tightening: %+v", c)
	}
	if got, ok := check(r, "pinned/cncf"); !ok || !got.OK {
		t.Fatalf("a withdrawn pinned rule must pass the pinned check: %+v", got)
	}
}

// The engine admits a pinned rule that meets the predicate with its fixed
// window, and nothing else: each case below differs from the admitted control
// by one defect.
func TestPinnedRuleThatFailsThePredicateIsNotAdmitted(t *testing.T) {
	base, _ := trees(t)
	ids := pinnableIDs(t, readPack(t, base, cncfRulesPath))
	for name, tc := range map[string]struct {
		edit  func(e map[string]any)
		valid bool
	}{
		"control: a pinned rule with its fixed window": {func(map[string]any) {}, true},
		"window one day long": {func(e map[string]any) {
			evidenceOf(e)["validUntil"] = shiftTime(t, evidenceOf(e)["validUntil"], 24*time.Hour)
		}, false},
		"window of a time lease": {func(e map[string]any) {
			evidenceOf(e)["validUntil"] = shiftTime(t, evidenceOf(e)["reviewedAt"], 90*24*time.Hour)
		}, false},
		"another operator": {func(e map[string]any) {
			delete(ruleOf(e), "condition")
			ruleOf(e)["operator"] = "forbid_target_version"
		}, false},
		"a range": {func(e map[string]any) {
			ruleOf(e)["range"] = map[string]any{"from": map[string]any{"gte": "0.0.0", "lt": "99.0.0"}, "to": map[string]any{"gte": "0.0.0", "lt": "99.0.0"}, "bounds": []any{}}
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			head := copyKnowledge(t)
			// Written without regenerating: the derived files are beside the point.
			p := readPack(t, head, cncfRulesPath)
			e := p.find(t, ids[0])
			pinRule(t, e, evidenceOf(e)["reviewedAt"].(string))
			tc.edit(e)
			p.write(t, head, cncfRulesPath)
			r := runGate(t, Options{Base: base, Head: head})
			if got, ok := check(r, "admit/cncf"); !ok || got.OK != tc.valid {
				t.Fatalf("admit/cncf = %+v, want ok=%v", got, tc.valid)
			}
		})
	}
}

// Pinned rules are exempt from the ISO-week stagger only: the same renewal
// window without the lease fails it, and the daily limit counts every pin.
func TestPinnedRulesAreExemptFromStaggerOnly(t *testing.T) {
	base, pinnedHead := trees(t)
	ids := pinnableIDs(t, readPack(t, base, cncfRulesPath))
	const reviewed = "2026-10-01T00:00:00Z"
	editPack(t, pinnedHead, cncfRulesPath, func(p *packDoc) {
		for _, id := range ids {
			pinRule(t, p.find(t, id), reviewed)
		}
	})
	_, timeHead := trees(t)
	editPack(t, timeHead, cncfRulesPath, func(p *packDoc) {
		for _, id := range ids {
			ev := evidenceOf(p.find(t, id))
			ev["reviewedAt"], ev["validUntil"] = reviewed, shiftTime(t, reviewed, 90*24*time.Hour)
		}
	})
	zero := 0
	pin := runGate(t, Options{Base: base, Head: pinnedHead, DailyLoosening: &zero})
	control := runGate(t, Options{Base: base, Head: timeHead, DailyLoosening: &zero})
	if got, ok := check(control, "stagger/cncf"); !ok || got.OK {
		t.Fatalf("setup: %d renewals into one week must break the stagger cap: %+v", len(ids), got)
	}
	if got, ok := check(pin, "stagger/cncf"); !ok || !got.OK {
		t.Fatalf("pinned rules must be exempt from the stagger cap: %+v", got)
	}
	if got, ok := check(pin, "stagger/cncf/records"); ok && !got.OK {
		t.Fatalf("pinned rules must be exempt from the records stagger cap: %+v", got)
	}
	if got, ok := check(pin, "limits/daily"); !ok || got.OK {
		t.Fatalf("the daily loosening limit must still bind %d pins: %+v", len(ids), got)
	}
	if pin.Passed() {
		t.Fatal("the gate passed pins no statement covers")
	}
}

func TestDailyLimitCountsPinsExactly(t *testing.T) {
	base, _ := trees(t)
	ids := pinnableIDs(t, readPack(t, base, cncfRulesPath))
	for _, tc := range []struct {
		n  int
		ok bool
	}{{DefaultMaxDailyLoosening, true}, {DefaultMaxDailyLoosening + 1, false}} {
		h := copyKnowledge(t)
		pinInTree(t, h, ids[:tc.n], nil)
		zero := 0
		r := runGate(t, Options{Base: base, Head: h, DailyLoosening: &zero})
		if got, ok := check(r, "limits/daily"); !ok || got.OK != tc.ok {
			t.Fatalf("%d pins: %+v", tc.n, got)
		}
	}
}

func stmtFor(role string, rows ...evidencereattest.RuleAttestation) statementResult {
	return statementResult{OK: true, Role: role, Stem: "0001", Statement: evidencereattest.Statement{Rules: rows}}
}

// pinnedPre admits a pin only for a verified human statement with a row that
// pins the rule, with the supported-client floor met.
func TestPinnedPreAdmissionIsNarrow(t *testing.T) {
	base, head := trees(t)
	ids := pinnableIDs(t, readPack(t, base, cncfRulesPath))
	pinInTree(t, head, ids[:1], nil)
	var spec PackSpec
	for _, candidate := range DefaultLayout().Packs {
		if candidate.Name == evidencereattest.PackCNCF {
			spec = candidate
		}
	}
	basePack, err := loadPack(base, spec)
	if err != nil {
		t.Fatal(err)
	}
	headPack, err := loadPack(head, spec)
	if err != nil {
		t.Fatal(err)
	}
	newChange := func() *Change {
		return &Change{RuleID: ids[0], base: basePack.Entries[ids[0]], head: headPack.Entries[ids[0]]}
	}
	writePin := func(tr Tree, version string) {
		writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(OldestClientPinPath)), []byte("ref="+strings.Repeat("a", 40)+"\nversion="+version+"\n"))
	}
	writePin(base, cncfcheck.PinnedLeaseMinClientVersion)
	writePin(head, cncfcheck.PinnedLeaseMinClientVersion)
	opts := Options{Base: base, Head: head}
	row := evidencereattest.RuleAttestation{RuleID: ids[0], Lease: constraintengine.LeasePinned}

	c := newChange()
	if !pinnedPre(c, stmtFor(evidencereattest.RoleHuman, row), opts) || !c.OK || c.Proof != ProofReattestation {
		t.Fatalf("a verified human row with the floor met must admit the pin: %+v", c)
	}
	refused := map[string]struct {
		stmt statementResult
		want string
	}{
		"automation statement":  {stmtFor(evidencereattest.RoleAutomation, row), "not a human statement"},
		"row without the lease": {stmtFor(evidencereattest.RoleHuman, evidencereattest.RuleAttestation{RuleID: ids[0]}), "no row that pins this rule"},
		"row of another rule":   {stmtFor(evidencereattest.RoleHuman, evidencereattest.RuleAttestation{RuleID: "other", Lease: constraintengine.LeasePinned}), "no row that pins this rule"},
		"no statement":          {statementResult{}, "no verified reattestation statement"},
		"statement that failed": {statementResult{Detail: "V3 mismatch"}, "V3 mismatch"},
	}
	for name, tc := range refused {
		c := newChange()
		if !pinnedPre(c, tc.stmt, opts) {
			t.Fatalf("%s: not decided", name)
		}
		requireRefusedAsPinned(t, c, tc.want)
	}
	for _, setup := range []func(){
		func() { writePin(base, "v0.1.0-beta.1") },
		func() { writePin(head, "v0.1.0-beta.1") },
	} {
		writePin(base, cncfcheck.PinnedLeaseMinClientVersion)
		writePin(head, cncfcheck.PinnedLeaseMinClientVersion)
		setup()
		c := newChange()
		pinnedPre(c, stmtFor(evidencereattest.RoleHuman, row), opts)
		requireRefusedAsPinned(t, c, "cannot read a pinned lease")
	}
	// A change that does not touch a pinned lease is not decided here.
	plain := &Change{RuleID: ids[0], base: basePack.Entries[ids[0]], head: basePack.Entries[ids[0]]}
	if pinnedPre(plain, stmtFor(evidencereattest.RoleHuman, row), opts) {
		t.Fatal("an unpinned change was decided by the pinned path")
	}
}
