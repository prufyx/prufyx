// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
)

// A rule changed in several ways at once (advice text, lease, sources) is one
// change and consumes one unit of every cap, next to changes of one kind. The
// per-change cap and the per-day limit are exercised at their boundaries.
func TestRemediationChangesConsumeOneCapUnitEach(t *testing.T) {
	t.Parallel()
	base, head := trees(t)
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	if len(ids) < 4 {
		t.Fatalf("only %d active reviewed rules", len(ids))
	}
	ids = ids[:4]
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		const text = "Changed advice."
		// 0: advice only. 1: advice and a later lease. 2: advice and a
		// re-pin. 3: a later lease only.
		ruleOf(p.find(t, ids[0]))["nextAction"] = text
		e1 := p.find(t, ids[1])
		ruleOf(e1)["nextAction"] = text
		evidenceOf(e1)["validUntil"] = shiftTime(t, evidenceOf(e1)["validUntil"], time.Hour)
		e2 := p.find(t, ids[2])
		ruleOf(e2)["nextAction"] = text
		evidenceOf(e2)["sources"].([]any)[0].(map[string]any)["endLine"] = json.Number("9999")
		e3 := p.find(t, ids[3])
		evidenceOf(e3)["validUntil"] = shiftTime(t, evidenceOf(e3)["validUntil"], time.Hour)
	})
	cls, err := Classify(DefaultLayout(), base, head)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string][]string{}
	for _, c := range cls.Changes {
		kinds[c.RuleID] = c.Kinds
	}
	if len(cls.Changes) != 4 {
		t.Fatalf("%d changes, want 4: %v", len(cls.Changes), kinds)
	}
	for i, id := range ids {
		k := kinds[id]
		hasText := containsKind(k, KindRemediationText)
		if hasText != (i < 3) {
			t.Errorf("rule %d kinds %v: remediation-text = %v", i, k, hasText)
		}
	}
	if k := kinds[ids[1]]; len(k) < 3 || !containsKind(k, KindRenew) || !containsKind(k, KindModify) {
		t.Fatalf("rule with advice and lease changed has kinds %v, want several", k)
	}
	if _, loosening := cls.Counts(); loosening != 4 {
		t.Fatalf("loosening %d, want 4 (one per changed rule, whatever its kinds)", loosening)
	}

	// Per-change cap at its boundary.
	for _, max := range []int{3, 4} {
		r, err := Limits(Options{Layout: DefaultLayout(), Base: base, Head: head, MaxLoosening: max})
		if err != nil {
			t.Fatal(err)
		}
		if r.Passed() != (max == 4) || r.Limits.Loosening != 4 {
			t.Errorf("cap %d: passed %v, loosening %d", max, r.Passed(), r.Limits.Loosening)
		}
	}
	// Per-day limit at its boundary: merged-before plus this change.
	for _, before := range []int{45, 46, 47} {
		b := before
		r, err := Limits(Options{Layout: DefaultLayout(), Base: base, Head: head, DailyLoosening: &b, MaxDailyLoosening: 50})
		if err != nil {
			t.Fatal(err)
		}
		if want := before+4 <= 50; r.Passed() != want || r.Daily.Change != 4 {
			t.Errorf("daily before %d: passed %v (want %v), change %d", before, r.Passed(), want, r.Daily.Change)
		}
	}
}

// The weekly stagger cap counts rules, whatever the kinds of their change: at
// the cap a week passes, one more rule in it fails.
func TestWeeklyStaggerCapBoundary(t *testing.T) {
	t.Parallel()
	const total = 100
	limit := evidencereattest.StaggerCap(total)
	week := time.Date(2027, 1, 20, 6, 0, 0, 0, time.UTC)
	for _, inWeek := range []int{limit, limit + 1} {
		h := &loadedPack{Entries: map[string]*entry{}}
		for i := 0; i < total; i++ {
			until := week
			if i >= inWeek {
				until = week.AddDate(0, 0, 7*(1+i%40))
			}
			h.Entries[fmt.Sprintf("r%03d", i)] = &entry{Evidence: evidenceView{ValidUntil: until.Format(time.RFC3339)}}
		}
		r := &Report{}
		r.staggerCheck(PackSpec{Name: "cncf"}, h, map[string]bool{evidencereattest.ISOWeek(week): true})
		if len(r.Checks) != 1 || r.Checks[0].OK != (inWeek == limit) {
			t.Errorf("%d rules in the week (cap %d): %+v", inWeek, limit, r.Checks)
		}
		if inWeek > limit && !strings.Contains(r.Checks[0].Detail, "holds") {
			t.Errorf("detail %q", r.Checks[0].Detail)
		}
	}
}
