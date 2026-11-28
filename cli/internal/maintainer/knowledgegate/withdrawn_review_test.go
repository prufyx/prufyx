// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"testing"
	"time"
)

// The review date of a withdrawn rule never moves earlier, also with a valid
// owner approval: a database signed before the earlier date would count as
// reviewed after the withdrawal.
func TestGateWithdrawnReviewDateNeverMovesEarlier(t *testing.T) {
	t.Parallel()
	key := newApprovalKey(t)
	for name, c := range map[string]struct {
		base, head string
		shift      time.Duration
		refused    bool
	}{
		"withdrawn, earlier":                  {"withdrawn", "withdrawn", -time.Hour, true},
		"withdrawal with an earlier date":     {"active", "withdrawn", -time.Hour, true},
		"re-activation with an earlier date":  {"withdrawn", "active", -time.Hour, true},
		"withdrawn, later date, approved":     {"withdrawn", "withdrawn", time.Hour, false},
		"re-activation with a later date, ok": {"withdrawn", "active", time.Hour, false},
	} {
		t.Run(name, func(t *testing.T) {
			base, head := trees(t)
			id := readPack(t, base, cncfRulesPath).activeReviewed()[0]
			editPack(t, base, cncfRulesPath, func(p *packDoc) { evidenceOf(p.find(t, id))["state"] = c.base })
			editPack(t, head, cncfRulesPath, func(p *packDoc) {
				evidence := evidenceOf(p.find(t, id))
				evidence["state"] = c.head
				evidence["reviewedAt"] = shiftTime(t, evidence["reviewedAt"], c.shift)
				evidence["validUntil"] = shiftTime(t, evidence["validUntil"], c.shift)
			})
			cls, err := Classify(DefaultLayout(), base, head)
			if err != nil {
				t.Fatal(err)
			}
			key.pinBoth(t, base, head, "airstand")
			writeFile(t, approvalPath(head, id), key.sign(t, ApprovalRecord{
				BaseDigest:      CandidateDigest(cls.base["cncf"].Entries[id].Canonical),
				CandidateDigest: CandidateDigest(cls.head["cncf"].Entries[id].Canonical),
				CandidateID:     "cand-1", DecidedAt: gateNow.Add(-time.Hour).Format(time.RFC3339),
				Decision: "approve", Identity: "airstand", Pack: "cncf", RuleID: id,
			}))
			r := runGate(t, Options{Base: base, Head: head})
			got := change(t, r, id)
			if c.refused {
				requireFail(t, r, "review date of a withdrawn rule")
				if got.OK || got.Proof != "" {
					t.Fatalf("change %+v", got)
				}
				return
			}
			if !got.OK || got.Proof != ProofApproval {
				t.Fatalf("change %+v", got)
			}
		})
	}
}

// A date the gate cannot read is refused for a withdrawn rule.
func TestWithdrawnReviewMovedEarlierUnreadable(t *testing.T) {
	t.Parallel()
	rule := func(state, reviewedAt string) *entry {
		return &entry{Evidence: evidenceView{State: state, ReviewedAt: reviewedAt}}
	}
	const at = "2026-10-01T00:00:00Z"
	for name, c := range map[string]*Change{
		"base unreadable": {base: rule("withdrawn", "later"), head: rule("withdrawn", at)},
		"head unreadable": {base: rule("withdrawn", at), head: rule("active", "")},
		"head withdrawn":  {base: rule("active", at), head: rule("withdrawn", "2026-09-30T23:59:59Z")},
		"offset, earlier": {base: rule("withdrawn", at), head: rule("withdrawn", "2026-10-01T00:00:00+01:00")},
	} {
		if withdrawnReviewProblem(c) == "" {
			t.Fatalf("%s: admitted", name)
		}
	}
	for name, c := range map[string]*Change{
		"same date":       {base: rule("withdrawn", at), head: rule("withdrawn", at)},
		"both active":     {base: rule("active", at), head: rule("active", "2026-09-01T00:00:00Z")},
		"new rule":        {head: rule("withdrawn", at)},
		"record change":   {Section: "pathPolicies", base: rule("withdrawn", at), head: rule("withdrawn", "later")},
		"removed ruleset": {base: rule("withdrawn", at)},
	} {
		if problem := withdrawnReviewProblem(c); problem != "" {
			t.Fatalf("%s: %s", name, problem)
		}
	}
}
