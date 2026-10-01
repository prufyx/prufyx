// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

// verifyStrict runs Verify on c the way the publish gate does: no pre-sign
// mode, against the supplied base and chain.
func verifyStrict(c cycle, base, chain *Chain) error {
	_, err := Verify(VerifyOptions{
		StatementRaw: c.res.StatementCanonical, PriorPackRaw: c.prior, NextPackRaw: c.res.NextPack,
		WorklistRaw: c.worklistRaw, Chain: chain, BaseChain: base, PackName: PackCNCF, PackPath: chainPackPath,
		EngineCapabilityDigest: testEngineCapabilityDigest, AttestedAtNow: c.at.Add(time.Hour), ReviewRecords: c.reviews,
	})
	return err
}

// A statement that renews rules, or records a review, is only accepted when
// the chain is the base chain plus exactly that statement. A chain equal to
// its base (the statement merged without its signed entry) is refused; the
// explicit pre-sign mode, which never gates a publish, still accepts it.
func TestVerifyRequiresARenewingStatementToBeAppendedToTheChain(t *testing.T) {
	f := newRoleFixture(t)
	c := prepareAutomated(t, f.chainFixture, automatedPack(t, baseNow), baseNow, cycleSpecs(12, baseNow), "rev-2", nil)
	base := f.chain()
	err := verifyStrict(c, base, f.chain())
	if err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "not appended") {
		t.Fatalf("a renewing statement with no chain entry must be refused, got %v", err)
	}
	if _, err := Verify(VerifyOptions{
		StatementRaw: c.res.StatementCanonical, PriorPackRaw: c.prior, NextPackRaw: c.res.NextPack, WorklistRaw: c.worklistRaw,
		Chain: f.chain(), BaseChain: base, PackName: PackCNCF, PackPath: chainPackPath,
		EngineCapabilityDigest: testEngineCapabilityDigest, AttestedAtNow: c.at.Add(time.Hour), PreSign: true,
	}); err != nil {
		t.Fatalf("the pre-sign structural mode must still accept an unappended statement: %v", err)
	}
	f.appendAutomated("0001", c.res.StatementCanonical)
	if err := verifyStrict(c, base, f.chain()); err != nil {
		t.Fatalf("the same statement appended as the one new entry must verify: %v", err)
	}
}

// A statement that renews nothing needs no chain entry: nothing in the
// pack may change for it, and the chain stays as it is.
func TestVerifyAcceptsAStatementThatRenewsNothingWithoutAChainEntry(t *testing.T) {
	f := newRoleFixture(t)
	pack := automatedPack(t, baseNow)
	// Every rule is not yet due, so nothing is renewed.
	at := baseNow.Add(-200 * 24 * time.Hour)
	c := prepareAutomated(t, f.chainFixture, pack, at, cycleSpecs(12, at), "rev-2", nil)
	if len(c.res.Statement.Rules) != 0 {
		t.Fatalf("setup: expected nothing renewed, got %s", renewedIDs(c.res))
	}
	if err := verifyStrict(c, f.chain(), f.chain()); err != nil {
		t.Fatalf("a statement that renews nothing must verify with an unchanged chain: %v", err)
	}
}

// A renewing automated statement that was merged without being appended to
// the chain must not let automation reset the cycle cap on the next run:
// the rules it renewed carry a reviewedAt later than the chain head, and
// automation counts no review record, however well formed, so it leaves
// those rules to a person instead of renewing them a third time.
func TestAutomationCannotResetTheCycleCapWithUnappendedStatementAndForgedRecords(t *testing.T) {
	f := newRoleFixture(t)
	t1 := baseNow
	prior := automatedPack(t, t1)

	c1 := prepareAutomated(t, f.chainFixture, prior, t1, cycleSpecs(12, t1), "rev-2", nil)
	f.appendAutomated("0001", c1.res.StatementCanonical)
	if err := verifyStrict(c1, &Chain{TrustRoot: f.root, ExpectedTrustRootDigest: f.digest}, f.chain()); err != nil {
		t.Fatal(err)
	}

	t2 := t1.Add(automatedSpacing)
	c2 := prepareAutomated(t, f.chainFixture, c1.res.NextPack, t2, cycleSpecs(12, t2), "rev-3", nil)
	if cyclesOf(c2, "rule-00") != 2 {
		t.Fatalf("setup: want cycles 2, got %d", cyclesOf(c2, "rule-00"))
	}
	// The gate refuses c2 while its entry is missing from the chain.
	if err := verifyStrict(c2, f.chain(), f.chain()); err == nil {
		t.Fatal("the gate accepted a renewing statement with no chain entry")
	}

	// Even if c2's pack were merged anyway, the next automated run must
	// not trust forged records for its rules.
	t3 := t2.Add(automatedSpacing)
	forged := map[string][]byte{}
	for i := 0; i < 12; i++ {
		id := fmt.Sprintf("rule-%02d", i)
		forged[id] = testReviewRecord(t, c2.res.NextPack, id, t3.Add(-time.Hour), "Nobody")
	}
	c3 := prepareAutomated(t, f.chainFixture, c2.res.NextPack, t3, cycleSpecs(12, t3), "rev-4", forged)
	if len(c3.res.Statement.Rules) != 0 || len(c3.res.Statement.IndividualReviews) != 0 {
		t.Fatalf("third automated renewal of %s using forged records (reviews %+v)", renewedIDs(c3.res), c3.res.Statement.IndividualReviews)
	}
	if got := worstClassOf(c3, "rule-00"); got != reasonReviewedOutsideChain {
		t.Fatalf("rule-00 must be left to a human as %s, got %q", reasonReviewedOutsideChain, got)
	}
}

// V6 refuses any change to a rule's reviewedAt or validUntil that no chain
// entry records, and a covered rule must carry exactly the statement's dates.
func TestCheckV6RefusesDateChangesTheChainDoesNotRecord(t *testing.T) {
	prior := map[string]json.RawMessage{"rule-a": ruleJSON(t, "rule-a", "2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z")}
	next := map[string]json.RawMessage{"rule-a": ruleJSON(t, "rule-a", "2026-02-01T00:00:00Z", "2026-04-01T00:00:00Z")}
	statement := Statement{AttestedAt: "2026-02-01T00:00:00Z", ValidUntil: "2026-04-01T00:00:00Z", Rules: []RuleAttestation{{RuleID: "rule-a"}}}
	if err := checkV6(prior, next, statement, nil, true); err != nil {
		t.Fatalf("a recorded statement covering the change must pass: %v", err)
	}
	if err := checkV6(prior, next, statement, nil, false); err == nil || !strings.Contains(err.Error(), "not recorded in the statement chain") {
		t.Fatalf("a statement the chain does not record must not cover a date change, got %v", err)
	}
	fresh := map[string]string{"rule-a": "sha256:" + strings.Repeat("ee", 32)}
	if err := checkV6(prior, next, Statement{}, fresh, false); err == nil {
		t.Fatal("a review record must not cover a date change when the statement is not recorded")
	}
	// Dates other than the statement's, for a rule it covers.
	other := map[string]json.RawMessage{"rule-a": ruleJSON(t, "rule-a", "2026-02-01T00:00:00Z", "2026-09-01T00:00:00Z")}
	if err := checkV6(prior, other, statement, nil, true); err == nil || !strings.Contains(err.Error(), "not the ones the statement gives it") {
		t.Fatalf("a covered rule with other dates than the statement's must be refused, got %v", err)
	}
	// An automated statement's own per-rule validUntil is the one that counts.
	auto := Statement{AttestedAt: "2026-02-01T00:00:00Z", ValidUntil: "2026-05-01T00:00:00Z", Rules: []RuleAttestation{{RuleID: "rule-a", ValidUntil: "2026-04-01T00:00:00Z"}}}
	if err := checkV6(prior, next, auto, nil, true); err != nil {
		t.Fatalf("an automated statement's per-rule validUntil must be the one compared: %v", err)
	}
}

// Rules reviewed after the chain head are excluded from automation even
// with no record supplied, and Verify's own recomputation agrees (so a
// statement built the old way no longer reproduces).
func TestAutomatedPrepareExcludesEveryRuleReviewedAfterTheChainHead(t *testing.T) {
	f := newRoleFixture(t)
	t1 := baseNow
	c1 := prepareAutomated(t, f.chainFixture, automatedPack(t, t1), t1, cycleSpecs(12, t1), "rev-2", nil)
	f.appendAutomated("0001", c1.res.StatementCanonical)
	t2 := t1.Add(automatedSpacing)
	// A change outside the chain moved one rule's dates.
	reviewedAt := t1.Add(24 * time.Hour)
	prior := setRuleDates(t, c1.res.NextPack, "rule-03", rfc3339(reviewedAt), rfc3339(t2.Add(10*24*time.Hour)))
	c2 := prepareAutomated(t, f.chainFixture, prior, t2, cycleSpecs(12, t2), "rev-3", nil)
	if got := worstClassOf(c2, "rule-03"); got != reasonReviewedOutsideChain {
		t.Fatalf("rule-03 must be excluded as %s, got %q", reasonReviewedOutsideChain, got)
	}
	for _, ra := range c2.res.Statement.Rules {
		if ra.RuleID == "rule-03" {
			t.Fatal("rule-03 was renewed")
		}
	}
	if len(c2.res.Statement.Rules) == 0 {
		t.Fatal("the other rules must still be renewed")
	}
	f.appendAutomated("0002", c2.res.StatementCanonical)
	base := &Chain{Entries: f.chain().Entries[:1], TrustRoot: f.root, ExpectedTrustRootDigest: f.digest}
	if err := verifyStrict(c2, base, f.chain()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// ---------------------------------------------------------------------
// V9: an independently produced worklist must agree
// ---------------------------------------------------------------------

func TestVerifyComparesAutomatedStatementWithAnIndependentWorklist(t *testing.T) {
	f := newRoleFixture(t)
	c := prepareAutomated(t, f.chainFixture, automatedPack(t, baseNow), baseNow, cycleSpecs(12, baseNow), "rev-2", nil)
	f.appendAutomated("0001", c.res.StatementCanonical)
	base := &Chain{TrustRoot: f.root, ExpectedTrustRootDigest: f.digest}
	verifyAgainst := func(independent []byte) error {
		_, err := Verify(VerifyOptions{
			StatementRaw: c.res.StatementCanonical, PriorPackRaw: c.prior, NextPackRaw: c.res.NextPack, WorklistRaw: c.worklistRaw,
			Chain: f.chain(), BaseChain: base, PackName: PackCNCF, PackPath: chainPackPath,
			EngineCapabilityDigest: testEngineCapabilityDigest, AttestedAtNow: c.at.Add(time.Hour), IndependentWorklistRaw: independent,
		})
		return err
	}
	if err := verifyAgainst(c.worklistRaw); err != nil {
		t.Fatalf("an identical independent worklist must pass: %v", err)
	}
	var wl evidencerepin.Worklist
	if err := json.Unmarshal(c.worklistRaw, &wl); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(w *evidencerepin.Worklist){
		"different class":        func(w *evidencerepin.Worklist) { w.Citations[0].Class = evidencerepin.ClassSpanIdentical },
		"different compared sha": func(w *evidencerepin.Worklist) { w.Citations[0].NewCommit = strings.Repeat("9", 40) },
		"different pinned sha":   func(w *evidencerepin.Worklist) { w.Citations[0].OldCommit = strings.Repeat("9", 40) },
		"citation missing":       func(w *evidencerepin.Worklist) { w.Citations = w.Citations[1:] },
		"duplicate citation":     func(w *evidencerepin.Worklist) { w.Citations = append(w.Citations, w.Citations[0]) },
		"different line":         func(w *evidencerepin.Worklist) { w.Citations[0].BaselineLine = "0.8" },
		"different compared tag": func(w *evidencerepin.Worklist) { w.Citations[0].BaselineTag = "v0.9.5" },
		"latest instead of line": func(w *evidencerepin.Worklist) { w.Citations[0].Baseline = evidencerepin.BaselineLatest },
		"line record missing":    func(w *evidencerepin.Worklist) { w.Lines = nil },
		"other pack path":        func(w *evidencerepin.Worklist) { w.Citations[0].RulePack = "/other/rules.json" },
	}
	for name, mutate := range cases {
		var mutated evidencerepin.Worklist
		raw, _ := json.Marshal(wl)
		if err := json.Unmarshal(raw, &mutated); err != nil {
			t.Fatal(err)
		}
		mutate(&mutated)
		err := verifyAgainst(marshalWorklist(t, mutated))
		if err == nil || !strings.Contains(err.Error(), "V9:") {
			t.Errorf("%s: expected a V9 failure, got %v", name, err)
		}
	}
	if err := verifyAgainst([]byte("{")); err == nil || !strings.Contains(err.Error(), "V9:") {
		t.Errorf("an undecodable independent worklist must be refused, got %v", err)
	}
}
