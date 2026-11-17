// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// prepareCapped prepares an automated batch over the standard twelve due
// rules with the given cap.
func prepareCapped(t *testing.T, f *roleFixture, pack []byte, maxRules int) (cycle, error) {
	t.Helper()
	wl, _ := buildWorklistAndPack(t, chainPackPath, baseNow, cycleSpecs(12, baseNow))
	lineBaselined(&wl)
	worklistRaw := marshalWorklist(t, wl)
	res, err := Prepare(PrepareOptions{
		Mode: ModeAutomated, MaxRules: maxRules, WorklistRaw: worklistRaw, PackName: PackCNCF, PackPath: chainPackPath, PackRaw: pack,
		Chain: f.chain(), AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest,
		ReviewRecords: map[string][]byte{},
	})
	return cycle{res: res, worklistRaw: worklistRaw, prior: pack, at: baseNow, reviews: map[string][]byte{}}, err
}

func TestAutomatedMaxRulesCapsAndDefersTheRest(t *testing.T) {
	f := newRoleFixture(t)
	pack := automatedPack(t, baseNow)
	full, err := prepareCapped(t, f, pack, 0)
	if err != nil || len(full.res.Statement.Rules) != 12 {
		t.Fatalf("uncapped: %d rules, %v", len(full.res.Statement.Rules), err)
	}
	// The cap takes the first N of the placement order: soonest-expiring
	// validUntil, then rule ID.
	doc, err := loadPack(pack)
	if err != nil {
		t.Fatal(err)
	}
	candidates, _, err := packCandidates(doc)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, ra := range full.res.Statement.Rules {
		order = append(order, ra.RuleID)
	}
	until := map[string]string{}
	for _, c := range candidates {
		until[c.RuleID] = c.Fields.Evidence.ValidUntil
	}
	sort.Slice(order, func(i, j int) bool {
		if until[order[i]] != until[order[j]] {
			return until[order[i]] < until[order[j]]
		}
		return order[i] < order[j]
	})

	for _, n := range []int{1, 5, 11, 12, 13, 500} {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			c, err := prepareCapped(t, f, pack, n)
			if err != nil {
				t.Fatal(err)
			}
			want := n
			if want > 12 {
				want = 12
			}
			if got := len(c.res.Statement.Rules); got != want {
				t.Fatalf("renewed %d, want %d", got, want)
			}
			renewed := map[string]bool{}
			for _, ra := range c.res.Statement.Rules {
				renewed[ra.RuleID] = true
			}
			for i, id := range order {
				if renewed[id] != (i < want) {
					t.Fatalf("rule %s (position %d) renewed=%v, want %v", id, i, renewed[id], i < want)
				}
				if i >= want && worstClassOf(c, id) != reasonStaggerDeferred {
					t.Fatalf("rule %s beyond the cap is %q, want %s", id, worstClassOf(c, id), reasonStaggerDeferred)
				}
			}
			if c.res.EligibleRuleCount+c.res.NotExtendedRuleCount != 92 {
				t.Fatalf("rules not accounted for: %d renewed + %d not extended", c.res.EligibleRuleCount, c.res.NotExtendedRuleCount)
			}
			again, err := prepareCapped(t, f, pack, n)
			if err != nil || string(again.res.StatementCanonical) != string(c.res.StatementCanonical) || string(again.res.NextPack) != string(c.res.NextPack) {
				t.Fatalf("two capped runs differ: %v", err)
			}
			if err := verifyCycle(c, f.chain()); err != nil {
				t.Fatalf("Verify rejected a statement capped at %d: %v", n, err)
			}
		})
	}
}

func TestAutomatedMaxRulesRejectedInputs(t *testing.T) {
	f := newRoleFixture(t)
	pack := automatedPack(t, baseNow)
	for _, n := range []int{-1, 501, 1000} {
		if _, err := prepareCapped(t, f, pack, n); err == nil {
			t.Fatalf("Prepare accepted max rules %d", n)
		}
	}
	wl, hpack := buildWorklistAndPack(t, chainPackPath, baseNow, cycleSpecs(3, baseNow))
	_, err := Prepare(PrepareOptions{
		Mode: ModeHuman, Wave: 1, MaxRules: 2, WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: chainPackPath, PackRaw: hpack,
		Chain: f.chain(), AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest,
	})
	if err == nil || !strings.Contains(err.Error(), "max rules") {
		t.Fatalf("human mode accepted max rules: %v", err)
	}
}

// A capped statement must not verify against a next pack that renews more
// (or other) rules than the statement lists.
func TestVerifyRejectsCappedStatementWithUncappedNextPack(t *testing.T) {
	f := newRoleFixture(t)
	pack := automatedPack(t, baseNow)
	capped, err := prepareCapped(t, f, pack, 5)
	if err != nil {
		t.Fatal(err)
	}
	full, err := prepareCapped(t, f, pack, 0)
	if err != nil {
		t.Fatal(err)
	}
	bad := capped
	bad.res.NextPack = full.res.NextPack
	if err := verifyCycle(bad, f.chain()); err == nil {
		t.Fatal("Verify accepted a capped statement with an uncapped next pack")
	}
}
