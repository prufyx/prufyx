// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

func basisOf(e map[string]any) string {
	ev, ok := ruleOf(e)["evidence"].(map[string]any)
	if !ok {
		return ""
	}
	b, _ := ev["basis"].(string)
	return b
}

// firstEntry returns the first pack entry for which pick is true.
func firstEntry(t *testing.T, p *packDoc, pick func(e map[string]any) bool) map[string]any {
	t.Helper()
	for _, e := range p.entries {
		if pick(e) {
			return e
		}
	}
	t.Fatal("no suitable entry in the pack")
	return nil
}

// Tests 6 and 7: a pack rule with a draft or needs_review basis (or any token
// outside the closed vocabulary) is refused by the gate, and no approval is
// written for a draft, needs_review or mechanical rule.
func TestGateAndApprovalRefuseDraftBases(t *testing.T) {
	spec := DefaultLayout().Packs[0]
	for _, tok := range []string{"draft", "needs_review", "safe", "Draft"} {
		base, head := trees(t)
		p := readPack(t, head, cncfRulesPath)
		e := firstEntry(t, p, func(e map[string]any) bool { b := basisOf(e); return b == "" || b == "reviewed" })
		id := ruleID(e)
		if _, ok := ruleOf(e)["evidence"].(map[string]any); !ok {
			ruleOf(e)["evidence"] = map[string]any{}
		}
		evidenceOf(e)["basis"] = tok
		p.write(t, head, cncfRulesPath)
		r, err := Verify(t.Context(), Options{Base: base, Head: head, Source: fixtureSource, Layout: DefaultLayout(), Now: gateNow, Citations: passingCitations{}})
		if err == nil && r.Passed() {
			t.Fatalf("basis %q: the gate passed a pack with a %q rule (%s)", tok, tok, id)
		}
		baseRaw, rerr := os.ReadFile(filepath.Join(base.Root, filepath.FromSlash(cncfRulesPath)))
		headRaw, herr := os.ReadFile(filepath.Join(head.Root, filepath.FromSlash(cncfRulesPath)))
		if rerr != nil || herr != nil {
			t.Fatal(rerr, herr)
		}
		if _, err := RuleApprovalSubject(spec, baseRaw, headRaw, id); err == nil {
			t.Fatalf("basis %q: an approval subject was built for a %q rule", tok, tok)
		}
	}
	// A mechanical rule is not approvable either.
	_, head, _ := mechanicalTrees(t, nil)
	p := readPack(t, head, cncfRulesPath)
	e := firstEntry(t, p, func(e map[string]any) bool { return basisOf(e) == "mechanical" })
	raw, err := os.ReadFile(filepath.Join(head.Root, filepath.FromSlash(cncfRulesPath)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RuleApprovalSubject(spec, raw, raw, ruleID(e)); err == nil || !strings.Contains(err.Error(), "admits only a reviewed rule") {
		t.Fatalf("mechanical rule: %v", err)
	}
}

// The per-pair gate check: a pair that recorded drafts is never attested,
// whatever else the record says.
func TestCrossCheckRefusesPairWithDrafts(t *testing.T) {
	a := lineattest.LineAttestation{Component: "pkg:github/kubernetes/kubernetes", Line: "1.25", FactFamily: lineattest.FamilyKubernetesRemovedServedGVK}
	pair := func(mut func(p *extract.PairRecord)) *extract.Output {
		p := extract.PairRecord{From: "1.24.0", To: "1.25.0", Status: extract.PairDerived, Rules: []string{},
			Attestation: &extract.PairAttestation{Status: extract.PairAttested, Line: "1.25", Families: []string{lineattest.FamilyKubernetesRemovedServedGVK}}}
		mut(&p)
		return &extract.Output{Manifest: extract.Manifest{Pairs: []extract.PairRecord{p}}}
	}
	for name, mut := range map[string]func(p *extract.PairRecord){
		"drafts and attested": func(p *extract.PairRecord) { p.Drafts = 1 },
		"drafts and not attested without the reason": func(p *extract.PairRecord) {
			p.Drafts = 2
			p.Attestation = &extract.PairAttestation{Status: extract.PairNotAttested, Line: "1.25", Families: []string{}, Reason: "other"}
		},
		"drafts and no attestation record": func(p *extract.PairRecord) { p.Drafts = 1; p.Attestation = nil },
	} {
		err := crossCheckAttestation(pair(mut), "", a, nil)
		if err == nil || !strings.Contains(err.Error(), "draft") {
			t.Fatalf("%s: err %v", name, err)
		}
	}
}
