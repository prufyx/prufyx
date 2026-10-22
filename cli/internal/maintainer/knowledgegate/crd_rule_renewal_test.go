// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"strings"
	"testing"
	"time"
)

// agedRule makes a stored mechanical rule look derived by an earlier build of
// its extractor, three days before the gate's clock.
func agedRule(e map[string]any) {
	ev := evidenceOf(e)
	if ev["extractor"] == nil {
		return
	}
	ev["extractor"].(map[string]any)["codeDigest"] = "sha256:" + strings.Repeat("0", 64)
	at := gateNow.Add(-72 * time.Hour)
	ev["derivedAt"] = at.Format(time.RFC3339)
	ev["reviewedAt"] = at.Format(time.RFC3339)
	ev["validUntil"] = at.Add(30 * 24 * time.Hour).Format(time.RFC3339)
}

// ruleRenewalTrees returns a base that stores the Argo CD CRD rules as an
// earlier build derived them, and a head that holds the ones the gate's build
// derives (changed by tamper). Attestations are the same on both sides.
func ruleRenewalTrees(t *testing.T, tamper func(e map[string]any)) (Tree, Tree) {
	t.Helper()
	base, head := crdAttestedTrees(t, func(b map[string]any, _ []map[string]any) []map[string]any {
		return []map[string]any{b}
	})
	editPack(t, base, cncfRulesPath, func(p *packDoc) {
		for _, e := range p.entries {
			agedRule(e)
		}
	})
	if tamper != nil {
		editPack(t, head, cncfRulesPath, func(p *packDoc) {
			for _, e := range p.entries {
				if evidenceOf(e)["extractor"] != nil {
					tamper(e)
				}
			}
		})
	}
	return base, head
}

// A shipped mechanical CRD rule replaced by the one the gate's own build
// re-derives is a loosening change of that rule: proven by re-derivation, no
// approval, counted toward the caps; a stale run or another build is refused.
func TestGateRenewedMechanicalCRDRules(t *testing.T) {
	t.Parallel()
	base, head := ruleRenewalTrees(t, nil)
	r := runGate(t, Options{Base: base, Head: head, Source: argoFixture, Author: DefaultBotLogin})
	requireAdmittedButUnsplit(t, r)
	renewed := 0
	for _, c := range r.Changes {
		if c.Pack != "cncf" || c.Basis != "mechanical" || !strings.Contains(c.RuleID, "crd-version-removal") {
			continue
		}
		renewed++
		if c.Proof != ProofRederived || c.Class != ClassLoosening || !c.OK {
			t.Fatalf("change %+v", c)
		}
	}
	if renewed == 0 || r.Limits.Loosening < renewed {
		t.Fatalf("renewed %d rule changes, limits %+v", renewed, r.Limits)
	}

	for name, tc := range map[string]struct {
		tamper func(e map[string]any)
		opts   func(o *Options)
		want   string
	}{
		"extractor identity is not the gate's": {func(e map[string]any) {
			evidenceOf(e)["extractor"].(map[string]any)["codeDigest"] = "sha256:" + strings.Repeat("1", 64)
		}, nil, "this gate runs"},
		"derivedAt is stale": {nil, func(o *Options) { o.Now = gateNow.Add(48 * time.Hour) }, "outside [now-24h, now+5m]"},
	} {
		t.Run(name, func(t *testing.T) {
			base, head := ruleRenewalTrees(t, tc.tamper)
			o := Options{Base: base, Head: head, Source: argoFixture, Author: DefaultBotLogin}
			if tc.opts != nil {
				tc.opts(&o)
			}
			r := runGate(t, o)
			requireFail(t, r, tc.want)
		})
	}
}
