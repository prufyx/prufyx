// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import "testing"

// TestBasisCheckUsesEngineFlags: the block-only check accepts every known
// basis the engine evaluates safely and refuses an unknown one on an active
// rule.
func TestBasisCheckUsesEngineFlags(t *testing.T) {
	for _, tc := range []struct {
		basis, state string
		ok           bool
	}{
		{"", "active", true},
		{"reviewed", "active", true},
		{"mechanical", "active", true},
		{"empirical", "active", true},
		{"consensus", "active", true},
		{"lead", "active", true},
		{"model", "active", false},
		{"Consensus", "active", false},
		{"model", "withdrawn", true},
	} {
		h := &loadedPack{Order: []string{"rule"}, Entries: map[string]*entry{"rule": {RuleID: "rule", Evidence: evidenceView{State: tc.state, Basis: tc.basis}}}}
		r := &Report{}
		r.basisCheck(PackSpec{Name: "cncf"}, h)
		if len(r.Checks) != 1 || r.Checks[0].Name != "block-only/cncf" || r.Checks[0].OK != tc.ok {
			t.Fatalf("basis %q %s: %+v", tc.basis, tc.state, r.Checks)
		}
	}
}
