// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import "testing"

// TestRulecheckBasis: rulecheck accepts every basis the engine accepts and
// refuses a provenance shape the engine refuses.
func TestRulecheckBasis(t *testing.T) {
	withBasis := func(basis string, derivedAt bool) map[string]any {
		entry := firstRealEntry(t)
		evidence := rule(entry)["evidence"].(map[string]any)
		evidence["basis"] = basis
		if derivedAt {
			evidence["derivedAt"] = evidence["reviewedAt"]
		}
		return entry
	}
	for _, basis := range []string{"empirical", "consensus", "lead"} {
		result, err := Validate(candidateFile(t, withBasis(basis, true)), Options{})
		if err != nil || !result.Valid {
			t.Fatalf("%s candidate rejected: err=%v findings=%+v", basis, err, result.Findings)
		}
		result, err = Validate(candidateFile(t, withBasis(basis, false)), Options{})
		if err != nil || result.Valid {
			t.Fatalf("%s candidate without derivedAt accepted: err=%v", basis, err)
		}
	}
	result, err := Validate(candidateFile(t, withBasis("model", true)), Options{})
	if err != nil || result.Valid {
		t.Fatalf("unknown basis accepted: err=%v", err)
	}
}
