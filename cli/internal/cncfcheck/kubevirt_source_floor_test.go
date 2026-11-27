// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"fmt"
	"testing"
)

// The upstream upgrade guide supports an upgrade only from the latest patch of
// the previous minor, so the binding-cardinality range starts at 1.8.4: below
// it nothing is decided, whatever the input declares.
func TestKubeVirtBindingRangeStartsAtSourceFloor(t *testing.T) {
	t.Parallel()
	const ruleID = "kubevirt.interface-binding-cardinality.1-8-4-to-1-9-0"
	for _, tc := range []struct {
		from, to string
		invalid  bool
		want     string
	}{
		{"1.8.0", "1.9.0", false, "UNKNOWN"},
		{"1.8.0", "1.9.0", true, "UNKNOWN"},
		{"1.8.3", "1.9.0", false, "UNKNOWN"},
		{"1.8.3", "1.9.1", true, "UNKNOWN"},
		{"1.8.4-rc.0", "1.9.0", false, "UNKNOWN"},
		{"1.7.2", "1.9.0", false, "UNKNOWN"},
		{"1.8.4", "1.10.0", false, "UNKNOWN"},
		{"1.8.4", "1.9.1", false, "PASS"},
		{"1.8.4", "1.9.1", true, "BLOCKED"},
	} {
		t.Run(fmt.Sprintf("%s/%s/%t", tc.from, tc.to, tc.invalid), func(t *testing.T) {
			input := fmt.Sprintf(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/kubevirt/kubevirt","version":%q,"facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kubevirt/kubevirt","version":%q,"facts":[{"id":"component.kubevirt.interface_binding_cardinality_invalid","state":"declared","boolValue":%t}]}]}}`, tc.from, tc.to, tc.invalid)
			report, err := Check("kubevirt", []byte(input), reviewClock(t))
			if err != nil {
				// A version the input grammar refuses decides nothing.
				if tc.want == "UNKNOWN" && tc.from == "1.8.4-rc.0" {
					return
				}
				t.Fatal(err)
			}
			found := false
			for _, claim := range report.Check.Claims {
				if claim.RuleID != ruleID {
					continue
				}
				found = true
				if claim.Status != tc.want {
					t.Fatalf("status %s, want %s", claim.Status, tc.want)
				}
			}
			if tc.want != "UNKNOWN" && !found {
				t.Fatal("rule omitted")
			}
			if tc.want == "UNKNOWN" && ClaimExit(report) != 11 {
				t.Fatalf("exit %d, want 11", ClaimExit(report))
			}
		})
	}
}
