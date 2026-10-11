// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import "testing"

// TestDependencyVersionNotComparableIsUnknown guards the dependency
// comparison: a declared version the engine cannot compare proves neither
// side of the bound, so the claim is UNKNOWN, never BLOCKED or UNSUPPORTED.
// The parser refuses such a version today; the evaluator must not rely on it.
func TestDependencyVersionNotComparableIsUnknown(t *testing.T) {
	const dependency = "pkg:github/kubernetes/kubernetes"
	for _, declared := range []string{"1.30", "1.30.2-gke.1", "v1.30.2", "", "99999999999.0.0"} {
		for _, severity := range []string{"", SeverityUnsupported} {
			input := inputDocument{Proposed: inputSide{Components: []inputComponent{{Component: dependency, Version: declared}}}}
			r := rule{Operator: "require_component_version", Severity: severity, Dependency: &componentCheck{Side: "proposed", Component: dependency, Comparison: "gte", Version: "1.30.0"}}
			claim := evaluateMatchedRule(input, r, Claim{})
			if claim.Status != "UNKNOWN" || claim.ReasonCode != ReasonDependencyVersionNotComparable || !publicText(claim.NextAction) {
				t.Errorf("declared %q severity %q: got %s %s %q", declared, severity, claim.Status, claim.ReasonCode, claim.NextAction)
			}
		}
	}
	// Comparable versions still decide.
	for declared, want := range map[string]string{"1.29.9": "BLOCKED", "1.30.0": "PASS", "1.31.0": "PASS"} {
		input := inputDocument{Proposed: inputSide{Components: []inputComponent{{Component: dependency, Version: declared}}}}
		r := rule{Operator: "require_component_version", Dependency: &componentCheck{Side: "proposed", Component: dependency, Comparison: "gte", Version: "1.30.0"}}
		if got := evaluateMatchedRule(input, r, Claim{}).Status; got != want {
			t.Errorf("declared %s: got %s, want %s", declared, got, want)
		}
	}
}
