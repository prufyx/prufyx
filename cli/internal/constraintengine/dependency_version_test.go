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

// A pre-release declared version is on its own line for a dependency bound:
// 1.38.0-alpha.2 satisfies "gte 1.38.0" and fails "lt 1.38.0", like 1.38.0.
func TestDependencyVersionPreReleaseUsesItsLine(t *testing.T) {
	const dependency = "pkg:github/kubernetes/kubernetes"
	for _, c := range []struct{ comparison, bound, want string }{
		{"gte", "1.38.0", "PASS"}, {"gte", "1.37.0", "PASS"}, {"gte", "1.39.0", "BLOCKED"},
		{"lt", "1.38.0", "BLOCKED"}, {"lt", "1.39.0", "PASS"}, {"lte", "1.38.0", "PASS"}, {"eq", "1.38.0", "PASS"},
	} {
		input := inputDocument{Proposed: inputSide{Components: []inputComponent{{Component: dependency, Version: "1.38.0-alpha.2"}}}}
		r := rule{Operator: "require_component_version", Dependency: &componentCheck{Side: "proposed", Component: dependency, Comparison: c.comparison, Version: c.bound}}
		if got := evaluateMatchedRule(input, r, Claim{}).Status; got != c.want {
			t.Errorf("1.38.0-alpha.2 %s %s: got %s, want %s", c.comparison, c.bound, got, c.want)
		}
	}
}

// A report decided on a pre-release is recognised from its disclosures.
func TestReportHasPreReleaseInput(t *testing.T) {
	plain := Report{Claims: []Claim{{SubjectMatch: &SubjectMatch{AnchorFrom: "1.24.1", AnchorTo: "1.25.0"}}}}
	if plain.HasPreReleaseInput() {
		t.Fatal("a release report is labelled")
	}
	for _, r := range []Report{
		{Claims: []Claim{{SubjectMatch: &SubjectMatch{AnchorFrom: "1.24.1", AnchorTo: "1.25.0-rc.1"}}}},
		{Claims: []Claim{{CrossingMatch: &CrossingMatch{AnchorFrom: "1.24.0-beta.1", AnchorTo: "1.25.0"}}}},
		{ScopeCompleteness: &ScopeCompleteness{Components: []ComponentScope{{Component: kubernetesComponent, From: "1.24.1", To: "1.25.0-alpha.1"}}}},
	} {
		if !r.HasPreReleaseInput() {
			t.Fatalf("not recognised: %+v", r)
		}
	}
}
