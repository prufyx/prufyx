// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"strings"
	"testing"
)

// The next action of an UNKNOWN claim is read by a person: it names what is
// missing or what to do in plain words, never an internal reference, and it
// never recommends a step that cannot succeed today.
func TestUnknownNextActionsArePlainAndActionable(t *testing.T) {
	registry := scopeRegistry(t)
	cases := []struct {
		name, rule, fact string
		reason           string
		must             []string
	}{
		{"stale", noticeRule("notice-a", scopeComponentA, "1.0.0", "2.0.0", "active", expiredUntil, ""), "", "RULE_EVIDENCE_STALE",
			[]string{"review of this rule expired on 20", "newer source build", "signed package you trust", "by hand"}},
		{"withdrawn", noticeRule("notice-a", scopeComponentA, "1.0.0", "2.0.0", "withdrawn", activeUntil, ""), "", "RULE_EVIDENCE_WITHDRAWN",
			[]string{"withdrawn", "evidence could not be verified", "by hand"}},
		{"applicability fact missing", noticeRule("notice-a", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, appliesWhenA(true)), "", "RULE_APPLICABILITY_FACT_UNAVAILABLE",
			[]string{"is missing from the input", "declare it in the input file"}},
		{"applicability not matched", noticeRule("notice-a", scopeComponentA, "1.0.0", "2.0.0", "active", activeUntil, appliesWhenA(true)), declaredFact(scopeFactA, false), "RULE_APPLICABILITY_NOT_MATCHED",
			[]string{"this rule does not apply", "does not match its condition", "no action is needed for this rule"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := parseNotice(t, nil, tc.rule)
			input := scopeInput(t, registry, false, componentInput{Component: scopeComponentA, From: "1.0.0", To: "2.0.0", Fact: tc.fact})
			report, err := Evaluate(input, rules, testNow(t))
			if err != nil {
				t.Fatal(err)
			}
			claim := report.Claims[0]
			if claim.ReasonCode != tc.reason {
				t.Fatalf("reason=%s want %s", claim.ReasonCode, tc.reason)
			}
			for _, want := range tc.must {
				if !strings.Contains(claim.NextAction, want) {
					t.Errorf("next action %q lacks %q", claim.NextAction, want)
				}
			}
			for _, banned := range []string{"inspect local", "pkg:", "select later declared", "mark missing", "db update"} {
				if strings.Contains(claim.NextAction, banned) {
					t.Errorf("next action %q contains internal or unusable wording %q", claim.NextAction, banned)
				}
			}
		})
	}
}

func TestDependencyActionNamesTheComponent(t *testing.T) {
	action := dependencyAction(componentCheck{Side: "proposed", Component: "pkg:github/example/controller", Comparison: "gte", Version: "1.2.0"})
	if !strings.Contains(action, "the controller version is missing from the input") || strings.Contains(action, "pkg:") || strings.Contains(action, "inspect local") {
		t.Fatalf("dependency action=%q", action)
	}
}
