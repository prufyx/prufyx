// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"testing"
)

// guardedCandidate is a real reviewed forbid_predicate_value entry with an
// appliesWhen entry on its own condition fact, holding guardValue.
func guardedCandidate(t *testing.T, guardValue bool) map[string]any {
	t.Helper()
	entry := firstRealEntry(t)
	setRuleID(t, entry, "vacuous-test.guarded-condition.1-0-0-to-2-0-0")
	body := rule(entry)
	if body["operator"] != "forbid_predicate_value" {
		t.Fatalf("first real entry is %v, not forbid_predicate_value", body["operator"])
	}
	condition := body["condition"].(map[string]any)
	guard := map[string]any{"side": condition["side"], "component": condition["component"], "factId": condition["factId"], "boolValue": guardValue}
	body["appliesWhen"] = []any{guard}
	return entry
}

// TestValidate_ConditionContradictingAppliesWhenIsVacuous: a guard that
// requires the condition's own fact to hold another value makes the rule
// unable to block. The author gets a precise finding, and the engine
// rejects it too.
func TestValidate_ConditionContradictingAppliesWhenIsVacuous(t *testing.T) {
	entry := guardedCandidate(t, true)
	if rule(entry)["condition"].(map[string]any)["boolValue"] != true {
		t.Fatal("fixture condition is not boolValue true")
	}
	if result, err := Validate(candidateFile(t, entry), Options{}); err != nil || !result.Valid {
		t.Fatalf("agreeing guard rejected: err=%v findings=%+v", err, result.Findings)
	}
	vacuous := guardedCandidate(t, false)
	result, err := Validate(candidateFile(t, vacuous), Options{})
	if err != nil || result.Valid || checks(result) != "engine-rejected,vacuous-condition" {
		t.Fatalf("err=%v checks=%s findings=%+v", err, checks(result), result.Findings)
	}
}

func TestContradictingApplicabilityEnum(t *testing.T) {
	condition := factCondition{Side: "proposed", Component: "pkg:oci/example/controller", FactID: "component.example.mode", EnumValue: "legacy"}
	for name, tc := range map[string]struct {
		guard factCondition
		want  bool
	}{
		"other token": {factCondition{Side: "proposed", Component: condition.Component, FactID: condition.FactID, EnumValue: "modern"}, true},
		"same token":  {factCondition{Side: "proposed", Component: condition.Component, FactID: condition.FactID, EnumValue: "legacy"}, false},
		"other side":  {factCondition{Side: "current", Component: condition.Component, FactID: condition.FactID, EnumValue: "modern"}, false},
	} {
		body := ruleBody{Operator: "forbid_predicate_value", Condition: &condition, AppliesWhen: []factCondition{tc.guard}}
		if _, got := contradictingApplicability(body); got != tc.want {
			t.Fatalf("%s: got %v", name, got)
		}
	}
}
