// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"strings"
	"testing"
)

// setCandidate turns a real reviewed entry into a forbid_set_member
// candidate over one set fact.
func setCandidate(t *testing.T) map[string]any {
	t.Helper()
	entry := firstRealEntry(t)
	setRuleID(t, entry, "set-test.removed-gate.1-0-0-to-2-0-0")
	body := rule(entry)
	component := body["subject"].(map[string]any)["component"].(string)
	delete(body, "condition")
	delete(body, "appliesWhen")
	body["operator"] = "forbid_set_member"
	body["setCondition"] = map[string]any{"side": "proposed", "component": component, "factId": "component.example.feature_gates_set", "members": []any{"RemovedGate"}}
	entry["requiredFacts"] = []any{map[string]any{"side": "proposed", "id": "component.example.feature_gates_set", "component": component, "type": "set", "enumTokens": nil, "description": "Feature gates the component sets."}}
	return entry
}

func checks(result Result) string {
	return strings.Join(SortedChecks(result.Findings), ",")
}

func TestValidate_SetRuleCandidate(t *testing.T) {
	result, err := Validate(candidateFile(t, setCandidate(t)), Options{})
	if err != nil || !result.Valid {
		t.Fatalf("valid set candidate rejected: err=%v findings=%+v", err, result.Findings)
	}
	for name, tc := range map[string]struct {
		mutate func(map[string]any)
		want   string
	}{
		"invalid member": {func(e map[string]any) {
			rule(e)["setCondition"].(map[string]any)["members"] = []any{"Gate=false"}
		}, "engine-rejected,set-member"},
		"unsorted members": {func(e map[string]any) {
			rule(e)["setCondition"].(map[string]any)["members"] = []any{"b", "a"}
		}, "engine-rejected,set-member"},
		"empty members": {func(e map[string]any) {
			rule(e)["setCondition"].(map[string]any)["members"] = []any{}
		}, "engine-rejected,set-member"},
		"undeclared set fact": {func(e map[string]any) {
			rule(e)["setCondition"].(map[string]any)["factId"] = "component.example.flags_set"
		}, "engine-rejected,fact-reference"},
		"set fact declared as bool": {func(e map[string]any) {
			e["requiredFacts"].([]any)[0].(map[string]any)["type"] = "bool"
		}, "engine-rejected"},
		"unknown condition field": {func(e map[string]any) {
			rule(e)["setCondition"].(map[string]any)["complete"] = true
		}, "rule-schema"},
	} {
		entry := setCandidate(t)
		tc.mutate(entry)
		result, err := Validate(candidateFile(t, entry), Options{})
		if err != nil || result.Valid || checks(result) != tc.want {
			t.Fatalf("%s: err=%v checks=%s findings=%+v", name, err, checks(result), result.Findings)
		}
	}
}
