// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import "testing"

// supportCandidate turns a real reviewed entry into a support-range
// candidate: require_component_version on its own subject with severity
// unsupported and a reason code of its own.
func supportCandidate(t *testing.T) map[string]any {
	t.Helper()
	entry := firstRealEntry(t)
	setRuleID(t, entry, "support-test.range.1-0-0-to-2-0-0")
	body := rule(entry)
	subject := body["subject"].(map[string]any)
	delete(body, "condition")
	body["operator"] = "require_component_version"
	body["dependency"] = map[string]any{"side": "proposed", "component": subject["component"], "comparison": "gte", "version": "1.0.0"}
	body["severity"] = "unsupported"
	body["reasonCode"] = "ADDON_KUBERNETES_SUPPORT_RANGE"
	entry["requiredFacts"] = []any{}
	return entry
}

// TestRulecheckSeverity: rulecheck accepts the severity field the engine
// accepts and reports every severity the engine refuses as engine-rejected.
func TestRulecheckSeverity(t *testing.T) {
	result, err := Validate(candidateFile(t, supportCandidate(t)), Options{})
	if err != nil || !result.Valid {
		t.Fatalf("valid support-range candidate rejected: err=%v findings=%+v", err, result.Findings)
	}
	for name, mutate := range map[string]func(map[string]any){
		"other severity":      func(e map[string]any) { rule(e)["severity"] = "blocking" },
		"engine reason code":  func(e map[string]any) { rule(e)["reasonCode"] = "RULE_DEPENDENCY_COMPONENT_MISSING" },
		"on another operator": func(e map[string]any) { delete(rule(e), "dependency"); rule(e)["operator"] = "forbid_target_version" },
	} {
		entry := supportCandidate(t)
		mutate(entry)
		result, err := Validate(candidateFile(t, entry), Options{})
		if err != nil || result.Valid || checks(result) != "engine-rejected" {
			t.Fatalf("%s: err=%v checks=%s findings=%+v", name, err, checks(result), result.Findings)
		}
	}
}
