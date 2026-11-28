// SPDX-License-Identifier: AGPL-3.0-only

package supportinventory

import (
	"strings"
	"testing"
)

func withdrawnTestEntry(state string, edit func(rule map[string]any)) map[string]any {
	rule := communityTestRule("grafana.synthetic-withdrawn", "forbid_predicate_value", "REVIEWED_SOURCE_CONSTRAINT", "n", nil)
	rule["evidence"].(map[string]any)["state"] = state
	if edit != nil {
		edit(rule)
	}
	return map[string]any{"project": "grafana", "description": "d", "requiredFacts": []any{}, "rule": rule}
}

// A withdrawn community rule is counted nowhere, gives no capability, and is
// listed by name.
func TestSupportInventory_CommunityWithdrawnRuleIsListedNotCounted(t *testing.T) {
	baseline, _, err := generateCommunity(t, func(map[string]any) {})
	if err != nil {
		t.Fatal(err)
	}
	document, markdown, err := generateCommunity(t, func(pack map[string]any) {
		withoutGrafanaVerdictRules(pack, withdrawnTestEntry("withdrawn", nil))
	})
	if err != nil {
		t.Fatal(err)
	}
	if project := communityProject(t, document, "grafana"); project != nil && hasExecutableCapability(project) {
		t.Fatalf("a project with only a withdrawn rule is executable: %v", project)
	}
	base, got := baseline["counts"].(map[string]any), document["counts"].(map[string]any)
	if got["communityProjectRuleProjects"] != base["communityProjectRuleProjects"].(float64)-1 || got["executableProjects"] != base["executableProjects"].(float64)-1 || got["cncfSourceRulesWithdrawn"] != base["cncfSourceRulesWithdrawn"] {
		t.Fatalf("counts=%v baseline=%v", got, base)
	}
	found := false
	for _, item := range document["withdrawnRules"].([]any) {
		entry := item.(map[string]any)
		if entry["ruleID"] == "grafana.synthetic-withdrawn" {
			found = entry["project"] == "grafana" && entry["family"] == "community_project_source_rule" && entry["reasonCode"] == "RULE_EVIDENCE_WITHDRAWN"
		}
	}
	if !found || !strings.Contains(markdown, "| `grafana.synthetic-withdrawn` | grafana | community_project_source_rule | RULE_EVIDENCE_WITHDRAWN |") {
		t.Fatalf("withdrawn rule not listed: %v", document["withdrawnRules"])
	}
}

// Only the two exact states are admitted, and a withdrawn rule is held to the
// same checks as an active one.
func TestSupportInventory_CommunityWithdrawnRuleStaysChecked(t *testing.T) {
	for name, entry := range map[string]map[string]any{
		"empty state":      withdrawnTestEntry("", nil),
		"unknown state":    withdrawnTestEntry("superseded", nil),
		"case variant":     withdrawnTestEntry("Withdrawn", nil),
		"padded state":     withdrawnTestEntry("withdrawn ", nil),
		"missing evidence": withdrawnTestEntry("withdrawn", func(rule map[string]any) { delete(rule["evidence"].(map[string]any), "sources") }),
		"no sources":       withdrawnTestEntry("withdrawn", func(rule map[string]any) { rule["evidence"].(map[string]any)["sources"] = []any{} }),
		"other component": withdrawnTestEntry("withdrawn", func(rule map[string]any) {
			rule["subject"].(map[string]any)["component"] = "pkg:github/ceph/ceph"
		}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := generateCommunity(t, func(pack map[string]any) {
				pack["entries"] = append(pack["entries"].([]any), entry)
			}); err == nil {
				t.Fatal("generator accepted the entry")
			}
		})
	}
	t.Run("duplicate of a withdrawn rule", func(t *testing.T) {
		if _, _, err := generateCommunity(t, func(pack map[string]any) {
			pack["entries"] = append(pack["entries"].([]any), withdrawnTestEntry("withdrawn", nil), withdrawnTestEntry("active", nil))
		}); err == nil {
			t.Fatal("generator accepted a duplicate id")
		}
	})
}
