// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// wideKubernetesAnchorEntry clones the cronjob removal as an exact-only anchor
// rule for 1.21.0 -> 1.25.0: a wide hop that crosses the 1.22 and 1.25
// release boundaries other rules cite, while this rule alone could pass.
func wideKubernetesAnchorEntry(t *testing.T) Entry {
	t.Helper()
	entry := ruleEntry(t, "kubernetes", cronJobRuleID)
	var rule map[string]any
	if err := json.Unmarshal(entry.Rule, &rule); err != nil {
		t.Fatal(err)
	}
	rule["id"] = "kubernetes.synthetic-wide-anchor.1-21-0-to-1-25-0"
	rule["subject"].(map[string]any)["from"] = "1.21.0"
	delete(rule, "range")
	raw, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	entry.Rule = raw
	return entry
}

// BOUNDARY-1 F1: a rule selection that drops a rule only because it is not a
// match must keep the rules whose release boundary the pair crosses outside
// their reviewed range, so the engine reports them as unreviewed and the exit
// is never 0.
func TestSelectionKeepsBoundaryCrossedRules(t *testing.T) {
	b, err := assembleSynthetic(syntheticPack(t, packSchemaRanged, nil, wideKubernetesAnchorEntry(t)), nil)
	if err != nil {
		t.Fatal(err)
	}
	inputRaw := kubernetesInput(t, "1.21.0", "1.25.0", false)
	input, err := constraintengine.ParseInput(inputRaw, b.registry)
	if err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{"generic", "family"} {
		var selected selection
		if selector == "generic" {
			selected, err = b.selectForInput("kubernetes", inputRaw)
		} else {
			selected, err = b.selectFamily("kubernetes", []string{"component.kubernetes.cronjob_v1beta1_removed_gvk_present"}, inputRaw)
		}
		if err != nil {
			t.Fatal(selector, err)
		}
		report, err := b.reportSelection("kubernetes", "", selector == "family", input, selected, inputRaw, mustTime(t, "2026-10-08T00:00:00Z"))
		if err != nil {
			t.Fatal(selector, err)
		}
		decided, boundary := 0, map[string]bool{}
		for _, claim := range report.Check.Claims {
			switch claim.ReasonCode {
			case constraintengine.ReasonReleaseBoundaryNotReviewed:
				if claim.Status != "UNKNOWN" {
					t.Errorf("%s: %s is %s", selector, claim.RuleID, claim.Status)
				}
				boundary[claim.RuleID] = true
			default:
				decided++
			}
		}
		if decided != 1 {
			t.Errorf("%s: want the one wide anchor rule decided, got %d", selector, decided)
		}
		// The 1.22 and 1.25 removals, among them the cronjob v1beta1 rule
		// anchored at 1.24 -> 1.25, must be present.
		// The generic selection holds every Kubernetes boundary rule (13 at
		// 1.22 and 7 at 1.25 in the shipped pack); the family selection only
		// those that read the cronjob fact.
		want := map[string]int{"generic": 20, "family": 1}[selector]
		if !boundary[cronJobRuleID] || len(boundary) < want {
			t.Errorf("%s: boundary claims dropped before evaluation: %d (cronjob present: %v)", selector, len(boundary), boundary[cronJobRuleID])
		}
		if exit := ClaimExit(report); exit == 0 {
			t.Errorf("%s: a hop crossing cited removals exited 0", selector)
		}
	}
}
