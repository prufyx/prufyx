// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package scanrun

// Run with: go test -tags prufyx_synthetic_knowledge ./internal/scanrun/

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

const wholeUpgradeRuleID = "kubernetes.synthetic-whole-upgrade.1-24-17-to-1-30-4"

// TestScanWholeUpgradeRule: a rule reviewed for the exact end-to-end pair
// matches no hop of a sequential plan. Its blocker is found on the whole
// upgrade, so it is never lost, and its pass alone never decides anything.
func TestScanWholeUpgradeRule(t *testing.T) {
	rule := `{"id":"` + wholeUpgradeRuleID + `","operator":"forbid_predicate_value","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.24.17","to":"1.30.4"},` +
		`"condition":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","factId":"component.kubernetes.flowcontrol_v1beta3_removed_gvk_present","boolValue":true},` +
		`"evidence":{"state":"active","reviewedAt":"2026-09-23T00:00:00Z","validUntil":"2026-12-20T00:00:00Z","sources":[` + testSource + `]},` +
		`"reasonCode":"REVIEWED_SOURCE_CONSTRAINT","nextAction":"synthetic test-only action"}`
	entry := cncfcheck.Entry{Project: "kubernetes", Description: "Synthetic test-only rule for a whole upgrade. Never published.",
		RequiredFacts: []cncfcheck.Fact{{Side: "proposed", ID: "component.kubernetes.flowcontrol_v1beta3_removed_gvk_present", Component: kubernetesKey, Type: constraintengine.FactBool, Description: "Synthetic."}},
		Rule:          json.RawMessage(rule)}
	restore, err := cncfcheck.UseSyntheticKnowledge(nil, []cncfcheck.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	knowledge := newKnowledge(t, knowledgeOptions{lines: []string{"1.25", "1.26", "1.27", "1.28", "1.29"}, policy: "current"})
	removed := "apiVersion: flowcontrol.apiserver.k8s.io/v1beta3\nkind: FlowSchema\nmetadata: {name: limits}\n"
	_, paths := files(t, map[string]string{"apf.yaml": removed})
	result := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
	if result.Exit != scanreport.ExitBlocked || len(result.Report.Findings) != 1 {
		t.Fatalf("exit %d findings %+v", result.Exit, result.Report.Findings)
	}
	finding := result.Report.Findings[0]
	if finding.RuleID != wholeUpgradeRuleID || !finding.Hop.WholeUpgrade || finding.Hop.From != "1.24.17" || finding.Hop.To != "1.30.4" || len(finding.Locations) != 1 {
		t.Fatalf("finding %+v", finding)
	}
	human := string(scanreport.Human(result.Report, scanreport.HumanOptions{}))
	if !strings.Contains(human, "whole upgrade 1.24.17 -> 1.30.4") {
		t.Fatalf("human:\n%s", human)
	}

	served := "apiVersion: flowcontrol.apiserver.k8s.io/v1\nkind: FlowSchema\nmetadata: {name: limits}\n"
	_, paths = files(t, map[string]string{"apf.yaml": served})
	result = mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
	if result.Exit == scanreport.ExitPass || len(result.Report.Findings) != 0 {
		t.Fatalf("served: exit %d", result.Exit)
	}
	passed := false
	for _, pass := range result.Report.Passes {
		passed = passed || pass.RuleID == wholeUpgradeRuleID && pass.Hop.WholeUpgrade
	}
	if !passed {
		t.Fatalf("passes %+v", result.Report.Passes)
	}
}
