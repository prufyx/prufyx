// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// crossingRule is a synthetic removal-crossing rule over the CronJob
// v1beta1 removal fact: C = 1.25.0, reviewed through 1.36.0, anchored
// 1.24.0 -> 1.25.0, blocking when the removed API is present. withRange adds the whole-line reviewed range, so the
// single-minor hops stay decided by the range and the crossing covers the
// wider hops.
func crossingRule(id string, withRange bool) string {
	rng := ""
	if withRange {
		rng = lineRange("1.24", "1.25", "1.26")
	}
	return `{"id":"` + id + `","operator":"forbid_predicate_value","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.24.0","to":"1.25.0"},` + rng +
		`"crossing":{"change":{"version":"1.25.0","basis":"REMOVED_IN_RELEASE","sourceId":"kubernetes-website-version-skew-upgrade-order"},"horizon":{"lt":"1.36.0","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"kubernetes-website-version-skew-upgrade-order"}},` +
		`"condition":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","factId":"` + cronjobFact + `","boolValue":true},` +
		`"evidence":{"state":"active",` + currentWindow + `,"sources":[` + skewSource + `]},` +
		`"reasonCode":"REVIEWED_SOURCE_CONSTRAINT","nextAction":"Migrate the CronJob to batch/v1 before upgrading."}`
}

const crossingRuleID = "kubernetes.synthetic-crossing.1-24-0-to-1-25-0"

// crossingKnowledge hides the published CronJob rule so that the synthetic
// crossing rule alone judges the removal fact.
func crossingKnowledge(t *testing.T, rule string, policy string) Knowledge {
	t.Helper()
	base := newKnowledge(t, knowledgeOptions{lines: allLines, policy: policy, unchecked: true, synthetic: []string{rule}, dropRuleIDs: map[string][]string{"1.25": {cronjobRuleID}}})
	return hiddenRules{Knowledge: base, hidden: map[string]bool{cronjobRuleID: true}}
}

func crossingFinding(t *testing.T, report scanreport.Report) scanreport.Finding {
	t.Helper()
	if len(report.Findings) != 1 || report.Findings[0].RuleID != crossingRuleID {
		t.Fatalf("findings %+v", report.Findings)
	}
	return report.Findings[0]
}

// TestScanCrossingBlockIsReportedNotAnIntegrityError: a removal crossing that
// blocks a stepped hop is a BLOCKED finding with match mode "crossing" and
// its disclosure. It used to abort the scan with ErrIntegrity, because the
// hop overlap test did not know the crossing, and it was labelled "anchor".
func TestScanCrossingBlockIsReportedNotAnIntegrityError(t *testing.T) {
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	for name, from := range map[string]string{"patch origin": "1.24.17", "anchor origin": "1.24.0"} {
		t.Run(name, func(t *testing.T) {
			knowledge := crossingKnowledge(t, crossingRule(crossingRuleID, false), "current")
			result, err := scan(t, knowledge, args(paths, "--from", "kubernetes="+from, "--to", "kubernetes=1.27.2")...)
			if errors.Is(err, ErrIntegrity) {
				t.Fatal("a crossing BLOCK aborted the scan with ErrIntegrity")
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.Exit != scanreport.ExitBlocked || result.Report.Verdict != scanreport.VerdictBlocked {
				t.Fatalf("exit %d verdict %s gaps %v", result.Exit, result.Report.Verdict, gapReasons(result.Report))
			}
			finding := crossingFinding(t, result.Report)
			if finding.Match != "crossing" || finding.Crossing == nil || finding.Crossing.Change != "1.25.0" || finding.Crossing.AnchorFrom != "1.24.0" || finding.Crossing.AnchorTo != "1.25.0" || finding.Crossing.CappedAt != "1.36.0" {
				t.Fatalf("finding does not disclose the crossing: %+v", finding)
			}
			if !strings.Contains(finding.Fix, "matched by removal crossing 1.25.0") {
				t.Fatalf("fix does not name the crossing: %q", finding.Fix)
			}
			if finding.Hop.To != "1.25" || result.Report.Paths[0].Hops[0].Status != scanreport.HopBlocked {
				t.Fatalf("hop %+v / %+v", finding.Hop, result.Report.Paths[0].Hops[0])
			}
			// The disclosure reaches the JSON and the SARIF properties.
			if !strings.Contains(string(jsonOf(t, result.Report)), `"crossing":{"mode":"crossing"`) {
				t.Fatal("JSON report lacks the crossing disclosure")
			}
		})
	}
}

// TestScanCrossingNeverPasses: with the removal fact false a crossing-only
// rule cannot decide a hop it covers only by crossing, so the scan never
// reports PASS; with a whole-line range next to the crossing the single-minor
// hops stay decided by the range and the stepped scan keeps its PASS (the
// crossing must not degrade it through the whole-upgrade evaluation).
func TestScanCrossingNeverPasses(t *testing.T) {
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	command := args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")

	only := mustScan(t, crossingKnowledge(t, crossingRule(crossingRuleID, false), "current"), command...)
	if only.Exit == scanreport.ExitPass || only.Report.Verdict == scanreport.VerdictPass || len(only.Report.Findings) != 0 {
		t.Fatalf("crossing-only rule with a false fact: exit %d verdict %s findings %d", only.Exit, only.Report.Verdict, len(only.Report.Findings))
	}

	ranged := mustScan(t, crossingKnowledge(t, crossingRule(crossingRuleID, true), "current"), command...)
	if ranged.Exit != scanreport.ExitPass || ranged.Report.Verdict != scanreport.VerdictPass {
		t.Fatalf("crossing with a range degraded the stepped scan: exit %d gaps %v", ranged.Exit, gapReasons(ranged.Report))
	}
	for _, gap := range ranged.Report.Gaps {
		if gap.Hop != nil && gap.Hop.WholeUpgrade {
			t.Fatalf("whole-upgrade gap for a crossing a hop already decided: %+v", gap)
		}
	}
	// The same crossing with a true fact is a blocker on the same plan.
	_, bad := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	blocked := mustScan(t, crossingKnowledge(t, crossingRule(crossingRuleID, true), "current"), args(bad, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
	if blocked.Exit != scanreport.ExitBlocked {
		t.Fatalf("crossing with a range and a true fact: exit %d", blocked.Exit)
	}
}

// TestScanCrossingWithoutAPathPolicy: a direct hop over many lines prepares
// no removed-API fact, so a crossing rule reads it as unavailable: the answer
// is a gap, never PASS and never an integrity error.
func TestScanCrossingWithoutAPathPolicy(t *testing.T) {
	for name, manifest := range map[string]string{"removed": cronjobV1beta1, "migrated": cronjobV1} {
		t.Run(name, func(t *testing.T) {
			_, paths := files(t, map[string]string{"applyset.yaml": manifest})
			result, err := scan(t, crossingKnowledge(t, crossingRule(crossingRuleID, false), ""), args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.27.2")...)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if result.Exit == scanreport.ExitPass || result.Report.Verdict == scanreport.VerdictPass {
				t.Fatalf("exit %d verdict %s", result.Exit, result.Report.Verdict)
			}
			if !reflect.DeepEqual(len(result.Report.Paths), 1) {
				t.Fatalf("paths %+v", result.Report.Paths)
			}
		})
	}
}

// TestScanCrossingOnlyForDeclaredUpstream: the engine input carries plain
// versions without a distribution, which a crossing reads as upstream, so a
// crossing match under any other declared distribution is an integrity
// failure rather than a finding about a build nobody normalised. An UNKNOWN
// claim that discloses the crossing (the fact is unavailable) is ordinary.
func TestScanCrossingOnlyForDeclaredUpstream(t *testing.T) {
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	base := crossingKnowledge(t, crossingRule(crossingRuleID, false), "current")
	command := append(append([]string{}, paths...), "--distribution", "custom_build", "--resource-scope-complete", "--target-api-apply-required", "--now", testNow, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.27.2")
	// With the declaration the preparation supports no fact, so no crossing
	// matches and the scan is merely not a pass.
	plain := mustScan(t, base, command...)
	if plain.Exit == scanreport.ExitPass || len(plain.Report.Findings) != 0 {
		t.Fatalf("custom build: exit %d findings %d", plain.Exit, len(plain.Report.Findings))
	}
	// A forged crossing BLOCK under that declaration is refused.
	forged := claimEditor{Knowledge: base, edit: func(claims []constraintengine.Claim) {
		for i := range claims {
			if claims[i].RuleID == crossingRuleID {
				claims[i].Status, claims[i].ReasonCode = "BLOCKED", "REVIEWED_SOURCE_CONSTRAINT"
				claims[i].CrossingMatch = &constraintengine.CrossingMatch{Mode: "crossing", AnchorFrom: "1.24.0", AnchorTo: "1.25.0", Change: "1.25.0", CappedAt: "1.36.0"}
			}
		}
	}}
	if _, err := scan(t, forged, command...); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("crossing match under a custom build: %v", err)
	}
}
