// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

const factlessRuleID = "kubernetes.synthetic-factless-skip.1-33-0-to-1-37-0"

// factlessSkipRule is a synthetic rule that reads no fact: 1.33 -> 1.37 must
// go through 1.34 (the shape of a no-minor-skip control-plane rule).
func factlessSkipRule() string {
	bound := func(name, basis string) string {
		return `{"bound":"` + name + `","basis":"` + basis + `","sourceId":"` + intermediateSkewSource + `"}`
	}
	return `{"id":"` + factlessRuleID + `","operator":"require_intermediate_version","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.33.0","to":"1.37.0"},` +
		`"intermediate":"1.34.0","range":{"from":{"gte":"1.33.0","lt":"1.34.0"},"to":{"gte":"1.37.0","lt":"1.38.0"},"bounds":[` +
		bound("from.gte", "UPGRADE_FROM_SERIES") + `,` + bound("from.lt", "UPGRADE_FROM_SERIES") + `,` + bound("to.gte", "TARGET_SERIES") + `,` + bound("to.lt", "TARGET_SERIES") + `]},` +
		`"evidence":{"state":"active",` + currentWindow + `,"sources":[` + skewSource + `]},` +
		`"reasonCode":"REVIEWED_SOURCE_CONSTRAINT","nextAction":"Upgrade through 1.34, 1.35 and 1.36 in order."}`
}

// selectionKnowledge is the Kubernetes knowledge of a verified store whose
// pack holds the published rules plus the rule, evaluated through the real
// fact-family selection. The synthetic rules of knowledgeOptions bypass that
// selection (testKnowledge.Evaluate evaluates them directly), so a rule that
// reads no fact can only be tested this way.
type selectionKnowledge struct {
	Embedded
	digest string
}

func (k selectionKnowledge) Evaluate(policy cncfcheck.TrustPolicy, project string, facts []string, inputRaw []byte, now time.Time) (Evaluation, error) {
	return evaluateSnapshot(k.ScanKnowledge, "external_declared", k.digest, policy, project, facts, inputRaw, now)
}

func newSelectionKnowledge(t testing.TB, rules ...string) Knowledge {
	t.Helper()
	exported, err := cncfcheck.ExportEmbeddedExternalBundle("1")
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(exported, &envelope); err != nil {
		t.Fatal(err)
	}
	var pack map[string]json.RawMessage
	if err := json.Unmarshal(envelope["pack"], &pack); err != nil {
		t.Fatal(err)
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(pack["entries"], &entries); err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		entries = append(entries, map[string]json.RawMessage{
			"project": json.RawMessage(`"kubernetes"`), "description": json.RawMessage(`"Synthetic test-only rule. Never published."`),
			"requiredFacts": json.RawMessage(`[]`), "rule": json.RawMessage(rule),
		})
	}
	id := func(entry map[string]json.RawMessage) string {
		var shape struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(entry["rule"], &shape); err != nil {
			t.Fatal(err)
		}
		return shape.ID
	}
	sort.SliceStable(entries, func(i, j int) bool { return id(entries[i]) < id(entries[j]) })
	if pack["entries"], err = json.Marshal(entries); err != nil {
		t.Fatal(err)
	}
	packRaw, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cncfcheck.ExportExternalBundleFromPack(packRaw, "1")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := cncfcheck.ParseExternalBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := cncfcheck.NewStoreScanKnowledge(map[string]cncfcheck.ExternalBundle{"kubernetes": bundle})
	if err != nil {
		t.Fatal(err)
	}
	return selectionKnowledge{Embedded{snapshot}, bundle.BundleDigest()}
}

var factlessLines = []string{"1.33", "1.34", "1.35", "1.36", "1.37"}

func factlessScan(t testing.TB, policy, from, to string) Result {
	t.Helper()
	knowledge := newKnowledge(t, knowledgeOptions{base: newSelectionKnowledge(t, factlessSkipRule()), lines: factlessLines, policy: policy})
	_, paths := files(t, map[string]string{"cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n"})
	return mustScan(t, knowledge, args(paths, "--from", "kubernetes="+from, "--to", "kubernetes="+to)...)
}

func mentionsFactless(t testing.TB, report scanreport.Report) bool {
	t.Helper()
	return hasFinding(report, factlessRuleID) || strings.Contains(string(jsonOf(t, report)), factlessRuleID)
}

// TestScanFactlessSkipBlocksDirectUpgrade: a rule that reads no fact is
// evaluated through the real selection; a scan that skips the intermediate
// line without a reviewed path policy is BLOCKED by it, with the gap that
// the route is unreviewed kept.
func TestScanFactlessSkipBlocksDirectUpgrade(t *testing.T) {
	t.Parallel()
	for _, policy := range []string{"", "direct"} {
		t.Run("policy "+policy, func(t *testing.T) {
			t.Parallel()
			result := factlessScan(t, policy, "1.33.2", "1.37.1")
			var found []scanreport.Finding
			for _, finding := range result.Report.Findings {
				if finding.RuleID == factlessRuleID {
					found = append(found, finding)
				}
			}
			if len(found) != 1 || result.Exit != scanreport.ExitBlocked {
				t.Fatalf("exit %d findings %+v", result.Exit, result.Report.Findings)
			}
			finding := found[0]
			if finding.Match != "range" || len(finding.Locations) != 0 || finding.Fix != "Upgrade through 1.34, 1.35 and 1.36 in order." {
				t.Fatalf("finding %+v", finding)
			}
			if policy == "" {
				gap := false
				for _, reason := range gapReasons(result.Report) {
					gap = gap || strings.HasPrefix(reason, scanreport.ReasonNoReviewedPathPolicy)
				}
				if !gap {
					t.Fatalf("gaps %v", gapReasons(result.Report))
				}
			}
		})
	}
}

// TestScanFactlessSkipGolden: the location-less BLOCKED finding in the human,
// JSON and SARIF output. It changes the working directory (display paths),
// so it does not run in parallel.
func TestScanFactlessSkipGolden(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{base: newSelectionKnowledge(t, factlessSkipRule()), lines: factlessLines})
	dir, _ := files(t, map[string]string{"cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n"})
	inDir(t, dir, func() {
		report := mustScan(t, knowledge, args([]string{"cm.yaml"}, "--from", "kubernetes=1.33.2", "--to", "kubernetes=1.37.1")...).Report
		golden(t, "factless-skip-blocked.txt", scanreport.Human(report, scanreport.HumanOptions{}))
		golden(t, "factless-skip-blocked.json", jsonOf(t, report))
		sarif, err := scanreport.SARIF(report)
		if err != nil {
			t.Fatal(err)
		}
		golden(t, "factless-skip-blocked.sarif", sarif)
	})
}

// TestScanFactlessSkipSatisfiedByPlan: a sequential plan stops on the
// intermediate line, so nothing in the report names the rule.
func TestScanFactlessSkipSatisfiedByPlan(t *testing.T) {
	t.Parallel()
	result := factlessScan(t, "current", "1.33.2", "1.37.1")
	if mentionsFactless(t, result.Report) {
		t.Fatalf("report names the rule: exit %d findings %+v gaps %v", result.Exit, result.Report.Findings, gapReasons(result.Report))
	}
}

// TestScanFactlessSkipOtherPairsUnchanged: pairs the rule does not match
// are decided as without it.
func TestScanFactlessSkipOtherPairsUnchanged(t *testing.T) {
	t.Parallel()
	for _, pair := range [][2]string{{"1.36.0", "1.37.0"}, {"1.33.1", "1.33.9"}, {"1.35.0", "1.37.0"}} {
		t.Run(pair[0]+"-"+pair[1], func(t *testing.T) {
			t.Parallel()
			for _, policy := range []string{"", "direct", "current"} {
				result := factlessScan(t, policy, pair[0], pair[1])
				if mentionsFactless(t, result.Report) {
					t.Fatalf("policy %q: report names the rule: %+v", policy, result.Report.Findings)
				}
			}
		})
	}
}

// TestScanFactlessSkipControl: the real-selection knowledge without the rule
// has no finding for the pair, so the finding above comes from the rule.
func TestScanFactlessSkipControl(t *testing.T) {
	t.Parallel()
	knowledge := newKnowledge(t, knowledgeOptions{base: newSelectionKnowledge(t), lines: factlessLines})
	_, paths := files(t, map[string]string{"cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n"})
	result := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.33.2", "--to", "kubernetes=1.37.1")...)
	if mentionsFactless(t, result.Report) {
		t.Fatalf("finding without the rule: %+v", result.Report.Findings)
	}
}
