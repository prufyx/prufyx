// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package scanrun

// Run with: go test -tags prufyx_synthetic_knowledge ./internal/scanrun/

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
)

// recordSet selects which records the synthetic pack carries for the hop
// 1.28 -> 1.29 and how they look.
type recordSet struct {
	attestation, policy, served bool
	window                      [2]string
	servedWindow, policyWindow  [2]string
	attestationRules            func([]string) []string
	extraServed                 []string
	// refused: the loader must refuse the pack; installRecords returns nil.
	refused bool
}

var (
	currentRecordWindow = [2]string{"2026-09-23T00:00:00Z", "2026-12-20T00:00:00Z"}
	staleRecordWindow   = [2]string{"2026-06-01T00:00:00Z", "2026-08-01T00:00:00Z"}
)

// installRecords puts the records into the real pack (through the real
// loader, the real admission checks and the real pack schema level) and
// returns the embedded knowledge that now reads them.
func installRecords(t *testing.T, set recordSet) Knowledge {
	t.Helper()
	if set.window == ([2]string{}) {
		set.window = currentRecordWindow
	}
	if set.servedWindow == ([2]string{}) {
		set.servedWindow = set.window
	}
	if set.policyWindow == ([2]string{}) {
		set.policyWindow = set.window
	}
	byScope, _, err := lineattest.RulesByScope(packRules(t))
	if err != nil {
		t.Fatal(err)
	}
	ids := byScope[lineattest.Key{Component: kubernetesKey, Line: "1.29", Family: lineattest.FamilyKubernetesRemovedServedGVK}]
	if set.attestationRules != nil {
		ids = set.attestationRules(ids)
	}
	sort.Strings(ids)
	encodedIDs, _ := json.Marshal(ids)
	evidence := func(window [2]string) string {
		return fmt.Sprintf(`{%s,"reviewedAt":%q,"validUntil":%q,"sources":[%s]}`, basisFields("mechanical", window[0]), window[0], window[1], testSource)
	}
	var records cncfcheck.SyntheticRecords
	if set.attestation {
		records.LineAttestations = json.RawMessage(fmt.Sprintf(`[{"component":%q,"line":"1.29","factFamily":%q,"completeness":"COMPLETE_REVIEWED_RULES_FOR_LINE","ruleIds":%s,"evidence":%s}]`,
			kubernetesKey, lineattest.FamilyKubernetesRemovedServedGVK, encodedIDs, evidence(set.window)))
	}
	if set.policy {
		records.PathPolicies = json.RawMessage(fmt.Sprintf(`[{"component":%q,"policy":"sequential_minor","evidence":{"state":"active",%s,"reviewedAt":%q,"validUntil":%q,"sources":[%s]}}]`,
			kubernetesKey, basisFields("mechanical", set.policyWindow[0]), set.policyWindow[0], set.policyWindow[1], testSource))
	}
	if set.served {
		var pairs []string
		for pair := range testServed {
			pairs = append(pairs, pair)
		}
		pairs = append(pairs, set.extraServed...)
		sort.Strings(pairs)
		encodedPairs, _ := json.Marshal(pairs)
		records.ServedAPIs = json.RawMessage(fmt.Sprintf(`[{"component":%q,"line":"1.29","completeness":%q,"apis":%s,"evidence":%s}]`,
			kubernetesKey, servedapis.Completeness, encodedPairs, evidence(set.servedWindow)))
	}
	restore, err := cncfcheck.UseSyntheticRecords(nil, nil, records)
	if err != nil {
		if set.refused {
			return nil
		}
		t.Fatalf("the pack with these records is not admissible: %v", err)
	}
	t.Cleanup(restore)
	embedded, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	return embedded
}

func scanHop(t *testing.T, knowledge Knowledge, manifest string) Result {
	t.Helper()
	_, paths := files(t, map[string]string{"applyset.yaml": manifest})
	return mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.28.6", "--to", "kubernetes=1.29.2")...)
}

// TestScanFirstPassFromPackRecords: with a served list and a line attestation
// for the target line in the pack, the real embedded-knowledge route returns
// SCOPE_COMPLETE_PASS for one hop. The path policy is not needed for a hop
// that enters one line from the line before it, and a stale one still stops.
func TestScanFirstPassFromPackRecords(t *testing.T) {
	both := recordSet{attestation: true, served: true}
	result := scanHop(t, installRecords(t, both), cronjobV1)
	if result.Exit != scanreport.ExitPass || result.Report.Verdict != scanreport.VerdictPass || len(result.Report.Gaps) != 0 || len(result.Report.Findings) != 0 {
		t.Fatalf("exit %d verdict %s gaps %v", result.Exit, result.Report.Verdict, gapReasons(result.Report))
	}
	if hops := result.Report.Paths[0].Hops; len(hops) != 1 || hops[0].Status != scanreport.HopCovered || hops[0].Attestation == nil || hops[0].Attestation.Basis != "mechanical" {
		t.Fatalf("hops %+v", hops)
	}
	if len(result.Report.Passes) == 0 {
		t.Fatal("a pass names the rules that decided the hop")
	}
	// A current path policy beside them changes nothing.
	if result := scanHop(t, installRecords(t, recordSet{attestation: true, served: true, policy: true}), cronjobV1); result.Exit != scanreport.ExitPass {
		t.Fatalf("with a path policy: exit %d gaps %v", result.Exit, gapReasons(result.Report))
	}
}

// TestScanFirstPassNeedsEveryRecord: each record missing, stale, incomplete
// or for another line keeps the answer UNKNOWN with a named gap.
func TestScanFirstPassNeedsEveryRecord(t *testing.T) {
	cases := []struct {
		name           string
		set            recordSet
		reason, detail string
	}{
		{"no records", recordSet{}, "LINE_NOT_ATTESTED", ""},
		{"no line attestation", recordSet{served: true}, "LINE_NOT_ATTESTED", ""},
		{"no served list", recordSet{attestation: true}, "API_VERSION_NOT_REVIEWED", "no reviewed list of the API versions"},
		{"stale line attestation", recordSet{attestation: true, served: true, window: staleRecordWindow, servedWindow: currentRecordWindow}, "LINE_NOT_ATTESTED", ""},
		{"stale served list", recordSet{attestation: true, served: true, servedWindow: staleRecordWindow}, "API_VERSION_NOT_REVIEWED", "is not current (stale)"},
		{"served list lacks the kind", recordSet{attestation: true, served: true, extraServed: nil}, "API_VERSION_NOT_REVIEWED", "does not list as served"},
		{"stale path policy", recordSet{attestation: true, served: true, policy: true, policyWindow: staleRecordWindow}, "PATH_POLICY_NOT_CURRENT", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest := cronjobV1
			if tc.name == "served list lacks the kind" {
				manifest += "---\napiVersion: v1\nkind: ComponentStatus\nmetadata: {name: a}\n"
			}
			result := scanHop(t, installRecords(t, tc.set), manifest)
			if result.Exit != scanreport.ExitUnknown || result.Report.Verdict == scanreport.VerdictPass {
				t.Fatalf("exit %d verdict %s", result.Exit, result.Report.Verdict)
			}
			if tc.reason != "" && !hasGap(result.Report, tc.reason, tc.detail) {
				t.Fatalf("want %s %q, got %+v", tc.reason, tc.detail, result.Report.Gaps)
			}
		})
	}
	// A line attestation that leaves out a rule of its line is refused by
	// the pack loader: the whole pack, not just the record.
	installRecords(t, recordSet{attestation: true, served: true, refused: true, attestationRules: func([]string) []string { return nil }})
	// After a refused pack nothing is left behind: the knowledge carries no
	// record and behaves exactly as today.
	if result := scanHop(t, mustEmbedded(t), cronjobV1); result.Exit != scanreport.ExitUnknown || !hasGap(result.Report, "API_VERSION_NOT_REVIEWED", "") || !hasGap(result.Report, "LINE_NOT_ATTESTED", "") {
		t.Fatalf("shipped knowledge: exit %d gaps %v", result.Exit, gapReasons(result.Report))
	}
}

func mustEmbedded(t *testing.T) Knowledge {
	t.Helper()
	embedded, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	return embedded
}

// TestScanFirstPassStillBlocksRemovedAPI: records never hide a removal. An
// object at a version the target removed is BLOCKED beside a complete set of
// records, and an object at a version removed before the hop is a named gap.
func TestScanFirstPassStillBlocksRemovedAPI(t *testing.T) {
	knowledge := installRecords(t, recordSet{attestation: true, served: true})
	removed := "apiVersion: flowcontrol.apiserver.k8s.io/v1beta2\nkind: FlowSchema\nmetadata: {name: a}\nspec: {priorityLevelConfiguration: {name: x}}\n"
	result := scanHop(t, knowledge, cronjobV1+"---\n"+removed)
	if result.Exit != scanreport.ExitBlocked || result.Report.Verdict == scanreport.VerdictPass || len(result.Report.Findings) == 0 {
		t.Fatalf("exit %d verdict %s findings %d gaps %v", result.Exit, result.Report.Verdict, len(result.Report.Findings), gapReasons(result.Report))
	}
	if !strings.Contains(result.Report.Findings[0].RuleID, "flowcontrol-v1beta2-removed") {
		t.Fatalf("finding %+v", result.Report.Findings[0])
	}
	// Removed on an earlier line (1.25) and no hop enters it: never served.
	old := "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: a}\nspec: {schedule: \"0 2 * * *\"}\n"
	if result := scanHop(t, knowledge, old); result.Exit == scanreport.ExitPass || !hasGap(result.Report, "API_VERSION_NOT_SERVED", "") {
		t.Fatalf("exit %d gaps %v", result.Exit, gapReasons(result.Report))
	}
}
