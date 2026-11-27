// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package scanrun

// Run with: go test -tags prufyx_synthetic_knowledge -run Lapsed ./internal/scanrun/
//
// A record that has expired, was withdrawn or was removed must leave the
// answer UNKNOWN with the missing evidence named: never a pass, never a
// covered hop and never a blocker decided from that record. Every case has a
// control with the record current, so a case cannot hold only because the
// scan never reached the record. This file uses only what release
// v0.1.0-beta.0 also has, so it can be copied onto that tag and run there.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// requireLapsedUnknown: exit UNKNOWN, no finding, no covered hop.
func requireLapsedUnknown(t *testing.T, result Result) {
	t.Helper()
	if result.Exit != scanreport.ExitUnknown || result.Report.Verdict == scanreport.VerdictPass || result.Report.Verdict == scanreport.VerdictBlocked || len(result.Report.Findings) != 0 {
		t.Fatalf("exit %d verdict %s findings %+v gaps %v", result.Exit, result.Report.Verdict, result.Report.Findings, gapReasons(result.Report))
	}
	for _, path := range result.Report.Paths {
		for _, hop := range path.Hops {
			if hop.Status == scanreport.HopCovered || hop.Status == scanreport.HopBlocked {
				t.Fatalf("hop %d is %s", hop.Index, hop.Status)
			}
		}
	}
}

func requireNamed(t *testing.T, result Result, reason string, details ...string) {
	t.Helper()
	for _, detail := range details {
		if !hasGap(result.Report, reason, detail) {
			t.Fatalf("want gap %s %q, got %+v", reason, detail, result.Report.Gaps)
		}
	}
}

func TestLapsedRule(t *testing.T) {
	ruleID := supersedeids.ID("kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0")
	cases := []struct {
		name  string
		edit  func(rule map[string]any) bool
		named string
	}{
		{"expired", func(rule map[string]any) bool {
			evidence := rule["evidence"].(map[string]any)
			evidence["reviewedAt"], evidence["validUntil"] = "2026-06-01T00:00:00Z", "2026-08-01T00:00:00Z"
			if _, mechanical := evidence["derivedAt"]; mechanical {
				evidence["derivedAt"] = "2026-06-01T00:00:00Z"
			}
			return true
		}, "(stale)"},
		{"withdrawn", func(rule map[string]any) bool {
			rule["evidence"].(map[string]any)["state"] = "withdrawn"
			return true
		}, "(withdrawn)"},
		{"removed", func(map[string]any) bool { return false }, ""},
	}
	scanRule := func(t *testing.T, layout string, edit func(map[string]any) bool, manifest string) Result {
		t.Helper()
		seen := false
		pack := editPack(t, embeddedPack(t), func(_ string, rule map[string]any) bool {
			if rule["id"] != ruleID {
				return true
			}
			seen = true
			return edit(rule)
		})
		if !seen {
			t.Fatalf("rule %s is not in the pack", ruleID)
		}
		// A removed rule leaves no line attestation that lists it.
		pack = withoutListingAttestations(t, pack, ruleID, edit)
		fixture := newStoreFixture(t, layout)
		fixture.importPack(pack, "7")
		dir, _ := files(t, map[string]string{"applyset.yaml": manifest})
		var result Result
		inDir(t, dir, func() {
			result = mustScan(t, openAt(t, fixture.store, testNow), storeArgs([]string{"applyset.yaml"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3")...)
		})
		return result
	}
	keep := func(map[string]any) bool { return true }
	for _, layout := range storeLayouts {
		t.Run(layout+"/control", func(t *testing.T) {
			result := scanRule(t, layout, keep, cronjobV1beta1)
			if result.Exit != scanreport.ExitBlocked || len(result.Report.Findings) != 1 || result.Report.Findings[0].RuleID != ruleID {
				t.Fatalf("control: exit %d findings %+v gaps %v", result.Exit, result.Report.Findings, gapReasons(result.Report))
			}
		})
		for _, tc := range cases {
			for manifestName, manifest := range map[string]string{"removed API": cronjobV1beta1, "migrated": cronjobV1} {
				t.Run(layout+"/"+tc.name+"/"+manifestName, func(t *testing.T) {
					result := scanRule(t, layout, tc.edit, manifest)
					requireLapsedUnknown(t, result)
					switch {
					case tc.named != "":
						requireNamed(t, result, "EVIDENCE_EXPIRED", ruleID, tc.named)
					default:
						// Nothing is left to name the rule by: the line it
						// belonged to is named as not reviewed.
						requireNamed(t, result, "LINE_NOT_ATTESTED", "1.25")
						if manifestName == "removed API" && !hasGap(result.Report, "API_VERSION_NOT_SERVED", "1.25") {
							t.Fatalf("removed API not named: %+v", result.Report.Gaps)
						}
					}
				})
			}
		}
	}
}

// withoutListingAttestations drops, when edit removes the rule, every line
// attestation that lists it.
func withoutListingAttestations(t *testing.T, raw []byte, ruleID string, edit func(map[string]any) bool) []byte {
	t.Helper()
	if edit(map[string]any{"id": ruleID, "evidence": map[string]any{}}) {
		return raw
	}
	var pack map[string]any
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	attestations, _ := pack["lineAttestations"].([]any)
	var kept []any
	for _, item := range attestations {
		listed := false
		ids, _ := item.(map[string]any)["ruleIds"].([]any)
		for _, id := range ids {
			listed = listed || id == ruleID
		}
		if !listed {
			kept = append(kept, item)
		}
	}
	if len(kept) == len(attestations) {
		t.Fatalf("no line attestation lists %s", ruleID)
	}
	pack["lineAttestations"] = kept
	out, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLapsedLineAttestationAndServedList(t *testing.T) {
	control := scanHop(t, installRecords(t, recordSet{attestation: true, served: true}), cronjobV1)
	if control.Exit != scanreport.ExitPass {
		t.Fatalf("control: exit %d gaps %v", control.Exit, gapReasons(control.Report))
	}
	cases := []struct {
		name    string
		set     recordSet
		reason  string
		details []string
		noList  bool
	}{
		{"expired line attestation", recordSet{attestation: true, served: true, window: staleRecordWindow, servedWindow: currentRecordWindow}, "LINE_NOT_ATTESTED", []string{"1.29", "stale"}, false},
		{"removed line attestation", recordSet{served: true}, "LINE_NOT_ATTESTED", []string{"1.29"}, false},
		{"expired served list", recordSet{attestation: true, served: true, servedWindow: staleRecordWindow}, "API_VERSION_NOT_REVIEWED", []string{"1.29", "is not current (stale)"}, true},
		{"removed served list", recordSet{attestation: true}, "API_VERSION_NOT_REVIEWED", []string{"1.29", "no reviewed list of the API versions"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := scanHop(t, installRecords(t, tc.set), cronjobV1)
			if result.Exit != scanreport.ExitUnknown || result.Report.Verdict == scanreport.VerdictPass || len(result.Report.Findings) != 0 {
				t.Fatalf("exit %d verdict %s findings %+v", result.Exit, result.Report.Verdict, result.Report.Findings)
			}
			requireNamed(t, result, tc.reason, tc.details...)
			if tc.noList {
				// The list is not relied on.
				if served := result.Report.Paths[0].ServedList; served != nil {
					t.Fatalf("served list %+v", served)
				}
			} else if hop := result.Report.Paths[0].Hops[0]; hop.Status == scanreport.HopCovered {
				t.Fatalf("hop covered %+v", hop)
			}
		})
	}
}

// lapsedPolicy is a sequential_minor Kubernetes path policy record.
func lapsedPolicy(t *testing.T, state string, window [2]string) upgradepath.Status {
	t.Helper()
	records, err := upgradepath.Parse([]byte(fmt.Sprintf(`[{"component":%q,"policy":"sequential_minor","evidence":{"state":%q,%s,"reviewedAt":%q,"validUntil":%q,"sources":[%s]}}]`,
		kubernetesKey, state, basisFields("", window[0]), window[0], window[1], testSource)))
	if err != nil {
		t.Fatal(err)
	}
	return upgradepath.NewIndex(records).Lookup(kubernetesKey, supersedeids.Clock())
}

func TestLapsedPathPolicy(t *testing.T) {
	scanTwoLines := func(t *testing.T, status upgradepath.Status, manifest string) Result {
		t.Helper()
		knowledge := policyKnowledge{Knowledge: installRecords(t, recordSet{attestation: true, served: true}), status: status}
		_, paths := files(t, map[string]string{"applyset.yaml": manifest})
		return mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.27.4", "--to", "kubernetes=1.29.2")...)
	}
	control := scanTwoLines(t, lapsedPolicy(t, "active", currentRecordWindow), cronjobV1)
	if p := control.Report.Paths[0]; p.Policy != "sequential_minor" || len(p.Hops) != 2 {
		t.Fatalf("control path %+v gaps %v", p, gapReasons(control.Report))
	}
	for _, tc := range []struct {
		name, freshness string
		status          upgradepath.Status
	}{
		{"expired", "(stale)", lapsedPolicy(t, "active", staleRecordWindow)},
		{"withdrawn", "(withdrawn)", lapsedPolicy(t, "withdrawn", currentRecordWindow)},
	} {
		for manifestName, manifest := range map[string]string{"migrated": cronjobV1, "removed API": cronjobV1beta1} {
			t.Run(tc.name+"/"+manifestName, func(t *testing.T) {
				result := scanTwoLines(t, tc.status, manifest)
				requireLapsedUnknown(t, result)
				requireNamed(t, result, "PATH_POLICY_NOT_CURRENT", tc.freshness)
				// No direct hop stands in for the policy.
				if p := result.Report.Paths[0]; len(p.Hops) != 0 || p.Policy != "" {
					t.Fatalf("path %+v", p)
				}
			})
		}
	}
	// A removed record cannot be told from one that never existed. The pair is
	// then one unplanned hop that is never covered, and the missing policy is
	// named.
	t.Run("removed", func(t *testing.T) {
		result := scanTwoLines(t, upgradepath.Status{}, cronjobV1)
		requireLapsedUnknown(t, result)
		requireNamed(t, result, "NO_REVIEWED_PATH_POLICY", "1.27.4", "1.29.2")
		if p := result.Report.Paths[0]; p.Policy != "" {
			t.Fatalf("path %+v", p)
		}
	})
}

// servedLinesKnowledge installs a served list and a line attestation for each
// line given, with the window of that line's list.
func servedLinesKnowledge(t *testing.T, listed map[string][2]string) Knowledge {
	t.Helper()
	byScope, _, err := lineattest.RulesByScope(packRules(t))
	if err != nil {
		t.Fatal(err)
	}
	var pairs []string
	for pair := range testServed {
		pairs = append(pairs, pair)
	}
	sort.Strings(pairs)
	encodedPairs, _ := json.Marshal(pairs)
	evidence := func(window [2]string) string {
		return fmt.Sprintf(`{%s,"reviewedAt":%q,"validUntil":%q,"sources":[%s]}`, basisFields(constraintengine.BasisMechanical, window[0]), window[0], window[1], testSource)
	}
	var attestations, served []string
	for _, line := range []string{"1.28", "1.29"} {
		ids := append([]string{}, byScope[lineattest.Key{Component: kubernetesKey, Line: line, Family: lineattest.FamilyKubernetesRemovedServedGVK}]...)
		sort.Strings(ids)
		encodedIDs, _ := json.Marshal(ids)
		if len(ids) == 0 {
			encodedIDs = []byte("[]")
		}
		attestations = append(attestations, fmt.Sprintf(`{"component":%q,"line":%q,"factFamily":%q,"completeness":"COMPLETE_REVIEWED_RULES_FOR_LINE","ruleIds":%s,"evidence":%s}`,
			kubernetesKey, line, lineattest.FamilyKubernetesRemovedServedGVK, encodedIDs, evidence(currentRecordWindow)))
		if window, ok := listed[line]; ok {
			served = append(served, fmt.Sprintf(`{"component":%q,"line":%q,"completeness":%q,"apis":%s,"evidence":%s}`,
				kubernetesKey, line, servedapis.Completeness, encodedPairs, evidence(window)))
		}
	}
	records := cncfcheck.SyntheticRecords{LineAttestations: json.RawMessage("[" + strings.Join(attestations, ",") + "]")}
	if len(served) > 0 {
		records.ServedAPIs = json.RawMessage("[" + strings.Join(served, ",") + "]")
	}
	restore, err := cncfcheck.UseSyntheticRecords(nil, nil, records)
	if err != nil {
		t.Fatalf("records are not admissible: %v", err)
	}
	t.Cleanup(restore)
	embedded, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	return embedded
}

// With an explicit target, an older line's list never answers for the target
// line whose list lapsed.
func TestLapsedNewestServedListExplicitTarget(t *testing.T) {
	for _, tc := range []struct {
		name, detail string
		listed       map[string][2]string
	}{
		{"expired", "is not current (stale)", map[string][2]string{"1.28": currentRecordWindow, "1.29": staleRecordWindow}},
		{"removed", "no reviewed list of the API versions", map[string][2]string{"1.28": currentRecordWindow}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := scanHop(t, servedLinesKnowledge(t, tc.listed), cronjobV1)
			if result.Exit != scanreport.ExitUnknown || result.Report.Verdict == scanreport.VerdictPass {
				t.Fatalf("exit %d verdict %s", result.Exit, result.Report.Verdict)
			}
			requireNamed(t, result, "API_VERSION_NOT_REVIEWED", "1.29", tc.detail)
			if served := result.Report.Paths[0].ServedList; served != nil {
				t.Fatalf("served list %+v", served)
			}
		})
	}
}

// KNOWN LIMIT, pinned here so a change is noticed: plan --to C=newest-covered
// picks the newest line that still has a current list. When the newest list lapses,
// the target moves to the older line and that scan can pass; the lapsed list
// is not named. Only the reported target version shows the move.
func TestLapsedNewestServedListNewestCoveredMovesToOlderLine(t *testing.T) {
	scanNewest := func(t *testing.T, listed map[string][2]string) (Result, error) {
		t.Helper()
		_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
		knowledge := servedLinesKnowledge(t, listed)
		request, err := ParseArgs(args(paths, "--from", "kubernetes=1.27.4"))
		if err != nil {
			t.Fatal(err)
		}
		// Only the plan command sets this, after parsing the arguments.
		request.NewestCovered = []string{kubernetesSlug}
		return Run(request, Options{Knowledge: knowledge, Build: &testBuild, Clock: func() time.Time { return request.Now }})
	}
	both := map[string][2]string{"1.28": currentRecordWindow, "1.29": currentRecordWindow}
	control, err := scanNewest(t, both)
	if err != nil || control.Report.Paths[0].To != "1.29.0" {
		t.Fatalf("control: %v %+v", err, control.Report.Paths)
	}
	for name, listed := range map[string]map[string][2]string{
		"expired": {"1.28": currentRecordWindow, "1.29": staleRecordWindow},
		"removed": {"1.28": currentRecordWindow},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := scanNewest(t, listed)
			if err != nil || len(result.Report.Paths) != 1 || result.Report.Paths[0].To != "1.28.0" || result.Exit != scanreport.ExitPass {
				t.Fatalf("known limit changed: %v exit %d paths %+v gaps %v", err, result.Exit, result.Report.Paths, gapReasons(result.Report))
			}
			for _, gap := range result.Report.Gaps {
				t.Fatalf("known limit changed, a gap is now named: %+v", gap)
			}
		})
	}
	// With no current list at all the target is refused.
	for name, listed := range map[string]map[string][2]string{
		"all expired": {"1.28": staleRecordWindow, "1.29": staleRecordWindow},
		"all removed": {},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := scanNewest(t, listed); !isUsage(err) {
				t.Fatalf("not refused: %v", err)
			}
		})
	}
}

// A custom-resource line review that expired or was removed decides nothing.
func TestLapsedCustomResourceLineAttestation(t *testing.T) {
	hopArgs := []string{"--from", "strimzi=0.50.1", "--to", "strimzi=0.51.0", "--resource-scope-complete"}
	current := crdLineAttestation(constraintengine.BasisMechanical)
	control := crdScan(t, newAttestedCRD(t, &current), []string{kafkaV1Doc}, hopArgs...)
	if hop := strimziHop(t, control.Report); len(hop.Families) != 1 || hop.Families[0].Status != scanreport.FamilyPass {
		t.Fatalf("control hop %+v", hop)
	}
	expired := crdLineAttestation(constraintengine.BasisMechanical)
	expired.Evidence.ValidUntil = "2026-10-01T00:00:00Z"
	for name, att := range map[string]*lineattest.LineAttestation{"expired": &expired, "removed": nil} {
		t.Run(name, func(t *testing.T) {
			result := crdScan(t, newAttestedCRD(t, att), []string{kafkaV1Doc}, hopArgs...)
			requireNeverCovered(t, result)
			if hop := strimziHop(t, result.Report); len(hop.Families) != 0 || len(result.Report.Findings) != 0 || result.Exit != scanreport.ExitUnknown {
				t.Fatalf("exit %d hop %+v", result.Exit, hop)
			}
			if att != nil {
				requireNamed(t, result, "LINE_NOT_ATTESTED", "0.51", "is not current (stale)")
				return
			}
			// KNOWN LIMIT: a removed review is not named; the report only
			// says the component is not covered.
			for _, gap := range result.Report.Gaps {
				if strings.Contains(gap.Detail, "0.51 ") && gap.Reason == "LINE_NOT_ATTESTED" {
					t.Fatalf("known limit changed, the line is now named: %+v", gap)
				}
			}
		})
	}
}
