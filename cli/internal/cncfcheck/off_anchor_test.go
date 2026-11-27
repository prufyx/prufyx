// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const (
	offAnchorRangedID  = "kubernetes.synthetic-off-anchor-ranged.1-40-0-to-1-41-0"
	offAnchorSiblingID = "kubernetes.synthetic-off-anchor-sibling.1-40-0-to-1-41-0"
	offAnchorCronFact  = "component.kubernetes.cronjob_v1beta1_removed_gvk_present"
	offAnchorFlowFact  = "component.kubernetes.flowcontrol_v1beta3_removed_gvk_present"
)

// offAnchorEntry clones the shipped CronJob rule into a test-only reviewed
// predicate rule over fact with the anchor from -> to. With ranged it covers
// every release of the two anchor lines 1.40 and 1.41.
func offAnchorEntry(t *testing.T, id, fact, from, to string, ranged bool, basis string) Entry {
	t.Helper()
	entry := ruleEntry(t, "kubernetes", cronJobRuleID)
	var rule map[string]any
	if err := json.Unmarshal(entry.Rule, &rule); err != nil {
		t.Fatal(err)
	}
	evidence := rule["evidence"].(map[string]any)
	source := evidence["sources"].([]any)[0].(map[string]any)["id"].(string)
	for _, key := range []string{"range", "appliesWhen", "setCondition", "crossing", "severity"} {
		delete(rule, key)
	}
	for _, key := range []string{"basis", "extractor", "derivedAt", "lease"} {
		delete(evidence, key)
	}
	evidence["reviewedAt"], evidence["validUntil"] = "2026-09-20T00:00:00Z", "2026-12-19T00:00:00Z"
	if basis != "" {
		evidence["basis"], evidence["derivedAt"] = basis, evidence["reviewedAt"]
	}
	rule["id"], rule["operator"] = id, "forbid_predicate_value"
	rule["subject"] = map[string]any{"component": "pkg:github/kubernetes/kubernetes", "from": from, "to": to}
	rule["condition"] = map[string]any{"side": "proposed", "component": "pkg:github/kubernetes/kubernetes", "factId": fact, "boolValue": true}
	rule["reasonCode"], rule["nextAction"] = "REVIEWED_SOURCE_CONSTRAINT", "synthetic test-only action"
	if ranged {
		bounds := []any{}
		for _, name := range []string{"from.gte", "from.lt", "to.gte", "to.lt"} {
			series := constraintengine.BasisUpgradeFromSeries
			if strings.HasPrefix(name, "to.") {
				series = constraintengine.BasisTargetSeries
			}
			bounds = append(bounds, map[string]any{"bound": name, "basis": series, "sourceId": source})
		}
		rule["range"] = map[string]any{"from": map[string]any{"gte": "1.40.0", "lt": "1.41.0"}, "to": map[string]any{"gte": "1.41.0", "lt": "1.42.0"}, "bounds": bounds}
	}
	raw, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	entry.Rule = raw
	entry.RequiredFacts = []Fact{entry.RequiredFacts[0]}
	entry.RequiredFacts[0].ID = fact
	return entry
}

func offAnchorBundle(t *testing.T, entries ...Entry) bundle {
	t.Helper()
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	b.pack.Entries = entries
	b.pack.Schema = packSchemaRanged
	return b
}

func claimByID(report Report, id string) (constraintengine.Claim, bool) {
	for _, claim := range report.Check.Claims {
		if claim.RuleID == id {
			return claim, true
		}
	}
	return constraintengine.Claim{}, false
}

func assertOffAnchorClaim(t *testing.T, report Report, id string) {
	t.Helper()
	claim, found := claimByID(report, id)
	if !found || claim.Status != "UNKNOWN" || claim.ReasonCode != "RULE_TRANSITION_NOT_REVIEWED" || !claim.IsOffAnchorSibling() || !strings.Contains(claim.NextAction, id) || claim.SubjectMatch != nil {
		t.Fatalf("%s: found=%v claim=%+v", id, found, claim)
	}
}

// TestOffAnchorSiblingNamed: a pair decided by a ranged rule keeps every exact
// verdict rule anchored inside that range, UNKNOWN and named, so a pass of the
// ranged rule alone no longer exits 0.
func TestOffAnchorSiblingNamed(t *testing.T) {
	t.Parallel()
	ranged := offAnchorEntry(t, offAnchorRangedID, offAnchorCronFact, "1.40.0", "1.41.0", true, "")
	sibling := offAnchorEntry(t, offAnchorSiblingID, offAnchorFlowFact, "1.40.0", "1.41.0", false, "")
	outside := offAnchorEntry(t, offAnchorSiblingID, offAnchorFlowFact, "1.38.0", "1.39.0", false, "")
	cases := []struct {
		name        string
		entries     []Entry
		from, to    string
		present     bool
		exit, count int
		named       bool
	}{
		{"off anchor pass is unknown", []Entry{ranged, sibling}, "1.40.1", "1.41.2", false, 11, 2, true},
		{"off anchor to side only", []Entry{ranged, sibling}, "1.40.0", "1.41.1", false, 11, 2, true},
		{"off anchor from side only", []Entry{ranged, sibling}, "1.40.1", "1.41.0", false, 11, 2, true},
		{"a blocker still blocks", []Entry{ranged, sibling}, "1.40.1", "1.41.2", true, 10, 2, true},
		{"anchor pair is unchanged", []Entry{ranged, sibling}, "1.40.0", "1.41.0", false, 11, 2, false},
		{"anchor outside the range stays out", []Entry{ranged, outside}, "1.40.1", "1.41.2", false, 0, 1, false},
		{"no ranged rule, no sibling", []Entry{ranged}, "1.40.1", "1.41.2", false, 0, 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := offAnchorBundle(t, tc.entries...)
			report, err := b.check("kubernetes", "", kubernetesInput(t, tc.from, tc.to, tc.present), rangeReviewClock)
			if err != nil {
				t.Fatal(err)
			}
			if got := ClaimExit(report); got != tc.exit || len(report.Check.Claims) != tc.count {
				t.Fatalf("exit=%d claims=%+v", got, report.Check.Claims)
			}
			if tc.named {
				assertOffAnchorClaim(t, report, offAnchorSiblingID)
			} else if claim, found := claimByID(report, offAnchorSiblingID); found && claim.IsOffAnchorSibling() {
				t.Fatalf("marked: %+v", claim)
			}
		})
	}
}

// TestOffAnchorSiblingFamilySelection: the fact-family selection keeps the
// sibling when its fact is in the family and never reaches outside the family.
func TestOffAnchorSiblingFamilySelection(t *testing.T) {
	t.Parallel()
	b := offAnchorBundle(t,
		offAnchorEntry(t, offAnchorRangedID, offAnchorCronFact, "1.40.0", "1.41.0", true, ""),
		offAnchorEntry(t, offAnchorSiblingID, offAnchorFlowFact, "1.40.0", "1.41.0", false, ""))
	input := kubernetesInput(t, "1.40.1", "1.41.2", false)
	report, err := b.checkFacts("kubernetes", []string{offAnchorCronFact, offAnchorFlowFact}, input, rangeReviewClock)
	if err != nil || ClaimExit(report) != 11 {
		t.Fatalf("exit=%d err=%v", ClaimExit(report), err)
	}
	assertOffAnchorClaim(t, report, offAnchorSiblingID)
	report, err = b.checkFacts("kubernetes", []string{offAnchorCronFact}, input, rangeReviewClock)
	if err != nil || len(report.Check.Claims) != 1 || ClaimExit(report) != 0 {
		t.Fatalf("a rule outside the family was selected: %+v %v", report.Check.Claims, err)
	}
}

// TestOffAnchorFactlessSibling: a mandatory-intermediate rule that reads no
// fact and is anchored inside a matched family range is kept too.
func TestOffAnchorFactlessSibling(t *testing.T) {
	t.Parallel()
	factless := factlessEntry(t, "require_intermediate_version", false, "")
	var rule map[string]any
	if err := json.Unmarshal(factless.Rule, &rule); err != nil {
		t.Fatal(err)
	}
	rule["subject"] = map[string]any{"component": "pkg:github/kubernetes/kubernetes", "from": "1.40.0", "to": "1.41.0"}
	rule["intermediate"] = "1.40.5"
	evidence := rule["evidence"].(map[string]any)
	delete(evidence, "lease")
	evidence["reviewedAt"], evidence["validUntil"] = "2026-09-20T00:00:00Z", "2026-12-19T00:00:00Z"
	raw, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	factless.Rule = raw
	b := offAnchorBundle(t, factless, offAnchorEntry(t, offAnchorRangedID, offAnchorCronFact, "1.40.0", "1.41.0", true, ""))
	report, err := b.checkFacts("kubernetes", []string{offAnchorCronFact}, kubernetesInput(t, "1.40.1", "1.41.2", false), rangeReviewClock)
	if err != nil || ClaimExit(report) != 11 {
		t.Fatalf("exit=%d err=%v claims=%+v", ClaimExit(report), err, report.Check.Claims)
	}
	assertOffAnchorClaim(t, report, factlessRuleID)
}

// TestOffAnchorSiblingTrustPolicy: a lead is no verdict rule and is not
// brought in; a consensus sibling the policy leaves out is counted as left out,
// so the check cannot pass.
func TestOffAnchorSiblingTrustPolicy(t *testing.T) {
	t.Parallel()
	ranged := offAnchorEntry(t, offAnchorRangedID, offAnchorCronFact, "1.40.0", "1.41.0", true, "")
	input := kubernetesInput(t, "1.40.1", "1.41.2", false)

	lead := offAnchorBundle(t, ranged, offAnchorEntry(t, offAnchorSiblingID, offAnchorFlowFact, "1.40.0", "1.41.0", false, constraintengine.BasisLead))
	report, err := lead.check("kubernetes", "", input, rangeReviewClock)
	if err != nil || len(report.Check.Claims) != 1 || ClaimExit(report) != 0 {
		t.Fatalf("lead: %+v %v", report.Check.Claims, err)
	}

	consensus := offAnchorBundle(t, ranged, offAnchorEntry(t, offAnchorSiblingID, offAnchorFlowFact, "1.40.0", "1.41.0", false, constraintengine.BasisConsensus))
	consensus.policy = mustPolicy(t, "reviewed")
	report, err = consensus.check("kubernetes", "", input, rangeReviewClock)
	if err != nil || ClaimExit(report) != 11 || report.TrustPolicy == nil || report.TrustPolicy.ExcludedRules != 1 {
		t.Fatalf("consensus left out: %+v %+v %v", report.Check.Claims, report.TrustPolicy, err)
	}
}

// TestOffAnchorSiblingExternalBundle: an external bundle is selected by the
// same function.
func TestOffAnchorSiblingExternalBundle(t *testing.T) {
	t.Parallel()
	parsed, err := ParseExternalBundle(externalFixture(t, []Entry{
		offAnchorEntry(t, offAnchorRangedID, offAnchorCronFact, "1.40.0", "1.41.0", true, ""),
		offAnchorEntry(t, offAnchorSiblingID, offAnchorFlowFact, "1.40.0", "1.41.0", false, ""),
	}))
	if err != nil {
		t.Fatal(err)
	}
	report, err := parsed.Evaluate("kubernetes", kubernetesInput(t, "1.40.1", "1.41.2", false), rangeReviewClock)
	if err != nil || ClaimExit(report) != 11 {
		t.Fatalf("exit=%d err=%v claims=%+v", ClaimExit(report), err, report.Check.Claims)
	}
	assertOffAnchorClaim(t, report, offAnchorSiblingID)
}

// TestOffAnchorChartSibling: the chart selection keeps an exact chart rule
// anchored inside a matched chart range.
func TestOffAnchorChartSibling(t *testing.T) {
	t.Parallel()
	exact := syntheticChartEntry(t)
	exact.Rule = json.RawMessage(strings.Replace(string(exact.Rule), `"from":"1.21.0","to":"1.25.0"`, `"from":"1.38.0","to":"1.39.0"`, 1))
	b := offAnchorBundle(t, exact, syntheticRangedChartEntry(t))
	side := func(version string) string {
		return `{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"` + version + `","chart":{"source":"https://charts.example.io","name":"kubernetes"},"facts":[]}]}`
	}
	input := []byte(`{"schema":"` + constraintengine.InputSchema + `","authority":"` + constraintengine.InputAuthority + `","current":` + side("1.38.1") + `,"proposed":` + side("1.39.2") + `}`)
	report, err := b.checkFacts("kubernetes", []string{syntheticSetFact}, input, rangeReviewClock)
	if err != nil || ClaimExit(report) != 11 || len(report.Check.Claims) != 2 {
		t.Fatalf("exit=%d err=%v claims=%+v", ClaimExit(report), err, report.Check.Claims)
	}
	assertOffAnchorClaim(t, report, syntheticChartRuleID)
}

// TestOffAnchorPublishedRules: the two published cases. Before the selection
// kept them, no claim named the exact rule at these pairs.
func TestOffAnchorPublishedRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		project, component, ruleID, fact, anchorFrom, anchorTo, from, to string
	}{
		{"crossplane", "pkg:github/crossplane/crossplane", "crossplane.composition-resources-mode-removed.1-20-2-0", `"id":"component.crossplane.composition_mode","state":"declared","enumValue":"resources"`, "1.20.0", "2.0.0", "1.20.1", "2.0.1"},
		{"strimzi", "pkg:github/strimzi/strimzi-kafka-operator", "strimzi.kafka-v1beta2-api-removed.1-0", `"id":"component.strimzi.kafka_v1beta2_api_present","state":"declared","boolValue":true`, "0.51.0", "1.0.0", "0.51.0", "1.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.project, func(t *testing.T) {
			t.Parallel()
			reviewed, _ := ruleEvidenceBounds(t, tc.ruleID)
			now := reviewed.Add(time.Hour)
			input := func(from, to string) []byte {
				return []byte(`{"schema":"` + constraintengine.InputSchema + `","authority":"` + constraintengine.InputAuthority + `","current":{"components":[{"component":"` + tc.component + `","version":"` + from + `","facts":[]}]},"proposed":{"components":[{"component":"` + tc.component + `","version":"` + to + `","facts":[{` + tc.fact + `}]}]}}`)
			}
			report, err := Check(tc.project, input(tc.from, tc.to), now)
			if err != nil || ClaimExit(report) != 11 {
				t.Fatalf("exit=%d err=%v", ClaimExit(report), err)
			}
			assertOffAnchorClaim(t, report, tc.ruleID)
			anchor, err := Check(tc.project, input(tc.anchorFrom, tc.anchorTo), now)
			if err != nil || ClaimExit(anchor) != 10 {
				t.Fatalf("anchor exit=%d err=%v", ClaimExit(anchor), err)
			}
			chain, err := Checker{}.CheckChain(tc.project, input(tc.anchorFrom, "2.1.0"), []string{tc.to}, now)
			if tc.project == "crossplane" && (err != nil || ChainExit(chain) == 0) {
				t.Fatalf("chain exit=%d err=%v", ChainExit(chain), err)
			}
		})
	}
}
