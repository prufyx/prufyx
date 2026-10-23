// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const (
	factlessRuleID   = "kubernetes.synthetic-factless-skip.1-33-0-to-1-37-0"
	factlessCronFact = "component.kubernetes.cronjob_v1beta1_removed_gvk_present"
)

// factlessEntry clones the shipped CronJob rule into a rule that reads no
// fact: operator over the 1.33.0 -> 1.37.0 transition, with a range when
// ranged. It is test-only and never published.
func factlessEntry(t *testing.T, operator string, ranged bool, basis string) Entry {
	t.Helper()
	entry := ruleEntry(t, "kubernetes", cronJobRuleID)
	var rule map[string]any
	if err := json.Unmarshal(entry.Rule, &rule); err != nil {
		t.Fatal(err)
	}
	source := rule["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)["id"].(string)
	for _, key := range []string{"condition", "appliesWhen", "setCondition", "range"} {
		delete(rule, key)
	}
	rule["id"], rule["operator"] = factlessRuleID, operator
	rule["subject"] = map[string]any{"component": "pkg:github/kubernetes/kubernetes", "from": "1.33.0", "to": "1.37.0"}
	rule["intermediate"] = "1.34.0"
	rule["reasonCode"], rule["nextAction"] = "REVIEWED_SOURCE_CONSTRAINT", "synthetic test-only action"
	evidence := rule["evidence"].(map[string]any)
	for _, key := range []string{"basis", "extractor", "derivedAt"} {
		delete(evidence, key)
	}
	if basis != "" {
		evidence["basis"], evidence["derivedAt"] = basis, evidence["reviewedAt"]
	}
	if ranged {
		bounds := []any{}
		for _, name := range []string{"from.gte", "from.lt", "to.gte", "to.lt"} {
			basis := constraintengine.BasisUpgradeFromSeries
			if strings.HasPrefix(name, "to.") {
				basis = constraintengine.BasisTargetSeries
			}
			bounds = append(bounds, map[string]any{"bound": name, "basis": basis, "sourceId": source})
		}
		rule["range"] = map[string]any{"from": map[string]any{"gte": "1.33.0", "lt": "1.34.0"}, "to": map[string]any{"gte": "1.37.0", "lt": "1.38.0"}, "bounds": bounds}
	}
	raw, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	entry.RequiredFacts = []Fact{}
	entry.Rule = raw
	return entry
}

// factlessClaims selects with the real fact-family selection and evaluates.
func factlessClaims(t *testing.T, b bundle, project string, facts []string, inputRaw []byte) ([]constraintengine.Claim, selection) {
	t.Helper()
	selected, err := b.selectFamily(project, facts, inputRaw)
	if err != nil {
		t.Fatal(err)
	}
	report, err := b.reportSelection(project, "", true, mustInput(t, b, inputRaw), selected, inputRaw, rangeReviewClock)
	if err != nil {
		t.Fatal(err)
	}
	return report.Check.Claims, selected
}

func factlessClaimsFor(claims []constraintengine.Claim, id string) []constraintengine.Claim {
	var out []constraintengine.Claim
	for _, claim := range claims {
		if claim.RuleID == id {
			out = append(out, claim)
		}
	}
	return out
}

func factlessBundle(t *testing.T, entries ...Entry) bundle {
	t.Helper()
	return factlessBundleUnder(t, packSchemaRanged, entries...)
}

func factlessBundleUnder(t *testing.T, schema string, entries ...Entry) bundle {
	t.Helper()
	b, err := assembleSynthetic(withoutPublishedFactlessSkips(t, syntheticPack(t, schema, nil, entries...)), nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// withoutPublishedFactlessSkips drops the published Kubernetes rules that
// read no fact and require an intermediate version (the control-plane
// no-minor-skip rules) from a synthetic pack. The engine refuses overlapping
// rules over one pair, and the synthetic rule of these tests stands for them
// on the same pair, so the published ones would collide with it. The other
// published rules stay, and the drop is by shape, not by id, so it needs no
// update when more of them are published.
func withoutPublishedFactlessSkips(t *testing.T, raw []byte) []byte {
	t.Helper()
	var pack rulePack
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	kept := make([]Entry, 0, len(pack.Entries))
	for _, entry := range pack.Entries {
		if entry.Project == "kubernetes" && ruleID(t, entry) != factlessRuleID {
			var shape ruleShape
			if err := json.Unmarshal(entry.Rule, &shape); err != nil {
				t.Fatal(err)
			}
			if shape.Operator == "require_intermediate_version" && len(entry.RequiredFacts) == 0 {
				continue
			}
		}
		kept = append(kept, entry)
	}
	pack.Entries = kept
	out, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestFactlessIntermediateRuleSelected: a rule that reads no fact and wants
// an intermediate version is evaluated by the fact-family selection when the
// pair matches it, whatever other fact family is asked for; it BLOCKS.
func TestFactlessIntermediateRuleSelected(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		ranged   bool
		from, to string
		wantMode string
	}{
		{"exact pair", false, "1.33.0", "1.37.0", ""},
		{"range pair", true, "1.33.2", "1.37.1", "range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := factlessBundle(t, factlessEntry(t, "require_intermediate_version", tc.ranged, ""))
			claims, _ := factlessClaims(t, b, "kubernetes", []string{factlessCronFact}, kubernetesInput(t, tc.from, tc.to, true))
			got := factlessClaimsFor(claims, factlessRuleID)
			if len(got) != 1 || got[0].Status != "BLOCKED" {
				t.Fatalf("claims %+v", got)
			}
			if mode := ""; got[0].SubjectMatch != nil {
				if mode = got[0].SubjectMatch.Mode; mode != tc.wantMode {
					t.Fatalf("mode %q, want %q", mode, tc.wantMode)
				}
			} else if tc.wantMode != "" {
				t.Fatalf("no subject match, want mode %q", tc.wantMode)
			}
		})
	}
}

// TestFactlessIntermediateRuleNeverNarrows: a matching fact-less rule adds a
// claim and nothing else; the claims of the fact family are those of the same
// bundle without it, and a pair the rule does not match gets no claim at all
// from it (no BLOCKED, no UNKNOWN).
func TestFactlessIntermediateRuleNeverNarrows(t *testing.T) {
	t.Parallel()
	with := factlessBundle(t, factlessEntry(t, "require_intermediate_version", true, ""))
	without := factlessBundle(t)
	cases := []struct {
		name     string
		from, to string
		wantRule bool
	}{
		{"skip pair", "1.33.2", "1.37.1", true},
		{"one-minor hop", "1.36.0", "1.37.0", false},
		{"patch jump", "1.33.1", "1.33.9", false},
		{"outside the range", "1.31.0", "1.37.0", false},
		{"downgrade", "1.37.0", "1.33.0", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := kubernetesInput(t, tc.from, tc.to, true)
			got, _ := factlessClaims(t, with, "kubernetes", []string{factlessCronFact}, input)
			base, _ := factlessClaims(t, without, "kubernetes", []string{factlessCronFact}, input)
			own := factlessClaimsFor(got, factlessRuleID)
			if tc.wantRule != (len(own) == 1) || len(own) > 1 {
				t.Fatalf("claims of the rule: %+v", own)
			}
			if len(got)-len(own) != len(base) {
				t.Fatalf("family claims changed: %d with, %d without", len(got)-len(own), len(base))
			}
			for i, claim := range base {
				if other := got[i+indexOffset(got, factlessRuleID, i)]; other.RuleID != claim.RuleID || other.Status != claim.Status {
					t.Fatalf("claim %d: %s %s, want %s %s", i, other.RuleID, other.Status, claim.RuleID, claim.Status)
				}
			}
		})
	}
}

// indexOffset is 1 when the claim at index i of claims comes after the one of
// rule id, else 0, so the other claims can be compared in order.
func indexOffset(claims []constraintengine.Claim, id string, i int) int {
	for j := 0; j <= i && j < len(claims); j++ {
		if claims[j].RuleID == id {
			return 1
		}
	}
	return 0
}

// TestFactlessOtherOperatorsStayOut: fact-less forbid_target_version and
// require_component_version rules are not selected for a matching pair, so
// the family report is the one without them.
func TestFactlessOtherOperatorsStayOut(t *testing.T) {
	t.Parallel()
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, project, ruleID string
		input                 string
	}{
		{"forbid_target_version", "etcd", "etcd.direct-minor-skip.3-2-32-to-3-7-1", `{"schema":"` + constraintengine.InputSchema + `","authority":"` + constraintengine.InputAuthority + `","current":{"components":[{"component":"pkg:github/etcd-io/etcd","version":"3.2.32","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/etcd-io/etcd","version":"3.7.1","facts":[]}]}}`},
		{"require_component_version", "rook", "rook.minimum-kubernetes.1-20", `{"schema":"` + constraintengine.InputSchema + `","authority":"` + constraintengine.InputAuthority + `","current":{"components":[{"component":"pkg:github/rook/rook","version":"1.19.5","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"1.31.0","facts":[]},{"component":"pkg:github/rook/rook","version":"1.20.0","facts":[]}]}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			entry := ruleEntry(t, tc.project, tc.ruleID)
			if ids, err := ruleFactIDs(entry.Rule); err != nil || len(ids) != 0 {
				t.Fatalf("%s reads facts %v (%v): the test needs a fact-less rule", tc.ruleID, ids, err)
			}
			claims, selected := factlessClaims(t, b, tc.project, []string{factlessCronFact}, []byte(tc.input))
			if got := factlessClaimsFor(claims, tc.ruleID); len(got) != 0 {
				t.Fatalf("selected: %+v", got)
			}
			if selected.excluded != 0 || selected.excludedLeads != 0 {
				t.Fatalf("selection %+v", selected)
			}
		})
	}
}

// TestFactlessIntermediateRuleUnderTrustPolicy: a policy that leaves out the
// rule's basis counts it as excluded and gives no claim.
func TestFactlessIntermediateRuleUnderTrustPolicy(t *testing.T) {
	t.Parallel()
	b := factlessBundleUnder(t, packSchemaBasis, factlessEntry(t, "require_intermediate_version", false, constraintengine.BasisConsensus))
	input := kubernetesInput(t, "1.33.0", "1.37.0", true)
	claims, _ := factlessClaims(t, b, "kubernetes", []string{factlessCronFact}, input)
	if got := factlessClaimsFor(claims, factlessRuleID); len(got) != 1 {
		t.Fatalf("default policy: claims %+v", got)
	}
	// The published family rules may be left out by the policy too: the rule
	// adds exactly one to the count.
	baseline := factlessBundle(t)
	baseline.policy = mustPolicy(t, "reviewed")
	_, base := factlessClaims(t, baseline, "kubernetes", []string{factlessCronFact}, input)
	b.policy = mustPolicy(t, "reviewed")
	claims, selected := factlessClaims(t, b, "kubernetes", []string{factlessCronFact}, input)
	if got := factlessClaimsFor(claims, factlessRuleID); len(got) != 0 || selected.excluded != base.excluded+1 {
		t.Fatalf("reviewed-only policy: claims %+v excluded %d, want %d", got, selected.excluded, base.excluded+1)
	}
}

// TestFactlessIntermediateRuleNotForChartHop: a rule about a chart is never
// selected for an application hop, whatever its numbers.
func TestFactlessIntermediateRuleNotForChartHop(t *testing.T) {
	t.Parallel()
	entry := factlessEntry(t, "require_intermediate_version", false, "")
	var rule map[string]any
	if err := json.Unmarshal(entry.Rule, &rule); err != nil {
		t.Fatal(err)
	}
	rule["subject"].(map[string]any)["chart"] = map[string]any{"source": "https://charts.example.io", "name": "kubernetes"}
	raw, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	entry.Rule = raw
	b, err := assembleSynthetic(syntheticPack(t, packSchemaChart, nil, entry), nil)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := factlessClaims(t, b, "kubernetes", []string{factlessCronFact}, kubernetesInput(t, "1.33.0", "1.37.0", true))
	if got := factlessClaimsFor(claims, factlessRuleID); len(got) != 0 {
		t.Fatalf("chart rule selected for an application hop: %+v", got)
	}
}

func TestTransitionOnlyBlocker(t *testing.T) {
	t.Parallel()
	cases := []struct {
		operator string
		want     bool
	}{
		{"require_intermediate_version", true},
		{"forbid_target_version", false},
		{"require_component_version", false},
		{"forbid_predicate_value", false},
		{"forbid_set_member", false},
		{"", false},
	}
	for _, tc := range cases {
		got, err := transitionOnlyBlocker(json.RawMessage(`{"operator":"` + tc.operator + `"}`))
		if err != nil || got != tc.want {
			t.Fatalf("%q: %v %v, want %v", tc.operator, got, err, tc.want)
		}
	}
	if _, err := transitionOnlyBlocker(json.RawMessage(`[`)); err == nil {
		t.Fatal("malformed rule accepted")
	}
}
