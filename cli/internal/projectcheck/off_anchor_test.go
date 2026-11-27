// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestOffAnchorSiblingNamed: the community project selection keeps an exact
// rule anchored inside the range of a matched ranged rule, UNKNOWN and named,
// and a rule selected by a native route is still the only one.
func TestOffAnchorSiblingNamed(t *testing.T) {
	t.Parallel()
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	var exact entry
	for _, candidate := range b.pack.Entries {
		if strings.Contains(string(candidate.Rule), `"`+lokiCompactorRuleID+`"`) {
			exact = candidate
		}
	}
	var rule map[string]any
	if err := json.Unmarshal(exact.Rule, &rule); err != nil {
		t.Fatal(err)
	}
	source := rule["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)["id"].(string)
	const rangedID = "loki.a-synthetic-ranged.2-9-to-3-0"
	const otherFact = "component.loki.structured_metadata_requires_tsdb_v13"
	rule["id"] = rangedID
	rule["condition"].(map[string]any)["factId"] = otherFact
	bounds := []any{}
	for _, name := range []string{"from.gte", "from.lt", "to.gte", "to.lt"} {
		basis := constraintengine.BasisUpgradeFromSeries
		if strings.HasPrefix(name, "to.") {
			basis = constraintengine.BasisTargetSeries
		}
		bounds = append(bounds, map[string]any{"bound": name, "basis": basis, "sourceId": source})
	}
	rule["range"] = map[string]any{"from": map[string]any{"gte": "2.9.0", "lt": "2.10.0"}, "to": map[string]any{"gte": "3.0.0", "lt": "3.1.0"}, "bounds": bounds}
	ranged := exact
	if ranged.Rule, err = json.Marshal(rule); err != nil {
		t.Fatal(err)
	}
	b.pack.Entries = []entry{ranged, exact}
	reviewed, err := time.Parse(time.RFC3339, rule["evidence"].(map[string]any)["reviewedAt"].(string))
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(`{"schema":"` + constraintengine.InputSchema + `","authority":"` + constraintengine.InputAuthority + `","current":{"components":[{"component":"pkg:github/grafana/loki","version":"2.9.9","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/grafana/loki","version":"3.0.1","facts":[{"id":"` + otherFact + `","state":"declared","boolValue":false}]}]}}`)
	report, err := checkWithBundle(b, "loki", input, reviewed.Add(time.Hour))
	if err != nil || ClaimExit(report) != 11 || len(report.Check.Claims) != 2 {
		t.Fatalf("exit=%d err=%v claims=%+v", ClaimExit(report), err, report.Check.Claims)
	}
	claim := report.Check.Claims[1]
	if claim.RuleID != lokiCompactorRuleID || claim.Status != "UNKNOWN" || claim.ReasonCode != "RULE_TRANSITION_NOT_REVIEWED" ||!strings.Contains(claim.NextAction, lokiCompactorRuleID) {
		t.Fatalf("claim=%+v", claim)
	}
	selected, err := checkWithBundleRule(b, "loki", input, reviewed.Add(time.Hour), rangedID)
	if err != nil || len(selected.Check.Claims) != 1 {
		t.Fatalf("a selected rule brought another in: %+v %v", selected.Check.Claims, err)
	}
}
