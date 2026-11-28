// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/projectprepare"
)

// The upstream operator upgrade guides say not to skip intermediate version
// upgrades. 0.38.1 to 25.0.0 passes 25.08.0, and 25.8.4 to 25.10.4 passes the
// 25.10.0 migration steps. Neither pair, nor a pair around them, may be
// decided, whatever the input declares.
func TestMariaDBOperatorRulesDecideNothingAcrossSkippedReleases(t *testing.T) {
	t.Parallel()
	for _, pair := range []struct{ from, to string }{
		{"0.38.1", "25.0.0"}, {"25.8.4", "25.10.4"}, {"0.38.1", "25.10.4"}, {"25.8.4", "25.10.0"}, {"25.8.4", "25.10.3"}, {"25.8.3", "25.10.4"},
	} {
		// The clean resource first, then one that sets each ruled field.
		specs := []struct{ pair, ruleID, spec string }{{spec: `{}`}}
		specs = append(specs, mariaDBCRDRules...)
		for _, tc := range specs {
			t.Run(fmt.Sprintf("%s/%s/%s", pair.from, pair.to, tc.spec), func(t *testing.T) {
				prepared, err := projectprepare.PrepareMariaDBOperatorResource([]byte(fmt.Sprintf(mdbCRDPairResource, tc.spec)), pair.from, pair.to, true, false)
				if err != nil {
					t.Fatal(err)
				}
				ruleID := ""
				if tc.pair == pair.from+"->"+pair.to {
					ruleID = tc.ruleID
				}
				assertWithdrawnOrUndecided(t, projectprepare.MariaDBOperatorProject, prepared.CanonicalInputJSON, scopedMariaDBOperatorInput(t, prepared.CanonicalInputJSON), ruleID)
			})
		}
	}
}

// Only the 26.3.0 to 26.6.0 prerequisite rule stays active.
func TestMariaDBOperatorOnlyActiveRule(t *testing.T) {
	t.Parallel()
	states := projectRuleStates(t, "mariadb-operator.")
	if len(states) != len(mariaDBCRDRules)+1 {
		t.Fatalf("rules=%v", states)
	}
	for _, tc := range mariaDBCRDRules {
		if states[tc.ruleID] != "withdrawn" {
			t.Fatalf("%s state %q", tc.ruleID, states[tc.ruleID])
		}
	}
	if id := "mariadb-operator.upgrade-26-6.requires-dataplane-prerequisite"; states[id] != "active" {
		t.Fatalf("%s state %q", id, states[id])
	}
}

func scopedMariaDBOperatorInput(t *testing.T, canonical []byte) []byte {
	t.Helper()
	var input map[string]any
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	if err := decoder.Decode(&input); err != nil {
		t.Fatal(err)
	}
	input["scope"] = map[string]any{"declaration": constraintengine.ScopeDeclaration, "components": []string{"pkg:github/mariadb-operator/mariadb-operator"}}
	out, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
