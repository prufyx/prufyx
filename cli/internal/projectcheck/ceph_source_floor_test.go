// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const cephComponent = "pkg:github/ceph/ceph"

// cephWithdrawnPairs maps each transition that has a Ceph rule to that rule.
var cephWithdrawnPairs = map[string]string{
	"15.2.17->20.2.4": "ceph.selected-osd-filestore.15-2-17-to-20-2-4",
	"16.2.15->20.2.4": "ceph.selected-osd-filestore.16-2-15-to-20-2-4",
	"17.2.9->20.2.4":  "ceph.selected-osd-filestore.17-2-9-to-20-2-4",
	"17.2.7->18.2.0":  "ceph.selected-osd-filestore.17-2-to-18-2",
	"18.2.8->20.2.4":  "ceph.selected-osd-filestore.18-2-8-to-20-2-4",
	"19.2.6->20.2.4":  "ceph.selected-osd-filestore.19-2-6-to-20-2-4",
}

// Upstream requires a cluster older than Reef to be upgraded to Reef or Squid
// before Tentacle, and supports and tests only the latest minor release of the
// target series as a destination. No Ceph transition below may be decided,
// whatever the input declares.
func TestCephRulesDecideNothingAgainstUpstreamSourceRules(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, from := range []string{"15.2.0", "15.2.17", "16.2.0", "16.2.15", "17.2.0", "17.2.7", "17.2.9", "18.2.0", "18.2.8", "19.2.6"} {
		for _, to := range []string{"18.2.0", "20.2.0", "20.2.4"} {
			if from == to {
				continue
			}
			for _, filestore := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/%t", from, to, filestore), func(t *testing.T) {
					assertWithdrawnOrUndecided(t, "ceph", cephInput(from, to, filestore, false), cephInput(from, to, filestore, true), cephWithdrawnPairs[from+"->"+to])
				})
			}
			seen[from+"->"+to] = true
		}
	}
	for pair := range cephWithdrawnPairs {
		if !seen[pair] {
			t.Fatalf("pair %s not exercised", pair)
		}
	}
}

// Ceph is left with no active rule. A new one needs its own review, which
// must change this test.
func TestCephHasNoActiveRule(t *testing.T) {
	t.Parallel()
	states := projectRuleStates(t, "ceph.")
	if len(states) != len(cephWithdrawnPairs) {
		t.Fatalf("rules=%v", states)
	}
	for _, id := range cephWithdrawnPairs {
		if states[id] != "withdrawn" {
			t.Fatalf("%s state %q", id, states[id])
		}
	}
}

// assertWithdrawnOrUndecided runs every verdict route of the package. Each
// claim must be UNKNOWN, and ruleID, when set, must be reported as withdrawn.
func assertWithdrawnOrUndecided(t *testing.T, project string, input, scopedInput []byte, ruleID string) {
	t.Helper()
	now := mustTime(t, "2026-11-28T00:00:00Z")
	for name, check := range map[string]func(string, []byte) (Report, error){
		"check": func(project string, raw []byte) (Report, error) {
			return Check(project, raw, now)
		},
		"native": func(project string, raw []byte) (Report, error) {
			return CheckNative(project, raw, now)
		},
	} {
		report, err := check(project, input)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := ClaimExit(report); got != 11 {
			t.Fatalf("%s: exit %d, want 11", name, got)
		}
		found := false
		for _, claim := range report.Check.Claims {
			if claim.Status != "UNKNOWN" {
				t.Fatalf("%s: claim %s is %s", name, claim.RuleID, claim.Status)
			}
			if ruleID != "" && claim.RuleID == ruleID {
				found = true
				if claim.ReasonCode != "RULE_EVIDENCE_WITHDRAWN" {
					t.Fatalf("%s: reason %s", name, claim.ReasonCode)
				}
			}
		}
		if ruleID != "" && !found {
			t.Fatalf("%s: withdrawn rule omitted from its own pair", name)
		}
	}
	scope, err := AssessScope(scopedInput, now)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	if scope.Assessment != constraintengine.AssessmentUnknown {
		t.Fatalf("scope assessment %q, want UNKNOWN", scope.Assessment)
	}
}

// projectRuleStates returns the evidence state of each rule with the prefix.
func projectRuleStates(t *testing.T, prefix string) map[string]string {
	t.Helper()
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, entry := range b.pack.Entries {
		var rule struct {
			ID       string `json:"id"`
			Evidence struct {
				State string `json:"state"`
			} `json:"evidence"`
		}
		if err := json.Unmarshal(entry.Rule, &rule); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(rule.ID, prefix) {
			out[rule.ID] = rule.Evidence.State
		}
	}
	return out
}

func cephInput(from, to string, filestore, scoped bool) []byte {
	scope := ""
	if scoped {
		scope = fmt.Sprintf(`"scope":{"declaration":%q,"components":[%q]},`, constraintengine.ScopeDeclaration, cephComponent)
	}
	return []byte(fmt.Sprintf(`{"schema":%q,"authority":%q,%s"current":{"components":[{"component":%q,"version":%q,"facts":[{"id":"component.ceph.selected_current_osd_filestore","state":"declared","boolValue":%t}]}]},"proposed":{"components":[{"component":%q,"version":%q,"facts":[]}]}}`,
		constraintengine.InputSchema, constraintengine.InputAuthority, scope, cephComponent, from, filestore, cephComponent, to))
}
