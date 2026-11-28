// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"fmt"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const cephComponent = "pkg:github/ceph/ceph"

// The upstream Tentacle upgrade notes require a cluster older than Reef to be
// upgraded to Reef or Squid first. No transition from Octopus, Pacific or Quincy
// into 20.2 may therefore be decided, whatever the input declares.
func TestCephRulesDecideNothingBelowTentacleSourceFloor(t *testing.T) {
	t.Parallel()
	withdrawn := map[string]string{
		"15.2.17": "ceph.selected-osd-filestore.15-2-17-to-20-2-4",
		"16.2.15": "ceph.selected-osd-filestore.16-2-15-to-20-2-4",
		"17.2.9":  "ceph.selected-osd-filestore.17-2-9-to-20-2-4",
	}
	for _, from := range []string{"15.2.0", "15.2.17", "16.2.0", "16.2.15", "17.2.0", "17.2.7", "17.2.9"} {
		for _, to := range []string{"20.2.0", "20.2.4"} {
			for _, filestore := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/%t", from, to, filestore), func(t *testing.T) {
					ruleID := ""
					if to == "20.2.4" {
						ruleID = withdrawn[from]
					}
					input := cephInput(from, to, filestore, false)
					for name, check := range map[string]func(string, []byte) (Report, error){
						"check": func(project string, raw []byte) (Report, error) {
							return Check(project, raw, mustTime(t, "2026-11-28T00:00:00Z"))
						},
						"native": func(project string, raw []byte) (Report, error) {
							return CheckNative(project, raw, mustTime(t, "2026-11-28T00:00:00Z"))
						},
					} {
						report, err := check("ceph", input)
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
					scope, err := AssessScope(cephInput(from, to, filestore, true), mustTime(t, "2026-11-28T00:00:00Z"))
					if err != nil {
						t.Fatal(err)
					}
					if scope.Assessment != constraintengine.AssessmentUnknown {
						t.Fatalf("scope assessment %q, want UNKNOWN", scope.Assessment)
					}
				})
			}
		}
	}
}

// The origins the Tentacle notes do cover keep their rules.
func TestCephRulesAtOrAboveTentacleSourceFloorStillDecide(t *testing.T) {
	t.Parallel()
	for _, from := range []string{"18.2.8", "19.2.6"} {
		for filestore, want := range map[bool]int{false: 0, true: 10} {
			t.Run(fmt.Sprintf("%s/%t", from, filestore), func(t *testing.T) {
				report, err := Check("ceph", cephInput(from, "20.2.4", filestore, false), mustTime(t, "2026-11-28T00:00:00Z"))
				if err != nil {
					t.Fatal(err)
				}
				if got := ClaimExit(report); got != want {
					t.Fatalf("exit %d, want %d", got, want)
				}
			})
		}
	}
}

func cephInput(from, to string, filestore, scoped bool) []byte {
	scope := ""
	if scoped {
		scope = fmt.Sprintf(`"scope":{"declaration":%q,"components":[%q]},`, constraintengine.ScopeDeclaration, cephComponent)
	}
	return []byte(fmt.Sprintf(`{"schema":%q,"authority":%q,%s"current":{"components":[{"component":%q,"version":%q,"facts":[{"id":"component.ceph.selected_current_osd_filestore","state":"declared","boolValue":%t}]}]},"proposed":{"components":[{"component":%q,"version":%q,"facts":[]}]}}`,
		constraintengine.InputSchema, constraintengine.InputAuthority, scope, cephComponent, from, filestore, cephComponent, to))
}
