// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"fmt"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

const argoExclusionsRule = "argo-cd.resource-exclusions-v2-visibility-preservation.3-0"

func TestArgoCDResourceExclusionsSelectedRuleLeavesRBACGeneric(t *testing.T) {
	yes := true
	raw := []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: argocd-cm\ndata:\n  resource.exclusions: '[]'\n")
	p, err := cncfprepare.PrepareArgoCDResourceExclusions(raw, cncfprepare.ArgoCDFrom, cncfprepare.ArgoCDTo, true, true, &yes)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 12, 1, 23, 59, 0, time.UTC)
	selected, err := CheckRule("argo-cd", argoExclusionsRule, p.CanonicalInputJSON, now)
	if err != nil || len(selected.Check.Claims) != 1 || selected.Check.Claims[0].Status != "PASS" || ClaimExit(selected) != 0 {
		t.Fatalf("selected=%+v err=%v", selected, err)
	}
	generic, err := Check("argo-cd", p.CanonicalInputJSON, now)
	if err != nil || len(generic.Check.Claims) != 2 || ClaimExit(generic) != 11 {
		t.Fatalf("generic=%+v err=%v", generic, err)
	}
}

func TestArgoCDResourceExclusionsIntentGuardsDefault(t *testing.T) {
	now := time.Date(2026, 9, 12, 1, 23, 59, 0, time.UTC)
	for _, tc := range []struct{ name, state, value, status string }{{"missing", "unsupported", "", "UNKNOWN"}, {"true", "declared", "true", "BLOCKED"}, {"false", "declared", "false", "UNKNOWN"}} {
		t.Run(tc.name, func(t *testing.T) {
			report, err := CheckRule("argo-cd", argoExclusionsRule, argoDefaultInput(tc.state, tc.value), now)
			if err != nil || len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != tc.status {
				t.Fatalf("report=%+v err=%v", report, err)
			}
		})
	}
}

func argoDefaultInput(intentState, intentValue string) []byte {
	intent := fmt.Sprintf(`{"id":"component.argo_cd.requires_v2_visibility_of_v3_default_excluded_resources","state":"%s"`, intentState)
	if intentValue != "" {
		intent += `,"boolValue":` + intentValue
	}
	intent += "}"
	return []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/argoproj/argo-cd","version":"2.14.0","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/argoproj/argo-cd","version":"3.0.0","facts":[` + intent + `,{"id":"component.argo_cd.resource_exclusions_source_default_selected","state":"declared","boolValue":true}]}]}}`)
}
