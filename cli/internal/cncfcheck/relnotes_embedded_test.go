// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestEmbeddedRelnotesCrossingRules holds every release-note removal rule of
// the embedded pack (a crossing-only forbid_set_member over a project's
// caller-supplied flag or config-key set) to what it may say: BLOCKED when
// the deployment sets the removed member before a hop that crosses the
// release, and never PASS otherwise (a crossing only blocks). The external
// bundle and the per-project targets leave these rules out
// (external_pack.go), which TestSplitTargetsCoverThePackExactlyAndAreDeterministic
// and TestExportEmbeddedExternalBundlePreservesCompletePack hold.
func TestEmbeddedRelnotesCrossingRules(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	count := 0
	for _, entry := range shippedPack(t).Entries {
		crossing, err := constraintengine.AnyCrossingRule([]json.RawMessage{entry.Rule})
		if err != nil || !crossing {
			continue
		}
		count++
		var rule struct {
			ID      string `json:"id"`
			Subject struct{ Component, From, To string }
			SetCondition struct {
				Side, Component, FactID string
				Members                 []string
			} `json:"setCondition"`
		}
		if err := json.Unmarshal(entry.Rule, &rule); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(rule.ID, ".relnotes.") || len(rule.SetCondition.Members) != 1 {
			t.Fatalf("crossing rule %s is not a release-note rule over one member", rule.ID)
		}
		input := func(fact string) []byte {
			return []byte(fmt.Sprintf(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":%q,"version":%q,"facts":[%s]}]},"proposed":{"components":[{"component":%q,"version":%q,"facts":[]}]}}`,
				rule.Subject.Component, rule.Subject.From, fact, rule.Subject.Component, rule.Subject.To))
		}
		declared := func(members ...string) string {
			raw, _ := json.Marshal(members)
			return `{"id":"` + rule.SetCondition.FactID + `","state":"declared","setValue":{"members":` + string(raw) + `,"complete":true}}`
		}
		for _, tc := range []struct {
			name, fact string
			blocked    bool
		}{
			{"member set", declared(rule.SetCondition.Members[0]), true},
			{"unrelated member set", declared("zz-unrelated"), false},
			{"empty set", declared(), false},
			{"fact unsupported", `{"id":"` + rule.SetCondition.FactID + `","state":"unsupported"}`, false},
		} {
			report, err := CheckRule(entry.Project, rule.ID, input(tc.fact), now)
			if err != nil || len(report.Check.Claims) != 1 {
				t.Fatalf("%s %s: report=%+v err=%v", rule.ID, tc.name, report, err)
			}
			status, exit := report.Check.Claims[0].Status, ClaimExit(report)
			if tc.blocked && (status != "BLOCKED" || exit != 10) {
				t.Fatalf("%s %s: status=%s exit=%d, want BLOCKED", rule.ID, tc.name, status, exit)
			}
			if !tc.blocked && (status == "PASS" || exit == 0) {
				t.Fatalf("%s %s: a crossing rule passed (status=%s exit=%d)", rule.ID, tc.name, status, exit)
			}
		}
	}
	if count != 9 {
		t.Fatalf("%d release-note crossing rules in the embedded pack, want 9", count)
	}
}
