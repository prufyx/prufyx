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
// the deployment sets the removed member, nothing else blocks, and an
// incomplete or missing set never passes. The external
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
			ID           string `json:"id"`
			Subject      struct{ Component, From, To string }
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
			if members == nil {
				members = []string{}
			}
			raw, _ := json.Marshal(members)
			return `{"id":"` + rule.SetCondition.FactID + `","state":"declared","setValue":{"members":` + string(raw) + `,"complete":true}}`
		}
		incomplete := `{"id":"` + rule.SetCondition.FactID + `","state":"declared","setValue":{"members":["zz-unrelated"],"complete":false}}`
		for _, tc := range []struct {
			name, fact string
			blocked    bool
			// mayPass: the rule decides its own anchor hop, so a complete
			// declared set without the member passes THAT rule only (as
			// every set rule does); an incomplete or missing set never does.
			mayPass bool
		}{
			{"member set", declared(rule.SetCondition.Members[0]), true, false},
			{"unrelated member set", declared("zz-unrelated"), false, true},
			{"empty set", declared(), false, true},
			{"incomplete set", incomplete, false, false},
			{"fact unsupported", `{"id":"` + rule.SetCondition.FactID + `","state":"unsupported"}`, false, false},
		} {
			report, err := CheckRule(entry.Project, rule.ID, input(tc.fact), now)
			if err != nil || len(report.Check.Claims) != 1 {
				t.Fatalf("%s %s: report=%+v err=%v", rule.ID, tc.name, report, err)
			}
			status, exit := report.Check.Claims[0].Status, ClaimExit(report)
			if tc.blocked && (status != "BLOCKED" || exit != 10) {
				t.Fatalf("%s %s: status=%s exit=%d, want BLOCKED", rule.ID, tc.name, status, exit)
			}
			if !tc.blocked && status == "BLOCKED" {
				t.Fatalf("%s %s: blocked without the member", rule.ID, tc.name)
			}
			if !tc.blocked && !tc.mayPass && (status == "PASS" || exit == 0) {
				t.Fatalf("%s %s: a crossing rule passed (status=%s exit=%d)", rule.ID, tc.name, status, exit)
			}
		}
	}
	if count != 6 {
		t.Fatalf("%d release-note crossing rules in the embedded pack, want 6", count)
	}
}

// The store view of a project keeps the identity of the embedded pack's
// crossing rules (scan_store.go): a store target never carries them, and the
// scan must name them as rules that need other evidence instead of passing a
// hop they cover because they are missing.
func TestStoreScanKeepsEmbeddedCrossingRuleIdentities(t *testing.T) {
	t.Parallel()
	raw, err := ExportEmbeddedExternalBundle("5")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := ParseExternalBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	k, err := NewStoreScanKnowledge(map[string]ExternalBundle{"cortex": bundle})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rule := range k.rules["cortex"] {
		if strings.Contains(rule.Scope.ID, ".relnotes.") {
			found = true
		}
	}
	if !found {
		t.Fatal("the store view of cortex lost the embedded crossing rule")
	}
	for _, entry := range bundle.pack.Entries {
		if strings.Contains(string(entry.Rule), `"crossing"`) {
			t.Fatal("the store bundle carries a crossing rule")
		}
	}
}

// The store-or-embedded comparison counts every embedded rule of a project,
// the crossing rules too (their review is the newest of the project), while a
// store target built from the same pack carries none of them: the store is
// then stale, so it must be strictly newer to win, and the rules are
// identical otherwise.
func TestCompareWithEmbeddedCountsCrossingRuleEvidence(t *testing.T) {
	t.Parallel()
	indexTarget, targets, err := BuildEmbeddedExternalTargets("5", nil)
	if err != nil {
		t.Fatal(err)
	}
	index, err := ParseExternalIndex(indexTarget.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	for _, target := range targets {
		if target.Path == ProjectTargetPath("cortex") {
			raw = target.Bytes
		}
	}
	bundle, err := AdmitExternalProjectTarget(index, "cortex", raw)
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := CompareWithEmbedded(map[string]ExternalBundle{"cortex": bundle})
	if err != nil {
		t.Fatal(err)
	}
	crossingAt := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	if !comparison.Identical || comparison.StaleProject != "cortex" || !comparison.EmbeddedEvidenceAt.Equal(crossingAt) || !comparison.StoreEvidenceAt.Before(crossingAt) {
		t.Fatalf("comparison=%+v", comparison)
	}
}
