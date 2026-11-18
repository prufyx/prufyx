// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

func strimziGatesInput(members string, complete bool) []byte {
	set := `{"members":` + members + `,"complete":` + map[bool]string{true: "true", false: "false"}[complete] + `}`
	return []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/strimzi/strimzi-kafka-operator","version":"0.41.0","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/strimzi/strimzi-kafka-operator","version":"0.44.0","facts":[{"id":"component.strimzi.cluster_operator_feature_gates_set","state":"declared","setValue":` + set + `}]}]}}`)
}

// The guard never turns a set into a pass: a complete set holding a name the
// operator does not know is handed over as incomplete, case-exact, and a set
// that is already incomplete or holds only known names is returned as it was.
func TestGuardStrimziOperatorGates(t *testing.T) {
	for _, test := range []struct {
		name       string
		members    string
		complete   bool
		downgraded bool
	}{
		{"known gate, complete", `["ContinueReconciliationOnManualRollingUpdateFailure"]`, true, false},
		{"removed gate, complete", `["UseKRaft"]`, true, false},
		{"empty, complete", `[]`, true, false},
		{"unknown gate, complete", `["SomeOtherGate"]`, true, true},
		{"case variant, complete", `["usekraft"]`, true, true},
		{"known beside unknown, complete", `["ContinueReconciliationOnManualRollingUpdateFailure","SomeOtherGate"]`, true, true},
		{"unknown gate, incomplete", `["SomeOtherGate"]`, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := strimziGatesInput(test.members, test.complete)
			guarded, downgraded, err := guardRelnotesSets(raw)
			if err != nil || downgraded != test.downgraded {
				t.Fatalf("downgraded=%v err=%v", downgraded, err)
			}
			if !test.downgraded {
				if string(guarded) != string(raw) {
					t.Fatalf("input must come back byte for byte: %s", guarded)
				}
				return
			}
			if !strings.Contains(string(guarded), `"complete":false`) || strings.Contains(string(guarded), `"complete":true`) {
				t.Fatalf("set not downgraded: %s", guarded)
			}
		})
	}
}

// The embedded rule forbids exactly what 0.44.0 removed, for the exact pair.
func TestEmbeddedStrimziUseKRaftRule(t *testing.T) {
	raw, err := os.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Entries []struct {
			Project string `json:"project"`
			Rule    struct {
				ID           string `json:"id"`
				Operator     string `json:"operator"`
				ReasonCode   string `json:"reasonCode"`
				Subject      struct{ From, To string }
				SetCondition struct {
					Side    string   `json:"side"`
					FactID  string   `json:"factId"`
					Members []string `json:"members"`
				} `json:"setCondition"`
				AppliesWhen []struct {
					FactID    string `json:"factId"`
					Side      string `json:"side"`
					EnumValue string `json:"enumValue"`
				} `json:"appliesWhen"`
				Evidence struct {
					Sources []struct {
						ID, URL string
					} `json:"sources"`
				} `json:"evidence"`
			} `json:"rule"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, entry := range pack.Entries {
		rule := entry.Rule
		if rule.ID != cncfprepare.StrimziOperatorGatesRuleID {
			continue
		}
		found++
		var removed []string
		for _, name := range cncfprepare.StrimziKnownGates041 {
			kept := false
			for _, other := range cncfprepare.StrimziKnownGates044 {
				kept = kept || name == other
			}
			if !kept {
				removed = append(removed, name)
			}
		}
		if entry.Project != "strimzi" || rule.Operator != "forbid_set_member" || rule.ReasonCode != "REVIEWED_SOURCE_CONSTRAINT" ||
			rule.Subject.From != "0.41.0" || rule.Subject.To != "0.44.0" ||
			rule.SetCondition.Side != "proposed" || rule.SetCondition.FactID != cncfprepare.StrimziOperatorGatesFact ||
			!reflect.DeepEqual(rule.SetCondition.Members, removed) ||
			len(rule.AppliesWhen) != 1 || rule.AppliesWhen[0].FactID != cncfprepare.StrimziDistributionFact || rule.AppliesWhen[0].EnumValue != "official_upstream" {
			t.Fatalf("rule drifted from its reviewed shape: %+v", entry)
		}
		// Every pinned known gate of the guard is a gate the preparer knows.
		if !reflect.DeepEqual(strimziKnownGates, cncfprepare.StrimziKnownGates041) {
			t.Fatalf("guard and preparer disagree on the known gates: %v vs %v", strimziKnownGates, cncfprepare.StrimziKnownGates041)
		}
		for _, source := range rule.Evidence.Sources {
			if !strings.HasPrefix(source.URL, "https://github.com/strimzi/strimzi-kafka-operator/blob/") {
				t.Fatalf("source %s is not a pinned upstream blob: %s", source.ID, source.URL)
			}
		}
	}
	if found != 1 {
		t.Fatalf("rule count %d", found)
	}
}

// A hand-written complete set that holds an unknown gate never passes, and a
// forbidden member still blocks whatever else the set holds.
func TestStrimziOperatorGatesNeverPassWithAnUnknownGate(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	distribution := `,{"id":"component.strimzi.distribution","state":"declared","enumValue":"official_upstream"}`
	for _, test := range []struct {
		name, members, status string
		complete              bool
	}{
		{"unknown gate, declared complete", `["SomeOtherGate"]`, "UNKNOWN", true},
		{"case variant, declared complete", `["usekraft"]`, "UNKNOWN", true},
		{"known gate, declared complete", `["ContinueReconciliationOnManualRollingUpdateFailure"]`, "PASS", true},
		{"known gate, incomplete", `["ContinueReconciliationOnManualRollingUpdateFailure"]`, "UNKNOWN", false},
		{"empty, incomplete", `[]`, "UNKNOWN", false},
		{"forbidden member beside an unknown gate", `["SomeOtherGate","UseKRaft"]`, "BLOCKED", true},
		{"forbidden member, incomplete", `["UseKRaft"]`, "BLOCKED", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := strimziGatesInput(test.members, test.complete)
			raw = []byte(strings.Replace(string(raw), `}]}]}}`, `}`+distribution+`]}]}}`, 1))
			report, err := Check("strimzi", raw, now)
			if err != nil {
				t.Fatal(err)
			}
			for _, claim := range report.Check.Claims {
				if claim.RuleID == "strimzi.feature-gate-usekraft-removed.0-44" {
					if claim.Status != test.status {
						t.Fatalf("status %s, want %s", claim.Status, test.status)
					}
					return
				}
			}
			t.Fatal("rule not reported")
		})
	}
}
