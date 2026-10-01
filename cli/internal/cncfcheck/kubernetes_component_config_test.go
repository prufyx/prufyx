// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

func TestCheckFactsEvaluatesOnlyTheNamedFactFamily(t *testing.T) {
	raw := []byte(`{"apiVersion":"batch/v1beta1","kind":"CronJob","metadata":{"name":"c"}}`)
	prepared, err := cncfprepare.PrepareKubernetesRemovedAPIs(raw, "1.24.0", "1.25.0", "official_upstream", true, true)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	family := cncfprepare.KubernetesRemovedAPIFacts("1.24.0", "1.25.0")
	report, err := CheckFacts("kubernetes", family, prepared.CanonicalInputJSON, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Check.Claims) != len(family) || ClaimExit(report) != 10 {
		t.Fatalf("claims=%d exit=%d", len(report.Check.Claims), ClaimExit(report))
	}
	one, err := CheckFacts("kubernetes", []string{"component.kubernetes.cronjob_v1beta1_removed_gvk_present"}, prepared.CanonicalInputJSON, now)
	if err != nil || len(one.Check.Claims) != 1 || one.Check.Claims[0].Status != "BLOCKED" {
		t.Fatalf("single-fact family err=%v claims=%+v", err, one.Check.Claims)
	}
	// A family that no published rule uses yields no claims and an explicit
	// UNKNOWN next action, never a PASS.
	empty, err := CheckFacts("kubernetes", []string{"component.kubernetes.not_published_anywhere"}, prepared.CanonicalInputJSON, now)
	if err != nil || len(empty.Check.Claims) != 0 || ClaimExit(empty) != 11 || !strings.Contains(empty.NextAction, "no reviewed rule") {
		t.Fatalf("empty family err=%v claims=%d next=%q", err, len(empty.Check.Claims), empty.NextAction)
	}
	if _, err := CheckFacts("kubernetes", nil, prepared.CanonicalInputJSON, now); err == nil {
		t.Fatal("empty fact list accepted")
	}
	if _, err := CheckFacts("not-a-project", family, prepared.CanonicalInputJSON, now); err == nil {
		t.Fatal("unknown project accepted")
	}
}

func TestRegisteredFact(t *testing.T) {
	if !RegisteredFact("component.kubernetes.cronjob_v1beta1_removed_gvk_present") || RegisteredFact("component.kubernetes.not_published_anywhere") {
		t.Fatal("RegisteredFact does not mirror the compiled registry")
	}
}

// TestKubernetesComponentConfigFactsMatchPublishedRules keeps the adapter
// table and the pack aligned: every published rule that consumes an adapter
// fact is registered and is anchored on a pair that crosses the adapter's line
// for that fact, so the adapter emits the fact exactly where the rule decides.
func TestKubernetesComponentConfigFactsMatchPublishedRules(t *testing.T) {
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	lines := cncfprepare.KubernetesComponentConfigFactLines()
	for _, entry := range b.pack.Entries {
		if entry.Project != "kubernetes" {
			continue
		}
		var shape ruleShape
		var identity struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(entry.Rule, &shape) != nil || json.Unmarshal(entry.Rule, &identity) != nil {
			t.Fatal("rule shape")
		}
		conditions := append([]conditionShape(nil), shape.AppliesWhen...)
		if shape.Condition != nil {
			conditions = append(conditions, *shape.Condition)
		}
		for _, condition := range conditions {
			if _, ours := lines[condition.FactID]; !ours {
				continue
			}
			if !RegisteredFact(condition.FactID) {
				t.Fatalf("%s: fact %s not registered", identity.ID, condition.FactID)
			}
			emitted := false
			for _, fact := range cncfprepare.KubernetesComponentConfigFacts(shape.Subject.From, shape.Subject.To) {
				emitted = emitted || fact == condition.FactID
			}
			if !emitted {
				t.Fatalf("%s: anchor %s -> %s does not cross line %s", identity.ID, shape.Subject.From, shape.Subject.To, lines[condition.FactID])
			}
		}
	}
}
