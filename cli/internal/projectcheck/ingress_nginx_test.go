// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// The pack loader rejects enum facts and admits one rule shape; the ingress-nginx
// entry must load under those unchanged rules, as one rule over three bool facts.
func TestIngressNginxEntryLoadsAsOneBoolRule(t *testing.T) {
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	var entries []entry
	for _, e := range b.pack.Entries {
		if e.Project == "ingress-nginx" {
			entries = append(entries, e)
		}
	}
	if len(entries) != 1 || len(entries[0].RequiredFacts) != 3 {
		t.Fatalf("entries=%d", len(entries))
	}
	for _, f := range entries[0].RequiredFacts {
		if f.Type != constraintengine.FactBool || len(f.EnumTokens) != 0 || f.Side != "proposed" {
			t.Fatalf("fact %+v", f)
		}
	}
	var binding ruleBinding
	if err := json.Unmarshal(entries[0].Rule, &binding); err != nil {
		t.Fatal(err)
	}
	if binding.Operator != "forbid_predicate_value" || binding.Subject.From != "1.10.0" || binding.Subject.To != "1.15.0" || len(binding.AppliesWhen) != 2 || binding.Condition == nil {
		t.Fatalf("rule %+v", binding)
	}
	// Not widened: CheckRule still admits only its two projects.
	if _, err := CheckRule("ingress-nginx", nil, time.Time{}, binding.ID); err != ErrInvalid {
		t.Fatalf("CheckRule admitted ingress-nginx: %v", err)
	}
}
