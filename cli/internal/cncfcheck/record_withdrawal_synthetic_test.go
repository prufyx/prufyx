// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package cncfcheck

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/servedapis"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// An embedded path-policy withdrawal binds a store scan: a store signed before
// it, with the same review date or with no record at all, gives no policy. A
// strictly later review does. The embedded pack is replaced for the test, so
// it does not run in parallel.
func TestStoreCannotUnwithdrawEmbeddedPathPolicy(t *testing.T) {
	raw, err := packagedRulePack()
	if err != nil {
		t.Fatal(err)
	}
	var packaged rulePack
	if err := json.Unmarshal(raw, &packaged); err != nil {
		t.Fatal(err)
	}
	records, err := upgradepath.Parse(packaged.PathPolicies)
	if err != nil || len(records) != 1 || records[0].Component != servedapis.KubernetesComponent || records[0].Evidence.State != upgradepath.StateActive {
		t.Fatalf("this test needs the one active kubernetes policy: %+v (%v)", records, err)
	}
	reviewed, err := reviewTime(records[0].Evidence.ReviewedAt)
	if err != nil {
		t.Fatal(err)
	}
	withdrawn := records[0]
	withdrawn.Evidence.State = upgradepath.StateWithdrawn
	section, err := upgradepath.Marshal([]upgradepath.Record{withdrawn})
	if err != nil {
		t.Fatal(err)
	}
	restore, err := UseSyntheticRecords(nil, nil, SyntheticRecords{LineAttestations: packaged.LineAttestations, PathPolicies: section, ServedAPIs: packaged.ServedAPIs})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)

	set := func(state string, at time.Time) func(map[string]any) {
		return func(pack map[string]any) {
			evidence := pack["pathPolicies"].([]any)[0].(map[string]any)["evidence"].(map[string]any)
			evidence["state"], evidence["reviewedAt"] = state, at.UTC().Format(time.RFC3339)
			// The validity moves too: a lease has a longest span.
			evidence["validUntil"] = reviewed.Add(80 * 24 * time.Hour).UTC().Format(time.RFC3339)
		}
	}
	for name, c := range map[string]struct {
		edit    func(map[string]any)
		current bool
	}{
		"same review date":    {set("active", reviewed), false},
		"earlier review date": {set("active", reviewed.Add(-time.Second)), false},
		"no record": {func(pack map[string]any) {
			delete(pack, "pathPolicies")
		}, false},
		"strictly later review": {set("active", reviewed.Add(time.Second)), true},
	} {
		status := recordSnapshot(t, recordStore(t, c.edit)).PathPolicyFor(servedapis.KubernetesComponent, reviewed.Add(24*time.Hour))
		if c.current {
			if status.Policy() == nil {
				t.Fatalf("%s: %+v", name, status)
			}
			continue
		}
		if !status.Found || status.Freshness != upgradepath.FreshnessWithdrawn || status.Policy() != nil || !status.RecordNotCurrent() {
			t.Fatalf("%s: %+v", name, status)
		}
	}
}
