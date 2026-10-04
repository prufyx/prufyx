// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"encoding/json"
	"testing"
)

// TestCommunityPacksRefuseBasis: no community project pack schema admits a
// consensus or lead rule; an empirical rule decides like a reviewed one.
func TestCommunityPacksRefuseBasis(t *testing.T) {
	verdict := json.RawMessage(`{"id":"verdict","operator":"forbid_target_version","evidence":{"state":"active"}}`)
	for _, basis := range []string{"consensus", "lead"} {
		rule := json.RawMessage(`{"id":"model","operator":"forbid_target_version","evidence":{"basis":"` + basis + `","derivedAt":"2026-01-01T00:00:00Z"}}`)
		for _, schema := range []string{packSchema, packSchemaRanged} {
			if validPackSchema(packDocument{Schema: schema, Entries: []entry{{Rule: verdict}, {Rule: rule}}}) {
				t.Fatalf("pack under %s with a %s rule accepted", schema, basis)
			}
		}
	}
	empirical := json.RawMessage(`{"id":"lab","operator":"forbid_target_version","evidence":{"basis":"empirical","derivedAt":"2026-01-01T00:00:00Z"}}`)
	if !validPackSchema(packDocument{Schema: packSchema, Entries: []entry{{Rule: verdict}, {Rule: empirical}}}) {
		t.Fatal("pack with an empirical rule refused")
	}
}
