// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"encoding/json"
	"testing"
)

// TestCommunityPacksRefuseSeverity: no community project pack schema admits
// a support-range rule, so an UNSUPPORTED claim can never reach this route.
func TestCommunityPacksRefuseSeverity(t *testing.T) {
	support := json.RawMessage(`{"id":"support","operator":"require_component_version","severity":"unsupported"}`)
	verdict := json.RawMessage(`{"id":"verdict","operator":"require_component_version"}`)
	for _, schema := range []string{packSchema, packSchemaRanged} {
		if validPackSchema(packDocument{Schema: schema, Entries: []entry{{Rule: verdict}, {Rule: support}}}) {
			t.Fatalf("pack under %s with a support-range rule accepted", schema)
		}
	}
	if !validPackSchema(packDocument{Schema: packSchema, Entries: []entry{{Rule: verdict}}}) {
		t.Fatal("pack without a severity refused")
	}
}
