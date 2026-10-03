// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"encoding/json"
	"testing"
)

// TestCommunityPacksRefuseNotices: no community project pack schema admits a
// one-way notice rule, so a NOTICE claim can never reach this route.
func TestCommunityPacksRefuseNotices(t *testing.T) {
	notice := json.RawMessage(`{"id":"notice","operator":"notice_one_way"}`)
	verdict := json.RawMessage(`{"id":"verdict","operator":"forbid_target_version"}`)
	for _, schema := range []string{packSchema, packSchemaRanged} {
		if validPackSchema(packDocument{Schema: schema, Entries: []entry{{Rule: verdict}, {Rule: notice}}}) {
			t.Fatalf("pack under %s with a notice accepted", schema)
		}
	}
	if !validPackSchema(packDocument{Schema: packSchema, Entries: []entry{{Rule: verdict}}}) {
		t.Fatal("pack without a notice refused")
	}
}
