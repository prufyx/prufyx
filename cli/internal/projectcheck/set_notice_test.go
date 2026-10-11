// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"encoding/json"
	"testing"
)

// TestCommunityPacksRefuseSetNotices: no community project pack schema
// admits a set notice, with or without a chart subject, at any level and
// at the CNCF pack's set-notice level name.
func TestCommunityPacksRefuseSetNotices(t *testing.T) {
	verdict := json.RawMessage(`{"id":"verdict","operator":"forbid_target_version","evidence":{"state":"active"}}`)
	for _, operator := range []string{"notice_set_member_present", "notice_set_member_absent"} {
		for _, subject := range []string{`{"component":"x"}`, `{"component":"x","chart":{"source":"https://charts.example.io","name":"x"}}`} {
			rule := json.RawMessage(`{"id":"notice","operator":"` + operator + `","subject":` + subject + `,"evidence":{"state":"active"}}`)
			for _, schema := range []string{packSchema, packSchemaRanged, packSchemaNotice, packSchemaSeverity, "prufyx.io/community-project-source-rule-pack/v1alpha5", "prufyx.io/cncf-source-rule-pack/v1alpha14"} {
				if validPackSchema(packDocument{Schema: schema, Entries: []entry{{Rule: verdict}, {Rule: rule}}}) {
					t.Fatalf("pack under %s with %s %s accepted", schema, operator, subject)
				}
			}
		}
	}
}
