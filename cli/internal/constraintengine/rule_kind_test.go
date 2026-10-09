// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"testing"
)

func TestRawRuleKind(t *testing.T) {
	for name, tc := range map[string]struct {
		raw  string
		want string
		ok   bool
	}{
		"verdict":       {`{"operator":"forbid_predicate_value"}`, "", true},
		"blocking rule": {`{"operator":"require_component_version"}`, "", true},
		"support range": {`{"operator":"require_component_version","severity":"unsupported"}`, RuleKindSupportRange, true},
		"notice":        {`{"operator":"notice_one_way"}`, RuleKindOneWayNotice, true},
		"not an object": {`[]`, "", false},
	} {
		got, err := RawRuleKind(json.RawMessage(tc.raw))
		if (err == nil) != tc.ok || got != tc.want {
			t.Fatalf("%s: kind=%q err=%v", name, got, err)
		}
	}
}
