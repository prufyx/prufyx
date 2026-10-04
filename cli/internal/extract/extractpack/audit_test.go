// SPDX-License-Identifier: AGPL-3.0-only

package extractpack

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func entry(id, state string, extra string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"project":"p","description":"d%s","requiredFacts":[],"rule":{"id":%q,"subject":{"component":"c","from":"1","to":"2"},"evidence":{"state":%q,"basis":"mechanical","extractor":{"id":"x"}}}}`, extra, id, state))
}

func mkPack(entries ...json.RawMessage) *Pack {
	return &Pack{Members: map[string]json.RawMessage{"schema": json.RawMessage(`"s1"`), "revision": json.RawMessage(`"r1"`)}, Entries: entries}
}

// The audit is the last line of defence: whatever a merge does, a result
// that touches a rule the run did not produce, or changes anything but a
// withdrawal in withdraw mode, is refused.
func TestAuditRefusesForeignChanges(t *testing.T) {
	base := mkPack(entry("a", "active", ""), entry("b", "active", ""))
	allow := map[string]bool{"a": true}

	cases := []struct {
		name     string
		head     func() *Pack
		allowed  map[string]bool
		withdraw bool
		want     bool // refused
	}{
		{"unchanged", func() *Pack { return mkPack(entry("a", "active", ""), entry("b", "active", "")) }, nil, false, false},
		{"allowed add", func() *Pack {
			return mkPack(entry("a", "active", ""), entry("b", "active", ""), entry("n", "active", ""))
		}, map[string]bool{"n": true}, false, false},
		{"unallowed add", func() *Pack {
			return mkPack(entry("a", "active", ""), entry("b", "active", ""), entry("n", "active", ""))
		}, nil, false, true},
		{"foreign edit", func() *Pack { return mkPack(entry("a", "active", ""), entry("b", "active", "!")) }, allow, false, true},
		{"allowed id edited in add mode", func() *Pack { return mkPack(entry("a", "active", "!"), entry("b", "active", "")) }, allow, false, true},
		{"removal", func() *Pack { return mkPack(entry("a", "active", "")) }, allow, false, true},
		{"member edit", func() *Pack {
			h := mkPack(entry("a", "active", ""), entry("b", "active", ""))
			h.Members["revision"] = json.RawMessage(`"r2"`)
			return h
		}, nil, false, true},
		{"new member", func() *Pack {
			h := mkPack(entry("a", "active", ""), entry("b", "active", ""))
			h.Members["policyId"] = json.RawMessage(`"x"`)
			return h
		}, nil, false, true},
		{"schema move in add mode", func() *Pack {
			h := mkPack(entry("a", "active", ""), entry("b", "active", ""))
			h.Members["schema"] = json.RawMessage(`"s2"`)
			return h
		}, nil, false, false},
		{"schema move in withdraw mode", func() *Pack {
			h := mkPack(entry("a", "withdrawn", ""), entry("b", "active", ""))
			h.Members["schema"] = json.RawMessage(`"s2"`)
			return h
		}, allow, true, true},
		{"withdraw allowed", func() *Pack { return mkPack(entry("a", "withdrawn", ""), entry("b", "active", "")) }, allow, true, false},
		{"withdraw foreign", func() *Pack { return mkPack(entry("a", "active", ""), entry("b", "withdrawn", "")) }, allow, true, true},
		{"withdraw plus edit", func() *Pack { return mkPack(entry("a", "withdrawn", "!"), entry("b", "active", "")) }, allow, true, true},
		{"withdraw mode adds a rule", func() *Pack {
			return mkPack(entry("a", "withdrawn", ""), entry("b", "active", ""), entry("n", "active", ""))
		}, map[string]bool{"a": true, "n": true}, true, true},
		{"reactivation", func() *Pack { return mkPack(entry("a", "active", ""), entry("b", "active", "")) }, allow, true, false},
	}
	for _, c := range cases {
		b := base
		if c.name == "reactivation" {
			b = mkPack(entry("a", "withdrawn", ""), entry("b", "active", ""))
			// A withdrawn rule made active again is not a state-only
			// tightening, and is refused even when its id is allowed.
			c.want = true
		}
		err := audit(b, c.head(), c.allowed, nil, c.withdraw)
		if c.want != (err != nil) {
			t.Errorf("%s: err = %v, want refusal %v", c.name, err, c.want)
		}
		if err != nil && !errors.Is(err, ErrForeignChange) {
			t.Errorf("%s: wrong error type: %v", c.name, err)
		}
	}
}
