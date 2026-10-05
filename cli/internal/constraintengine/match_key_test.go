// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"encoding/json"
	"testing"
)

func TestConstraintKeyExported(t *testing.T) {
	cases := map[string]struct {
		rule string
		want string
	}{
		"fact":       {`{"operator":"forbid_fact","condition":{"side":"to","component":"k","factId":"f","boolValue":true}}`, "forbid_fact\x00to\x00k\x00f"},
		"set":        {`{"operator":"forbid_set_member","setCondition":{"side":"to","component":"k","factId":"s","members":["a"]}}`, "forbid_set_member\x00to\x00k\x00s"},
		"dependency": {`{"operator":"require_component_version","dependency":{"side":"proposed","component":"c","comparison":"gte","version":"1.0.0"}}`, "require_component_version\x00proposed\x00c"},
		"operator":   {`{"operator":"forbid_intermediate"}`, "forbid_intermediate"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ConstraintKey([]byte(tc.rule))
			if err != nil || got != tc.want {
				t.Fatalf("key %q, %v; want %q", got, err, tc.want)
			}
			var r rule
			if err := json.Unmarshal([]byte(tc.rule), &r); err != nil || constraintKey(r) != got {
				t.Fatalf("the exported key differs from the one the overlap lint compares")
			}
		})
	}
	if _, err := ConstraintKey([]byte(`"not a rule"`)); err == nil {
		t.Fatal("a non-object rule has a key")
	}
	if _, err := ConstraintKey([]byte(`{`)); err == nil {
		t.Fatal("broken JSON has a key")
	}
}
