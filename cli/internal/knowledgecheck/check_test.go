// SPDX-License-Identifier: AGPL-3.0-only

package knowledgecheck

import (
	"strings"
	"testing"
)

func TestReplayJSONGateBoundsDepthMembersStringsAndNumbers(t *testing.T) {
	if err := validateReplayJSON([]byte(`{"apiVersion":"x","version":1}`)); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"depth":  []byte(strings.Repeat(`{"x":`, 33) + `0` + strings.Repeat(`}`, 33)),
		"string": []byte(`{"x":"` + strings.Repeat("a", 64<<10+1) + `"}`),
		"number": []byte(`{"x":123456789012345678901}`),
		"float":  []byte(`{"x":1.5}`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateReplayJSON(raw); err == nil {
				t.Fatal("unbounded replay JSON accepted")
			}
		})
	}
	members := `[` + strings.Repeat(`0,`, 32768) + `0]`
	if err := validateReplayJSON([]byte(members)); err == nil {
		t.Fatal("oversized member count accepted")
	}
}
