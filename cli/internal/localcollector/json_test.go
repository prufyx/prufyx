// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"fmt"
	"strings"
	"testing"
)

func TestDecodeStrict(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		raw  string
		ok   bool
	}{
		{"object", `{"items":[true,null,3,"x"]}`, true},
		{"duplicate root", `{"items":[],"items":[]}`, false},
		{"duplicate nested", `{"x":{"a":1,"a":2}}`, false},
		{"trailing value", `{} []`, false},
		{"nonstandard number", `{"x":NaN}`, false},
		{"truncated", `{"x":`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeStrict([]byte(tc.raw))
			if (err == nil) != tc.ok {
				t.Fatalf("DecodeStrict error = %v, want success %v", err, tc.ok)
			}
		})
	}
}

func TestDecodeStrictBounds(t *testing.T) {
	t.Parallel()
	deep := strings.Repeat("[", maxJSONDepth+2) + strings.Repeat("]", maxJSONDepth+2)
	if _, err := DecodeStrict([]byte(deep)); err == nil {
		t.Fatal("deep value accepted")
	}
	items := make([]string, maxJSONNodes+1)
	for i := range items {
		items[i] = fmt.Sprint(i)
	}
	if _, err := DecodeStrict([]byte("[" + strings.Join(items, ",") + "]")); err == nil {
		t.Fatal("oversized node graph accepted")
	}
}
