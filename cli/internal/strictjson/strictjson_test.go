// SPDX-License-Identifier: AGPL-3.0-only

package strictjson

import (
	"errors"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	for _, tc := range []struct {
		name, doc string
		ok        bool
	}{
		{"plain", `{"a":1,"b":[{"c":"d"},{"c":"e"}],"rule":{"id":"x"}}`, true},
		{"same name in sibling objects", `[{"a":1},{"a":2}]`, true},
		{"scalar", `"x"`, true},
		{"repeated top", `{"a":1,"a":2}`, false},
		{"repeated deep", `{"entries":[{"rule":{"evidence":{"state":"a","state":"b"}}}]}`, false},
		{"case variant", `{"rule":1,"Rule":2}`, false},
		{"case variant deep", `{"entries":[{"x":1},{"rule":{"Id":"a","id":"b"}}]}`, false},
		{"escaped case variant", `{"rule":1,"Rule":2}`, false},
		{"kelvin sign", "{\"kind\":1,\"Kind\":2}", false},
		{"long s", "{\"state\":1,\"ſtate\":2}", false},
		{"non-ascii fold", "{\"é\":1,\"É\":2}", false},
		{"invalid utf8", "{\"a\":\"\xff\"}", false},
		{"trailing data", `{"a":1} {"b":2}`, false},
		{"truncated", `{"a":`, false},
		{"too deep", strings.Repeat("[", DefaultMaxDepth+2) + strings.Repeat("]", DefaultMaxDepth+2), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Check([]byte(tc.doc))
			if (err == nil) != tc.ok {
				t.Fatalf("Check(%s) = %v, want ok=%v", tc.doc, err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrAmbiguous) {
				t.Fatalf("error %v is not ErrAmbiguous", err)
			}
		})
	}
}

func TestFoldKeyMatchesStructDecoding(t *testing.T) {
	for _, pair := range [][2]string{{"rule", "RULE"}, {"kind", "Kind"}, {"state", "ſtate"}, {"été", "ÉTÉ"}} {
		if FoldKey(pair[0]) != FoldKey(pair[1]) {
			t.Fatalf("FoldKey(%q) != FoldKey(%q)", pair[0], pair[1])
		}
	}
	if FoldKey("rule") == FoldKey("rules") {
		t.Fatal("different names fold together")
	}
}

func TestDecode(t *testing.T) {
	var v struct {
		A string `json:"a"`
	}
	if err := Decode([]byte(`{"a":"x"}`), &v); err != nil || v.A != "x" {
		t.Fatalf("Decode = %v, %+v", err, v)
	}
	for _, doc := range []string{`{"a":"x","A":"y"}`, `{"a":"x","b":1}`, `{"a":"x"}{}`} {
		if err := Decode([]byte(doc), &v); err == nil {
			t.Fatalf("Decode(%s) accepted", doc)
		}
	}
}
