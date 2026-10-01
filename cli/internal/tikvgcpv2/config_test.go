// SPDX-License-Identifier: AGPL-3.0-only

package tikvgcpv2

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPrepare(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		target  string
		op      string
		want    *bool
		class   string
		planned bool
		wantErr bool
	}{
		{"kebab false", "[backup]\ngcp-v2-enable=false\n[server]\naddr='private-canary'\n", "8.5.8", ReviewedOperation, ptr(false), CoveredTarget, true, false},
		{"underscore true", "[backup]\ngcp_v2_enable=true\n", "8.5.8", ReviewedOperation, ptr(true), CoveredTarget, true, false},
		{"both unavailable", "[backup]\ngcp-v2-enable=true\ngcp_v2_enable=true\n", "8.5.8", ReviewedOperation, nil, CoveredTarget, true, false},
		{"absent unavailable", "[server]\naddr='private-canary'\n", "8.5.8", ReviewedOperation, nil, CoveredTarget, true, false},
		{"non table unavailable", "backup=1\n", "8.5.8", ReviewedOperation, nil, CoveredTarget, true, false},
		{"non bool unavailable", "[backup]\ngcp-v2-enable=1\n", "8.5.8", ReviewedOperation, nil, CoveredTarget, true, false},
		{"unsupported target retained", "[backup]\ngcp-v2-enable=true\n", "8.5.9", ReviewedOperation, ptr(true), UnsupportedTarget, true, false},
		{"other operation retained", "[backup]\ngcp-v2-enable=true\n", "8.5.8", "restore", ptr(true), CoveredTarget, false, false},
		{"duplicate syntax", "[backup]\ngcp-v2-enable=true\ngcp-v2-enable=false\n", "8.5.8", ReviewedOperation, nil, "", false, true},
		{"bad version", "[backup]\ngcp-v2-enable=true\n", "v8.5.8", ReviewedOperation, nil, "", false, true},
		{"bad operation", "[backup]\ngcp-v2-enable=true\n", "8.5.8", "GCS", nil, "", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, err := Prepare([]byte(tc.raw), tc.target, tc.op)
			if tc.wantErr {
				if !errors.Is(err, ErrInput) {
					t.Fatalf("err=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if o.TargetVersionClass != tc.class || o.PlannedGCSFullBackupWithWIF != tc.planned || !same(o.BackupGCPV2Enable, tc.want) {
				t.Fatalf("got %#v", o)
			}
			encoded, _ := json.Marshal(o)
			if string(encoded) == "" || strings.Contains(string(encoded), "private-canary") {
				t.Fatalf("raw leaked: %s", encoded)
			}
		})
	}
}

func TestSupportedSpellingsCanonicalizeEqually(t *testing.T) {
	kebabRaw := []byte("[backup]\ngcp-v2-enable=true\n")
	underscoreRaw := []byte("[backup]\ngcp_v2_enable=true\n")
	kebab, err := Prepare(kebabRaw, "8.5.8", ReviewedOperation)
	if err != nil {
		t.Fatal(err)
	}
	underscore, err := Prepare(underscoreRaw, "8.5.8", ReviewedOperation)
	if err != nil {
		t.Fatal(err)
	}
	kebabCanonical, _ := MarshalObservation(kebab)
	underscoreCanonical, _ := MarshalObservation(underscore)
	if !bytes.Equal(kebabCanonical, underscoreCanonical) || bytes.Equal(kebabRaw, underscoreRaw) {
		t.Fatalf("canonical equality=%t raw equality=%t", bytes.Equal(kebabCanonical, underscoreCanonical), bytes.Equal(kebabRaw, underscoreRaw))
	}
}

func ptr(v bool) *bool { return &v }
func same(a, b *bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
