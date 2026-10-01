// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestPrepareCephSelectedOSDMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, raw, id, state string
		want                 *bool
		complete             bool
	}{
		{"filestore", `{"id":7,"osd_objectstore":"filestore","hostname":"private-node"}`, "7", "PREPARED", boolPointer(true), true},
		{"bluestore", `{"id":7,"osd_objectstore":"bluestore"}`, "7", "PREPARED", boolPointer(false), true},
		{"incomplete", `{"id":7,"osd_objectstore":"filestore"}`, "7", "UNKNOWN", nil, false},
		{"mismatch", `{"id":8,"osd_objectstore":"filestore"}`, "7", "UNKNOWN", nil, true},
		{"unknown-store", `{"id":7,"osd_objectstore":"memstore"}`, "7", "UNKNOWN", nil, true},
		{"wrong-type", `{"id":"7","osd_objectstore":"filestore"}`, "7", "UNKNOWN", nil, true},
		{"fraction", `{"id":7.0,"osd_objectstore":"filestore"}`, "7", "UNKNOWN", nil, true},
		{"exponent", `{"id":7e0,"osd_objectstore":"filestore"}`, "7", "UNKNOWN", nil, true},
		{"raw-id-overflow", `{"id":9223372036854775808,"osd_objectstore":"filestore"}`, "7", "UNKNOWN", nil, true},
		{"case-variant", `{"ID":7,"osd_objectstore":"filestore"}`, "7", "UNKNOWN", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareSelectedOSDMetadata(CephProject, []byte(tc.raw), tc.id, CephFrom, CephTo, tc.complete)
			if err != nil || prepared.State != tc.state {
				t.Fatalf("state=%q err=%v", prepared.State, err)
			}
			assertCanonicalCurrentFact(t, prepared.CanonicalInputJSON, CephFact, tc.want)
			if bytes.Contains(prepared.CanonicalInputJSON, []byte("private-node")) || bytes.Contains(prepared.CanonicalInputJSON, []byte(`"id":7`)) {
				t.Fatal("raw selected metadata leaked")
			}
		})
	}
	for _, raw := range []string{
		`{"id":7,"id":7,"osd_objectstore":"filestore"}`,
		`{"id":7,"osd_objectstore":"filestore","osd_objectstore":"bluestore"}`,
		`{"id":7,`,
	} {
		if _, err := PrepareSelectedOSDMetadata(CephProject, []byte(raw), "7", CephFrom, CephTo, true); err == nil {
			t.Fatalf("invalid JSON accepted: %q", raw)
		}
	}
	for _, id := range []string{"", "07", "-1", "+7", "7.0", "9223372036854775808", "999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999"} {
		if _, err := PrepareSelectedOSDMetadata(CephProject, []byte(`{"id":7,"osd_objectstore":"filestore"}`), id, CephFrom, CephTo, true); err == nil {
			t.Fatalf("invalid selected id accepted: %q", id)
		}
	}
}

func assertCanonicalCurrentFact(t *testing.T, raw []byte, id string, want *bool) {
	t.Helper()
	var doc struct {
		Current struct {
			Components []struct {
				Facts []struct {
					ID        string `json:"id"`
					State     string `json:"state"`
					BoolValue *bool  `json:"boolValue"`
				} `json:"facts"`
			} `json:"components"`
		} `json:"current"`
		Proposed struct {
			Components []struct {
				Facts []any `json:"facts"`
			} `json:"components"`
		} `json:"proposed"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Proposed.Components[0].Facts) != 0 {
		t.Fatal("current-side fact appeared on proposed side")
	}
	fact := doc.Current.Components[0].Facts[0]
	if fact.ID != id {
		t.Fatalf("fact id %q", fact.ID)
	}
	if want == nil {
		if fact.State != "unsupported" || fact.BoolValue != nil {
			t.Fatalf("unsupported fact=%+v", fact)
		}
		return
	}
	if fact.State != "declared" || fact.BoolValue == nil || *fact.BoolValue != *want {
		t.Fatalf("fact=%+v want=%v", fact, *want)
	}
}
