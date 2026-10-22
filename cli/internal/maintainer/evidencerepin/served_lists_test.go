// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"strings"
	"testing"
)

// servedListPack adds one served-API list to recordPack.
func servedListPack(t *testing.T) []byte {
	t.Helper()
	digest := "sha256:" + strings.Repeat("cd", 32)
	return recordPack(t, func(pack map[string]any) {
		pack["servedAPIs"] = []map[string]any{{
			"component": "pkg:github/kubernetes/kubernetes", "line": "1.37", "completeness": "COMPLETE_SERVED_API_LIST_FOR_LINE",
			"apis": []string{"apps/v1 Deployment", "v1 ConfigMap"},
			"evidence": map[string]any{
				"basis": "reviewed", "reviewedAt": "2026-09-12T10:00:00Z", "validUntil": "2026-12-11T10:00:00Z",
				"sources": []map[string]any{source("k8s-openapi", "kubernetes", "kubernetes", commitB, "api/openapi-spec/swagger.json", digest, 1, 90000)},
			},
		}}
	})
}

// A served-API list is a record like a line attestation: it has a record ID
// of its own, its citation is monitored and it can be renewed.
func TestPackRecordsReadsServedLists(t *testing.T) {
	records, err := PackRecords(servedListPack(t))
	if err != nil {
		t.Fatalf("PackRecords: %v", err)
	}
	id := ServedListRecordID("pkg:github/kubernetes/kubernetes", "1.37")
	var found *PackRecord
	for i := range records {
		if records[i].ID == id {
			found = &records[i]
		}
	}
	if found == nil || found.Project != RecordProjectServedLists || len(found.Sources) != 1 || found.State != "active" {
		t.Fatalf("served-list record not read: %+v", records)
	}
	if !IsRecordID(id) || !strings.HasPrefix(id, "served-list.") {
		t.Fatalf("record ID %q is not recognised as a record ID", id)
	}
	if id == ServedListRecordID("pkg:github/kubernetes/kubernetes", "1.36") {
		t.Fatal("two lines share a record ID")
	}
	citations, err := LoadCitations("rules.json", servedListPack(t))
	if err != nil {
		t.Fatalf("LoadCitations: %v", err)
	}
	var cited bool
	for _, c := range citations {
		cited = cited || (c.RuleID == id && c.Project == RecordProjectServedLists)
	}
	if !cited {
		t.Fatalf("the served list's citation is not monitored: %+v", citations)
	}
}

func TestPackEntryMayNotLookLikeAServedListRecord(t *testing.T) {
	id := ServedListRecordID("pkg:github/kubernetes/kubernetes", "1.37")
	if err := CheckPackEntry("kubernetes", id); err == nil {
		t.Fatal("a rule with a served-list record ID was admitted")
	}
	if err := CheckPackEntry(RecordProjectServedLists, "kubernetes.rule"); err == nil {
		t.Fatal("a rule in the served-lists record project was admitted")
	}
}
