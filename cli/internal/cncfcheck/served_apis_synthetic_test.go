// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package cncfcheck

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const servedEvidence = `{"basis":"reviewed","reviewedAt":"2026-09-23T00:00:00Z","validUntil":"2026-12-20T00:00:00Z","sources":[{"id":"s","url":"https://github.com/kubernetes/website/blob/9f1af2971c32124bff0a1f42255ba5a2f3c8a16f/content/en/docs/reference/using-api/deprecation-guide.md","revision":"9f1af2971c32124bff0a1f42255ba5a2f3c8a16f","contentDigest":"sha256:96f34a49cbdd7bd53008cc7b7cc8aff58c373ad323e64eef0155cbbc44494f61","startLine":40,"endLine":49}]}`

// TestServedAPIsSectionAdmission: a pack with a served-list section loads at
// the served-list schema level and answers lookups; a section naming a
// component the catalog has no project for, or malformed, refuses the pack.
func TestServedAPIsSectionAdmission(t *testing.T) {
	section := func(component string) json.RawMessage {
		return json.RawMessage(`[{"component":"` + component + `","line":"1.29","completeness":"COMPLETE_SERVED_API_LIST_FOR_LINE","apis":["v1 ConfigMap"],"evidence":` + servedEvidence + `}]`)
	}
	restore, err := UseSyntheticRecords(nil, nil, SyntheticRecords{ServedAPIs: section("pkg:github/kubernetes/kubernetes")})
	if err != nil {
		t.Fatal(err)
	}
	b, err := load()
	if err != nil || b.pack.Schema != packSchemaServedAPIs {
		t.Fatalf("schema %q err %v", b.pack.Schema, err)
	}
	k, err := LoadScanKnowledge()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	if status, ok := k.ServedAPIsFor("pkg:github/kubernetes/kubernetes", "1.29", now); !ok || !status.Current() || status.Record.APIs[0] != "v1 ConfigMap" {
		t.Fatalf("%+v %v", status, ok)
	}
	if _, ok := k.ServedAPIsFor("pkg:github/kubernetes/kubernetes", "1.30", now); ok {
		t.Fatal("a list for another line")
	}
	restore()
	// After restore the embedded pack carries none.
	k, err = LoadScanKnowledge()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := k.ServedAPIsFor("pkg:github/kubernetes/kubernetes", "1.29", now); ok {
		t.Fatal("served list left behind")
	}
	// A component the catalog has no project for: the whole pack is refused.
	if restore, err := UseSyntheticRecords(nil, nil, SyntheticRecords{ServedAPIs: json.RawMessage(strings.Replace(string(section("pkg:github/kubernetes/kubernetes")), "kubernetes/kubernetes", "nobody/nothing", 1))}); err == nil {
		restore()
		t.Fatal("unknown component admitted")
	}
	// Malformed section: refused.
	if restore, err := UseSyntheticRecords(nil, nil, SyntheticRecords{ServedAPIs: json.RawMessage(`[{"component":"x"}]`)}); err == nil {
		restore()
		t.Fatal("malformed section admitted")
	}
}
