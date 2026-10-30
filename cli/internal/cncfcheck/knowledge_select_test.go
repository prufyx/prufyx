// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"strings"
	"testing"
	"time"
)

// storeBundles builds the per-project envelopes of the embedded pack for the
// named projects, as a store holds them, with mutate applied to each rule's
// JSON text.
func storeBundles(t *testing.T, projects []string, mutate func(string) string) map[string]ExternalBundle {
	t.Helper()
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	records, err := splitRecords(base.pack, base.knowledgeProjects())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]ExternalBundle{}
	for _, project := range projects {
		var entries []Entry
		for _, entry := range base.pack.Entries {
			if entry.Project == project {
				entry.Rule = []byte(mutate(string(entry.Rule)))
				entries = append(entries, entry)
			}
		}
		raw, err := encodeExternalEnvelopeWithRecords(base, "7", "operator_provided", entries, records[project])
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := parseExternalBundle(raw, &base)
		if err != nil {
			t.Fatalf("%s: %v", project, err)
		}
		out[project] = bundle
	}
	return out
}

func TestCompareWithEmbedded(t *testing.T) {
	projects := []string{"kyverno"}
	same := storeBundles(t, projects, func(s string) string { return s })
	cmp, err := CompareWithEmbedded(same)
	if err != nil || !cmp.Identical || !cmp.StoreEvidenceAt.Equal(cmp.EmbeddedEvidenceAt) || cmp.StoreEvidenceAt.IsZero() {
		t.Fatalf("identical: %+v %v", cmp, err)
	}

	// Every review one day later (and its window with it): newer evidence.
	shift := func(s string) string {
		shiftDate := func(s, key string) string {
			marker := `"` + key + `": "`
			i := strings.Index(s, marker)
			if i < 0 {
				return s
			}
			start := i + len(marker)
			at, err := time.Parse(time.RFC3339, s[start:start+20])
			if err != nil {
				t.Fatal(err)
			}
			return s[:start] + at.Add(24*time.Hour).Format(time.RFC3339) + s[start+20:]
		}
		return shiftDate(shiftDate(s, "reviewedAt"), "validUntil")
	}
	newer := storeBundles(t, projects, shift)
	cmp, err = CompareWithEmbedded(newer)
	if err != nil || cmp.Identical || !cmp.StoreEvidenceAt.After(cmp.EmbeddedEvidenceAt) || cmp.StoreEvidenceAt.Sub(cmp.EmbeddedEvidenceAt) != 24*time.Hour {
		t.Fatalf("newer: %+v %v", cmp, err)
	}

	// A project the store lacks is an empty envelope: no evidence, not identical.
	empty, err := EmptyExternalBundle("7", "operator_provided")
	if err != nil {
		t.Fatal(err)
	}
	cmp, err = CompareWithEmbedded(map[string]ExternalBundle{"kyverno": empty})
	if err != nil || cmp.Identical || !cmp.StoreEvidenceAt.IsZero() || cmp.EmbeddedEvidenceAt.IsZero() {
		t.Fatalf("absent: %+v %v", cmp, err)
	}
}
