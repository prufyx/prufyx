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

// shiftReviews moves every reviewedAt and validUntil of a rule by d.
func shiftReviews(t *testing.T, d time.Duration) func(string) string {
	t.Helper()
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
		return s[:start] + at.Add(d).Format(time.RFC3339) + s[start+20:]
	}
	return func(s string) string { return shiftDate(shiftDate(s, "reviewedAt"), "validUntil") }
}

func TestCompareWithEmbedded(t *testing.T) {
	projects := []string{"kyverno"}
	same := storeBundles(t, projects, func(s string) string { return s })
	cmp, err := CompareWithEmbedded(same)
	if err != nil || !cmp.Identical || !cmp.StoreEvidenceAt.Equal(cmp.EmbeddedEvidenceAt) || cmp.StoreEvidenceAt.IsZero() {
		t.Fatalf("identical: %+v %v", cmp, err)
	}

	// Every review one day later (and its window with it): newer evidence.
	shift := shiftReviews(t, 24*time.Hour)
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

// TestCompareWithEmbeddedMixedProjects: newer on one project and older on
// another is reported as stale for the older one, with that project's dates.
func TestCompareWithEmbeddedMixedProjects(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	other := ""
	for _, entry := range base.pack.Entries {
		if entry.Project != "kyverno" {
			other = entry.Project
			break
		}
	}
	if other == "" {
		t.Skip("no second project with rules")
	}
	newer := storeBundles(t, []string{"kyverno"}, shiftReviews(t, 24*time.Hour))
	older := storeBundles(t, []string{other}, shiftReviews(t, -24*time.Hour))
	cmp, err := CompareWithEmbedded(map[string]ExternalBundle{"kyverno": newer["kyverno"], other: older[other]})
	if err != nil || cmp.StaleProject != other || cmp.Identical {
		t.Fatalf("mixed: %+v %v", cmp, err)
	}
	if got := cmp.EmbeddedEvidenceAt.Sub(cmp.StoreEvidenceAt); got != 24*time.Hour {
		t.Fatalf("dates are not the stale project's: %v", got)
	}
	// Both newer: nothing stale.
	both := storeBundles(t, []string{"kyverno", other}, shiftReviews(t, 24*time.Hour))
	if cmp, err := CompareWithEmbedded(both); err != nil || cmp.StaleProject != "" {
		t.Fatalf("both newer: %+v %v", cmp, err)
	}
}
