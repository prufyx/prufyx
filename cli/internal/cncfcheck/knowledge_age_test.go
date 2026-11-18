// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestKnowledgeAgeEmbedded: the embedded pack's active rules are listed with
// their end dates, and a withdrawn rule is not. The expectation is read from
// the pack file directly.
func TestKnowledgeAgeEmbedded(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("data", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Entries []struct {
			Rule struct {
				Evidence struct {
					State      string `json:"state"`
					ValidUntil string `json:"validUntil"`
				} `json:"evidence"`
			} `json:"rule"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	active, withdrawn := 0, 0
	var earliest time.Time
	for _, entry := range pack.Entries {
		if entry.Rule.Evidence.State != "active" {
			withdrawn++
			continue
		}
		active++
		end, err := time.Parse(time.RFC3339, entry.Rule.Evidence.ValidUntil)
		if err != nil {
			t.Fatal(err)
		}
		if earliest.IsZero() || end.Before(earliest) {
			earliest = end
		}
	}
	sources, err := EmbeddedKnowledgeAge()
	if err != nil || len(sources) != 1 || sources[0].ID != "embedded" {
		t.Fatalf("%+v %v", sources, err)
	}
	if len(sources[0].Expiries) != active || withdrawn == 0 {
		t.Fatalf("listed %d rules, want %d active (%d not active)", len(sources[0].Expiries), active, withdrawn)
	}
	var first time.Time
	for _, end := range sources[0].Expiries {
		if first.IsZero() || end.Before(first) {
			first = end
		}
	}
	if !first.Equal(earliest) {
		t.Fatalf("earliest %s, want %s", first, earliest)
	}
	snapshot, err := LoadScanKnowledge()
	if err != nil {
		t.Fatal(err)
	}
	if got := snapshot.KnowledgeAge(); len(got) != 1 || len(got[0].Expiries) != active {
		t.Fatalf("snapshot lists %d sources", len(got))
	}
}

// TestActiveRuleEndsSkipsInactive: only active rules count.
func TestActiveRuleEndsSkipsInactive(t *testing.T) {
	t.Parallel()
	entries := []Entry{
		{Rule: json.RawMessage(`{"evidence":{"state":"active","validUntil":"2026-12-07T00:00:00Z"}}`)},
		{Rule: json.RawMessage(`{"evidence":{"state":"withdrawn","validUntil":"2026-11-01T00:00:00Z"}}`)},
		{Rule: json.RawMessage(`{"evidence":{"state":"active","validUntil":"soon"}}`)},
		{Rule: json.RawMessage(`not json`)},
	}
	got := activeRuleEnds(entries)
	if len(got) != 1 || !got[0].Equal(time.Date(2026, 12, 7, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("%v", got)
	}
}

// TestPinnedRulesAreTheirOwnAgeBucket: an active rule on a pinned lease is not
// an end date (it never counts as expiring ten years out); it is reported in
// its own bucket with its reviewedAt. A pinned rule that is withdrawn is in
// neither, and the strict listing still refuses an unreadable pinned date.
func TestPinnedRulesAreTheirOwnAgeBucket(t *testing.T) {
	t.Parallel()
	entries := []Entry{
		{Rule: json.RawMessage(`{"evidence":{"state":"active","validUntil":"2026-12-07T00:00:00Z"}}`)},
		{Rule: json.RawMessage(`{"evidence":{"state":"active","lease":"pinned","reviewedAt":"2027-03-02T00:00:00Z","validUntil":"2037-03-02T00:00:00Z"}}`)},
		{Rule: json.RawMessage(`{"evidence":{"state":"active","lease":"pinned","reviewedAt":"2027-03-01T00:00:00Z","validUntil":"2037-03-01T00:00:00Z"}}`)},
		{Rule: json.RawMessage(`{"evidence":{"state":"withdrawn","lease":"pinned","reviewedAt":"2026-01-01T00:00:00Z","validUntil":"2036-01-01T00:00:00Z"}}`)},
		{Rule: json.RawMessage(`{"evidence":{"state":"active","lease":"time","validUntil":"2027-01-01T00:00:00Z"}}`)},
	}
	if got := activeRuleEnds(entries); len(got) != 2 || got[0].Year() != 2026 || got[1].Year() != 2027 {
		t.Fatalf("a pinned rule is in the end dates: %v", got)
	}
	reviews := pinnedRuleReviews(entries)
	if len(reviews) != 2 || !reviews[1].Equal(time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("pinned bucket: %v", reviews)
	}
	strict, err := strictRuleEnds(entries)
	if err != nil || len(strict) != 2 {
		t.Fatalf("strict ends %v %v", strict, err)
	}
	bad := []Entry{{Rule: json.RawMessage(`{"evidence":{"state":"active","lease":"pinned","validUntil":"soon"}}`)}}
	if _, err := strictRuleEnds(bad); err == nil {
		t.Fatal("an unreadable pinned date was accepted")
	}
}
