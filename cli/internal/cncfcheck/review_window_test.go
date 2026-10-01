// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func reviewWindowRule(t *testing.T, reviewed, validUntil time.Time) []byte {
	t.Helper()
	entry := kyvernoEntry(t)
	var rule map[string]json.RawMessage
	if err := json.Unmarshal(entry.Rule, &rule); err != nil {
		t.Fatal(err)
	}
	evidence := map[string]json.RawMessage{}
	if err := json.Unmarshal(rule["evidence"], &evidence); err != nil {
		t.Fatal(err)
	}
	evidence["reviewedAt"], _ = json.Marshal(reviewed.UTC().Format(time.RFC3339))
	evidence["validUntil"], _ = json.Marshal(validUntil.UTC().Format(time.RFC3339))
	rule["evidence"], _ = json.Marshal(evidence)
	raw, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCNCFReviewWindowBoundaries(t *testing.T) {
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	reviewed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name       string
		validUntil time.Time
		wantErr    bool
	}{
		{name: "exactly-90-days", validUntil: reviewed.Add(maxCNCFReviewWindow)},
		{name: "shorter", validUntil: reviewed.Add(24 * time.Hour)},
		{name: "90-days-plus-one-second", validUntil: reviewed.Add(maxCNCFReviewWindow + time.Second), wantErr: true},
		{name: "equal", validUntil: reviewed, wantErr: true},
		{name: "before", validUntil: reviewed.Add(-time.Second), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			rule := reviewWindowRule(t, reviewed, test.validUntil)
			_, err := b.parseRules([]json.RawMessage{rule})
			if (err != nil) != test.wantErr {
				t.Fatalf("parse error=%v wantErr=%v", err, test.wantErr)
			}
		})
	}
	invalid := reviewWindowRule(t, reviewed, reviewed.Add(maxCNCFReviewWindow))
	invalid = bytes.Replace(invalid, []byte(`"reviewedAt":"2026-01-01T00:00:00Z"`), []byte(`"reviewedAt":"not-a-time"`), 1)
	if _, err := b.parseRules([]json.RawMessage{invalid}); err == nil {
		t.Fatal("invalid review timestamp accepted")
	}
}

func TestExternalParserSharesCNCFReviewWindow(t *testing.T) {
	reviewed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	entry := kyvernoEntry(t)
	entry.Rule = reviewWindowRule(t, reviewed, reviewed.Add(maxCNCFReviewWindow+time.Second))
	if _, err := ParseExternalBundle(externalFixture(t, []Entry{entry})); err == nil {
		t.Fatal("external rule exceeded the CNCF 90-day review window")
	}

	entry.Rule = reviewWindowRule(t, reviewed, reviewed.Add(maxCNCFReviewWindow))
	if _, err := ParseExternalBundle(externalFixture(t, []Entry{entry})); err != nil {
		t.Fatalf("exact CNCF 90-day review window rejected: %v", err)
	}
}
