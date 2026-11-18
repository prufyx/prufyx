// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"
)

// packClock returns an instant inside the review window of every rule and
// record of the embedded pack: one hour after the newest reviewedAt or
// derivedAt anywhere in it. It is derived from the
// rule data, so renewing rules (a data-only change) never needs a test edit.
// Every lease is far longer than one hour, so no rule is stale at this clock.
func packClock(t *testing.T) time.Time {
	t.Helper()
	raw, err := os.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var newest time.Time
	var walk func(any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			for key, child := range v {
				if text, ok := child.(string); ok && (key == "reviewedAt" || key == "derivedAt") {
					at, err := time.Parse(time.RFC3339, text)
					if err != nil {
						t.Fatalf("%s %q: %v", key, text, err)
					}
					if at.After(newest) {
						newest = at
					}
					continue
				}
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(doc)
	if newest.IsZero() {
		t.Fatal("the embedded pack holds no review time")
	}
	return newest.UTC().Add(time.Hour)
}

// ruleClock is one hour after the named rule's reviewedAt: inside its window.
func ruleClock(t *testing.T, ruleID string) time.Time {
	t.Helper()
	reviewed, _ := ruleEvidenceBounds(t, ruleID)
	return reviewed.Add(time.Hour)
}

func entryEvidenceBounds(t *testing.T, entry Entry) (reviewed, until time.Time) {
	t.Helper()
	var rule struct {
		Evidence struct {
			ReviewedAt string `json:"reviewedAt"`
			ValidUntil string `json:"validUntil"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(entry.Rule, &rule); err != nil {
		t.Fatal(err)
	}
	var err error
	if reviewed, err = time.Parse(time.RFC3339, rule.Evidence.ReviewedAt); err != nil {
		t.Fatal(err)
	}
	if until, err = time.Parse(time.RFC3339, rule.Evidence.ValidUntil); err != nil {
		t.Fatal(err)
	}
	return reviewed, until
}

var (
	syntheticOnce                     sync.Once
	syntheticReviewed, syntheticUntil string
)

// syntheticWindow is the review window of the synthetic test rules: it starts
// a day before the pack's clock and lasts 60 days, so a synthetic rule is
// current at packClock whatever the real rules' review dates are.
func syntheticWindow() (reviewed, until string) {
	syntheticOnce.Do(func() {
		b, err := load()
		if err != nil {
			panic(err)
		}
		var newest time.Time
		for _, entry := range b.pack.Entries {
			var rule struct {
				Evidence struct {
					ReviewedAt string `json:"reviewedAt"`
				} `json:"evidence"`
			}
			if json.Unmarshal(entry.Rule, &rule) != nil {
				panic("rule evidence")
			}
			at, err := time.Parse(time.RFC3339, rule.Evidence.ReviewedAt)
			if err != nil {
				panic(err)
			}
			if at.After(newest) {
				newest = at
			}
		}
		start := newest.Add(-24 * time.Hour).UTC()
		syntheticReviewed = start.Format(time.RFC3339)
		syntheticUntil = start.Add(60 * 24 * time.Hour).Format(time.RFC3339)
	})
	return syntheticReviewed, syntheticUntil
}
