// SPDX-License-Identifier: AGPL-3.0-only

package releasefreshness

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledgeage"
)

func TestCheck(t *testing.T) {
	commit := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	boundary := commit.AddDate(0, 0, 30)
	cases := []struct {
		name     string
		earliest time.Time
		ok       bool
	}{
		{"later", boundary.Add(24 * time.Hour), true},
		{"equal boundary", boundary, true},
		{"one second earlier", boundary.Add(-time.Second), false},
		{"earlier", commit, false},
		{"offset zone same instant", boundary.In(time.FixedZone("x", 3*3600)), true},
	}
	for _, c := range cases {
		if err := Check(c.earliest, commit, DefaultMinDays); (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestEarliest(t *testing.T) {
	a := time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)
	b := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	got, err := Earliest([]knowledgeage.Source{{ID: "a", Expiries: []time.Time{a}}, {ID: "b", Expiries: []time.Time{a, b}}})
	if err != nil || !got.Equal(b) {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := Earliest([]knowledgeage.Source{{ID: "empty"}}); err == nil {
		t.Fatal("no evidence must fail")
	}
}

func TestRunOnEmbeddedData(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run(nil, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	earliest, err := time.Parse(time.RFC3339, strings.TrimSpace(out.String()))
	if err != nil || earliest.Location() != time.UTC {
		t.Fatalf("not canonical UTC RFC 3339: %q", out.String())
	}
	// The minimum over all evidence cannot be later than the minimum over the
	// CNCF pack alone (rules, line attestations, served APIs, path policies).
	pack, err := cncfcheck.EmbeddedEvidenceAge()
	if err != nil {
		t.Fatal(err)
	}
	limit, err := Earliest(pack)
	if err != nil {
		t.Fatal(err)
	}
	if earliest.After(limit) {
		t.Fatalf("earliest %s ignores part of the CNCF pack (<= %s expected)", earliest.Format(time.RFC3339), limit.Format(time.RFC3339))
	}
	out.Reset()
	if err := Run([]string{"--min-days", "0"}, &out, &errOut); err == nil {
		t.Fatal("--min-days below 1 must be rejected")
	}
	if err := Run([]string{"--commit-date", "2000-01-01T00:00:00+02:00"}, &out, &errOut); err != nil {
		t.Fatalf("old commit must pass: %v", err)
	}
	if err := Run([]string{"--commit-date", earliest.Format(time.RFC3339)}, &out, &errOut); err == nil {
		t.Fatal("commit at the earliest expiry must fail")
	}
	if err := Run([]string{"--commit-date", "garbage"}, &out, &errOut); err == nil {
		t.Fatal("bad date must fail")
	}
}
