// SPDX-License-Identifier: AGPL-3.0-only

package knowledgeage

import (
	"strings"
	"testing"
	"time"
)

var base = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func one(ends ...time.Time) []Source { return []Source{{ID: "a", Expiries: ends}} }

// TestWindowBoundaries: a rule ending exactly 30 days after the instant is
// inside the window; one second later it is not. A rule ending at the
// instant has expired, one second later it is expiring. These are the
// boundaries the engine itself uses (a rule is stale from its end date on).
func TestWindowBoundaries(t *testing.T) {
	cases := []struct {
		name              string
		end               time.Time
		expired, expiring int
	}{
		{"31 days", base.Add(Window + 24*time.Hour), 0, 0},
		{"30 days plus one second", base.Add(Window + time.Second), 0, 0},
		{"exactly 30 days", base.Add(Window), 0, 1},
		{"30 days minus one second", base.Add(Window - time.Second), 0, 1},
		{"one second left", base.Add(time.Second), 0, 1},
		{"exactly now", base, 1, 0},
		{"one second ago", base.Add(-time.Second), 1, 0},
		{"long ago", base.Add(-400 * 24 * time.Hour), 1, 0},
	}
	for _, c := range cases {
		got := Summarize(one(c.end), base)
		if got.Expired != c.expired || got.Expiring != c.expiring {
			t.Errorf("%s: %+v, want expired %d expiring %d", c.name, got, c.expired, c.expiring)
		}
		if line := Line(got, base, true); (line == "") != (c.expired+c.expiring == 0) {
			t.Errorf("%s: line %q", c.name, line)
		}
	}
}

func TestLineWording(t *testing.T) {
	soon := base.Add(17*24*time.Hour + 3*time.Hour)
	summary := Summarize(one(soon, soon.Add(24*time.Hour), base.Add(90*24*time.Hour)), base)
	want := "note: 2 knowledge rules expire within 30 days, the earliest on 2026-12-07 (in 17 days). No official update yet: build from newer source, or `prufyx db import` a signed package you trust (then use --knowledge-db) before they expire."
	if got := Line(summary, base, true); got != want {
		t.Errorf("embedded:\n%s\n%s", got, want)
	}
	want = "note: 2 knowledge rules expire within 30 days, the earliest on 2026-12-07 (in 17 days). No official update yet: `prufyx db import` a newer signed package you trust, or build from newer source before they expire."
	if got := Line(summary, base, false); got != want {
		t.Errorf("store:\n%s\n%s", got, want)
	}
	ended := base.Add(-2*24*time.Hour - time.Hour)
	want = "note: 1 knowledge rule has expired, the earliest on 2026-11-18 (2 days ago). No official update yet: build from newer source, or `prufyx db import` a signed package you trust (then use --knowledge-db). Expired rules answer UNKNOWN."
	if got := Line(Summarize(one(ended, soon), base), base, true); got != want {
		t.Errorf("expired:\n%s\n%s", got, want)
	}
	if got := Line(Summarize(one(base.Add(time.Hour)), base), base, false); !strings.Contains(got, "(in less than a day)") || !strings.Contains(got, "1 knowledge rule expires") {
		t.Errorf("under a day: %s", got)
	}
	if got := Line(Summarize(one(base.Add(-time.Hour)), base), base, false); !strings.Contains(got, "(less than a day ago)") {
		t.Errorf("under a day ago: %s", got)
	}
	if got := Line(Summarize(one(base.Add(24*time.Hour)), base), base, false); !strings.Contains(got, "(in 1 day)") {
		t.Errorf("one day: %s", got)
	}
}

// TestLineBounds: one line, plain text, at most 256 bytes even for very
// large counts, and no path.
func TestLineBounds(t *testing.T) {
	ends := make([]time.Time, 100000)
	for i := range ends {
		ends[i] = base.Add(-10000 * 24 * time.Hour)
	}
	for _, embedded := range []bool{true, false} {
		for _, summary := range []Summary{Summarize(one(ends...), base), Summarize(one(base.Add(time.Hour)), base)} {
			line := Line(summary, base, embedded)
			if len(line) == 0 || len(line) > 256-len("prufyx: \n") || strings.ContainsAny(line, "\n\r\t/\\") {
				t.Errorf("%q", line)
			}
		}
	}
}

// TestSourcesCountedOnce: a body of knowledge used several times counts
// once; different bodies add up.
func TestSourcesCountedOnce(t *testing.T) {
	end := base.Add(24 * time.Hour)
	same := []Source{{ID: "x", Expiries: []time.Time{end}}, {ID: "x", Expiries: []time.Time{end}}, {ID: "y", Expiries: []time.Time{end, end}}}
	if got := Summarize(same, base); got.Expiring != 3 {
		t.Errorf("%+v", got)
	}
	if got := Summarize(nil, base); got != (Summary{}) || Line(got, base, true) != "" {
		t.Errorf("empty: %+v", got)
	}
	merged := Merge([]Source{{ID: "b"}}, []Source{{ID: "a"}})
	if merged[0].ID != "a" || merged[1].ID != "b" {
		t.Errorf("%+v", merged)
	}
}

// TestDeterministic: the same inputs give the same line.
func TestDeterministic(t *testing.T) {
	a := Line(Summarize(one(base.Add(5*24*time.Hour)), base), base, true)
	b := Line(Summarize(one(base.Add(5*24*time.Hour)), base), base, true)
	if a != b || a == "" {
		t.Fatal(a, b)
	}
}

// TestLineAdviceWorksToday: no official knowledge feed exists, so the note
// must not send the user to a command that cannot succeed for them
// (`prufyx db update` needs a source and a trust root they do not have). It
// names what works today: newer source, or a signed package they trust.
func TestLineAdviceWorksToday(t *testing.T) {
	ended := base.Add(-2 * 24 * time.Hour)
	soon := base.Add(5 * 24 * time.Hour)
	for _, embedded := range []bool{true, false} {
		for _, end := range []time.Time{ended, soon} {
			line := Line(Summarize(one(end), base), base, embedded)
			if strings.Contains(line, "db update") || !strings.Contains(line, "`prufyx db import`") || !strings.Contains(line, "newer source") || !strings.Contains(line, "No official update yet") {
				t.Errorf("embedded=%v: %q", embedded, line)
			}
			if embedded != strings.Contains(line, "--knowledge-db") {
				t.Errorf("embedded=%v: --knowledge-db advice is wrong: %q", embedded, line)
			}
		}
	}
	if line := Line(Summarize(one(ended), base), base, true); !strings.Contains(line, "answer UNKNOWN") {
		t.Errorf("an expired line must say what the expired rules answer: %q", line)
	}
}
