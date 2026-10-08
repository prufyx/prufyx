// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
	"github.com/prufyx/prufyx/cli/internal/knowledgeage"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

func scanAt(t *testing.T, knowledge Knowledge, now string, extra ...string) Result {
	t.Helper()
	argv := append(append([]string{"applyset.yaml"}, declared...), "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3")
	if now != "" {
		argv = append(argv, "--now", now)
	}
	return mustScan(t, knowledge, append(argv, extra...)...)
}

// ageInstants are the shared clock and the instants 14 days before it and 20
// days after it: before, inside and after the 30-day window of the earliest
// expiry of the embedded pack (derived from the pack, see supersedeids.Clock).
// insideNow is the instant inside the age window, as a --now value.
func insideNow() string {
	_, inside, _ := ageInstants()
	return inside
}

func ageInstants() (before, inside, after string) {
	b, i, a := supersedeids.AgeClocks()
	return b.Format(time.RFC3339), i.Format(time.RFC3339), a.Format(time.RFC3339)
}

func embeddedEarliest(t *testing.T) time.Time {
	t.Helper()
	sources, err := cncfcheck.EmbeddedKnowledgeAge()
	if err != nil {
		t.Fatal(err)
	}
	var first time.Time
	for _, end := range sources[0].Expiries {
		if first.IsZero() || end.Before(first) {
			first = end
		}
	}
	return first
}

// TestScanKnowledgeAgeEmbedded: before the window no note, inside it a note
// that names the earliest end date, after it a note that says the rules
// expired. The window edges are exact: 30 days before the earliest end date
// is inside, one second earlier is not; the end date itself is expired.
func TestScanKnowledgeAgeEmbedded(t *testing.T) {
	dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	first := embeddedEarliest(t)
	_, inside, after := ageInstants()
	at := func(d time.Duration) string { return first.Add(d).Format(time.RFC3339) }
	cases := []struct {
		name, now string
		want      string // substring of the note; "" for none
	}{
		{"31 days before", at(-31 * 24 * time.Hour), ""},
		{"edge: one second outside", at(-knowledgeage.Window - time.Second), ""},
		{"edge: exactly 30 days", at(-knowledgeage.Window), "expire within 30 days"},
		{"inside", inside, "expire within 30 days, the earliest on " + first.Format("2006-01-02") + " (in 17 days)"},
		{"one second before the end", at(-time.Second), "expire within 30 days"},
		{"the end date", at(0), "have expired, the earliest on " + first.Format("2006-01-02")},
		{"after", after, "have expired, the earliest on " + first.Format("2006-01-02") + " (2 days ago)"},
	}
	inDir(t, dir, func() {
		for _, c := range cases {
			result := scanAt(t, nil, c.now)
			switch {
			case c.want == "" && result.KnowledgeAge != "":
				t.Errorf("%s: note %q", c.name, result.KnowledgeAge)
			case c.want != "" && !strings.Contains(result.KnowledgeAge, c.want):
				t.Errorf("%s: note %q, want %q", c.name, result.KnowledgeAge, c.want)
			}
			if result.KnowledgeAge != "" {
				if !strings.Contains(result.KnowledgeAge, "No official update yet: build from newer source, or `prufyx db import` a signed package you trust (then use --knowledge-db)") || strings.Contains(result.KnowledgeAge, "db update") || len("prufyx: "+result.KnowledgeAge+"\n") > 256 {
					t.Errorf("%s: %q", c.name, result.KnowledgeAge)
				}
			}
			again := scanAt(t, nil, c.now)
			if again.KnowledgeAge != result.KnowledgeAge {
				t.Errorf("%s: not deterministic", c.name)
			}
		}
	})
}

// TestScanKnowledgeAgeNotInReport: the note is not part of any output. The
// report and every rendering are the same whether or not the knowledge can
// tell its age.
func TestScanKnowledgeAgeNotInReport(t *testing.T) {
	dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	inDir(t, dir, func() {
		for _, clock := range ageClocks {
			aged := scanAt(t, nil, clock.now)
			plain := scanAt(t, agelessKnowledge{LoadEmbeddedForTest(t)}, clock.now)
			if plain.KnowledgeAge != "" {
				t.Fatalf("knowledge without ages gave a note: %q", plain.KnowledgeAge)
			}
			if aged.Exit != plain.Exit {
				t.Errorf("%s: exit %d vs %d", clock.name, aged.Exit, plain.Exit)
			}
			for _, format := range scanreport.Formats() {
				a, _ := scanreport.Render(aged.Report, format, scanreport.RenderOptions{Verbose: true, ShowPasses: true})
				b, _ := scanreport.Render(plain.Report, format, scanreport.RenderOptions{Verbose: true, ShowPasses: true})
				if string(a) != string(b) || strings.Contains(string(a), "knowledge rules") {
					t.Errorf("%s/%s: output differs or carries the note", clock.name, format)
				}
			}
		}
	})
}

// agelessKnowledge hides the optional age method of the knowledge it wraps.
type agelessKnowledge struct{ Knowledge }

// LoadEmbeddedForTest loads the embedded knowledge.
func LoadEmbeddedForTest(t *testing.T) Knowledge {
	t.Helper()
	embedded, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	return embedded
}

// TestScanKnowledgeAgeRedact: --redact changes nothing about the note, and
// the note names neither a path nor an input.
func TestScanKnowledgeAgeRedact(t *testing.T) {
	dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	inDir(t, dir, func() {
		plain := scanAt(t, nil, insideNow())
		redacted := scanAt(t, nil, insideNow(), "--redact")
		if plain.KnowledgeAge == "" || plain.KnowledgeAge != redacted.KnowledgeAge || redacted.Exit != plain.Exit {
			t.Fatalf("%q vs %q", plain.KnowledgeAge, redacted.KnowledgeAge)
		}
		for _, forbidden := range []string{dir, "applyset", "nightly-report", "/"} {
			if strings.Contains(plain.KnowledgeAge, forbidden) {
				t.Errorf("note names %q: %s", forbidden, plain.KnowledgeAge)
			}
		}
	})
}

// renewedWindow is the lease of renewedAll: reviewed 9 days before the "after"
// instant (so before it, after the pack's own clock) and valid for 89 days.
func renewedWindow() (reviewed, until time.Time) {
	_, _, after := supersedeids.AgeClocks()
	reviewed = after.AddDate(0, 0, -9)
	return reviewed, reviewed.AddDate(0, 0, 89)
}

// renewedAll is the embedded pack with every rule reviewed and valid for
// renewedWindow.
func renewedAll(t *testing.T) []byte {
	reviewed, until := renewedWindow()
	return editPack(t, embeddedPack(t), func(project string, rule map[string]any) bool {
		evidence := rule["evidence"].(map[string]any)
		evidence["reviewedAt"], evidence["validUntil"] = reviewed.Format(time.RFC3339), until.Format(time.RFC3339)
		return true
	})
}

// TestScanKnowledgeAgeStore: the note describes the database's own rules,
// not the embedded pack, in either layout (a single-target database serves
// every project's rules, a per-project one the opened project's), and its
// hint does not tell the operator to use a database they already use.
func TestScanKnowledgeAgeStore(t *testing.T) {
	reviewed, end := renewedWindow()
	endDay := end.Format("2006-01-02")
	before, _, after := ageInstants()
	first := embeddedEarliest(t)
	for _, layout := range storeLayouts {
		renewed := newStoreFixture(t, layout)
		renewed.importPack(renewedAll(t), "6")
		stale := newStoreFixture(t, layout)
		stale.importPack(nil, "5")
		dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
		inDir(t, dir, func() {
			active := countRules(t, layout, "9999-01-01T00:00:00Z")
			if active == 0 {
				t.Fatal("no rules counted")
			}
			note := func(store *Store) string { return scanAt(t, store, "").KnowledgeAge }
			cases := []struct{ at, want string }{
				{reviewed.AddDate(0, 0, 14).Format(time.RFC3339), ""},
				{end.Add(-knowledgeage.Window - time.Second).Format(time.RFC3339), ""},
				{end.Add(-knowledgeage.Window).Format(time.RFC3339), "note: " + itoa(active) + " knowledge rules expire within 30 days, the earliest on " + endDay + " (in 30 days). No official update yet: `prufyx db import` a newer signed package you trust, or build from newer source before they expire."},
				{end.AddDate(0, 0, -18).Format(time.RFC3339), "note: " + itoa(active) + " knowledge rules expire within 30 days, the earliest on " + endDay + " (in 18 days). No official update yet: `prufyx db import` a newer signed package you trust, or build from newer source before they expire."},
				{end.Format(time.RFC3339), "note: " + itoa(active) + " knowledge rules have expired, the earliest on " + endDay + " (less than a day ago). No official update yet: `prufyx db import` a newer signed package you trust, or build from newer source. Expired rules answer UNKNOWN."},
				{end.AddDate(0, 0, 2).Format(time.RFC3339), "note: " + itoa(active) + " knowledge rules have expired, the earliest on " + endDay + " (2 days ago). No official update yet: `prufyx db import` a newer signed package you trust, or build from newer source. Expired rules answer UNKNOWN."},
			}
			for _, c := range cases {
				if got := note(openAt(t, renewed.store, c.at)); got != c.want {
					t.Errorf("%s %s:\n%q\nwant %q", layout, c.at, got, c.want)
				}
			}
			// The embedded-pack database is described by its own dates: the
			// embedded end dates are in December, the renewed ones are not.
			expired := countRules(t, layout, after)
			want := "note: " + itoa(expired) + " knowledge " + plural(expired, "rule has", "rules have") + " expired, the earliest on " + first.Format("2006-01-02") + " (2 days ago). No official update yet: `prufyx db import` a newer signed package you trust, or build from newer source. Expired rules answer UNKNOWN."
			if got := note(openAt(t, stale.store, after)); got != want || expired == 0 {
				t.Errorf("%s stale database: %q, want %q", layout, got, want)
			}
			if got := note(openAt(t, stale.store, before)); got != "" {
				t.Errorf("%s stale database before the window: %q", layout, got)
			}
			if got := note(openAt(t, renewed.store, after)); got != "" {
				t.Errorf("%s renewed database at a date the embedded pack would warn at: %q", layout, got)
			}
		})
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// countRules counts the embedded pack's active rules a database of the
// layout serves for the kubernetes scan whose end date is not after at.
func countRules(t *testing.T, layout, at string) int {
	t.Helper()
	limit, err := time.Parse(time.RFC3339, at)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	editPack(t, embeddedPack(t), func(project string, rule map[string]any) bool {
		evidence := rule["evidence"].(map[string]any)
		end, err := time.Parse(time.RFC3339, evidence["validUntil"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if evidence["state"] == "active" && !end.After(limit) && (layout == cncfknowledge.LayoutSingleTarget || project == kubernetesSlug) {
			count++
		}
		return true
	})
	return count
}
