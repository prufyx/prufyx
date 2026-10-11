// SPDX-License-Identifier: AGPL-3.0-only

package chartidentity

import (
	"reflect"
	"testing"
	"time"
)

// TestProjectChart: only an active row before its validUntil is usable; a
// withdrawn or expired row is counted, never returned, and the usable chart
// names of the project are listed for a caller that names an unknown chart.
func TestProjectChart(t *testing.T) {
	project, comp := slugComponent(t)
	row := func(repo, chart, state, until string) SourceRecord {
		return SourceRecord{RepoURL: repo, Chart: chart, Component: comp, Project: project,
			Evidence: SourceEvidence{State: state, ReviewedAt: "2030-01-01T00:00:00Z", ValidUntil: until, Sources: src()}}
	}
	table := &SourceTable{Schema: SourcesSchema, Records: []SourceRecord{
		row("https://a.example.com/charts", "agones", StateActive, "2030-06-01T00:00:00Z"),
		row("https://a.example.com/charts", "agones-old", StateWithdrawn, "2030-06-01T00:00:00Z"),
		row("https://b.example.com/charts", "agones", StateActive, "2030-03-01T00:00:00Z"),
		row("https://b.example.com/charts", "agones-short", StateActive, "2030-02-01T00:00:00Z"),
	}}
	if err := table.Validate(); err != nil {
		t.Fatal(err)
	}
	at := func(s string) time.Time { v, _ := time.Parse(time.RFC3339, s); return v }
	got := table.ProjectChart(project, "agones", at("2030-01-15T00:00:00Z"))
	if len(got.Usable) != 2 || got.Unusable != 0 || !reflect.DeepEqual(got.Charts, []string{"agones", "agones-short"}) {
		t.Fatalf("before expiry %+v", got)
	}
	got = table.ProjectChart(project, "agones", at("2030-04-01T00:00:00Z"))
	if len(got.Usable) != 1 || got.Usable[0].RepoURL != "https://a.example.com/charts" || got.Unusable != 1 {
		t.Fatalf("one expired %+v", got)
	}
	got = table.ProjectChart(project, "agones-old", at("2030-01-15T00:00:00Z"))
	if len(got.Usable) != 0 || got.Unusable != 1 {
		t.Fatalf("withdrawn %+v", got)
	}
	got = table.ProjectChart(project, "nope", at("2030-01-15T00:00:00Z"))
	if len(got.Usable) != 0 || got.Unusable != 0 || len(got.Charts) != 2 {
		t.Fatalf("unknown %+v", got)
	}
	if got := table.ProjectChart("other", "agones", at("2030-01-15T00:00:00Z")); len(got.Usable) != 0 || len(got.Charts) != 0 {
		t.Fatalf("other project %+v", got)
	}
}
