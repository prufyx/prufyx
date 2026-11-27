// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"reflect"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/chartidentity"
	"github.com/prufyx/prufyx/cli/internal/intake"
)

func helmAndAppLabels(slug string) (both, chartOnly, appOnly []intake.Document) {
	one := func(labels map[string]any) []intake.Document { return []intake.Document{workload(labels, nil)} }
	return one(map[string]any{labelHelmChart: slug + "-9.8.7", labelAppName: slug, labelAppVersion: "0.0.1"}),
		one(map[string]any{labelHelmChart: slug + "-9.8.7"}),
		one(map[string]any{labelAppName: slug, labelAppVersion: "0.0.1"})
}

// A chart label of a chart a reviewed table mentions is never ignored: with no
// usable source for it, an app version beside it is a conflict, never the
// answer.
func TestChartLabelWithoutUsableSourceIsNotIgnored(t *testing.T) {
	charts, err := loadEmbeddedCharts()
	if err != nil {
		t.Fatal(err)
	}
	const slug = "cert-manager"
	var now time.Time
	var component string
	for _, source := range charts.sources.Records {
		if source.Chart == slug && source.Project == slug {
			reviewed, err := time.Parse(time.RFC3339, source.Evidence.ReviewedAt)
			if err != nil {
				t.Fatal(err)
			}
			now, component = reviewed.Add(time.Hour), source.Component
		}
	}
	if now.IsZero() {
		t.Fatal("no embedded cert-manager chart source")
	}
	edit := func(change func(*chartidentity.SourceRecord) bool) embeddedCharts {
		table := *charts.sources
		table.Records = nil
		for _, row := range charts.sources.Records {
			if row.Chart != slug || change(&row) {
				table.Records = append(table.Records, row)
			}
		}
		return embeddedCharts{sources: &table, versions: charts.versions}
	}
	removed := func(*chartidentity.SourceRecord) bool { return false }
	orphaned := edit(removed)
	orphaned.versions = &chartidentity.AppVersionTable{Schema: charts.versions.Schema, Records: []chartidentity.AppVersionRecord{{
		Component: component, Chart: slug, ChartVersion: "9.8.7", AppVersion: "1.2.3",
		Evidence: chartidentity.AppVersionEvidence{ValidUntil: now.AddDate(0, 1, 0).Format(time.RFC3339)}}}}
	both, chartOnly, appOnly := helmAndAppLabels(slug)
	for name, tables := range map[string]embeddedCharts{
		"current source, no app version row": charts,
		"expired": edit(func(r *chartidentity.SourceRecord) bool {
			r.Evidence.ValidUntil = now.Format(time.RFC3339)
			return true
		}),
		"withdrawn": edit(func(r *chartidentity.SourceRecord) bool {
			r.Evidence.State = chartidentity.StateWithdrawn
			return true
		}),
		"source removed, app version row kept": orphaned,
	} {
		t.Run(name, func(t *testing.T) {
			got := detectVersions(both, []string{slug}, tables, now)[slug]
			if got.Version != "" || !got.Conflict || got.Unusable != 1 {
				t.Fatalf("disagreeing labels: %+v", got)
			}
			got = detectVersions(chartOnly, []string{slug}, tables, now)[slug]
			if got.Version != "" || got.Conflict || got.Unusable != 1 {
				t.Fatalf("chart label alone: %+v", got)
			}
			// Control: without a chart label the app label still detects.
			if got := detectVersions(appOnly, []string{slug}, tables, now)[slug]; got.Version != "0.0.1" || got.Conflict {
				t.Fatalf("app label alone: %+v", got)
			}
		})
	}
	// KNOWN LIMIT, pinned so a change is noticed: with every row about the
	// chart removed it cannot be told from a chart never reviewed, and the
	// app label decides.
	t.Run("every row removed", func(t *testing.T) {
		got := detectVersions(both, []string{slug}, edit(removed), now)[slug]
		if got.Version != "0.0.1" || got.Conflict || got.Unusable != 0 {
			t.Fatalf("known limit changed: %+v", got)
		}
	})
}

// A Helm install of a project no chart table mentions is read as before: the
// app label decides, and the chart label alone says nothing.
func TestChartLabelOfUnmentionedChartIsNotRead(t *testing.T) {
	charts, err := loadEmbeddedCharts()
	if err != nil {
		t.Fatal(err)
	}
	const slug = "strimzi"
	if charts.Mentions(slug) {
		t.Fatalf("%s is in a chart table; pick another project", slug)
	}
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	both, chartOnly, appOnly := helmAndAppLabels(slug)
	want := detection{Version: "0.0.1", Signals: []string{signalAppLabel}, Seen: 1}
	for name, documents := range map[string][]intake.Document{"both labels": both, "app label alone": appOnly} {
		if got := detectVersions(documents, []string{slug}, charts, now)[slug]; !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: %+v", name, got)
		}
	}
	if got, found := detectVersions(chartOnly, []string{slug}, charts, now)[slug]; found {
		t.Fatalf("chart label alone: %+v", got)
	}
}
