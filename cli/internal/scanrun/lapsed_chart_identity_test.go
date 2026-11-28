// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

// Chart records that expired, were withdrawn or were removed. Run with:
// go test -run Lapsed ./internal/scanrun/

import (
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/chartidentity"
	"github.com/prufyx/prufyx/cli/internal/intake"
)

// lapsedChartSubject is the embedded chart-source table's cert-manager chart,
// at an instant its source is current, with one app-version row added for the
// test (the shipped app-version table may hold none).
func lapsedChartSubject(t *testing.T) (embeddedCharts, chartidentity.AppVersionRecord, time.Time) {
	t.Helper()
	charts, err := loadEmbeddedCharts()
	if err != nil {
		t.Fatal(err)
	}
	const name = "cert-manager"
	for _, source := range charts.sources.Records {
		if source.Chart != name || source.Project != name {
			continue
		}
		now, err := time.Parse(time.RFC3339, source.Evidence.ReviewedAt)
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Hour)
		row := chartidentity.AppVersionRecord{Component: source.Component, Chart: name, ChartVersion: "9.8.7", AppVersion: "1.2.3",
			Evidence: chartidentity.AppVersionEvidence{DerivedAt: now.Add(-time.Hour).Format(time.RFC3339), ValidUntil: now.AddDate(0, 1, 0).Format(time.RFC3339)}}
		charts.versions = &chartidentity.AppVersionTable{Schema: charts.versions.Schema, Records: []chartidentity.AppVersionRecord{row}}
		return charts, row, now
	}
	t.Fatal("no embedded cert-manager chart source")
	return embeddedCharts{}, chartidentity.AppVersionRecord{}, time.Time{}
}

// editSources returns the tables with the subject's chart-source rows edited;
// a row for which edit returns false is removed.
func editSources(charts embeddedCharts, chart string, edit func(*chartidentity.SourceRecord) bool) embeddedCharts {
	table := *charts.sources
	table.Records = nil
	for _, row := range charts.sources.Records {
		if row.Chart != chart || edit(&row) {
			table.Records = append(table.Records, row)
		}
	}
	return embeddedCharts{sources: &table, versions: charts.versions}
}

func lapsedWorkload(labels map[string]any) []intake.Document {
	return []intake.Document{{APIVersion: "apps/v1", Kind: "Deployment", Value: map[string]any{"metadata": map[string]any{"labels": labels}}}}
}

func TestLapsedChartRecords(t *testing.T) {
	charts, row, now := lapsedChartSubject(t)
	slug := row.Chart
	app, _ := charts.AppVersion(row.Component, row.Chart, row.ChartVersion, now)
	chartOnly := lapsedWorkload(map[string]any{labelHelmChart: slug + "-" + row.ChartVersion})
	// The two labels disagree.
	disagreeing := lapsedWorkload(map[string]any{labelHelmChart: slug + "-" + row.ChartVersion, labelAppName: slug, labelAppVersion: "0.0.1"})
	if got := detectVersions(chartOnly, []string{slug}, charts, now)[slug]; got.Version != app {
		t.Fatalf("control: %+v", got)
	}
	if got := detectVersions(disagreeing, []string{slug}, charts, now)[slug]; got.Version != "" || !got.Conflict {
		t.Fatalf("control conflict: %+v", got)
	}

	sources := map[string]embeddedCharts{
		"expired": editSources(charts, slug, func(r *chartidentity.SourceRecord) bool {
			r.Evidence.ValidUntil = now.Format(time.RFC3339)
			return true
		}),
		"withdrawn": editSources(charts, slug, func(r *chartidentity.SourceRecord) bool {
			r.Evidence.State = chartidentity.StateWithdrawn
			return true
		}),
		"removed": editSources(charts, slug, func(*chartidentity.SourceRecord) bool { return false }),
	}
	for name, lapsed := range sources {
		t.Run("source "+name, func(t *testing.T) {
			if got, found := detectVersions(chartOnly, []string{slug}, lapsed, now)[slug]; found {
				t.Fatalf("a chart label read through a %s source: %+v", name, got)
			}
			// KNOWN LIMIT, pinned so a change is noticed: without a usable
			// source the chart label is ignored altogether, so a disagreement
			// with the app label is no longer seen and the app label's version
			// is detected.
			if got := detectVersions(disagreeing, []string{slug}, lapsed, now)[slug]; got.Version != "0.0.1" || got.Conflict {
				t.Fatalf("known limit changed: %+v", got)
			}
		})
	}

	versions := map[string]func(*chartidentity.AppVersionRecord) bool{
		"expired": func(r *chartidentity.AppVersionRecord) bool {
			r.Evidence.ValidUntil = now.Format(time.RFC3339)
			return true
		},
		"removed": func(*chartidentity.AppVersionRecord) bool { return false },
	}
	for name, edit := range versions {
		t.Run("app version "+name, func(t *testing.T) {
			table := *charts.versions
			table.Records = nil
			for _, r := range charts.versions.Records {
				if r.Component != row.Component || r.Chart != row.Chart || r.ChartVersion != row.ChartVersion || edit(&r) {
					table.Records = append(table.Records, r)
				}
			}
			lapsed := embeddedCharts{sources: charts.sources, versions: &table}
			for _, documents := range [][]intake.Document{chartOnly, disagreeing} {
				if got := detectVersions(documents, []string{slug}, lapsed, now)[slug]; got.Version != "" || got.Unusable != 1 {
					t.Fatalf("%+v", got)
				}
			}
		})
	}
}

// A declared chart whose reviewed source expired is refused by name.
func TestLapsedChartSourceDeclaredChart(t *testing.T) {
	_, row, now := lapsedChartSubject(t)
	if _, err := resolveChart(row.Chart, row.Chart, now); err != nil {
		t.Fatalf("control: %v", err)
	}
	ref, err := resolveChart(row.Chart, row.Chart, now.AddDate(5, 0, 0))
	if !isUsage(err) || ref.Name != "" || ref.Source != "" || !strings.Contains(err.Error(), row.Chart) {
		t.Fatalf("ref %+v err %v", ref, err)
	}
}
