// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/chartidentity"
	"github.com/prufyx/prufyx/cli/internal/intake"
)

// A chart label named like the project is never ignored: with no usable
// source for it, an app version beside it is a conflict, never the answer.
func TestChartLabelWithoutUsableSourceIsNotIgnored(t *testing.T) {
	charts, err := loadEmbeddedCharts()
	if err != nil {
		t.Fatal(err)
	}
	const slug = "cert-manager"
	var now time.Time
	for _, source := range charts.sources.Records {
		if source.Chart == slug && source.Project == slug {
			reviewed, err := time.Parse(time.RFC3339, source.Evidence.ReviewedAt)
			if err != nil {
				t.Fatal(err)
			}
			now = reviewed.Add(time.Hour)
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
	one := func(labels map[string]any) []intake.Document { return []intake.Document{workload(labels, nil)} }
	disagreeing := one(map[string]any{labelHelmChart: slug + "-9.8.7", labelAppName: slug, labelAppVersion: "0.0.1"})
	chartOnly := one(map[string]any{labelHelmChart: slug + "-9.8.7"})
	appOnly := one(map[string]any{labelAppName: slug, labelAppVersion: "0.0.1"})
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
		"removed": edit(func(*chartidentity.SourceRecord) bool { return false }),
	} {
		t.Run(name, func(t *testing.T) {
			got := detectVersions(disagreeing, []string{slug}, tables, now)[slug]
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
}
