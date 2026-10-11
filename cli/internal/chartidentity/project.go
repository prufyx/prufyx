// SPDX-License-Identifier: AGPL-3.0-only

package chartidentity

import (
	"sort"
	"time"
)

// ProjectChart is the outcome of looking up a project's chart by name in a
// chart-source table at one instant.
type ProjectChart struct {
	// Usable are the rows of the project and chart that are active and
	// not expired at the instant, in table order.
	Usable []SourceRecord
	// Unusable counts the rows of the project and chart that are
	// withdrawn or expired at the instant.
	Unusable int
	// Charts lists the chart names of the project's usable rows, sorted and
	// without repeats, so a caller can name them when the chart is unknown.
	Charts []string
}

// usable reports a row that is active and not expired at now.
func (r SourceRecord) usable(now time.Time) bool {
	until, err := parseTime(r.Evidence.ValidUntil)
	return err == nil && r.Evidence.State == StateActive && now.Before(until)
}

// ProjectChart returns the rows of this table that tie project to a chart
// named chart, split by whether they can be used at now. A row is usable
// only while it is active and now is before its validUntil, exactly as
// ComponentFor reads it.
func (t *SourceTable) ProjectChart(project, chart string, now time.Time) ProjectChart {
	var out ProjectChart
	names := map[string]bool{}
	for _, r := range t.Records {
		if r.Project != project {
			continue
		}
		ok := r.usable(now)
		if ok {
			names[r.Chart] = true
		}
		if r.Chart != chart {
			continue
		}
		if ok {
			out.Usable = append(out.Usable, r)
		} else {
			out.Unusable++
		}
	}
	for name := range names {
		out.Charts = append(out.Charts, name)
	}
	sort.Strings(out.Charts)
	return out
}

// LookupProjectChart is ProjectChart over the embedded reviewed table.
func LookupProjectChart(project, chart string, now time.Time) (ProjectChart, error) {
	s, _, err := LoadEmbedded()
	if err != nil {
		return ProjectChart{}, err
	}
	return s.ProjectChart(project, chart, now), nil
}
