// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/chartidentity"
)

// chartRange is a range over two chart lines with the given bounds, every
// bound citing the candidate's source.
func chartRange(fromGte, fromLt, toGte, toLt string, bases ...string) map[string]any {
	names := []string{"from.gte", "from.lt", "to.gte", "to.lt"}
	bounds := make([]any, len(bases))
	for i, basis := range bases {
		bounds[i] = map[string]any{"bound": names[i], "basis": basis, "sourceId": "schema-to"}
	}
	return map[string]any{"from": map[string]any{"gte": fromGte, "lt": fromLt}, "to": map[string]any{"gte": toGte, "lt": toLt}, "bounds": bounds}
}

// rangedChartCandidate is the synthetic require_set_member chart rule
// 1.16.0 -> 1.17.0 widened to every release of both lines.
func rangedChartCandidate() map[string]any {
	entry := chartCandidate()
	rule(entry)["range"] = chartRange("1.16.0", "1.17.0", "1.17.0", "1.18.0", "PREVIOUS_MINOR_LINE", "CHANGED_IN_RELEASE", "CHANGED_IN_RELEASE", "TARGET_SERIES")
	return entry
}

func TestRulecheckRangedChartRule(t *testing.T) {
	maintainer := Options{AllowRange: true, ChartSources: chartTable(chartidentity.StateActive, chartTestComponent)}
	accepted := map[string]map[string]any{
		"consecutive lines": rangedChartCandidate(),
		"whole lines over a gap": func() map[string]any {
			e := chartCandidate()
			rule(e)["subject"].(map[string]any)["to"] = "1.18.0"
			rule(e)["range"] = chartRange("1.16.0", "1.17.0", "1.18.0", "1.19.0", "UPGRADE_FROM_SERIES", "UPGRADE_FROM_SERIES", "TARGET_SERIES", "TARGET_SERIES")
			return e
		}(),
		"forbid with a removal boundary": func() map[string]any {
			e := rangedChartCandidate()
			rule(e)["operator"] = "forbid_set_member"
			rule(e)["range"] = chartRange("1.16.0", "1.17.0", "1.17.0", "1.18.0", "PREVIOUS_MINOR_LINE", "REMOVED_IN_RELEASE", "REMOVED_IN_RELEASE", "TARGET_SERIES")
			return e
		}(),
	}
	for name, entry := range accepted {
		if findings := chartFindings(t, entry, maintainer); len(findings) != 0 {
			t.Fatalf("%s rejected: %v", name, findings)
		}
	}
	cases := map[string]struct {
		edit func(map[string]any)
		opts Options
		want string
	}{
		"without AllowRange": {func(map[string]any) {}, Options{ChartSources: maintainer.ChartSources}, "not accepted from a community contribution"},
		"from anchor not the line start": {func(e map[string]any) {
			rule(e)["subject"].(map[string]any)["from"] = "1.16.2"
		}, maintainer, "anchors must be the first releases of its two lines"},
		"to anchor not the line start": {func(e map[string]any) {
			rule(e)["subject"].(map[string]any)["to"] = "1.17.1"
		}, maintainer, "anchors must be the first releases of its two lines"},
		"ANCHOR_ONLY basis": {func(e map[string]any) {
			rule(e)["range"] = chartRange("1.16.0", "1.16.1", "1.17.0", "1.18.0", "ANCHOR_ONLY", "ANCHOR_ONLY", "TARGET_SERIES", "TARGET_SERIES")
		}, maintainer, "consecutive-line shape"},
		"RESTORED_IN_RELEASE basis": {func(e map[string]any) {
			rule(e)["range"] = chartRange("1.16.0", "1.17.0", "1.17.0", "1.18.0", "PREVIOUS_MINOR_LINE", "CHANGED_IN_RELEASE", "CHANGED_IN_RELEASE", "RESTORED_IN_RELEASE")
		}, maintainer, "consecutive-line shape"},
		"whole lines that are consecutive": {func(e map[string]any) {
			rule(e)["range"] = chartRange("1.16.0", "1.17.0", "1.17.0", "1.18.0", "UPGRADE_FROM_SERIES", "UPGRADE_FROM_SERIES", "TARGET_SERIES", "TARGET_SERIES")
		}, maintainer, "consecutive-line shape"},
		"a crossing": {func(e map[string]any) {
			delete(rule(e), "range")
			rule(e)["crossing"] = map[string]any{"change": map[string]any{"version": "1.17.0", "basis": "REMOVED_IN_RELEASE", "sourceId": "schema-to"}, "horizon": map[string]any{"lt": "1.19.0", "basis": "REVIEWED_THROUGH_MINOR_LINE", "sourceId": "schema-to"}, "distributions": []any{"upstream"}}
		}, maintainer, "cannot carry a crossing"},
		"a set notice with a range": {func(e map[string]any) {
			r := rule(e)
			r["operator"], r["reasonCode"] = "notice_set_member_present", "HELM_VALUES_KEY_NOT_REFERENCED"
			r["nextAction"] = "review the listed keys in the values supplied for the chart before upgrading"
		}, maintainer, "anchor-only"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			entry := rangedChartCandidate()
			tc.edit(entry)
			findings := chartFindings(t, entry, tc.opts)
			if !strings.Contains(strings.Join(findings, "\n"), tc.want) {
				t.Fatalf("want %q in %v", tc.want, findings)
			}
		})
	}
}
