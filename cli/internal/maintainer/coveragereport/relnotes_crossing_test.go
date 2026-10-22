// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"fmt"
	"testing"
)

// A crossing-only forbid_set_member rule over a relnotes set fact (no range):
// anchor subject newest final of the previous line -> X.Y.0, crossing change
// X.Y.0 (REMOVED_IN_RELEASE), horizon X.(Y+1).0 (REVIEWED_THROUGH_MINOR_LINE).
// It decides its own pair as B and no other pair. Test-only pack.
func relnotesSetRule(id, from, to, crossing string) string {
	if crossing != "" {
		crossing = "," + crossing
	}
	const comp = "pkg:github/prometheus/prometheus"
	return fmt.Sprintf(`{"project":"prometheus","rule":{"id":%q,"operator":"forbid_set_member","subject":{"component":%q,"from":%q,"to":%q}%s,"setCondition":{"side":"proposed","component":%q,"factId":"component.prometheus.cli_flags_set","members":["synthetic-removed-flag"]},"evidence":{"state":"active","reviewedAt":"2026-09-01T00:00:00Z","validUntil":%q}}}`, id, comp, from, to, crossing, comp, valid)
}

func TestRelnotesCrossingOnlySetRuleCountsB(t *testing.T) {
	const crossing = `"crossing":{"change":{"version":"1.9.0","basis":"REMOVED_IN_RELEASE","sourceId":"s"},"horizon":{"lt":"1.10.0","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"s"}}`
	run := func(rule string, window ...string) string {
		report, err := Compute(Input{Pack: pack([]string{rule}, nil), Lines: lines("prometheus", window...), Now: baselineNow})
		if err != nil {
			t.Fatal(err)
		}
		return statuses(report.Projects[0])
	}
	cases := []struct {
		name, rule string
		window     []string
		want       string
	}{
		{"crossing-only, its pair", relnotesSetRule("p.r", "1.8.2", "1.9.0", crossing), []string{"1.8", "1.9"}, "B"},
		{"crossing-only decides no other pair", relnotesSetRule("p.r", "1.8.2", "1.9.0", crossing), []string{"1.8", "1.9", "1.10"}, "BG"},
		{"the same anchor without a crossing is a spot", relnotesSetRule("p.r", "1.8.2", "1.9.0", ""), []string{"1.8", "1.9"}, "S"},
	}
	for _, c := range cases {
		if got := run(c.rule, c.window...); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}
