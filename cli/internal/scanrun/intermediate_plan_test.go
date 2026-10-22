// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

const intermediateSkewSource = "kubernetes-website-version-skew-upgrade-order"

// intermediateRule is a synthetic require_intermediate_version rule for
// 1.24 -> 1.28 that wants 1.25.0 in between.
func intermediateRule(id string) string {
	bound := func(name, basis string) string {
		return `{"bound":"` + name + `","basis":"` + basis + `","sourceId":"` + intermediateSkewSource + `"}`
	}
	return `{"id":"` + id + `","operator":"require_intermediate_version","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.24.0","to":"1.28.0"},` +
		`"intermediate":"1.25.0","range":{"from":{"gte":"1.24.0","lt":"1.25.0"},"to":{"gte":"1.28.0","lt":"1.29.0"},"bounds":[` +
		bound("from.gte", "UPGRADE_FROM_SERIES") + `,` + bound("from.lt", "UPGRADE_FROM_SERIES") + `,` + bound("to.gte", "TARGET_SERIES") + `,` + bound("to.lt", "TARGET_SERIES") + `]},` +
		`"evidence":{"state":"active",` + currentWindow + `,"sources":[` + skewSource + `]},` +
		`"reasonCode":"REVIEWED_SOURCE_CONSTRAINT","nextAction":"synthetic test-only action"}`
}

func hasFinding(report scanreport.Report, id string) bool {
	for _, finding := range report.Findings {
		if finding.RuleID == id {
			return true
		}
	}
	return false
}

// TestScanIntermediateSatisfiedByPlan: a sequential plan visits the rule's
// intermediate line, so the end-to-end check does not block on the rule; a
// direct plan does not visit it and the rule still blocks.
func TestScanIntermediateSatisfiedByPlan(t *testing.T) {
	t.Parallel()
	const id = "kubernetes.synthetic-intermediate.1-24-to-1-28"
	cases := []struct {
		name        string
		policy      string
		wantBlocked bool
	}{
		{"sequential plan visits 1.25", "current", false},
		{"direct plan skips 1.25", "direct", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			knowledge := newKnowledge(t, knowledgeOptions{lines: append([]string{"1.24"}, allLines...), policy: tc.policy, synthetic: []string{intermediateRule(id)}})
			_, paths := files(t, map[string]string{"cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n"})
			result := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.24.2", "--to", "kubernetes=1.28.3")...)
			if got := hasFinding(result.Report, id); got != tc.wantBlocked {
				t.Fatalf("finding %v, want %v; exit %d findings %+v", got, tc.wantBlocked, result.Exit, result.Report.Findings)
			}
			if tc.wantBlocked && result.Exit != scanreport.ExitBlocked {
				t.Fatalf("exit %d, want blocked", result.Exit)
			}
		})
	}
}

func TestVisitsIntermediate(t *testing.T) {
	t.Parallel()
	hops := func(ends ...string) upgradepath.Plan {
		var plan upgradepath.Plan
		for i := 1; i < len(ends); i++ {
			plan.Hops = append(plan.Hops, upgradepath.Hop{Index: i, From: endpoint(ends[i-1]), To: endpoint(ends[i])})
		}
		return plan
	}
	cases := []struct {
		name         string
		plan         upgradepath.Plan
		intermediate string
		want         bool
	}{
		{"every line visited", hops("1.33.2", "1.34", "1.35", "1.36", "1.37.1"), "1.34.0", true},
		{"intermediate is an exact endpoint", hops("1.33.2", "1.34.5", "1.37.1"), "1.34.0", true},
		{"two hops skip the line", hops("1.33.2", "1.35", "1.37.1"), "1.34.0", false},
		{"direct hop", hops("1.33.2", "1.37.1"), "1.34.0", false},
		{"other operator has no intermediate", hops("1.33.2", "1.34", "1.37.1"), "", false},
		{"unparseable intermediate", hops("1.33.2", "1.34", "1.37.1"), "latest", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := visitsIntermediate(tc.plan, cncfcheck.ScanRule{Intermediate: tc.intermediate}); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// endpoint reads "M.m" as a minor line and "M.m.p" as an exact version.
func endpoint(s string) upgradepath.Endpoint {
	if len(s) > 0 && len(s) <= 5 && s[len(s)-1] != '.' && countDots(s) == 1 {
		return upgradepath.Endpoint{Line: s}
	}
	return upgradepath.Endpoint{Version: s}
}

func countDots(s string) int {
	n := 0
	for _, c := range s {
		if c == '.' {
			n++
		}
	}
	return n
}
