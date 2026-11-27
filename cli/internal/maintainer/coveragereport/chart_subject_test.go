// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"fmt"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// asChart gives a synthetic rule a chart subject: its versions are then chart
// versions, whose numbers may equal the project's release lines.
func asChart(t *testing.T, rule string) string {
	t.Helper()
	out := strings.Replace(rule, `"subject":{`, `"subject":{"chart":{"source":"https://charts.example.invalid/stable","name":"synthetic"},`, 1)
	if out == rule {
		t.Fatalf("rule has no subject: %s", rule)
	}
	return out
}

// A chart rule is about a chart line, not about a pair of the project's release
// lines: it never makes such a pair A, B or S. Every case carries the same rule
// without the chart as its control.
func TestChartSubjectRuleDecidesNoReleasePair(t *testing.T) {
	ranged := ruleJSON("r", "1.31.0", "1.32.0", rangeJSON("1.31.0", "1.32.0", "1.32.0", "1.33.0"), valid)
	exact := ruleJSON("r", "1.31.3", "1.32.1", "", valid)
	crossing := ruleJSON("r", "1.31.0", "1.32.0", `"crossing":{"change":{"version":"1.32.0","basis":"REMOVED_IN_RELEASE","sourceId":"s"},"horizon":{"lt":"1.40.0","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"s"}}`, valid)
	cases := []struct {
		name    string
		rule    string
		atts    []string
		control string
	}{
		{"ranged", ranged, nil, "B"},
		{"exact", exact, nil, "S"},
		{"crossing", crossing, nil, "B"},
		{"listed by an attestation", ranged, []string{attJSON("1.32", valid, "r")}, "A"},
		{"exact listed by an attestation", exact, []string{attJSON("1.32", valid, "r")}, "S"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := statuses(run(t, []string{c.rule}, c.atts, "1.31", "1.32")); got != c.control {
				t.Fatalf("without chart: %s, want %s", got, c.control)
			}
			p := run(t, []string{asChart(t, c.rule)}, c.atts, "1.31", "1.32")
			if got := statuses(p); got != "G" || p.A+p.B+p.S != 0 || len(p.Pairs[0].Families) != 0 {
				t.Fatalf("with chart: %s (%+v), want G", got, p)
			}
		})
	}
}

// A chart rule beside an application rule takes nothing away from it.
func TestChartSubjectRuleLeavesApplicationRules(t *testing.T) {
	app := ruleJSON("app", "1.31.3", "1.32.1", "", valid)
	chart := asChart(t, ruleJSON("chart", "1.31.0", "1.32.0", rangeJSON("1.31.0", "1.32.0", "1.32.0", "1.33.0"), valid))
	if got := statuses(run(t, []string{app, chart}, nil, "1.31", "1.32")); got != "S" {
		t.Fatalf("statuses = %s, want S", got)
	}
}

// One attestation lists an application rule and a chart rule: it is not
// line-wide, so the pair keeps only what the application rule gives by itself,
// and only the application rule falls in the window.
func TestChartSubjectRuleBesideApplicationRuleInOneAttestation(t *testing.T) {
	app := ruleJSON("app", "1.31.3", "1.32.1", "", valid)
	listed := ruleJSON("chart", "1.31.0", "1.32.0", rangeJSON("1.31.0", "1.32.0", "1.32.0", "1.33.0"), valid)
	atts := []string{attJSON("1.32", valid, "app", "chart")}

	control := run(t, []string{app, listed}, atts, "1.31", "1.32")
	if control.RulesInWindow != 2 || control.ValidRules != 2 {
		t.Fatalf("without chart: rulesInWindow %d, validRules %d, want 2 and 2", control.RulesInWindow, control.ValidRules)
	}

	p := run(t, []string{app, asChart(t, listed)}, atts, "1.31", "1.32")
	if got := statuses(p); got != "S" || p.A != 0 || p.B != 0 || len(p.Pairs[0].Families) != 0 {
		t.Fatalf("with chart: %s (%+v), want S", got, p)
	}
	if p.RulesInWindow != 1 || p.ValidRules != 2 {
		t.Fatalf("with chart: rulesInWindow %d, validRules %d, want 1 and 2", p.RulesInWindow, p.ValidRules)
	}
}

// The changelog families: a chart rule bounds no changelog pair, and an
// attestation that lists one is typed like any rule that is not line-wide.
func TestChartSubjectRuleInChangelogFamilies(t *testing.T) {
	const comp = "pkg:github/strimzi/strimzi-kafka-operator"
	rels := map[string][]string{"1.8": {"1.8.0"}, "1.9": {"1.9.0"}}
	rec := &ruleRec{id: "r", valid: true, tr: constraintengine.RuleTransition{Component: comp, From: "1.8.0", To: "1.9.0",
		Range: &constraintengine.VersionRange{
			From: constraintengine.VersionBound{Gte: "1.8.0", Lt: "1.9.0"},
			To:   constraintengine.VersionBound{Gte: "1.9.0", Lt: "1.10.0"},
		},
		Chart: &constraintengine.ChartRef{Source: "https://charts.example.invalid/stable", Name: "synthetic"}}}
	byID := map[string]*ruleRec{"r": rec}
	for _, family := range []string{FamilyChangelogAttested, FamilyChangelogListed} {
		att := clAtt(comp, family, "2027-01-01T00:00:00Z", []string{"1.8.0"}, []string{"1.9.0"})
		pair := classify("strimzi", "1.8", "1.9", []*ruleRec{rec}, []lineattest.LineAttestation{att}, byID, rels)
		if pair.Status != StatusG || !pair.Changelog || pair.canBlock {
			t.Fatalf("%s, unlisted chart rule: %+v", family, pair)
		}
		att.RuleIDs = []string{"r"}
		atts := []lineattest.LineAttestation{att}
		pair = classify("strimzi", "1.8", "1.9", []*ruleRec{rec}, atts, byID, rels)
		if pair.Status != StatusG || pair.Changelog || len(pair.Families) != 0 {
			t.Fatalf("%s, listed chart rule: %+v", family, pair)
		}
		if r := changelogGapReason(comp, "1.8", "1.9", atts, baselineNow, byID, rels, nil); r != GapRuleNotLineWide {
			t.Fatalf("%s: reason %s", family, r)
		}
	}
}

// The complete predicate: an attestation that lists a chart rule decides no pair.
func TestChartSubjectRuleNeverCompletes(t *testing.T) {
	reg := shippedID(t, "kubernetes", lineattest.FamilyKubernetesRemovedServedGVK)
	digest, err := reg.digest()
	if err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf(`{"id":"src-a","url":"https://github.com/kubernetes/kubernetes/blob/%s/api/file.go","revision":%q,"contentDigest":"sha256:%s","startLine":1,"endLine":2}`, rev, rev, strings.Repeat("a", 64))
	evidence := fmt.Sprintf(`{"state":"active","basis":"mechanical","extractor":{"id":%q,"version":%q,"codeDigest":%q},"derivedAt":%q,"reviewedAt":%q,"validUntil":%q,"sources":[%s]}`,
		reg.extractorID, reg.version, digest, allReviewed, allReviewed, allUntil, source)
	scene := func(rule string) scenario {
		s := k8sScenario("1.19", "1.20", "1.21")
		s.extra = []string{rule}
		s.skip = map[string]bool{"1.21": true}
		s.declared = declJSON(declRecord("kubernetes", lineattest.FamilyKubernetesRemovedServedGVK, "1.20", "1.21", ReasonScanNotClean, "2026-12-15T00:00:00Z"))
		s.mutate = func(a *lineattest.LineAttestation) { a.RuleIDs = []string{"rule-one"} }
		return s
	}
	rule := mechanicalRule(t, "rule-one", evidence)
	assertComplete(t, scene(rule).project(t), true, "")
	p := scene(asChart(t, rule)).project(t)
	assertComplete(t, p, false, whyUndeclared)
	if p.Decided != 0 || p.A+p.B+p.S != 0 {
		t.Fatalf("a chart rule decided a pair: %+v", p)
	}
}
