// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/chartidentity"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// Evidence that lapses or is removed leaves the answer UNKNOWN, and the
// report names what is missing.

const lapsedFrom, lapsedStale = "2026-06-01T00:00:00Z", "2026-08-01T00:00:00Z"

func lapsedScan(t *testing.T, knowledge Knowledge, manifest, from, to string) Result {
	t.Helper()
	dir, _ := files(t, map[string]string{"applyset.yaml": manifest})
	var result Result
	inDir(t, dir, func() {
		result = mustScan(t, knowledge, args([]string{"applyset.yaml"}, "--from", "kubernetes="+from, "--to", "kubernetes="+to)...)
	})
	return result
}

// wantUnknown requires an UNKNOWN answer with a gap of the reason whose detail
// holds every named part.
func wantUnknown(t *testing.T, result Result, reason string, named ...string) {
	t.Helper()
	report := result.Report
	if result.Exit != scanreport.ExitUnknown || report.Verdict != scanreport.VerdictUnknown || len(report.Findings) != 0 {
		t.Fatalf("exit %d verdict %s findings %d gaps %v", result.Exit, report.Verdict, len(report.Findings), gapReasons(report))
	}
	var seen []string
next:
	for _, gap := range report.Gaps {
		if gap.Reason != reason {
			continue
		}
		seen = append(seen, gap.Detail)
		for _, part := range named {
			if !strings.Contains(gap.Detail, part) {
				continue next
			}
		}
		if gap.Action == "" {
			t.Fatalf("gap without a next action: %+v", gap)
		}
		return
	}
	t.Fatalf("no %s gap naming %q: %q (gaps %v)", reason, named, seen, gapReasons(report))
}

func TestScanExpiredOrWithdrawnRuleIsUnknown(t *testing.T) {
	const id = "kubernetes.synthetic-lapsed.1-25-0-to-1-26-0"
	current := `"state":"active","basis":"reviewed",` + currentWindow
	rule := func(blocks bool, evidence string) string {
		// basisRule forbids the value; the manifests declare the fact false.
		out := basisRule(id, "reviewed", !blocks)
		was := `"state":"active","basis":"reviewed","derivedAt":"` + currentReviewed + `",` + currentWindow
		if !strings.Contains(out, was) {
			t.Fatal("synthetic rule shape changed")
		}
		return strings.Replace(out, was, evidence, 1)
	}
	run := func(blocks bool, evidence string) Result {
		knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", unchecked: true,
			synthetic: []string{rule(blocks, evidence)}, extraRuleIDs: map[string][]string{"1.26": {id}}})
		return lapsedScan(t, knowledge, cronjobV1, "1.24.17", "1.30.4")
	}
	if got := run(false, current); got.Exit != scanreport.ExitPass {
		t.Fatalf("current rule: exit %d gaps %v", got.Exit, gapReasons(got.Report))
	}
	if got := run(true, current); got.Exit != scanreport.ExitBlocked {
		t.Fatalf("current blocking rule: exit %d gaps %v", got.Exit, gapReasons(got.Report))
	}
	for freshness, evidence := range map[string]string{
		"stale":     fmt.Sprintf(`"state":"active","basis":"reviewed","reviewedAt":%q,"validUntil":%q`, lapsedFrom, lapsedStale),
		"withdrawn": `"state":"withdrawn","basis":"reviewed",` + currentWindow,
	} {
		for _, blocks := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s blocks=%v", freshness, blocks), func(t *testing.T) {
				wantUnknown(t, run(blocks, evidence), scanreport.ReasonEvidenceExpired, id, freshness)
			})
		}
	}
}

func TestScanRemovedAttestationIsUnknown(t *testing.T) {
	for _, line := range []string{"1.30", "1.27"} {
		knowledge := newKnowledge(t, knowledgeOptions{lines: without(allLines, line), policy: "current"})
		result := lapsedScan(t, knowledge, cronjobV1, "1.24.17", "1.30.4")
		wantUnknown(t, result, scanreport.ReasonLineNotAttested, line)
		for _, hop := range result.Report.Paths[0].Hops {
			if hop.To.Line == line && hop.Status == scanreport.HopCovered {
				t.Fatalf("the hop into %s is covered without its review", line)
			}
		}
	}
}

// indexedServed answers served lists from a real index, so a removed record is
// absent exactly as it is from published knowledge.
type indexedServed struct {
	Knowledge
	index servedapis.Index
}

func (k indexedServed) ServedAPIs(component, line string, now time.Time) ServedStatus {
	status, found := k.index.For(component, line, now)
	if !found {
		return ServedStatus{}
	}
	apis := map[string]bool{}
	for _, pair := range status.Record.APIs {
		apis[pair] = true
	}
	return ServedStatus{Found: true, Freshness: status.Freshness, List: ServedList{Component: status.Record.Component, Line: status.Record.Line,
		Basis: status.Record.Evidence.Basis, ValidUntil: status.Record.Evidence.ValidUntil, APIs: apis}}
}

func TestScanRemovedOrExpiredServedListIsUnknown(t *testing.T) {
	record := func(line, reviewedAt, validUntil string) string {
		return fmt.Sprintf(`{"component":%q,"line":%q,"completeness":"COMPLETE_SERVED_API_LIST_FOR_LINE","apis":["batch/v1 CronJob","v1 ConfigMap"],"evidence":{"basis":"reviewed","reviewedAt":%q,"validUntil":%q,"sources":[%s]}}`,
			kubernetesKey, line, reviewedAt, validUntil, testSource)
	}
	base := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	run := func(records ...string) Result {
		parsed, err := servedapis.Parse([]byte("[" + strings.Join(records, ",") + "]"))
		if err != nil {
			t.Fatal(err)
		}
		return lapsedScan(t, indexedServed{Knowledge: base, index: servedapis.NewIndex(parsed)}, cronjobV1, "1.29.6", "1.30.4")
	}
	older := record("1.29", currentReviewed, currentUntil)
	got := run(older, record("1.30", currentReviewed, currentUntil))
	if got.Exit != scanreport.ExitPass {
		t.Fatalf("baseline: exit %d gaps %v", got.Exit, gapReasons(got.Report))
	}
	// The newest list is removed: the older line's list does not answer for it.
	removed := run(older)
	wantUnknown(t, removed, scanreport.ReasonAPIVersionNotReviewed, "1.30")
	if list := removed.Report.Paths[0].ServedList; list != nil {
		t.Fatalf("a served list answered for a removed one: %+v", list)
	}
	expired := run(older, record("1.30", lapsedFrom, lapsedStale))
	wantUnknown(t, expired, scanreport.ReasonAPIVersionNotReviewed, "1.30", "stale")
	if list := expired.Report.Paths[0].ServedList; list != nil {
		t.Fatalf("an expired served list is reported as used: %+v", list)
	}
}

// A direct path policy that is withdrawn or expired allows no hop at all.
func TestScanLapsedDirectPathPolicyAllowsNoHop(t *testing.T) {
	base := newKnowledge(t, knowledgeOptions{lines: allLines})
	instant, err := time.Parse(time.RFC3339, testNow)
	if err != nil {
		t.Fatal(err)
	}
	run := func(state, reviewedAt, validUntil string) Result {
		records, err := upgradepath.Parse([]byte(fmt.Sprintf(`[{"component":%q,"policy":"direct","evidence":{"state":%q,"basis":"reviewed","reviewedAt":%q,"validUntil":%q,"sources":[%s]}}]`,
			kubernetesKey, state, reviewedAt, validUntil, testSource)))
		if err != nil {
			t.Fatal(err)
		}
		status := upgradepath.NewIndex(records).Lookup(kubernetesKey, instant)
		return lapsedScan(t, jumpPolicyKnowledge{Knowledge: base, status: status}, cronjobV1, "1.24.17", "1.30.4")
	}
	current := run("active", currentReviewed, currentUntil)
	if current.Report.Paths[0].Policy != "direct" || len(current.Report.Paths[0].Hops) != 1 {
		t.Fatalf("baseline path %+v", current.Report.Paths[0])
	}
	for freshness, window := range map[string][3]string{
		"stale":     {"active", lapsedFrom, lapsedStale},
		"withdrawn": {"withdrawn", currentReviewed, currentUntil},
	} {
		t.Run(freshness, func(t *testing.T) {
			result := run(window[0], window[1], window[2])
			wantUnknown(t, result, scanreport.ReasonPathPolicyNotCurrent, kubernetesSlug, freshness)
			if path := result.Report.Paths[0]; path.Policy != "" || len(path.Hops) != 0 || path.Gap != scanreport.ReasonPathPolicyNotCurrent {
				t.Fatalf("path %+v", path)
			}
		})
	}
}

// An expired chart record resolves nothing, and the refusal names the chart.
func TestExpiredChartRecordIsNotUsed(t *testing.T) {
	sources, versions, err := chartidentity.LoadEmbedded()
	if err != nil || len(sources.Records) == 0 || len(versions.Records) == 0 {
		t.Fatalf("embedded chart tables: %v", err)
	}
	after := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	charts, err := loadEmbeddedCharts()
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range sources.Records {
		chart, err := resolveChart(record.Project, record.Chart, after)
		if err == nil || !strings.Contains(err.Error(), record.Chart) || !strings.Contains(err.Error(), record.Project) || chart.Name != "" {
			t.Fatalf("%s %s: chart %+v err %v", record.Project, record.Chart, chart, err)
		}
		if component, ok := charts.Component(record.Project, record.Chart, after); ok {
			t.Fatalf("expired source resolved %s", component)
		}
	}
	for _, record := range versions.Records {
		if version, ok := charts.AppVersion(record.Component, record.Chart, record.ChartVersion, after); ok {
			t.Fatalf("expired app version resolved %s", version)
		}
	}
}
