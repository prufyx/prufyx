// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package scanrun

// Run with: go test -tags prufyx_synthetic_knowledge ./internal/scanrun/

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// The synthetic community project of community_synthetic_test.go is scanned
// over several hops once the knowledge holds a path policy for it. The
// policies here are test records, never published.

// policyKnowledge answers the path policy of one component and nothing else
// differently from the embedded knowledge.
type policyKnowledge struct {
	Knowledge
	status upgradepath.Status
}

func (k policyKnowledge) PathPolicyFor(string, time.Time) upgradepath.Status { return k.status }

func appPolicy(t *testing.T, policy string, window [2]string) upgradepath.Status {
	t.Helper()
	records, err := upgradepath.Parse([]byte(fmt.Sprintf(`[{"component":%q,"policy":%q,"evidence":{"state":"active",%s,"reviewedAt":%q,"validUntil":%q,"sources":[%s]}}]`, gwComponent, policy, basisFields("", window[0]), window[0], window[1], testSource)))
	if err != nil {
		t.Fatal(err)
	}
	instant, _ := time.Parse(time.RFC3339, testNow)
	return upgradepath.NewIndex(records).Lookup(gwComponent, instant)
}

// gwPairEntry is a rule for the exact pair from -> to of the synthetic
// project; it forbids version v1beta1 of Gateway, as gwEntry does for 1.1.0 ->
// 1.2.0.
func gwPairEntry(from, to string) (cncfcheck.Entry, string) {
	id := "gateway-api.crd-version-removal.gateways-gateway-networking-k8s-io." + strings.ReplaceAll(from, ".", "-") + "-to-" + strings.ReplaceAll(to, ".", "-")
	entry := gwEntry()
	entry.Rule = json.RawMessage(strings.NewReplacer(gwRuleID, id, `"from":"1.1.0","to":"1.2.0"`, `"from":"`+from+`","to":"`+to+`"`).Replace(string(entry.Rule)))
	return entry, id
}

func installPairs(t *testing.T, pairs ...[2]string) (Knowledge, []string) {
	t.Helper()
	var entries []cncfcheck.Entry
	var ids []string
	for _, pair := range pairs {
		entry, id := gwPairEntry(pair[0], pair[1])
		entries = append(entries, entry)
		ids = append(ids, id)
	}
	restore, err := cncfcheck.UseSyntheticKnowledge(nil, entries)
	if err != nil {
		t.Fatalf("synthetic knowledge refused: %v", err)
	}
	t.Cleanup(restore)
	embedded, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	return embedded, ids
}

func gwPath(t *testing.T, report scanreport.Report) scanreport.Path {
	t.Helper()
	for _, p := range report.Paths {
		if p.Component == gwSlug {
			return p
		}
	}
	t.Fatalf("no path for %s: %+v", gwSlug, report.Paths)
	return scanreport.Path{}
}

// A sequential_minor policy gives one hop per minor line, line ends in the
// middle; no hop of an uncovered intermediate line passes.
func TestScanAppMultiHopSequentialMinor(t *testing.T) {
	base, _ := installPairs(t, [2]string{"1.1.0", "1.2.0"})
	k := policyKnowledge{Knowledge: base, status: appPolicy(t, "sequential_minor", [2]string{currentReviewed, currentUntil})}
	result := mustScan(t, k, append(append([]string{}, mustPaths(t, gwServed)...), "--now", testNow, "--from", "gateway-api=1.1.0", "--to", "gateway-api=1.4.0", "--resource-scope-complete")...)
	path := gwPath(t, result.Report)
	if path.Policy != "sequential_minor" || len(path.Hops) != 3 {
		t.Fatalf("policy %q hops %d gaps %v", path.Policy, len(path.Hops), gapReasons(result.Report))
	}
	want := [][2]string{{"1.1.0", "1.2"}, {"1.2", "1.3"}, {"1.3", "1.4.0"}}
	for i, hop := range path.Hops {
		from := hop.From.Version + hop.From.Line
		to := hop.To.Version + hop.To.Line
		if hop.Index != i+1 || from != want[i][0] || to != want[i][1] {
			t.Fatalf("hop %d: %+v", i, hop)
		}
		if hop.Status == "PASS" || len(hop.Families) != 0 {
			t.Fatalf("hop %d passes: %+v", i, hop)
		}
	}
	if len(result.Report.Findings) != 0 || result.Report.Verdict == scanreport.VerdictPass {
		t.Fatalf("verdict %s findings %+v", result.Report.Verdict, result.Report.Findings)
	}
}

// A rule for the pair from -> target matches no single hop: it fires once, at
// the whole upgrade, and the intermediate hops do not repeat it.
func TestScanAppMultiHopWholeUpgradeRuleFiresOnce(t *testing.T) {
	base, ids := installPairs(t, [2]string{"1.1.0", "1.4.0"})
	k := policyKnowledge{Knowledge: base, status: appPolicy(t, "sequential_minor", [2]string{currentReviewed, currentUntil})}
	result := mustScan(t, k, append(append([]string{}, mustPaths(t, gwRemoved)...), "--now", testNow, "--from", "gateway-api=1.1.0", "--to", "gateway-api=1.4.0", "--resource-scope-complete")...)
	if result.Exit != scanreport.ExitBlocked || len(result.Report.Findings) != 1 {
		t.Fatalf("exit %d findings %+v gaps %v", result.Exit, result.Report.Findings, gapReasons(result.Report))
	}
	finding := result.Report.Findings[0]
	if finding.RuleID != ids[0] || !finding.Hop.WholeUpgrade || finding.Hop.From != "1.1.0" || finding.Hop.To != "1.4.0" || len(finding.AlsoAt) != 0 {
		t.Fatalf("finding %+v", finding)
	}
	if got := len(gwPath(t, result.Report).Hops); got != 3 {
		t.Fatalf("hops %d", got)
	}
}

// Under sequential_major the hops end on whole major lines and are not
// evaluated; the rule for the whole pair is still judged, once.
func TestScanAppMultiHopSequentialMajorWholeUpgradeRuleFires(t *testing.T) {
	base, ids := installPairs(t, [2]string{"1.1.0", "3.1.0"})
	k := policyKnowledge{Knowledge: base, status: appPolicy(t, "sequential_major", [2]string{currentReviewed, currentUntil})}
	result := mustScan(t, k, append(append([]string{}, mustPaths(t, gwRemoved)...), "--now", testNow, "--from", "gateway-api=1.1.0", "--to", "gateway-api=3.1.0", "--resource-scope-complete")...)
	path := gwPath(t, result.Report)
	if path.Policy != "sequential_major" || len(path.Hops) < 2 {
		t.Fatalf("policy %q hops %d gaps %v", path.Policy, len(path.Hops), gapReasons(result.Report))
	}
	if result.Exit != scanreport.ExitBlocked || len(result.Report.Findings) != 1 || result.Report.Findings[0].RuleID != ids[0] || !result.Report.Findings[0].Hop.WholeUpgrade {
		t.Fatalf("exit %d findings %+v gaps %v", result.Exit, result.Report.Findings, gapReasons(result.Report))
	}
}

// Without a path policy the upgrade is the one direct hop, as before; a
// record that is not current is a gap and never a direct hop.
func TestScanAppWithoutPathPolicyIsOneDirectHop(t *testing.T) {
	base, _ := installPairs(t, [2]string{"1.1.0", "1.4.0"})
	scan := func(k Knowledge) Result {
		return mustScan(t, k, append(append([]string{}, mustPaths(t, gwRemoved)...), "--now", testNow, "--from", "gateway-api=1.1.0", "--to", "gateway-api=1.4.0", "--resource-scope-complete")...)
	}
	none := scan(policyKnowledge{Knowledge: base})
	path := gwPath(t, none.Report)
	if path.Policy != "" || len(path.Hops) != 1 || path.Hops[0].From.Version != "1.1.0" || path.Hops[0].To.Version != "1.4.0" {
		t.Fatalf("path %+v", path)
	}
	if none.Exit != scanreport.ExitBlocked || len(none.Report.Findings) != 1 || none.Report.Findings[0].Hop.WholeUpgrade {
		t.Fatalf("exit %d findings %+v", none.Exit, none.Report.Findings)
	}

	stale := scan(policyKnowledge{Knowledge: base, status: appPolicy(t, "sequential_minor", [2]string{"2026-06-01T00:00:00Z", "2026-08-01T00:00:00Z"})})
	path = gwPath(t, stale.Report)
	if path.Gap != scanreport.ReasonPathPolicyNotCurrent || len(path.Hops) != 0 || len(stale.Report.Findings) != 0 {
		t.Fatalf("stale: path %+v findings %+v", path, stale.Report.Findings)
	}
}

func mustPaths(t *testing.T, doc string) []string {
	t.Helper()
	_, paths := files(t, map[string]string{"gw.yaml": doc})
	return paths
}
