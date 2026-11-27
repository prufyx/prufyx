// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestOffAnchorSiblingIsListedByName: every human output names a rule left
// unreviewed inside a matched range, and never counts it as a rule for another
// transition.
func TestOffAnchorSiblingIsListedByName(t *testing.T) {
	t.Parallel()
	const ruleID = "crossplane.composition-resources-mode-removed.1-20-2-0"
	input := []byte(`{"schema":"` + constraintengine.InputSchema + `","authority":"` + constraintengine.InputAuthority + `","current":{"components":[{"component":"pkg:github/crossplane/crossplane","version":"1.20.1","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/crossplane/crossplane","version":"2.0.1","facts":[{"id":"component.crossplane.composition_mode","state":"declared","enumValue":"resources"}]}]}}`)
	// The newest review among the project's rules plus one hour.
	probe, err := cncfcheck.Check("crossplane", input, time.Date(2026, 11, 28, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var newest time.Time
	for _, claim := range probe.Check.Claims {
		reviewed, err := time.Parse(time.RFC3339, claim.EvidenceReviewedAt)
		if err != nil {
			t.Fatal(err)
		}
		if reviewed.After(newest) {
			newest = reviewed
		}
	}
	report, err := cncfcheck.Check("crossplane", input, newest.Add(time.Hour))
	if err != nil || cncfcheck.ClaimExit(report) != 11 {
		t.Fatalf("exit=%d err=%v", cncfcheck.ClaimExit(report), err)
	}
	listed := false
	for _, claim := range summarizeClaims(report.Check.Claims, false).shown {
		listed = listed || claim.RuleID == ruleID
	}
	if !listed {
		t.Fatal("quiet output collapses the sibling")
	}
	var quiet bytes.Buffer
	if err := writeNativeClaims(&quiet, summarizeClaims(report.Check.Claims, false), report.Check.Claims); err != nil {
		t.Fatal(err)
	}
	var human bytes.Buffer
	if err := writeHumanReport(&human, humanRoute{exit: cncfcheck.ClaimExit(report), claims: report.Check.Claims, project: "crossplane", from: "1.20.1", to: "2.0.1"}); err != nil {
		t.Fatal(err)
	}
	chain, err := cncfcheck.Checker{}.CheckChain("crossplane", []byte(strings.Replace(string(input), `"version":"2.0.1"`, `"version":"2.0.2"`, 1)), []string{"2.0.1"}, newest.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var hop strings.Builder
	writeChainHop(&hop, "hop 1", chain.Hops[0], false)
	for name, text := range map[string]string{"quiet": quiet.String(), "human": human.String(), "chain": hop.String()} {
		if !strings.Contains(text, ruleID) || strings.Contains(text, "another transition not applicable") {
			t.Fatalf("%s output does not name the sibling:\n%s", name, text)
		}
	}
}
