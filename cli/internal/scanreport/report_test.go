// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// TestCatalogBounds: every catalog string is at most MaxText bytes per line,
// and every gap message, filled with the longest values its arguments take
// (a 128-byte rule id or reason in any one position, 29 bytes elsewhere),
// fits without being cut. A longer value is cut on a character boundary.
func TestCatalogBounds(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "messages.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	ast.Inspect(parsed, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		text, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(text, "\n") {
			count++
			if len(line) > MaxText {
				t.Errorf("catalog line longer than %d bytes: %q", MaxText, line)
			}
		}
		return true
	})
	if count < 50 {
		t.Fatalf("only %d catalog strings found", count)
	}
	for _, key := range GapKeys() {
		n := GapArgs(key)
		for long := 0; long < max(n, 1); long++ {
			args := make([]any, n)
			for i := range args {
				args[i] = strings.Repeat("9", 29)
				if i == long {
					args[i] = strings.Repeat("x", 128)
				}
			}
			message := gapMessages[key]
			for _, text := range []string{fill(message.detail, args), fill(message.action, args)} {
				if len(text) > MaxText || text == "" || strings.Contains(text, "%") {
					t.Errorf("%s renders %d bytes: %q", key, len(text), text)
				}
			}
		}
	}
	gap := NewGap("kubernetes", nil, GapRuleNotDecided, strings.Repeat("é", 300), "x")
	if len(gap.Detail) > MaxText || !strings.HasPrefix(gap.Detail, "rule é") || strings.ContainsRune(gap.Detail, '�') {
		t.Fatalf("long detail not cut on a character boundary: %d", len(gap.Detail))
	}
	if unknown := NewGap("x", nil, GapKey("NO_SUCH"), "a"); unknown.Reason != ReasonRuleNotDecided {
		t.Fatalf("unknown key renders as %s", unknown.Reason)
	}
	if wrong := NewGap("x", nil, GapLineNotAttested, "only one"); wrong.Reason != ReasonRuleNotDecided {
		t.Fatalf("wrong argument count renders as %s", wrong.Reason)
	}
}

func ref(index int, from, to string) HopRef { return HopRef{Index: index, From: from, To: to} }

// TestFinalizeOrder: findings by hop then rule id, the whole upgrade after
// every hop; locations by file, document and item; gaps by component, hop
// and reason, component-level first; exact duplicates of a gap removed.
func TestFinalizeOrder(t *testing.T) {
	whole := HopRef{From: "1.24.0", To: "1.30.0", WholeUpgrade: true}
	report := Report{
		Findings: []Finding{
			{RuleID: "b", Component: "kubernetes", Hop: ref(2, "1.25", "1.26")},
			{RuleID: "z", Component: "kubernetes", Hop: whole},
			{RuleID: "c", Component: "kubernetes", Hop: ref(1, "1.24.0", "1.25"), Locations: []Location{
				{File: "b.yaml", Document: 0, Item: -1}, {File: "a.yaml", Document: 2, Item: 1}, {File: "a.yaml", Document: 2, Item: 0}, {File: "a.yaml", Document: 1, Item: -1},
			}, AlsoAt: []HopRef{whole, ref(3, "1.26", "1.27")}},
			{RuleID: "a", Component: "kubernetes", Hop: ref(2, "1.25", "1.26")},
		},
		Gaps: []Gap{
			NewGap("kubernetes", &HopRef{Index: 2, From: "1.25", To: "1.26"}, GapIntermediateLine, "r"),
			NewGap("kubernetes", nil, GapDeclarationScope, "kubernetes"),
			NewGap("etcd", nil, GapComponentNotCovered, "etcd"),
			NewGap("kubernetes", &whole, GapRuleNotDecided, "r", "X"),
			NewGap("kubernetes", &HopRef{Index: 1, From: "1.24.0", To: "1.25"}, GapLineNotAttested, "kubernetes", "1.25"),
			NewGap("kubernetes", nil, GapDeclarationScope, "kubernetes"),
		},
		Paths: []Path{{Component: "kubernetes", Hops: []Hop{{Index: 1, Status: HopBlocked}}}},
	}
	Finalize(&report)
	var findings []string
	for _, finding := range report.Findings {
		findings = append(findings, finding.RuleID)
	}
	if !reflect.DeepEqual(findings, []string{"c", "a", "b", "z"}) {
		t.Fatalf("findings %v", findings)
	}
	var locations []string
	for _, location := range report.Findings[0].Locations {
		locations = append(locations, location.File+"#"+strconv.Itoa(location.Document)+"/"+strconv.Itoa(location.Item))
	}
	if !reflect.DeepEqual(locations, []string{"a.yaml#1/-1", "a.yaml#2/0", "a.yaml#2/1", "b.yaml#0/-1"}) {
		t.Fatalf("locations %v", locations)
	}
	if report.Findings[0].AlsoAt[0].Index != 3 || !report.Findings[0].AlsoAt[1].WholeUpgrade {
		t.Fatalf("alsoAt %+v", report.Findings[0].AlsoAt)
	}
	var gaps []string
	for _, gap := range report.Gaps {
		hop := "-"
		if gap.Hop != nil {
			hop = gap.Hop.To
		}
		gaps = append(gaps, gap.Component+" "+hop+" "+gap.Reason)
	}
	want := []string{"etcd - COMPONENT_NOT_COVERED", "kubernetes - DECLARATION_MISSING", "kubernetes 1.25 LINE_NOT_ATTESTED", "kubernetes 1.26 INTERMEDIATE_LINE_NOT_COVERED_BY_RANGE", "kubernetes 1.30.0 RULE_NOT_DECIDED"}
	if !reflect.DeepEqual(gaps, want) {
		t.Fatalf("gaps %v", gaps)
	}
	if report.Verdict != VerdictBlocked || report.Headline != "BLOCKED: 4 problems must be fixed before this upgrade" || report.Summary.Blockers != 4 || report.Summary.Gaps != 5 {
		t.Fatalf("verdict %s headline %q summary %+v", report.Verdict, report.Headline, report.Summary)
	}
}

// TestVerdict: PASS needs no finding, no gap, at least one path, every path
// planned and every hop COVERED, and every targeted component evaluated.
func TestVerdict(t *testing.T) {
	covered := func() Report {
		return Report{
			Inventory: []Component{{Name: "kubernetes", Target: "1.30.4", Covered: true}},
			Paths:     []Path{{Component: "kubernetes", Hops: []Hop{{Index: 1, Status: HopCovered}, {Index: 2, Status: HopCovered}}}},
		}
	}
	cases := map[string]struct {
		change  func(*Report)
		verdict string
		exit    int
	}{
		"all covered":          {func(*Report) {}, VerdictPass, ExitPass},
		"one gap":              {func(r *Report) { r.Gaps = []Gap{NewGap("kubernetes", nil, GapDeclarationScope, "kubernetes")} }, VerdictUnknown, ExitUnknown},
		"partial hop":          {func(r *Report) { r.Paths[0].Hops[1].Status = HopPartial }, VerdictUnknown, ExitUnknown},
		"no data hop":          {func(r *Report) { r.Paths[0].Hops[0].Status = HopNoData }, VerdictUnknown, ExitUnknown},
		"unknown status":       {func(r *Report) { r.Paths[0].Hops[0].Status = "NOTICE" }, VerdictUnknown, ExitUnknown},
		"no path":              {func(r *Report) { r.Paths = nil }, VerdictUnknown, ExitUnknown},
		"path without hops":    {func(r *Report) { r.Paths[0].Hops = nil }, VerdictUnknown, ExitUnknown},
		"path gap":             {func(r *Report) { r.Paths[0].Gap = "PATH_NOT_PLANNABLE" }, VerdictUnknown, ExitUnknown},
		"target not evaluated": {func(r *Report) { r.Inventory = append(r.Inventory, Component{Name: "etcd", Target: "3.6.0"}) }, VerdictUnknown, ExitUnknown},
		"finding":              {func(r *Report) { r.Findings = []Finding{{RuleID: "x"}}; r.Paths[0].Hops[0].Status = HopBlocked }, VerdictBlocked, ExitBlocked},
	}
	for name, tc := range cases {
		report := covered()
		tc.change(&report)
		Finalize(&report)
		if report.Verdict != tc.verdict || Exit(report) != tc.exit {
			t.Errorf("%s: verdict %s exit %d", name, report.Verdict, Exit(report))
		}
	}
	report := covered()
	Finalize(&report)
	if report.Headline != "PASS FOR THE DECLARED SCOPE" {
		t.Fatal(report.Headline)
	}
	report.Gaps = []Gap{{}}
	report.Paths[0].Hops[0].Status = HopPartial
	Finalize(&report)
	if report.Headline != "NO BLOCKERS FOUND IN COVERED CHECKS: 1 area was not checked" {
		t.Fatal(report.Headline)
	}
	// A manifest the target does not serve never reads as "no blockers".
	report.Gaps = []Gap{NewGap("kubernetes", nil, GapAPIVersionNotServed, 1, "1.30")}
	Finalize(&report)
	if report.Headline != "UNKNOWN: manifests use API versions the target does not serve; migrate them before upgrading (1 area was not checked)" {
		t.Fatal(report.Headline)
	}
	report.Gaps = append(report.Gaps, NewGap("kubernetes", nil, GapAPIVersionNotServedCrossed, 1, "1.30"), Gap{})
	Finalize(&report)
	if report.Headline != "UNKNOWN: manifests use API versions the target does not serve; migrate them before upgrading (3 areas were not checked)" {
		t.Fatal(report.Headline)
	}
	// A blocker still leads.
	report.Findings = []Finding{{RuleID: "r", Component: "kubernetes", Hop: ref(1, "1.24.0", "1.25")}}
	Finalize(&report)
	if report.Verdict != VerdictBlocked || report.Headline != "BLOCKED: 1 problem must be fixed before this upgrade" {
		t.Fatal(report.Headline)
	}
}

// TestHumanLocations: at most five locations print per finding, then a
// count; redacted values print as a digest prefix.
func TestHumanLocations(t *testing.T) {
	finding := Finding{RuleID: "r", Component: "kubernetes", Hop: ref(1, "1.24.0", "1.25"), Title: "title", Fix: "fix it"}
	for i := 0; i < 7; i++ {
		finding.Locations = append(finding.Locations, Location{File: "f.yaml", Document: i, Item: -1, Kind: "CronJob", Name: "n" + strconv.Itoa(i)})
	}
	report := Report{Findings: []Finding{finding}, Paths: []Path{{Component: "kubernetes", Hops: []Hop{{Index: 1, Status: HopBlocked}}}}}
	Finalize(&report)
	human := string(Human(report, HumanOptions{}))
	if !strings.Contains(human, "f.yaml#4  CronJob n4") || strings.Contains(human, "n5") || !strings.Contains(human, "... and 2 more") {
		t.Fatalf("human:\n%s", human)
	}
	Redact(&report)
	human = string(Human(report, HumanOptions{}))
	if strings.Contains(human, "f.yaml") || strings.Contains(human, " n0") || !strings.Contains(human, RedactValue("f.yaml")[:19]+"#0  CronJob "+RedactValue("n0")[:19]+"\n") {
		t.Fatalf("redacted human:\n%s", human)
	}
	if RedactValue("") != "" || RedactValue("a") == RedactValue("b") {
		t.Fatal("redaction")
	}
}
