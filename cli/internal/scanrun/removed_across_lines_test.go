// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// A manifest object at an API version the target line does not serve never
// yields a "no blockers" answer. When a reviewed rule covers the removal on a
// line the upgrade enters, the answer is BLOCKED even if the upgrade skips
// lines; otherwise it is UNKNOWN with a named gap and a next action.

const cronjobOnlyV1beta1 = "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: nightly\n  namespace: demo\nspec:\n  schedule: \"0 1 * * *\"\n"

// embeddedOnly is the knowledge the shipped binary uses, with nothing added
// (no line review, no path policy, no served list).
func embeddedOnly(t *testing.T) Knowledge {
	t.Helper()
	knowledge, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	return knowledge
}

// notPassLike fails when the report reads like a pass while a manifest is
// at an API version the target does not serve.
func notPassLike(t *testing.T, report scanreport.Report) {
	t.Helper()
	if strings.Contains(report.Headline, "NO BLOCKERS FOUND") || report.Verdict == scanreport.VerdictPass {
		t.Fatalf("pass-like answer %s %q", report.Verdict, report.Headline)
	}
	for _, gap := range report.Gaps {
		if strings.Contains(gap.Detail, "removed before the evaluated hops") {
			t.Fatalf("false gap text %q", gap.Detail)
		}
		if gap.Action == "none" {
			t.Fatalf("gap without a next action %+v", gap)
		}
	}
}

// sameStep compares the step a finding names, and checks that the step's
// engine input digest is recorded.
func sameStep(got *scanreport.CrossedLine, want scanreport.CrossedLine) bool {
	return got != nil && got.Line == want.Line && got.From == want.From && got.To == want.To && strings.HasPrefix(got.InputDigest, "sha256:") && len(got.InputDigest) == len("sha256:")+64
}

func findingFor(t *testing.T, report scanreport.Report, ruleID string) scanreport.Finding {
	t.Helper()
	for _, finding := range report.Findings {
		if finding.RuleID == ruleID {
			return finding
		}
	}
	t.Fatalf("no finding for %s in %+v", ruleID, report.Findings)
	return scanreport.Finding{}
}

// TestScanC1RemovedAPIAcrossSkippedLines reproduces the audit's C1 exactly:
// a CronJob at batch/v1beta1, 1.24.17 -> 1.30.4, every declaration, the
// shipped knowledge. Kubernetes 1.25 removed the version and the reviewed
// 1.24 -> 1.25 rule covers every release of both lines, so the step that
// enters 1.25 blocks, and with it the upgrade. It used to answer "NO BLOCKERS
// FOUND IN COVERED CHECKS" (exit 11) with a gap saying the version was
// "removed before the evaluated hops".
func TestScanC1RemovedAPIAcrossSkippedLines(t *testing.T) {
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobOnlyV1beta1})
	result := mustScan(t, embeddedOnly(t), args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
	report := result.Report
	notPassLike(t, report)
	if result.Exit != scanreport.ExitBlocked || report.Verdict != scanreport.VerdictBlocked || report.Headline != "BLOCKED: 1 problem must be fixed before this upgrade" {
		t.Fatalf("exit %d verdict %s headline %q gaps %v", result.Exit, report.Verdict, report.Headline, gapReasons(report))
	}
	finding := findingFor(t, report, cronjobRuleID)
	want := scanreport.CrossedLine{Line: "1.25", From: "1.24.17", To: "1.25"}
	if !sameStep(finding.CrossedLine, want) || finding.Hop.From != "1.24.17" || finding.Hop.To != "1.30.4" || finding.Match != "range" {
		t.Fatalf("finding %+v crossed line %+v", finding, finding.CrossedLine)
	}
	if !strings.HasSuffix(finding.Fix, "Decided on the step 1.24.17 -> 1.25, which this upgrade takes to enter Kubernetes 1.25.") {
		t.Fatalf("fix does not name the step: %q", finding.Fix)
	}
	if len(finding.Locations) != 1 || finding.Locations[0].Kind != "CronJob" || finding.Locations[0].Name != "nightly" {
		t.Fatalf("locations %+v", finding.Locations)
	}
	if hop := report.Paths[0].Hops[0]; hop.Status != scanreport.HopBlocked {
		t.Fatalf("hop %+v", hop)
	}
	// The blocker is decided, so no gap repeats it; the skipped lines stay
	// a named gap.
	if hasGap(report, scanreport.ReasonAPIVersionNotServed, "") || !hasGap(report, scanreport.ReasonNoReviewedPathPolicy, "skips release lines") {
		t.Fatalf("gaps %+v", report.Gaps)
	}
}

// TestScanRemovedAPIAcrossSkippedLinesVariants: multi-minor hops that cross
// one or several removal lines, with and without a path policy that keeps the
// hop direct. Every removal a reviewed rule covers on an entered line blocks,
// at the step that enters that line.
func TestScanRemovedAPIAcrossSkippedLinesVariants(t *testing.T) {
	const (
		ingressExtensions = "apiVersion: extensions/v1beta1\nkind: Ingress\nmetadata:\n  name: web\n  namespace: demo\n"
		hpaV2beta2        = "apiVersion: autoscaling/v2beta2\nkind: HorizontalPodAutoscaler\nmetadata:\n  name: web\n  namespace: demo\n"
		flowSchemaV1beta2 = "apiVersion: flowcontrol.apiserver.k8s.io/v1beta2\nkind: FlowSchema\nmetadata:\n  name: tenants\n"
	)
	direct := newKnowledge(t, knowledgeOptions{lines: append([]string{"1.22", "1.23", "1.24"}, allLines...), policy: "direct", unchecked: true})
	cases := []struct {
		name, from, to string
		knowledge      Knowledge
		manifests      []string
		// steps maps a rule id to the step it must be decided on.
		steps map[string]scanreport.CrossedLine
	}{
		{"1.21 -> 1.26 across 1.25", "1.21.0", "1.26.0", embeddedOnly(t), []string{cronjobOnlyV1beta1},
			map[string]scanreport.CrossedLine{cronjobRuleID: {Line: "1.25", From: "1.24", To: "1.25"}}},
		{"1.21 -> 1.26 across 1.22 and onto 1.26", "1.21.0", "1.26.0", embeddedOnly(t), []string{ingressExtensions, hpaV2beta2},
			map[string]scanreport.CrossedLine{
				"kubernetes.ingress-extensions-v1beta1-removed.1-21-0-to-1-22-0": {Line: "1.22", From: "1.21.0", To: "1.22"},
				"kubernetes.hpa-v2beta2-removed.1-25-0-to-1-26-0":                {Line: "1.26", From: "1.25", To: "1.26.0"},
			}},
		{"1.24 -> 1.30 across 1.25 and 1.29", "1.24.17", "1.30.4", embeddedOnly(t), []string{cronjobOnlyV1beta1, flowSchemaV1beta2},
			map[string]scanreport.CrossedLine{
				cronjobRuleID: {Line: "1.25", From: "1.24.17", To: "1.25"},
				"kubernetes.flowcontrol-v1beta2-removed.1-28-0-to-1-29-0": {Line: "1.29", From: "1.28", To: "1.29"},
			}},
		{"direct policy 1.24 -> 1.30 across 1.25 and 1.29", "1.24.17", "1.30.4", direct, []string{cronjobOnlyV1beta1, flowSchemaV1beta2},
			map[string]scanreport.CrossedLine{
				cronjobRuleID: {Line: "1.25", From: "1.24.17", To: "1.25"},
				"kubernetes.flowcontrol-v1beta2-removed.1-28-0-to-1-29-0": {Line: "1.29", From: "1.28", To: "1.29"},
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, paths := files(t, map[string]string{"applyset.yaml": strings.Join(tc.manifests, "---\n")})
			result := mustScan(t, tc.knowledge, args(paths, "--from", "kubernetes="+tc.from, "--to", "kubernetes="+tc.to)...)
			notPassLike(t, result.Report)
			if result.Exit != scanreport.ExitBlocked || len(result.Report.Findings) != len(tc.steps) {
				t.Fatalf("exit %d findings %+v gaps %v", result.Exit, result.Report.Findings, gapReasons(result.Report))
			}
			for id, step := range tc.steps {
				finding := findingFor(t, result.Report, id)
				if !sameStep(finding.CrossedLine, step) {
					t.Fatalf("%s decided on %+v, want %+v", id, finding.CrossedLine, step)
				}
			}
			if hasGap(result.Report, scanreport.ReasonAPIVersionNotServed, "") {
				t.Fatalf("decided objects repeated as a gap: %+v", result.Report.Gaps)
			}
		})
	}
}

// TestScanRemovedAPIUndecidedIsExplicitUnknown: when no reviewed rule decides
// the removal (the pack lacks it, the trust policy leaves it out, a
// declaration is missing, or it was removed at or before the current line),
// the answer is UNKNOWN with a headline that names the object, a gap that
// says why, and a next action. It is never "no blockers".
func TestScanRemovedAPIUndecidedIsExplicitUnknown(t *testing.T) {
	without := hiddenRules{Knowledge: embeddedOnly(t), hidden: map[string]bool{cronjobRuleID: true}}
	cases := []struct {
		name      string
		knowledge Knowledge
		from      string
		extra     []string
		detail    string
	}{
		{"pack lacks the rule", without, "1.24.17", nil, "removed on a line this upgrade enters"},
		{"trust policy leaves the rule out", embeddedOnly(t), "1.24.17", []string{"--require-basis", "mechanical"}, "removed on a line this upgrade enters"},
		{"removed at or before the current line", embeddedOnly(t), "1.25.2", nil, "removed at or before that release"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, paths := files(t, map[string]string{"applyset.yaml": cronjobOnlyV1beta1})
			result := mustScan(t, tc.knowledge, args(paths, append([]string{"--from", "kubernetes=" + tc.from, "--to", "kubernetes=1.30.4"}, tc.extra...)...)...)
			report := result.Report
			notPassLike(t, report)
			if result.Exit != scanreport.ExitUnknown || !strings.HasPrefix(report.Headline, "UNKNOWN: manifests use API versions the target does not serve; migrate them before upgrading (") {
				t.Fatalf("exit %d headline %q", result.Exit, report.Headline)
			}
			if !hasGap(report, scanreport.ReasonAPIVersionNotServed, tc.detail) || !hasGap(report, scanreport.ReasonAPIVersionNotServed, "Kubernetes 1.30 does not serve") {
				t.Fatalf("gaps %+v", report.Gaps)
			}
		})
	}
	// A missing declaration keeps the rule from deciding on a planned path
	// too: the hop that enters 1.25 evaluates the rule, which cannot decide,
	// and the object is still named (the backstop of the line's rule).
	planned := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobOnlyV1beta1})
	command := append(append([]string{}, paths...), "--distribution", "official_upstream", "--target-api-apply-required", "--now", testNow, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")
	result := mustScan(t, planned, command...)
	notPassLike(t, result.Report)
	if result.Exit != scanreport.ExitUnknown || !hasGap(result.Report, scanreport.ReasonAPIVersionNotServed, "removed on a line this upgrade enters") || !hasGap(result.Report, scanreport.ReasonDeclarationMissing, "") {
		t.Fatalf("exit %d gaps %+v", result.Exit, result.Report.Gaps)
	}
	// With every declaration the same plan blocks, and the gap is gone.
	full := mustScan(t, planned, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
	if full.Exit != scanreport.ExitBlocked || hasGap(full.Report, scanreport.ReasonAPIVersionNotServed, "") {
		t.Fatalf("exit %d gaps %+v", full.Exit, full.Report.Gaps)
	}
	if finding := findingFor(t, full.Report, cronjobRuleID); finding.CrossedLine != nil {
		t.Fatalf("a hop that enters one line needs no step disclosure: %+v", finding.CrossedLine)
	}
}

// TestScanRemovedAPIAcrossSkippedLinesFormats: the BLOCKED answer and the
// UNKNOWN fallback read the same in every format: no "no blockers" headline,
// no false gap text, the step disclosed, and JSON within the schema.
func TestScanRemovedAPIAcrossSkippedLinesFormats(t *testing.T) {
	runs := []struct {
		name      string
		knowledge Knowledge
		exit      int
		headline  string
	}{
		{"blocked", embeddedOnly(t), scanreport.ExitBlocked, "BLOCKED: 1 problem must be fixed before this upgrade"},
		{"unknown", hiddenRules{Knowledge: embeddedOnly(t), hidden: map[string]bool{cronjobRuleID: true}}, scanreport.ExitUnknown,
			"UNKNOWN: manifests use API versions the target does not serve; migrate them before upgrading (3 areas were not checked)"},
	}
	for _, run := range runs {
		dir, _ := files(t, map[string]string{"applyset.yaml": cronjobOnlyV1beta1})
		for _, format := range scanreport.Formats() {
			t.Run(run.name+"/"+format, func(t *testing.T) {
				var result Result
				inDir(t, dir, func() {
					result = mustScan(t, run.knowledge, args([]string{"applyset.yaml"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4", "--format", format)...)
				})
				if result.Exit != run.exit || result.Report.Headline != run.headline {
					t.Fatalf("exit %d headline %q", result.Exit, result.Report.Headline)
				}
				out, err := scanreport.Render(result.Report, format, scanreport.RenderOptions{})
				if err != nil {
					t.Fatal(err)
				}
				text := string(out)
				if strings.Contains(text, "NO BLOCKERS FOUND") || strings.Contains(text, "removed before the evaluated hops") || !strings.Contains(text, run.headline) {
					t.Fatalf("%s output:\n%s", format, text)
				}
				step := "Decided on the step 1.24.17 -> 1.25, which this upgrade takes to enter Kubernetes 1.25."
				if run.exit == scanreport.ExitBlocked && format != "json" && !strings.Contains(text, step) {
					t.Fatalf("%s output lacks the step:\n%s", format, text)
				}
				switch format {
				case "json":
					conformReport(t, run.name, result.Report)
					if run.exit == scanreport.ExitBlocked && !strings.Contains(text, strings.ReplaceAll(step, ">", `\u003e`)) {
						t.Fatalf("JSON lacks the step:\n%s", text)
					}
					if run.exit == scanreport.ExitBlocked && !strings.Contains(text, `"crossedLine":{"line":"1.25","from":"1.24.17","to":"1.25","inputDigest":"sha256:`) {
						t.Fatalf("JSON lacks the step:\n%s", text)
					}
				case "sarif":
					var log struct {
						Runs []struct {
							Results []struct {
								Properties struct {
									CrossedLine *scanreport.CrossedLine `json:"crossedLine"`
								} `json:"properties"`
							} `json:"results"`
						} `json:"runs"`
					}
					if err := json.Unmarshal(out, &log); err != nil {
						t.Fatal(err)
					}
					results := log.Runs[0].Results
					if run.exit == scanreport.ExitBlocked && (len(results) != 1 || results[0].Properties.CrossedLine == nil || results[0].Properties.CrossedLine.Line != "1.25") {
						t.Fatalf("SARIF results %+v", results)
					}
				}
			})
		}
	}
}

// TestScanLineReviewGapAgreesWithBlocker: a report where a reviewed 1.25
// removal rule decided BLOCKED never also says 1.25 "has not been reviewed
// for removed APIs"; the missing evidence is a review that the rules are the
// complete list for the line, and the gap says so.
func TestScanLineReviewGapAgreesWithBlocker(t *testing.T) {
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobOnlyV1beta1})
	result := mustScan(t, embeddedOnly(t), args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3")...)
	if result.Exit != scanreport.ExitBlocked {
		t.Fatalf("exit %d", result.Exit)
	}
	for _, gap := range result.Report.Gaps {
		if strings.Contains(gap.Detail, "has not been reviewed for removed APIs") {
			t.Fatalf("contradicting gap %q", gap.Detail)
		}
	}
	if !hasGap(result.Report, scanreport.ReasonLineNotAttested, "no review confirms that the removed-API rules for kubernetes 1.25 name every API that line removes") {
		t.Fatalf("gaps %+v", result.Report.Gaps)
	}
}

// TestScanDowngradeGapHasNextAction: the downgrade gap names a real next
// action, never "none".
func TestScanDowngradeGapHasNextAction(t *testing.T) {
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	result := mustScan(t, embeddedOnly(t), args(paths, "--from", "kubernetes=1.25.2", "--to", "kubernetes=1.24.1")...)
	for _, gap := range result.Report.Gaps {
		if gap.Reason == scanreport.ReasonDowngradeNotReviewed {
			if gap.Action == "none" || !strings.Contains(gap.Action, "swap --from and --to") || !strings.Contains(gap.Action, "kubernetes rollback notes") {
				t.Fatalf("downgrade action %q", gap.Action)
			}
			return
		}
	}
	t.Fatalf("no downgrade gap: %+v", result.Report.Gaps)
}
