// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

const (
	skewSource    = `{"id":"kubernetes-website-version-skew-upgrade-order","url":"https://github.com/kubernetes/website/blob/9f1af2971c32124bff0a1f42255ba5a2f3c8a16f/content/en/releases/version-skew-policy.md","revision":"9f1af2971c32124bff0a1f42255ba5a2f3c8a16f","contentDigest":"sha256:7d33809eeb313cbd589018a8dde893974065c50f5ee8cde27d99e879d0dde81f","startLine":189,"endLine":193}`
	currentWindow = `"reviewedAt":"2026-09-23T00:00:00Z","validUntil":"2026-12-20T00:00:00Z"`
	staleWindow   = `"reviewedAt":"2026-06-01T00:00:00Z","validUntil":"2026-08-01T00:00:00Z"`
)

// lineRange is a reviewed range covering the whole lines from-line and
// to-line, licensed by the version-skew source.
func lineRange(fromLine, toLine, next string) string {
	return `"range":{"from":{"gte":"` + fromLine + `.0","lt":"` + toLine + `.0"},"to":{"gte":"` + toLine + `.0","lt":"` + next + `.0"},"bounds":[` +
		`{"bound":"from.gte","basis":"PREVIOUS_MINOR_LINE","sourceId":"kubernetes-website-version-skew-upgrade-order"},` +
		`{"bound":"from.lt","basis":"CHANGED_IN_RELEASE","sourceId":"kubernetes-website-version-skew-upgrade-order"},` +
		`{"bound":"to.gte","basis":"CHANGED_IN_RELEASE","sourceId":"kubernetes-website-version-skew-upgrade-order"},` +
		`{"bound":"to.lt","basis":"TARGET_SERIES","sourceId":"kubernetes-website-version-skew-upgrade-order"}]},`
}

// noticeRule is a synthetic one-way notice rule.
func noticeRule(id, from, to, rangeJSON, window string) string {
	return `{"id":"` + id + `","operator":"notice_one_way","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"` + from + `","to":"` + to + `"},` + rangeJSON +
		`"evidence":{"state":"active",` + window + `,"sources":[` + skewSource + `]},` +
		`"reasonCode":"ONE_WAY_TRANSITION","nextAction":"Back up etcd before you start; the stored objects are rewritten."}`
}

// verdictRule is a synthetic forbid_predicate_value rule on one fact.
func verdictRule(id, from, to, rangeJSON, fact string) string {
	return `{"id":"` + id + `","operator":"forbid_predicate_value","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"` + from + `","to":"` + to + `"},` + rangeJSON +
		`"condition":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","factId":"` + fact + `","boolValue":true},` +
		`"evidence":{"state":"active",` + currentWindow + `,"sources":[` + testSource + `,` + skewSource + `]},` +
		`"reasonCode":"REVIEWED_SOURCE_CONSTRAINT","nextAction":"synthetic test-only action"}`
}

func hasGap(report scanreport.Report, reason, detail string) bool {
	for _, gap := range report.Gaps {
		if gap.Reason == reason && strings.Contains(gap.Detail, detail) {
			return true
		}
	}
	return false
}

// TestScanAPIVersionsAtTarget: an object at a version the target no longer
// serves is never a pass, whether it was removed on a line no hop crosses or
// is a version no served list of the target names.
func TestScanAPIVersionsAtTarget(t *testing.T) {
	full := knowledgeOptions{lines: allLines, policy: "current"}
	cases := []struct {
		name, manifest, from string
		knowledge            knowledgeOptions
		reason, detail       string
	}{
		{"CronJob removed before the current line", "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: a}\n", "1.25.3", full, "API_VERSION_NOT_SERVED", "no longer serves"},
		{"CronJob, adjacent line, no policy, one review", "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: a}\n", "1.29.6", knowledgeOptions{lines: []string{"1.30"}}, "API_VERSION_NOT_SERVED", "no longer serves"},
		{"Ingress networking v1beta1", "apiVersion: networking.k8s.io/v1beta1\nkind: Ingress\nmetadata: {name: a}\n", "1.24.17", full, "API_VERSION_NOT_SERVED", "no longer serves"},
		{"PodSecurityPolicy", "apiVersion: policy/v1beta1\nkind: PodSecurityPolicy\nmetadata: {name: a}\n", "1.25.0", full, "API_VERSION_NOT_SERVED", "no longer serves"},
		{"HPA v2beta2", "apiVersion: autoscaling/v2beta2\nkind: HorizontalPodAutoscaler\nmetadata: {name: a}\n", "1.26.0", full, "API_VERSION_NOT_SERVED", "no longer serves"},
		{"Deployment extensions v1beta1", "apiVersion: extensions/v1beta1\nkind: Deployment\nmetadata: {name: a}\n", "1.24.17", full, "API_VERSION_NOT_REVIEWED", "does not list as served"},
		{"DaemonSet apps v1beta2", "apiVersion: apps/v1beta2\nkind: DaemonSet\nmetadata: {name: a}\n", "1.24.17", full, "API_VERSION_NOT_REVIEWED", "does not list as served"},
		{"no served list", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\n", "1.24.17", knowledgeOptions{lines: allLines, policy: "current", noServedList: true}, "API_VERSION_NOT_REVIEWED", "no reviewed list"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, paths := files(t, map[string]string{"applyset.yaml": tc.manifest})
			result := mustScan(t, newKnowledge(t, tc.knowledge), args(paths, "--from", "kubernetes="+tc.from, "--to", "kubernetes=1.30.4")...)
			if result.Exit == scanreport.ExitPass || !hasGap(result.Report, tc.reason, tc.detail) {
				t.Fatalf("exit %d gaps %+v", result.Exit, result.Report.Gaps)
			}
		})
	}
	// A served object on the same knowledge passes.
	_, paths := files(t, map[string]string{"applyset.yaml": "apiVersion: apps/v1\nkind: DaemonSet\nmetadata: {name: a}\n"})
	if result := mustScan(t, newKnowledge(t, full), args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...); result.Exit != scanreport.ExitPass {
		t.Fatalf("served object: exit %d gaps %v", result.Exit, gapReasons(result.Report))
	}
}

// TestScanNonFamilyRuleInsideLine: a rule outside the removed-API family that
// applies to some releases of an intermediate line leaves that hop PARTIAL.
func TestScanNonFamilyRuleInsideLine(t *testing.T) {
	rule := verdictRule("kubernetes.synthetic-other-evidence.1-25-7-to-1-26-0", "1.25.7", "1.26.0", "", "component.kubernetes.in_tree_dockershim_required")
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", synthetic: []string{rule}})
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	result := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
	hop := result.Report.Paths[0].Hops[1]
	if result.Exit != scanreport.ExitUnknown || hop.Status != scanreport.HopPartial || !reflect.DeepEqual(hop.Reasons, []string{scanreport.ReasonIntermediateLineNotCovered}) {
		t.Fatalf("exit %d hop %+v", result.Exit, hop)
	}
}

// TestScanRuleInsideLine: a removed-API rule reviewed for one patch inside
// an intermediate line (1.25.7 -> 1.26.0) does not match the engine input
// 1.25.0 -> 1.26.0, but it applies to the hop 1.25 -> 1.26. It is found by
// overlap and keeps the hop undecided, even when the line review leaves it
// out.
func TestScanRuleInsideLine(t *testing.T) {
	const id = "kubernetes.synthetic-inside-line.1-25-7-to-1-26-0"
	rule := verdictRule(id, "1.25.7", "1.26.0", "", "component.kubernetes.flowcontrol_v1beta3_removed_gvk_present")
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", unchecked: true, synthetic: []string{rule}, dropRuleIDs: map[string][]string{"1.26": {id}}})
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	result := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
	hop := result.Report.Paths[0].Hops[1]
	if result.Exit != scanreport.ExitUnknown || hop.Status != scanreport.HopPartial || !reflect.DeepEqual(gapReasons(result.Report), []string{"INTERMEDIATE_LINE_NOT_COVERED_BY_RANGE 1.25->1.26", "LINE_NOT_ATTESTED 1.25->1.26"}) {
		t.Fatalf("exit %d hop %+v gaps %v", result.Exit, hop, gapReasons(result.Report))
	}
}

// TestScanWholeUpgradeRule: a rule reviewed for the exact end-to-end pair
// matches no hop of a sequential plan. Its blocker is found on the whole
// upgrade, so it is never lost, and its pass alone never decides anything.
func TestScanWholeUpgradeRule(t *testing.T) {
	const id = "kubernetes.synthetic-whole-upgrade.1-24-17-to-1-30-4"
	rule := verdictRule(id, "1.24.17", "1.30.4", "", "component.kubernetes.flowcontrol_v1beta3_removed_gvk_present")
	knowledge := newKnowledge(t, knowledgeOptions{lines: []string{"1.25", "1.26", "1.27", "1.28", "1.29"}, policy: "current", synthetic: []string{rule}})
	_, paths := files(t, map[string]string{"apf.yaml": "apiVersion: flowcontrol.apiserver.k8s.io/v1beta3\nkind: FlowSchema\nmetadata: {name: limits}\n"})
	result := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
	if result.Exit != scanreport.ExitBlocked || len(result.Report.Findings) != 1 {
		t.Fatalf("exit %d findings %+v", result.Exit, result.Report.Findings)
	}
	finding := result.Report.Findings[0]
	if finding.RuleID != id || !finding.Hop.WholeUpgrade || finding.Hop.From != "1.24.17" || finding.Hop.To != "1.30.4" || len(finding.Locations) != 1 {
		t.Fatalf("finding %+v", finding)
	}
	if human := string(scanreport.Human(result.Report, scanreport.HumanOptions{})); !strings.Contains(human, "whole upgrade 1.24.17 -> 1.30.4") {
		t.Fatalf("human:\n%s", human)
	}
	_, paths = files(t, map[string]string{"apf.yaml": "apiVersion: flowcontrol.apiserver.k8s.io/v1\nkind: FlowSchema\nmetadata: {name: limits}\n"})
	result = mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
	passed := false
	for _, pass := range result.Report.Passes {
		passed = passed || pass.RuleID == id && pass.Hop.WholeUpgrade
	}
	if result.Exit == scanreport.ExitPass || len(result.Report.Findings) != 0 || !passed {
		t.Fatalf("served: exit %d passes %+v", result.Exit, result.Report.Passes)
	}
}

// TestScanRefusedLine: a hop into a line whose removals the knowledge has no
// rule for is NO_DATA, even when a (malformed) review of the line exists:
// whether the knowledge lacks the line's facts or only the rules over them.
func TestScanRefusedLine(t *testing.T) {
	for _, line := range []struct {
		line, from, to, removed string
	}{
		{"1.33", "1.32.4", "1.33.1", "apiVersion: authentication.k8s.io/v1beta1\nkind: SelfSubjectReview\nmetadata: {name: a}\n"},
		{"1.34", "1.33.2", "1.34.0", "apiVersion: admissionregistration.k8s.io/v1beta1\nkind: ValidatingAdmissionPolicy\nmetadata: {name: a}\n"},
		{"1.37", "1.36.5", "1.37.1", "apiVersion: networking.k8s.io/v1beta1\nkind: IPAddress\nmetadata: {name: a}\n"},
		{"1.37", "1.36.0", "1.37.0", "apiVersion: storage.k8s.io/v1beta1\nkind: VolumeAttributesClass\nmetadata: {name: a}\n"},
	} {
		knowledge := newKnowledge(t, knowledgeOptions{lines: []string{line.line}, policy: "current", unchecked: true})
		for _, manifest := range []string{"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\n", line.removed} {
			_, paths := files(t, map[string]string{"applyset.yaml": manifest})
			result := mustScan(t, knowledge, args(paths, "--from", "kubernetes="+line.from, "--to", "kubernetes="+line.to)...)
			hop := result.Report.Paths[0].Hops[0]
			if result.Exit != scanreport.ExitUnknown || hop.Status != scanreport.HopNoData || !hasGap(result.Report, "LINE_NOT_ATTESTED", "no reviewed rule covers yet") {
				t.Fatalf("%s: exit %d hop %+v gaps %+v", line.line, result.Exit, hop, result.Report.Gaps)
			}
		}
	}
}

// TestScanRegisteredLineWithARule: once a rule reads one of a line's
// removal facts, the hop is evaluated: a removed version blocks, and a
// served one is not reported as a line without rules.
func TestScanRegisteredLineWithARule(t *testing.T) {
	const id = "kubernetes.synthetic-volumeattributesclass.1-36-0-to-1-37-0"
	rule := verdictRule(id, "1.36.0", "1.37.0", "", "component.kubernetes.volumeattributesclass_v1beta1_removed_gvk_present")
	knowledge := newKnowledge(t, knowledgeOptions{lines: []string{"1.37"}, policy: "current", unchecked: true, synthetic: []string{rule}})
	_, paths := files(t, map[string]string{"applyset.yaml": "apiVersion: storage.k8s.io/v1beta1\nkind: VolumeAttributesClass\nmetadata: {name: a}\n"})
	result := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.36.0", "--to", "kubernetes=1.37.0")...)
	if result.Exit != scanreport.ExitBlocked || len(result.Report.Findings) != 1 || result.Report.Findings[0].RuleID != id {
		t.Fatalf("exit %d findings %+v gaps %+v", result.Exit, result.Report.Findings, result.Report.Gaps)
	}
	_, paths = files(t, map[string]string{"applyset.yaml": "apiVersion: storage.k8s.io/v1\nkind: VolumeAttributesClass\nmetadata: {name: a}\n"})
	result = mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.36.0", "--to", "kubernetes=1.37.0")...)
	hop := result.Report.Paths[0].Hops[0]
	if result.Exit == scanreport.ExitBlocked || hop.Status == scanreport.HopNoData || hasGap(result.Report, "LINE_NOT_ATTESTED", "no reviewed rule covers yet") {
		t.Fatalf("exit %d hop %+v gaps %+v", result.Exit, hop, result.Report.Gaps)
	}
}

// hiddenRules is test knowledge without some published rules (and their
// claims): a pack that lacks the rule for a removal the preparation knows.
type hiddenRules struct {
	Knowledge
	hidden map[string]bool
}

func (k hiddenRules) Rules(project string) []cncfcheck.ScanRule {
	var out []cncfcheck.ScanRule
	for _, rule := range k.Knowledge.Rules(project) {
		if !k.hidden[rule.Scope.ID] {
			out = append(out, rule)
		}
	}
	return out
}

func (k hiddenRules) Evaluate(policy cncfcheck.TrustPolicy, project string, facts []string, inputRaw []byte, now time.Time) (Evaluation, error) {
	evaluation, err := k.Knowledge.Evaluate(policy, project, facts, inputRaw, now)
	var claims []constraintengine.Claim
	for _, claim := range evaluation.Claims {
		if !k.hidden[claim.RuleID] {
			claims = append(claims, claim)
		}
	}
	evaluation.Claims = claims
	return evaluation, err
}

// TestScanTrueFactWithoutRule: a fact the preparation found true that no
// rule deciding the hop reads keeps the hop from COVERED, even when the
// line's review lists every remaining rule.
func TestScanTrueFactWithoutRule(t *testing.T) {
	const cronjob = "kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0"
	base := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", unchecked: true, dropRuleIDs: map[string][]string{"1.25": {cronjob}}})
	knowledge := hiddenRules{Knowledge: base, hidden: map[string]bool{cronjob: true}}
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	result := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
	hop := result.Report.Paths[0].Hops[0]
	if result.Exit != scanreport.ExitUnknown || hop.Status != scanreport.HopPartial || !hasGap(result.Report, "LINE_NOT_ATTESTED", "no reviewed rule decides") {
		t.Fatalf("exit %d hop %+v gaps %+v", result.Exit, hop, result.Report.Gaps)
	}
}

// TestScanTwoLinesWithoutPolicy: skipping one line without a reviewed
// policy is named as such.
func TestScanTwoLinesWithoutPolicy(t *testing.T) {
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	result := mustScan(t, newKnowledge(t, knowledgeOptions{lines: allLines}), args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.26.3")...)
	if result.Exit != scanreport.ExitUnknown || !reflect.DeepEqual(gapReasons(result.Report), []string{"NO_REVIEWED_PATH_POLICY"}) {
		t.Fatalf("exit %d gaps %v", result.Exit, gapReasons(result.Report))
	}
}

// withoutNotices drops the notices and their count from a JSON report.
func withoutNotices(t *testing.T, report scanreport.Report) string {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(jsonOf(t, report), &value); err != nil {
		t.Fatal(err)
	}
	delete(value, "notices")
	delete(value["summary"].(map[string]any), "notices")
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestScanNoticesAreVerdictNeutral: one-way notices are listed and never
// change the verdict, the gaps, the exit code or any other part of the
// report, whatever the base answer and whatever the notice's own state.
func TestScanNoticesAreVerdictNeutral(t *testing.T) {
	const covering, stale, inside = "kubernetes.synthetic-notice.1-25-0-to-1-26-0", "kubernetes.synthetic-notice-stale.1-26-0-to-1-27-0", "kubernetes.synthetic-notice-inside.1-27-3-to-1-28-0"
	notices := []string{
		noticeRule(covering, "1.25.0", "1.26.0", lineRange("1.25", "1.26", "1.27"), currentWindow),
		noticeRule(stale, "1.26.0", "1.27.0", lineRange("1.26", "1.27", "1.28"), staleWindow),
		noticeRule(inside, "1.27.3", "1.28.0", "", currentWindow),
	}
	bases := []struct {
		name     string
		manifest string
		lines    []string
		exit     int
	}{
		{"pass", cronjobV1, allLines, scanreport.ExitPass},
		{"blocked", cronjobV1beta1, allLines, scanreport.ExitBlocked},
		{"unknown", cronjobV1, without(allLines, "1.29"), scanreport.ExitUnknown},
	}
	for _, base := range bases {
		t.Run(base.name, func(t *testing.T) {
			dir, _ := files(t, map[string]string{"applyset.yaml": base.manifest})
			var plain, noticed Result
			inDir(t, dir, func() {
				plain = mustScan(t, newKnowledge(t, knowledgeOptions{lines: base.lines, policy: "current"}), args([]string{"applyset.yaml"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
				// The review of 1.26 lists the covering notice: a notice never
				// supports or spoils a review.
				noticed = mustScan(t, newKnowledge(t, knowledgeOptions{lines: base.lines, policy: "current", synthetic: notices, unchecked: true,
					extraRuleIDs: map[string][]string{"1.26": {covering}}}), args([]string{"applyset.yaml"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
			})
			if plain.Exit != base.exit || noticed.Exit != base.exit {
				t.Fatalf("exit %d / %d, want %d; gaps %v", plain.Exit, noticed.Exit, base.exit, gapReasons(noticed.Report))
			}
			if withoutNotices(t, plain.Report) != withoutNotices(t, noticed.Report) {
				t.Fatalf("notices changed the report:\n%s\n%s", withoutNotices(t, plain.Report), withoutNotices(t, noticed.Report))
			}
			if len(plain.Report.Notices) != 0 || noticed.Report.Summary.Notices != 3 {
				t.Fatalf("notices %+v", noticed.Report.Notices)
			}
			got := map[string]string{}
			for _, notice := range noticed.Report.Notices {
				got[notice.RuleID] = notice.Reason
				if notice.Established != (notice.Reason == "") || notice.Text == "" {
					t.Fatalf("notice %+v", notice)
				}
			}
			want := map[string]string{covering: "", stale: "RULE_EVIDENCE_STALE", inside: scanreport.ReasonIntermediateLineNotCovered}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("notices %v", got)
			}
			human := string(scanreport.Human(noticed.Report, scanreport.HumanOptions{}))
			if !strings.Contains(human, "ONE-WAY CHANGES (3)") || !strings.Contains(human, "cannot be rolled back: "+covering) || !strings.Contains(human, "before you upgrade: Back up etcd") || strings.Contains(strings.ToLower(human), "safe") {
				t.Fatalf("human:\n%s", human)
			}
			if strings.Contains(string(scanreport.Human(plain.Report, scanreport.HumanOptions{})), "ONE-WAY") {
				t.Fatal("notice section without notices")
			}
		})
	}
}

// claimEditor rewrites the claims of the knowledge it wraps.
type claimEditor struct {
	Knowledge
	edit func([]constraintengine.Claim)
	// extend, when set, returns the claims with more added.
	extend func([]constraintengine.Claim) []constraintengine.Claim
}

func (k claimEditor) Evaluate(policy cncfcheck.TrustPolicy, project string, facts []string, inputRaw []byte, now time.Time) (Evaluation, error) {
	evaluation, err := k.Knowledge.Evaluate(policy, project, facts, inputRaw, now)
	if err == nil && k.edit != nil {
		k.edit(evaluation.Claims)
	}
	if err == nil && k.extend != nil {
		evaluation.Claims = k.extend(evaluation.Claims)
	}
	return evaluation, err
}

// TestScanNoticeIntegrity: a NOTICE from a verdict rule, a verdict from a
// notice rule, or a notice claim of a rule scan does not know as a notice is
// an integrity failure, never an answer.
func TestScanNoticeIntegrity(t *testing.T) {
	const covering = "kubernetes.synthetic-notice.1-25-0-to-1-26-0"
	base := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", unchecked: true, synthetic: []string{noticeRule(covering, "1.25.0", "1.26.0", lineRange("1.25", "1.26", "1.27"), currentWindow)}})
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	edits := map[string]func([]constraintengine.Claim){
		"NOTICE from a verdict rule": func(claims []constraintengine.Claim) {
			for i := range claims {
				if !claims[i].IsNotice() && claims[i].Status == "PASS" {
					claims[i].Status = constraintengine.StatusNotice
				}
			}
		},
		"PASS from a notice rule": func(claims []constraintengine.Claim) {
			for i := range claims {
				if claims[i].IsNotice() && claims[i].Status == constraintengine.StatusNotice {
					claims[i].Status = "PASS"
				}
			}
		},
		"verdict rule claims to be a notice": func(claims []constraintengine.Claim) {
			for i := range claims {
				if !claims[i].IsNotice() && claims[i].Status == "UNKNOWN" {
					claims[i].Operator = constraintengine.OperatorNoticeOneWay
				}
			}
		},
		"notice rule claims to be a verdict rule": func(claims []constraintengine.Claim) {
			for i := range claims {
				if claims[i].IsNotice() && claims[i].Status == "UNKNOWN" {
					claims[i].Operator = "forbid_predicate_value"
				}
			}
		},
	}
	if result := mustScan(t, claimEditor{Knowledge: base, edit: func([]constraintengine.Claim) {}}, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...); len(result.Report.Notices) != 1 || !result.Report.Notices[0].Established {
		t.Fatalf("unedited: notices %+v", result.Report.Notices)
	}
	for name, edit := range edits {
		_, err := scan(t, claimEditor{Knowledge: base, edit: edit}, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
		if !errors.Is(err, ErrIntegrity) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestScanWholeUpgradeNotice: a notice reviewed for the exact end-to-end
// pair is listed on the whole upgrade and does not change a pass.
func TestScanWholeUpgradeNotice(t *testing.T) {
	const id = "kubernetes.synthetic-notice-whole.1-24-17-to-1-30-4"
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", unchecked: true, synthetic: []string{noticeRule(id, "1.24.17", "1.30.4", "", currentWindow)}})
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	result := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
	if result.Exit != scanreport.ExitPass || len(result.Report.Notices) != 1 || !result.Report.Notices[0].Hop.WholeUpgrade || !result.Report.Notices[0].Established {
		t.Fatalf("exit %d gaps %v notices %+v", result.Exit, gapReasons(result.Report), result.Report.Notices)
	}
}

// TestScanDirectPolicyRemovedVersion: a direct hop across several lines
// evaluates none of their removals, so an object removed on one of them is
// still named as not served.
func TestScanDirectPolicyRemovedVersion(t *testing.T) {
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	direct := newKnowledge(t, knowledgeOptions{lines: append([]string{"1.24"}, allLines...), policy: "direct"})
	// Removed on a line inside the hop, and on the hop's own target line.
	for _, from := range []string{"1.24.17", "1.23.17"} {
		to := "1.30.4"
		if from == "1.23.17" {
			to = "1.25.3"
		}
		result := mustScan(t, direct, args(paths, "--from", "kubernetes="+from, "--to", "kubernetes="+to)...)
		if result.Exit == scanreport.ExitPass || !hasGap(result.Report, "API_VERSION_NOT_SERVED", "no longer serves") {
			t.Fatalf("%s: exit %d gaps %+v", from, result.Exit, result.Report.Gaps)
		}
	}
}
