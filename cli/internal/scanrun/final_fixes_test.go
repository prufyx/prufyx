// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

const cronjobFact = "component.kubernetes.cronjob_v1beta1_removed_gvk_present"

var (
	cronjobRuleID = supersedeids.ID("kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0")
	pdbRuleID     = supersedeids.ID("kubernetes.pdb-v1beta1-removed.1-24-0-to-1-25-0")
)

// rangedRule is a synthetic removed-API family rule over the whole lines
// 1.24 -> 1.25 on fact, with an optional appliesWhen member.
func rangedRule(id, fact string, value bool, appliesWhen string) string {
	return `{"id":"` + id + `","operator":"forbid_predicate_value","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.24.0","to":"1.25.0"},` + lineRange("1.24", "1.25", "1.26") + appliesWhen +
		`"condition":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","factId":"` + fact + `","boolValue":` + map[bool]string{true: "true", false: "false"}[value] + `},` +
		`"evidence":{"state":"active",` + currentWindow + `,"sources":[` + skewSource + `]},` +
		`"reasonCode":"REVIEWED_SOURCE_CONSTRAINT","nextAction":"synthetic test-only action"}`
}

// TestScanTrueFactJudgedByVerdict: a true fact counts as judged only by a
// PASS or BLOCKED claim that requires it; a rule whose applicability did not
// hold does not judge it, even when a (wrong) served list names the object.
func TestScanTrueFactJudgedByVerdict(t *testing.T) {
	const id = "kubernetes.synthetic-applies-when.1-24-0-to-1-25-0"
	applies := `"appliesWhen":[{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","factId":"component.kubernetes.psp_v1beta1_removed_gvk_present","boolValue":true}],`
	base := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", unchecked: true, servedExtra: []string{"batch/v1beta1 CronJob"},
		synthetic: []string{rangedRule(id, cronjobFact, true, applies)}, dropRuleIDs: map[string][]string{"1.25": {cronjobRuleID}}})
	knowledge := hiddenRules{Knowledge: base, hidden: map[string]bool{cronjobRuleID: true}}
	_, paths := files(t, map[string]string{"applyset.yaml": "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: a}\n"})
	result := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.5")...)
	hop := result.Report.Paths[0].Hops[0]
	if result.Exit != scanreport.ExitUnknown || hop.Status != scanreport.HopPartial || !hasGap(result.Report, "LINE_NOT_ATTESTED", "no reviewed rule decides") {
		t.Fatalf("exit %d hop %+v gaps %+v", result.Exit, hop, result.Report.Gaps)
	}
}

// TestScanEveryTrueFactJudged: with two true facts, one judged by a PASS
// claim and one by no rule, the hop is not covered, whatever the order the
// facts are checked in.
func TestScanEveryTrueFactJudged(t *testing.T) {
	const id = "kubernetes.synthetic-cronjob-pass.1-24-0-to-1-25-0"
	base := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", unchecked: true, servedExtra: []string{"batch/v1beta1 CronJob", "policy/v1beta1 PodDisruptionBudget"},
		synthetic: []string{rangedRule(id, cronjobFact, false, "")}, dropRuleIDs: map[string][]string{"1.25": {cronjobRuleID, pdbRuleID}}})
	knowledge := hiddenRules{Knowledge: base, hidden: map[string]bool{cronjobRuleID: true, pdbRuleID: true}}
	_, paths := files(t, map[string]string{"applyset.yaml": "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: a}\n---\napiVersion: policy/v1beta1\nkind: PodDisruptionBudget\nmetadata: {name: b}\n"})
	for run := 0; run < 12; run++ {
		result := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.5")...)
		hop := result.Report.Paths[0].Hops[0]
		if result.Exit != scanreport.ExitUnknown || hop.Status != scanreport.HopPartial || !hasGap(result.Report, "LINE_NOT_ATTESTED", "no reviewed rule decides") {
			t.Fatalf("run %d: exit %d hop %+v gaps %+v", run, result.Exit, hop, result.Report.Gaps)
		}
	}
}

// TestScanServedLists: Kubernetes API group objects (every dotless group and
// every *.k8s.io group) must be named by a served list that is current, for
// the target line and component, and whose basis the trust policy admits;
// and the list names a kind, not only a version.
func TestScanServedLists(t *testing.T) {
	full := knowledgeOptions{lines: allLines, policy: "current"}
	with := func(change func(*knowledgeOptions)) knowledgeOptions {
		options := full
		change(&options)
		return options
	}
	cases := []struct {
		name, manifest string
		knowledge      knowledgeOptions
		detail         string
	}{
		{"core group spelled out", "apiVersion: core/v1\nkind: ConfigMap\nmetadata: {name: a}\n", full, "does not list as served"},
		{"rbac without a domain", "apiVersion: rbac/v1\nkind: Role\nmetadata: {name: a}\n", full, "does not list as served"},
		{"another kind of a served version", "apiVersion: v1\nkind: ComponentStatus\nmetadata: {name: a}\n", full, "does not list as served"},
		{"stale list", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\n", with(func(o *knowledgeOptions) { o.servedFreshness = "stale" }), "is not current (stale)"},
		{"withdrawn list", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\n", with(func(o *knowledgeOptions) { o.servedFreshness = "withdrawn" }), "is not current (withdrawn)"},
		{"list for another line", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\n", with(func(o *knowledgeOptions) { o.servedOverride.Line = "1.29" }), "names another line or component"},
		{"list for another component", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\n", with(func(o *knowledgeOptions) { o.servedOverride.Component = "pkg:github/etcd-io/etcd" }), "names another line or component"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, paths := files(t, map[string]string{"applyset.yaml": tc.manifest})
			result := mustScan(t, newKnowledge(t, tc.knowledge), args(paths, "--from", "kubernetes=1.29.6", "--to", "kubernetes=1.30.4")...)
			if result.Exit == scanreport.ExitPass || !hasGap(result.Report, "API_VERSION_NOT_REVIEWED", tc.detail) {
				t.Fatalf("exit %d gaps %+v", result.Exit, result.Report.Gaps)
			}
		})
	}
	// An object of a custom resource group is not a Kubernetes group object.
	_, paths := files(t, map[string]string{"applyset.yaml": "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata: {name: a}\n"})
	if result := mustScan(t, newKnowledge(t, full), args(paths, "--from", "kubernetes=1.29.6", "--to", "kubernetes=1.30.4")...); result.Exit != scanreport.ExitPass {
		t.Fatalf("custom resource: exit %d gaps %v", result.Exit, gapReasons(result.Report))
	}
}

// TestScanPolicyExcludedClaimIntegrity: a claim from a rule the trust policy
// leaves out is an integrity failure.
func TestScanPolicyExcludedClaimIntegrity(t *testing.T) {
	const id = "kubernetes.synthetic-lead.1-25-0-to-1-26-0"
	base := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", unchecked: true, synthetic: []string{basisRule(id, "lead", false)}})
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	command := args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")
	mustScan(t, claimEditor{Knowledge: base}, command...)
	extend := func(claims []constraintengine.Claim) []constraintengine.Claim {
		// Only on the hop the lead covers, so no other guard trips first.
		for _, claim := range claims {
			if claim.Status == "PASS" && claim.RuleID == supersedeids.ID("kubernetes.flowcontrol-v1beta1-removed.1-25-0-to-1-26-0") {
				claim.RuleID, claim.EvidenceBasis, claim.Status, claim.ReasonCode = id, constraintengine.BasisLead, constraintengine.StatusNotice, constraintengine.ReasonLeadNotVerified
				return append(claims, claim)
			}
		}
		return claims
	}
	if _, err := scan(t, claimEditor{Knowledge: base, extend: extend}, command...); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("claim of a left-out lead: %v", err)
	}
}

// supportRule is a synthetic support-range rule over the whole lines
// 1.25 -> 1.26: Kubernetes itself must be below version on the proposed side.
func supportRule(id, version string) string {
	return `{"id":"` + id + `","operator":"require_component_version","severity":"unsupported","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.25.0","to":"1.26.0"},` + lineRange("1.25", "1.26", "1.27") +
		`"dependency":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","comparison":"lt","version":"` + version + `"},` +
		`"evidence":{"state":"active",` + currentWindow + `,"sources":[` + skewSource + `]},` +
		`"reasonCode":"OUTSIDE_TESTED_RANGE","nextAction":"Move to a combination inside the documented support range."}`
}

// TestScanUnsupportedCombinations: an UNSUPPORTED claim is listed with its
// rule, reason and next action, keeps its hop from covered, and never makes
// the answer BLOCKED or PASS; a support-range rule that holds passes.
func TestScanUnsupportedCombinations(t *testing.T) {
	const id = "kubernetes.synthetic-support-range.1-25-0-to-1-26-0"
	outside := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", unchecked: true, synthetic: []string{supportRule(id, "1.26.0")}})
	inside := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", unchecked: true, synthetic: []string{supportRule(id, "1.27.0")}})
	for _, base := range []struct {
		manifest string
		exit     int
	}{{cronjobV1, scanreport.ExitUnknown}, {cronjobV1beta1, scanreport.ExitBlocked}} {
		_, paths := files(t, map[string]string{"applyset.yaml": base.manifest})
		result := mustScan(t, outside, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
		hop := result.Report.Paths[0].Hops[1]
		if result.Exit != base.exit || len(result.Report.Unsupported) != 1 || hop.Status != scanreport.HopPartial || !reflect.DeepEqual(hop.Reasons, []string{"UNSUPPORTED_COMBINATION"}) {
			t.Fatalf("exit %d unsupported %+v hop %+v", result.Exit, result.Report.Unsupported, hop)
		}
		entry := result.Report.Unsupported[0]
		if entry.RuleID != id || entry.Reason != "OUTSIDE_TESTED_RANGE" || entry.Fix == "" || entry.Hop.To != "1.26" {
			t.Fatalf("entry %+v", entry)
		}
		for _, finding := range result.Report.Findings {
			if finding.RuleID == id {
				t.Fatal("an unsupported combination is a blocker")
			}
		}
		human := string(scanreport.Human(result.Report, scanreport.HumanOptions{}))
		if !strings.Contains(human, "UNSUPPORTED COMBINATIONS (1)") || !strings.Contains(human, "outside a documented support range: "+id+" (OUTSIDE_TESTED_RANGE)") {
			t.Fatalf("human:\n%s", human)
		}
		passing := mustScan(t, inside, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
		if want := map[int]int{scanreport.ExitUnknown: scanreport.ExitPass, scanreport.ExitBlocked: scanreport.ExitBlocked}[base.exit]; passing.Exit != want || len(passing.Report.Unsupported) != 0 {
			t.Fatalf("inside the range: exit %d", passing.Exit)
		}
	}
	// UNSUPPORTED from a rule without the severity is an integrity failure.
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	edit := func(claims []constraintengine.Claim) {
		for i := range claims {
			if claims[i].Status == "PASS" {
				claims[i].Status = constraintengine.StatusUnsupported
			}
		}
	}
	if _, err := scan(t, claimEditor{Knowledge: inside, edit: edit}, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("UNSUPPORTED from a rule without severity: %v", err)
	}
}
