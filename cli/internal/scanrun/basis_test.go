// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// basisRule is a synthetic rule of the given evidence basis on the
// flow-control v1beta1 fact, covering the whole lines 1.25 -> 1.26. It
// blocks when the fact has value.
func basisRule(id, basis string, value bool) string {
	return `{"id":"` + id + `","operator":"forbid_predicate_value","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.25.0","to":"1.26.0"},` + lineRange("1.25", "1.26", "1.27") +
		`"condition":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","factId":"component.kubernetes.flowcontrol_v1beta1_removed_gvk_present","boolValue":` + map[bool]string{true: "true", false: "false"}[value] + `},` +
		`"evidence":{"state":"active","basis":"` + basis + `","derivedAt":"2026-09-23T00:00:00Z",` + currentWindow + `,"sources":[` + skewSource + `]},` +
		`"reasonCode":"REVIEWED_SOURCE_CONSTRAINT","nextAction":"Check the FlowSchema objects of this cluster before the upgrade."}`
}

const allBases = "reviewed,mechanical,empirical,consensus,lead"

// withoutKeys drops top-level and summary members from a JSON report.
func withoutKeys(t *testing.T, report scanreport.Report, keys ...string) string {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(jsonOf(t, report), &value); err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		delete(value, key)
		delete(value["summary"].(map[string]any), key)
	}
	raw, _ := json.Marshal(value)
	return string(raw)
}

// TestScanLeadsAreVerdictNeutral: a lead that would block is listed and
// never changes the answer; by default leads are left out and only counted.
func TestScanLeadsAreVerdictNeutral(t *testing.T) {
	const id = "kubernetes.synthetic-lead.1-25-0-to-1-26-0"
	lead := basisRule(id, "lead", false)
	bases := []struct {
		name, manifest string
		lines          []string
		exit           int
	}{
		{"pass", cronjobV1, allLines, scanreport.ExitPass},
		{"blocked", cronjobV1beta1, allLines, scanreport.ExitBlocked},
		{"unknown", cronjobV1, without(allLines, "1.29"), scanreport.ExitUnknown},
	}
	for _, base := range bases {
		t.Run(base.name, func(t *testing.T) {
			dir, _ := files(t, map[string]string{"applyset.yaml": base.manifest})
			var plain, listed, defaulted Result
			command := args([]string{"applyset.yaml"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")
			inDir(t, dir, func() {
				plain = mustScan(t, newKnowledge(t, knowledgeOptions{lines: base.lines, policy: "current"}), append(command, "--require-basis", allBases)...)
				withLead := newKnowledge(t, knowledgeOptions{lines: base.lines, policy: "current", unchecked: true, synthetic: []string{lead}})
				listed = mustScan(t, withLead, append(command, "--require-basis", allBases)...)
				defaulted = mustScan(t, withLead, command...)
			})
			if plain.Exit != base.exit || listed.Exit != base.exit || defaulted.Exit != base.exit {
				t.Fatalf("exit %d / %d / %d, want %d", plain.Exit, listed.Exit, defaulted.Exit, base.exit)
			}
			if withoutKeys(t, plain.Report, "leads") != withoutKeys(t, listed.Report, "leads") {
				t.Fatalf("a lead changed the report:\n%s\n%s", withoutKeys(t, plain.Report, "leads"), withoutKeys(t, listed.Report, "leads"))
			}
			if len(listed.Report.Leads) != 1 || listed.Report.Leads[0].RuleID != id || listed.Report.Leads[0].Hop.To != "1.26" || listed.Report.TrustPolicy != nil {
				t.Fatalf("leads %+v policy %+v", listed.Report.Leads, listed.Report.TrustPolicy)
			}
			if len(defaulted.Report.Leads) != 0 || defaulted.Report.TrustPolicy == nil || defaulted.Report.TrustPolicy.ExcludedLeadRules != 1 || defaulted.Report.TrustPolicy.ExcludedRules != 0 ||
				!reflect.DeepEqual(gapReasons(defaulted.Report), gapReasons(plain.Report)) {
				t.Fatalf("default policy: leads %+v policy %+v gaps %v", defaulted.Report.Leads, defaulted.Report.TrustPolicy, gapReasons(defaulted.Report))
			}
			human := string(scanreport.Human(listed.Report, scanreport.HumanOptions{}))
			if !strings.Contains(human, "UNVERIFIED LEADS (1)") || !strings.Contains(human, "unverified lead (does not block): "+id) {
				t.Fatalf("human:\n%s", human)
			}
			if human := string(scanreport.Human(defaulted.Report, scanreport.HumanOptions{})); !strings.Contains(human, "1 unverified lead(s) not shown") {
				t.Fatalf("default human:\n%s", human)
			}
		})
	}
}

// TestScanConsensus: a consensus rule may block, and where it finds nothing
// its claim never decides the hop.
func TestScanConsensus(t *testing.T) {
	const id = "kubernetes.synthetic-consensus.1-25-0-to-1-26-0"
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	// Blocks when the fact is false (no flow-control v1beta1 object).
	blocking := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", unchecked: true, synthetic: []string{basisRule(id, "consensus", false)}})
	result := mustScan(t, blocking, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
	if result.Exit != scanreport.ExitBlocked || len(result.Report.Findings) != 1 || result.Report.Findings[0].Basis != "consensus" {
		t.Fatalf("consensus block: exit %d findings %+v", result.Exit, result.Report.Findings)
	}
	if human := string(scanreport.Human(result.Report, scanreport.HumanOptions{})); !strings.Contains(human, "1 finding(s) rely on model consensus") {
		t.Fatalf("human:\n%s", human)
	}
	// Finds nothing when the fact is false and the rule wants true.
	quiet := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", unchecked: true, synthetic: []string{basisRule(id, "consensus", true)}})
	result = mustScan(t, quiet, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
	hop := result.Report.Paths[0].Hops[1]
	if result.Exit != scanreport.ExitUnknown || hop.Status != scanreport.HopPartial || !reflect.DeepEqual(gapReasons(result.Report), []string{"RULE_NOT_DECIDED 1.25->1.26"}) || !strings.Contains(result.Report.Gaps[0].Detail, "never pass") {
		t.Fatalf("consensus no known issue: exit %d hop %+v gaps %+v", result.Exit, hop, result.Report.Gaps)
	}
}

// TestScanRequireBasis: a rule that applies but that --require-basis leaves
// out keeps the hop undecided, and the report says how many were left out.
// The policy also selects the evidence the line reviews, the path policy and
// the served lists rest on.
func TestScanRequireBasis(t *testing.T) {
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	command := args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4", "--require-basis", "reviewed")
	reviewed := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", recordBasis: "reviewed"})
	result := mustScan(t, reviewed, command...)
	policy := result.Report.TrustPolicy
	if result.Exit != scanreport.ExitUnknown || policy == nil || policy.ExcludedRules != 11 || !reflect.DeepEqual(policy.RequiredBasis, []string{"reviewed"}) || len(result.Report.Passes) != 0 {
		t.Fatalf("exit %d policy %+v passes %d gaps %v", result.Exit, policy, len(result.Report.Passes), gapReasons(result.Report))
	}
	if !hasGap(result.Report, "RULE_NOT_DECIDED", "left out by --require-basis") {
		t.Fatalf("gaps %+v", result.Report.Gaps)
	}
	if human := string(scanreport.Human(result.Report, scanreport.HumanOptions{})); !strings.Contains(human, "trust policy: evidence basis reviewed only; 11 rule(s) that apply were left out") {
		t.Fatalf("human:\n%s", human)
	}
	// Records whose basis the policy leaves out are not used.
	records := []struct {
		name           string
		options        knowledgeOptions
		reason, detail string
	}{
		{"path policy", knowledgeOptions{lines: allLines, policy: "current", recordBasis: "reviewed", policyBasis: "mechanical"}, "NO_REVIEWED_PATH_POLICY", "upgrade-path policy for kubernetes rests on evidence basis mechanical"},
		{"line review", knowledgeOptions{lines: allLines, policy: "current", recordBasis: "reviewed", reviewBasis: "mechanical"}, "LINE_NOT_ATTESTED", "rests on basis mechanical"},
		{"served list", knowledgeOptions{lines: allLines, policy: "current", recordBasis: "reviewed", servedOverride: ServedList{Basis: "mechanical"}}, "API_VERSION_NOT_REVIEWED", "served list of Kubernetes 1.30 rests on basis mechanical"},
	}
	for _, record := range records {
		result := mustScan(t, newKnowledge(t, record.options), command...)
		if result.Exit != scanreport.ExitUnknown || !hasGap(result.Report, record.reason, record.detail) {
			t.Fatalf("%s: exit %d gaps %+v", record.name, result.Exit, result.Report.Gaps)
		}
	}
	if result := mustScan(t, newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", recordBasis: "reviewed"}), args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...); result.Exit != scanreport.ExitPass {
		t.Fatalf("reviewed records under the default policy: exit %d gaps %v", result.Exit, gapReasons(result.Report))
	}
	// The default policy and the explicit default list give the same report.
	knowledge := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"})
	a := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
	b := mustScan(t, knowledge, args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4", "--require-basis", "reviewed,mechanical,empirical,consensus")...)
	if string(jsonOf(t, a.Report)) != string(jsonOf(t, b.Report)) || a.Exit != scanreport.ExitPass {
		t.Fatal("explicit default policy differs")
	}
	for _, bad := range []string{"", "reviewed,reviewed", "trusted", "reviewed,,lead"} {
		if _, err := ParseArgs([]string{"--require-basis", bad}); !isUsage(err) {
			t.Fatalf("--require-basis %q: %v", bad, err)
		}
	}
}

// TestScanBasisIntegrity: claims that contradict their rule's basis are an
// integrity failure, never an answer.
func TestScanBasisIntegrity(t *testing.T) {
	const id = "kubernetes.synthetic-lead.1-25-0-to-1-26-0"
	base := newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current", unchecked: true, synthetic: []string{basisRule(id, "lead", false)}})
	_, paths := files(t, map[string]string{"applyset.yaml": cronjobV1})
	command := args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4", "--require-basis", allBases)
	if result := mustScan(t, claimEditor{Knowledge: base, edit: func([]constraintengine.Claim) {}}, command...); len(result.Report.Leads) != 1 {
		t.Fatalf("unedited: leads %+v", result.Report.Leads)
	}
	edits := map[string]func([]constraintengine.Claim){
		"verdict claim says lead": func(claims []constraintengine.Claim) {
			for i := range claims {
				if !claims[i].IsLead() && claims[i].Status == "UNKNOWN" {
					claims[i].EvidenceBasis = constraintengine.BasisLead
				}
			}
		},
		"lead blocks": func(claims []constraintengine.Claim) {
			for i := range claims {
				if claims[i].IsLead() && claims[i].Status == constraintengine.StatusNotice {
					claims[i].Status = "BLOCKED"
				}
			}
		},
		"reviewed rule finds no known issue": func(claims []constraintengine.Claim) {
			for i := range claims {
				if !claims[i].IsLead() && claims[i].Status == "PASS" {
					claims[i].Status = constraintengine.StatusNoKnownIssue
				}
			}
		},
	}
	for name, edit := range edits {
		if _, err := scan(t, claimEditor{Knowledge: base, edit: edit}, command...); !errors.Is(err, ErrIntegrity) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
