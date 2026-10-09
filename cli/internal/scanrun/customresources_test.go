// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/intake"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

const (
	crdSetFact   = "component.strimzi.custom_resource_versions_set"
	crdComponent = "pkg:github/strimzi/strimzi-kafka-operator"
	crdRuleID    = "strimzi.crd-version-removal.kafkas-kafka-strimzi-io.0-51-0-to-1-0-0"
	crdRevision  = "4836c7dd74ce973f06d97936916ed7f20c1a2ff0"
)

// crdRule is a test-only rule of the shape the CRD extractor derives. It is
// never published.
var crdRule = `{"id":"` + crdRuleID + `","operator":"forbid_set_member","subject":{"component":"` + crdComponent + `","from":"0.51.0","to":"1.0.0"},` +
	`"setCondition":{"side":"proposed","component":"` + crdComponent + `","factId":"` + crdSetFact + `","members":["kafka.strimzi.io/v1beta2/Kafka"]},` +
	`"evidence":{"state":"active","reviewedAt":"` + currentReviewed + `","validUntil":"` + currentUntil + `","sources":[{"id":"crd-1-0-0","url":"https://github.com/strimzi/strimzi-kafka-operator/blob/` + crdRevision + `/install/cluster-operator/040-Crd-kafka.yaml","revision":"` + crdRevision + `","contentDigest":"sha256:` + "0000000000000000000000000000000000000000000000000000000000000000" + `","startLine":1,"endLine":2}]},` +
	`"reasonCode":"CRD_VERSION_NOT_SERVED","nextAction":"change apiVersion of Kafka to kafka.strimzi.io/v1 before upgrading to 1.0.0"}`

// crdLeadRule is a test-only lead over the same set: it never decides.
var crdLeadRule = `{"id":"strimzi.synthetic-lead.kafkatopics.0-51-0-to-1-0-0","operator":"forbid_set_member","subject":{"component":"` + crdComponent + `","from":"0.51.0","to":"1.0.0"},` +
	`"setCondition":{"side":"proposed","component":"` + crdComponent + `","factId":"` + crdSetFact + `","members":["kafka.strimzi.io/v1beta2/KafkaTopic"]},` +
	`"evidence":{"state":"active","basis":"lead","derivedAt":"` + currentReviewed + `","reviewedAt":"` + currentReviewed + `","validUntil":"` + currentUntil + `","sources":[{"id":"crd-1-0-0","url":"https://github.com/strimzi/strimzi-kafka-operator/blob/` + crdRevision + `/install/cluster-operator/043-Crd-kafkatopic.yaml","revision":"` + crdRevision + `","contentDigest":"sha256:` + "0000000000000000000000000000000000000000000000000000000000000000" + `","startLine":1,"endLine":2}]},` +
	`"reasonCode":"CRD_VERSION_NOT_SERVED","nextAction":"check KafkaTopic objects"}`

// crdOtherPairID is a rule of another release pair (1.0.0 -> 1.1.0).
const crdOtherPairID = "strimzi.crd-version-removal.kafkas-kafka-strimzi-io.1-0-0-to-1-1-0"

var crdOtherPairRule = strings.NewReplacer(crdRuleID, crdOtherPairID, `"from":"0.51.0","to":"1.0.0"`, `"from":"1.0.0","to":"1.1.0"`).Replace(crdRule)

// crdKnowledge adds test-only Strimzi rules to the test knowledge and
// evaluates the ones the trust policy admits with the unchanged engine on
// the scan's prepared input. refuse makes the evaluation refuse the input;
// forge adds claims the engine did not give.
type crdKnowledge struct {
	Knowledge
	raw    []string
	rules  []cncfcheck.ScanRule
	refuse bool
	forge  []constraintengine.Claim
	// relabel copies the engine's claim of one rule as a claim of another.
	relabel map[string]string
	// unevaluated rules are listed but never given to the engine.
	unevaluated map[string]bool
}

func newCRDKnowledge(t *testing.T, raws ...string) crdKnowledge {
	t.Helper()
	if len(raws) == 0 {
		raws = []string{crdRule}
	}
	k := crdKnowledge{Knowledge: newKnowledge(t, knowledgeOptions{}), raw: raws}
	for _, raw := range raws {
		rule, err := cncfcheck.NewScanRule("strimzi", "Strimzi 1.0.0 no longer serves version v1beta2 of Kafka. Test only.", json.RawMessage(raw))
		if err != nil {
			t.Fatal(err)
		}
		k.rules = append(k.rules, rule)
	}
	return k
}

func (k crdKnowledge) Rules(project string) []cncfcheck.ScanRule {
	rules := k.Knowledge.Rules(project)
	if project == "strimzi" {
		rules = append(rules, k.rules...)
	}
	return rules
}

func (k crdKnowledge) Evaluate(policy cncfcheck.TrustPolicy, project string, facts []string, inputRaw []byte, now time.Time) (Evaluation, error) {
	evaluation, err := k.Knowledge.Evaluate(policy, project, facts, inputRaw, now)
	if err != nil || project != "strimzi" {
		return evaluation, err
	}
	if k.refuse {
		return Evaluation{}, ErrRefused
	}
	var admitted []json.RawMessage
	for i, rule := range k.rules {
		if policy.Admits(rule.Basis) && !k.unevaluated[rule.Scope.ID] {
			admitted = append(admitted, json.RawMessage(k.raw[i]))
		}
	}
	evaluation.Claims = append(evaluation.Claims, k.forge...)
	if len(admitted) == 0 {
		return evaluation, nil
	}
	registry, err := constraintengine.NewCompiledRegistry([]constraintengine.FactDefinition{{ID: crdSetFact, Component: crdComponent, Type: constraintengine.FactSet}})
	if err != nil {
		return Evaluation{}, err
	}
	input, err := constraintengine.ParseInput(inputRaw, registry)
	if err != nil {
		return Evaluation{}, err
	}
	schema, err := constraintengine.RulesSchemaFor(admitted)
	if err != nil {
		return Evaluation{}, err
	}
	document, _ := json.Marshal(map[string]any{"schema": schema, "revision": "synthetic-test", "policyId": "synthetic-test", "policyDigest": "sha256:" + strings.Repeat("0", 64), "rules": admitted})
	rules, err := constraintengine.ParseRuleSet(document, registry)
	if err != nil {
		return Evaluation{}, err
	}
	report, err := constraintengine.Evaluate(input, rules, now)
	if err != nil {
		return Evaluation{}, err
	}
	evaluation.Claims = append(evaluation.Claims, report.Claims...)
	for _, claim := range report.Claims {
		if to, ok := k.relabel[claim.RuleID]; ok {
			claim.RuleID = to
			evaluation.Claims = append(evaluation.Claims, claim)
		}
	}
	if evaluation.EngineContractDigest == "" {
		evaluation.EngineContractDigest = report.EngineContractDigest
	}
	return evaluation, nil
}

const (
	kafkaV1beta2Doc = "apiVersion: kafka.strimzi.io/v1beta2\nkind: Kafka\nmetadata:\n  name: events\n  namespace: kafka\n"
	kafkaV1Doc      = "apiVersion: kafka.strimzi.io/v1\nkind: Kafka\nmetadata:\n  name: events\n  namespace: kafka\n"
	certificateDoc  = "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata:\n  name: tls\n  namespace: kafka\n"
	settingsDoc     = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n  namespace: kafka\n"
)

func crdScan(t *testing.T, knowledge Knowledge, docs []string, extra ...string) Result {
	t.Helper()
	_, paths := files(t, map[string]string{"kafka.yaml": strings.Join(docs, "---\n")})
	return mustScan(t, knowledge, append(append([]string{}, paths...), append([]string{"--now", testNow}, extra...)...)...)
}

func hasComponentGap(report scanreport.Report, component, reason, detail string) bool {
	for _, gap := range report.Gaps {
		if gap.Component == component && gap.Reason == reason && strings.Contains(gap.Detail, detail) {
			return true
		}
	}
	return false
}

func strimziHop(t *testing.T, report scanreport.Report) scanreport.Hop {
	t.Helper()
	for _, path := range report.Paths {
		if path.Component == "strimzi" {
			if len(path.Hops) != 1 {
				t.Fatalf("strimzi path %+v", path)
			}
			return path.Hops[0]
		}
	}
	t.Fatal("no strimzi path")
	return scanreport.Hop{}
}

// A Strimzi upgrade is evaluated for custom-resource versions: a removed
// version is a located finding, with or without a complete scope.
func TestScanCustomResourceBlocked(t *testing.T) {
	knowledge := newCRDKnowledge(t)
	for _, scope := range [][]string{{"--resource-scope-complete"}, nil} {
		result := crdScan(t, knowledge, []string{settingsDoc, kafkaV1beta2Doc}, append([]string{"--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0"}, scope...)...)
		report := result.Report
		if result.Exit != 10 || report.Verdict != scanreport.VerdictBlocked || len(report.Findings) != 1 {
			t.Fatalf("exit %d verdict %s findings %+v gaps %v", result.Exit, report.Verdict, report.Findings, gapReasons(report))
		}
		finding := report.Findings[0]
		if finding.RuleID != crdRuleID || finding.Component != "strimzi" || finding.Fix != "change apiVersion of Kafka to kafka.strimzi.io/v1 before upgrading to 1.0.0" || len(finding.Locations) != 1 {
			t.Fatalf("finding %+v", finding)
		}
		if l := finding.Locations[0]; l.Kind != "Kafka" || l.Name != "events" || l.Namespace != "kafka" || l.Document != 1 || l.Line != 7 {
			t.Fatalf("location %+v", l)
		}
		if hop := strimziHop(t, report); hop.Status != scanreport.HopBlocked || hop.InputDigest == "" {
			t.Fatalf("hop %+v", hop)
		}
		if !hasComponentGap(report, "strimzi", scanreport.ReasonComponentNotCovered, "only for custom-resource versions") {
			t.Fatalf("gaps %v", gapReasons(report))
		}
		if (scope == nil) != hasComponentGap(report, "strimzi", scanreport.ReasonDeclarationMissing, "complete set") {
			t.Fatalf("scope gap: %v", gapReasons(report))
		}
	}
}

// A served version is decided but never covers the component: scan has no
// review that lists every custom-resource rule of a release, so the answer
// stays UNKNOWN and names why.
func TestScanCustomResourceNeverPasses(t *testing.T) {
	knowledge := newCRDKnowledge(t)
	result := crdScan(t, knowledge, []string{settingsDoc, kafkaV1Doc}, "--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0", "--resource-scope-complete")
	report := result.Report
	if result.Exit != 11 || report.Verdict == scanreport.VerdictPass || len(report.Findings) != 0 || len(report.Passes) != 1 || report.Passes[0].RuleID != crdRuleID {
		t.Fatalf("exit %d verdict %s passes %+v gaps %v", result.Exit, report.Verdict, report.Passes, gapReasons(report))
	}
	hop := strimziHop(t, report)
	if hop.Status != scanreport.HopPartial || len(hop.Reasons) != 1 || hop.Reasons[0] != scanreport.ReasonComponentNotCovered {
		t.Fatalf("hop %+v", hop)
	}
	if len(report.Gaps) != 1 || !hasComponentGap(report, "strimzi", scanreport.ReasonComponentNotCovered, "only for custom-resource versions") {
		t.Fatalf("gaps %v", gapReasons(report))
	}
	for _, component := range report.Inventory {
		if component.Name == "strimzi" && component.Covered {
			t.Fatal("strimzi reported as covered")
		}
	}
}

// Every partial set is a named gap and never a pass.
func TestScanCustomResourcePartialSets(t *testing.T) {
	knowledge := newCRDKnowledge(t)
	for name, tc := range map[string]struct {
		docs   []string
		extra  []string
		reason string
		detail string
	}{
		"scope not declared":  {[]string{kafkaV1Doc}, nil, scanreport.ReasonDeclarationMissing, "complete set"},
		"unattributed group":  {[]string{kafkaV1Doc, certificateDoc}, []string{"--resource-scope-complete"}, scanreport.ReasonDocumentsNotEvaluated, "custom-resource groups that no reviewed project owns"},
		"templated documents": {[]string{kafkaV1Doc, "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Values.name }}\n"}, []string{"--resource-scope-complete"}, scanreport.ReasonDocumentsTemplated, "unrendered templates"},
	} {
		t.Run(name, func(t *testing.T) {
			result := crdScan(t, knowledge, tc.docs, append([]string{"--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0"}, tc.extra...)...)
			report := result.Report
			if result.Exit != 11 || len(report.Passes) != 0 || len(report.Findings) != 0 {
				t.Fatalf("exit %d passes %+v", result.Exit, report.Passes)
			}
			if !hasComponentGap(report, "strimzi", tc.reason, tc.detail) {
				t.Fatalf("gaps %v", gapReasons(report))
			}
			hop := strimziHop(t, report)
			found := false
			for _, reason := range hop.Reasons {
				found = found || reason == tc.reason
			}
			if hop.Status != scanreport.HopPartial || !found {
				t.Fatalf("hop %+v", hop)
			}
		})
	}
}

func TestScanCustomResourcePath(t *testing.T) {
	knowledge := newCRDKnowledge(t)
	// The rule is anchored at 0.51.0 -> 1.0.0: a direct upgrade from 0.50.0
	// is another transition, which no rule decides.
	result := crdScan(t, knowledge, []string{kafkaV1beta2Doc}, "--from", "strimzi=0.50.0", "--to", "strimzi=1.0.0", "--resource-scope-complete")
	if hop := strimziHop(t, result.Report); result.Exit != 11 || len(result.Report.Findings) != 0 || len(result.Report.Passes) != 0 || hop.Status != scanreport.HopNoData {
		t.Fatalf("other transition: exit %d hop %+v gaps %v", result.Exit, hop, gapReasons(result.Report))
	}
	// No current version: no plan.
	result = crdScan(t, knowledge, []string{kafkaV1beta2Doc}, "--to", "strimzi=1.0.0", "--resource-scope-complete")
	if result.Exit != 11 || !hasComponentGap(result.Report, "strimzi", scanreport.ReasonVersionNotDetected, "strimzi") {
		t.Fatalf("no current version: exit %d gaps %v", result.Exit, gapReasons(result.Report))
	}
	// A downgrade is not evaluated.
	result = crdScan(t, knowledge, []string{kafkaV1beta2Doc}, "--from", "strimzi=1.0.0", "--to", "strimzi=0.51.0", "--resource-scope-complete")
	if result.Exit != 11 || !hasComponentGap(result.Report, "strimzi", scanreport.ReasonDowngradeNotReviewed, "strimzi") {
		t.Fatalf("downgrade: exit %d gaps %v", result.Exit, gapReasons(result.Report))
	}
	// Without the rule (embedded knowledge) the hop has no data, and objects
	// of groups no reviewed project owns are still named.
	result = crdScan(t, newKnowledge(t, knowledgeOptions{}), []string{kafkaV1beta2Doc, certificateDoc}, "--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0", "--resource-scope-complete")
	if hop := strimziHop(t, result.Report); result.Exit != 11 || hop.Status != scanreport.HopNoData || !hasComponentGap(result.Report, "strimzi", scanreport.ReasonDocumentsNotEvaluated, "1 manifest(s) use custom-resource groups") {
		t.Fatalf("no rules: exit %d hop %+v gaps %v", result.Exit, hop, gapReasons(result.Report))
	}
	// Kubernetes and Strimzi in one scan: the Strimzi blocker is reported
	// next to the Kubernetes evaluation.
	result = crdScan(t, knowledge, []string{kafkaV1beta2Doc}, "--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0", "--from", "kubernetes=1.29.6", "--to", "kubernetes=1.30.4",
		"--resource-scope-complete", "--distribution", "official_upstream", "--target-api-apply-required")
	if result.Exit != 10 || len(result.Report.Findings) != 1 || result.Report.Findings[0].Component != "strimzi" || len(result.Report.Paths) != 2 {
		t.Fatalf("two components: exit %d findings %+v", result.Exit, result.Report.Findings)
	}
}

const topicV1beta2Doc = "apiVersion: kafka.strimzi.io/v1beta2\nkind: KafkaTopic\nmetadata:\n  name: orders\n  namespace: kafka\n"

// A finding is located at the objects of the versions its rule forbids,
// not at every object of the set.
func TestScanCustomResourceFindingLocationsAreTheMatchedMembers(t *testing.T) {
	result := crdScan(t, newCRDKnowledge(t), []string{topicV1beta2Doc, kafkaV1beta2Doc, topicV1beta2Doc}, "--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0", "--resource-scope-complete")
	if result.Exit != 10 || len(result.Report.Findings) != 1 {
		t.Fatalf("exit %d findings %+v", result.Exit, result.Report.Findings)
	}
	locations := result.Report.Findings[0].Locations
	if len(locations) != 1 || locations[0].Kind != "Kafka" || locations[0].Document != 1 {
		t.Fatalf("locations %+v", locations)
	}
}

// A lead over the set is verdict-neutral: whether the trust policy admits
// it or not, exit, gaps, findings and passes are those of the scan without
// it.
func TestScanCustomResourceLeadIsNeutral(t *testing.T) {
	for _, docs := range [][]string{{kafkaV1Doc, topicV1beta2Doc}, {kafkaV1beta2Doc, topicV1beta2Doc}} {
		for _, basis := range [][]string{nil, {"--require-basis", "reviewed,mechanical,empirical,consensus,lead"}} {
			extra := append([]string{"--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0", "--resource-scope-complete"}, basis...)
			plain := crdScan(t, newCRDKnowledge(t), docs, extra...)
			lead := crdScan(t, newCRDKnowledge(t, crdRule, crdLeadRule), docs, extra...)
			if plain.Exit != lead.Exit || strings.Join(gapReasons(plain.Report), ",") != strings.Join(gapReasons(lead.Report), ",") || len(plain.Report.Findings) != len(lead.Report.Findings) || len(plain.Report.Passes) != len(lead.Report.Passes) || lead.Report.TrustPolicy != nil {
				t.Fatalf("lead changed the answer: exit %d/%d gaps %v / %v trust %+v", plain.Exit, lead.Exit, gapReasons(plain.Report), gapReasons(lead.Report), lead.Report.TrustPolicy)
			}
		}
	}
}

// A decided claim of a rule that does not overlap the hop, a claim of a
// rule the trust policy leaves out, and an UNSUPPORTED claim are integrity
// failures.
func TestScanCustomResourceClaimIntegrity(t *testing.T) {
	_, paths := files(t, map[string]string{"kafka.yaml": kafkaV1Doc})
	base := append(append([]string{}, paths...), "--now", testNow, "--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0", "--resource-scope-complete")
	// The engine's PASS for the 0.51.0 -> 1.0.0 rule, presented as a claim
	// of the 1.0.0 -> 1.1.0 rule.
	forged := newCRDKnowledge(t, crdRule, crdOtherPairRule)
	forged.relabel = map[string]string{crdRuleID: crdOtherPairID}
	forged.unevaluated = map[string]bool{crdOtherPairID: true}
	if _, err := scan(t, forged, base...); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("non-overlapping PASS accepted: %v", err)
	}
	excluded := newCRDKnowledge(t)
	excluded.forge = []constraintengine.Claim{{RuleID: crdRuleID, Operator: "forbid_set_member", Status: "PASS"}}
	if _, err := scan(t, excluded, append(base, "--require-basis", "mechanical")...); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("claim of an excluded rule accepted: %v", err)
	}
	unsupported := newCRDKnowledge(t, crdRule, crdOtherPairRule)
	unsupported.forge = []constraintengine.Claim{{RuleID: crdOtherPairID, Operator: "forbid_set_member", Status: constraintengine.StatusUnsupported}}
	if _, err := scan(t, unsupported, base...); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("UNSUPPORTED claim accepted: %v", err)
	}
	// Without forged claims the same scans are accepted.
	if _, err := scan(t, newCRDKnowledge(t, crdRule, crdOtherPairRule), base...); err != nil {
		t.Fatal(err)
	}
}

// A rule the trust policy leaves out is not evaluated: the hop names it,
// the report discloses it, and a removed version it forbids is not reported
// as a finding.
func TestScanCustomResourceTrustPolicy(t *testing.T) {
	result := crdScan(t, newCRDKnowledge(t), []string{kafkaV1beta2Doc}, "--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0", "--resource-scope-complete", "--require-basis", "mechanical")
	if result.Exit != 11 || len(result.Report.Findings) != 0 || result.Report.TrustPolicy == nil || result.Report.TrustPolicy.ExcludedRules != 1 {
		t.Fatalf("exit %d findings %+v trust %+v", result.Exit, result.Report.Findings, result.Report.TrustPolicy)
	}
	found := false
	for _, gap := range result.Report.Gaps {
		found = found || (gap.Reason == scanreport.ReasonRuleNotDecided && strings.Contains(gap.Detail, crdRuleID) && strings.Contains(gap.Detail, "--require-basis"))
	}
	if !found {
		t.Fatalf("gaps %v", gapReasons(result.Report))
	}
}

// Knowledge that refuses the input leaves the hop without data, never
// covered.
func TestScanCustomResourceRefusedInput(t *testing.T) {
	k := newCRDKnowledge(t)
	k.refuse = true
	result := crdScan(t, k, []string{kafkaV1beta2Doc}, "--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0", "--resource-scope-complete")
	hop := strimziHop(t, result.Report)
	if result.Exit != 11 || hop.Status != scanreport.HopNoData || len(hop.Reasons) != 1 || hop.Reasons[0] != scanreport.ReasonComponentNotCovered || len(result.Report.Findings) != 0 {
		t.Fatalf("exit %d hop %+v", result.Exit, hop)
	}
}

// Component gaps: an empty input, documents of each omission kind, and an
// omission reason scan does not know (counted as a document that is not a
// Kubernetes object).
func TestScanCustomResourceDocumentGaps(t *testing.T) {
	result := crdScan(t, newCRDKnowledge(t), []string{"# nothing here\n"}, "--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0", "--resource-scope-complete")
	if !hasComponentGap(result.Report, "strimzi", scanreport.ReasonDocumentsNotEvaluated, "no Kubernetes manifests") {
		t.Fatalf("empty input gaps %v", gapReasons(result.Report))
	}
	result = crdScan(t, newCRDKnowledge(t), []string{kafkaV1Doc, "replicas: 3\n"}, "--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0", "--resource-scope-complete")
	if !hasComponentGap(result.Report, "strimzi", scanreport.ReasonDocumentsNotEvaluated, "1 document(s) are not Kubernetes objects") {
		t.Fatalf("values document gaps %v", gapReasons(result.Report))
	}
	run := &customResourceRun{slug: "strimzi", report: &scanreport.Report{}, declarations: declarations{scopeComplete: true},
		workspace: intake.Workspace{Documents: []intake.Document{{APIVersion: "v1", Kind: "ConfigMap"}}, Omissions: []intake.Omission{{Reason: "A_FUTURE_REASON"}, {Reason: intake.ReasonNestedList}}}}
	run.rootGaps = map[scanreport.GapKey]scanreport.Gap{}
	run.componentGaps()
	for key, detail := range map[scanreport.GapKey]string{scanreport.GapDocumentsShape: "1 document(s) are not Kubernetes objects", scanreport.GapDocumentsLists: "1 document(s) are nested lists"} {
		if gap, found := run.rootGaps[key]; !found || !strings.HasPrefix(gap.Detail, detail) {
			t.Fatalf("%s: %+v (all %+v)", key, gap, run.rootGaps)
		}
	}
}
