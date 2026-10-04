// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
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
const crdRule = `{"id":"` + crdRuleID + `","operator":"forbid_set_member","subject":{"component":"` + crdComponent + `","from":"0.51.0","to":"1.0.0"},` +
	`"setCondition":{"side":"proposed","component":"` + crdComponent + `","factId":"` + crdSetFact + `","members":["kafka.strimzi.io/v1beta2/Kafka"]},` +
	`"evidence":{"state":"active","reviewedAt":"2026-09-23T00:00:00Z","validUntil":"2026-12-20T00:00:00Z","sources":[{"id":"crd-1-0-0","url":"https://github.com/strimzi/strimzi-kafka-operator/blob/` + crdRevision + `/install/cluster-operator/040-Crd-kafka.yaml","revision":"` + crdRevision + `","contentDigest":"sha256:` + "0000000000000000000000000000000000000000000000000000000000000000" + `","startLine":1,"endLine":2}]},` +
	`"reasonCode":"CRD_VERSION_NOT_SERVED","nextAction":"change apiVersion of Kafka to kafka.strimzi.io/v1 before upgrading to 1.0.0"}`

// crdKnowledge adds the test-only Strimzi rule to the test knowledge and
// evaluates it with the unchanged engine on the scan's prepared input.
type crdKnowledge struct {
	Knowledge
	rule cncfcheck.ScanRule
}

func newCRDKnowledge(t *testing.T) crdKnowledge {
	t.Helper()
	rule, err := cncfcheck.NewScanRule("strimzi", "Strimzi 1.0.0 no longer serves version v1beta2 of Kafka. Test only.", json.RawMessage(crdRule))
	if err != nil {
		t.Fatal(err)
	}
	return crdKnowledge{Knowledge: newKnowledge(t, knowledgeOptions{}), rule: rule}
}

func (k crdKnowledge) Rules(project string) []cncfcheck.ScanRule {
	rules := k.Knowledge.Rules(project)
	if project == "strimzi" {
		rules = append(rules, k.rule)
	}
	return rules
}

func (k crdKnowledge) Evaluate(policy cncfcheck.TrustPolicy, project string, facts []string, inputRaw []byte, now time.Time) (Evaluation, error) {
	evaluation, err := k.Knowledge.Evaluate(policy, project, facts, inputRaw, now)
	if err != nil || project != "strimzi" || !policy.Admits(k.rule.Basis) {
		return evaluation, err
	}
	registry, err := constraintengine.NewCompiledRegistry([]constraintengine.FactDefinition{{ID: crdSetFact, Component: crdComponent, Type: constraintengine.FactSet}})
	if err != nil {
		return Evaluation{}, err
	}
	input, err := constraintengine.ParseInput(inputRaw, registry)
	if err != nil {
		return Evaluation{}, err
	}
	document, _ := json.Marshal(map[string]any{"schema": constraintengine.RulesSchemaSet, "revision": "synthetic-test", "policyId": "synthetic-test", "policyDigest": "sha256:" + strings.Repeat("0", 64), "rules": []json.RawMessage{json.RawMessage(crdRule)}})
	rules, err := constraintengine.ParseRuleSet(document, registry)
	if err != nil {
		return Evaluation{}, err
	}
	report, err := constraintengine.Evaluate(input, rules, now)
	if err != nil {
		return Evaluation{}, err
	}
	evaluation.Claims = append(evaluation.Claims, report.Claims...)
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
