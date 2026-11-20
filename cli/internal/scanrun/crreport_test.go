// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/intake"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

const kafkaOtherDoc = "apiVersion: kafka.strimzi.io/v1\nkind: Kafka\nmetadata:\n  name: other\n  namespace: kafka\n"

func crByName(t *testing.T, report scanreport.Report, name string) scanreport.CustomResource {
	t.Helper()
	for _, cr := range report.CustomResources {
		if cr.Name == name {
			return cr
		}
	}
	t.Fatalf("custom resource %q absent from %+v", name, report.CustomResources)
	return scanreport.CustomResource{}
}

// Every custom resource is listed: the blocked one is EVALUATED BLOCKED, a
// served one is EVALUATED NO_FINDING (never a pass), a core object is not a
// custom resource, and an unattributed group is NOT_EVALUATED with a reason.
func TestScanReportsEveryCustomResourceEvaluated(t *testing.T) {
	t.Parallel()
	result := crdScan(t, newCRDKnowledge(t), []string{settingsDoc, kafkaV1beta2Doc, kafkaOtherDoc, unownedGroupDoc}, "--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0")
	report := result.Report
	if len(report.CustomResources) != 3 {
		t.Fatalf("custom resources %+v", report.CustomResources)
	}
	if cr := crByName(t, report, "events"); cr.Status != scanreport.CRStatusEvaluated || cr.Verdict != scanreport.CRVerdictBlocked || cr.Component != "strimzi" || cr.Line == 0 {
		t.Fatalf("blocked %+v", cr)
	}
	if cr := crByName(t, report, "other"); cr.Status != scanreport.CRStatusEvaluated || cr.Verdict != scanreport.CRVerdictNoFinding || cr.Reason != "" || cr.Next == "" {
		t.Fatalf("served %+v", cr)
	}
	if cr := crByName(t, report, "metrics"); cr.Status != scanreport.CRStatusNotEvaluated || cr.Reason != scanreport.CRKindNotInKnowledge || cr.Verdict != "" || cr.Next == "" {
		t.Fatalf("unattributed %+v", cr)
	}
	if result.Exit != 10 {
		t.Fatalf("exit %d", result.Exit)
	}
}

// Without the component versions no custom resource is silently skipped: each
// is NOT_EVALUATED with the typed reason and the flags to pass, and the
// verdict and exit code are those of a scan that evaluated nothing.
func TestScanReportsCustomResourcesWithoutVersions(t *testing.T) {
	t.Parallel()
	result := crdScan(t, newCRDKnowledge(t), []string{kafkaV1beta2Doc, unownedGroupDoc}, "--from", "kubernetes=1.30.0", "--to", "kubernetes=1.31.0")
	report := result.Report
	if len(report.CustomResources) != 2 {
		t.Fatalf("custom resources %+v", report.CustomResources)
	}
	cr := crByName(t, report, "events")
	if cr.Status != scanreport.CRStatusNotEvaluated || cr.Reason != scanreport.CRComponentVersionUnknown || !strings.Contains(cr.Next, "--from strimzi=") || !strings.Contains(cr.Next, "--to strimzi=") {
		t.Fatalf("kafka %+v", cr)
	}
	if cr := crByName(t, report, "metrics"); cr.Reason != scanreport.CRKindNotInKnowledge {
		t.Fatalf("unattributed %+v", cr)
	}
	if report.Verdict == scanreport.VerdictPass || result.Exit == 0 {
		t.Fatalf("exit %d verdict %s", result.Exit, report.Verdict)
	}
	for _, cr := range report.CustomResources {
		if cr.Verdict != "" {
			t.Fatalf("verdict without evaluation %+v", cr)
		}
	}
}

// A pair no reviewed rule decides is NOT_EVALUATED, never EVALUATED.
func TestScanReportsCustomResourcesOfUncoveredPair(t *testing.T) {
	t.Parallel()
	result := crdScan(t, newCRDKnowledge(t), []string{kafkaV1Doc}, "--from", "strimzi=1.0.0", "--to", "strimzi=1.1.0")
	cr := crByName(t, result.Report, "events")
	if cr.Status != scanreport.CRStatusNotEvaluated || cr.Reason != scanreport.CRPairNotCovered || cr.Verdict != "" {
		t.Fatalf("uncovered %+v", cr)
	}
	if result.Exit != 11 {
		t.Fatalf("exit %d", result.Exit)
	}
}

// A target version without a current one is a version gap, not an evaluation.
func TestScanReportsCustomResourcesCurrentVersionMissing(t *testing.T) {
	t.Parallel()
	result := crdScan(t, newCRDKnowledge(t), []string{kafkaV1Doc}, "--to", "strimzi=1.0.0")
	cr := crByName(t, result.Report, "events")
	if cr.Status != scanreport.CRStatusNotEvaluated || cr.Reason != scanreport.CRComponentVersionUnknown || cr.Verdict != "" {
		t.Fatalf("missing current %+v", cr)
	}
}

// Input without custom resources lists none, and redaction hides names.
func TestScanCustomResourceListRedactedAndEmpty(t *testing.T) {
	t.Parallel()
	none := crdScan(t, newCRDKnowledge(t), []string{settingsDoc}, "--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0")
	if len(none.Report.CustomResources) != 0 {
		t.Fatalf("listed %+v", none.Report.CustomResources)
	}
	result := crdScan(t, newCRDKnowledge(t), []string{kafkaV1beta2Doc}, "--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0", "--redact")
	for _, cr := range result.Report.CustomResources {
		if cr.Name == "events" || cr.Namespace == "kafka" || strings.Contains(cr.File, "kafka.yaml") {
			t.Fatalf("not redacted %+v", cr)
		}
	}
	if len(result.Report.CustomResources) != 1 {
		t.Fatalf("%+v", result.Report.CustomResources)
	}
}

// An owned kind that no decided rule names is NOT_EVALUATED even though other
// rules decided the same pair: nearby evidence is not coverage.
func TestScanCustomResourceKindWithoutRuleIsNotEvaluated(t *testing.T) {
	t.Parallel()
	const topicDoc = "apiVersion: kafka.strimzi.io/v1\nkind: KafkaTopic\nmetadata:\n  name: orders\n  namespace: kafka\n"
	result := crdScan(t, newCRDKnowledge(t), []string{kafkaV1beta2Doc, topicDoc}, "--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0")
	if cr := crByName(t, result.Report, "events"); cr.Status != scanreport.CRStatusEvaluated {
		t.Fatalf("covered kind %+v", cr)
	}
	cr := crByName(t, result.Report, "orders")
	if cr.Status != scanreport.CRStatusNotEvaluated || cr.Reason != scanreport.CRKindNotCoveredByRules || cr.Verdict != "" || !strings.Contains(cr.Next, "KafkaTopic") {
		t.Fatalf("uncovered kind %+v", cr)
	}
}

// Every hop must decide the object: a hop that decided nothing for it makes
// the object NOT_EVALUATED and is named.
func TestCustomResourceReportNeedsEveryHop(t *testing.T) {
	t.Parallel()
	workspace, err := intake.Decode("k.yaml", []byte(kafkaV1Doc))
	if err != nil {
		t.Fatal(err)
	}
	inventory := map[string]*scanreport.Component{"strimzi": {Name: "strimzi", Current: "0.50.0", Target: "1.0.0"}}
	kind := "kafka.strimzi.io/Kafka"
	run := func(hops ...*hopCover) map[string]*customResourceRun {
		return map[string]*customResourceRun{"strimzi": {ran: true, decided: true, hops: hops, blocked: map[intake.Source]bool{}}}
	}
	decided := &hopCover{label: "hop 1 A -> B", evaluated: true, decided: true, kinds: map[string]bool{kind: true}}
	empty := &hopCover{label: "hop 2 B -> C", evaluated: true, kinds: map[string]bool{}}
	never := func(string) bool { return false }
	got := customResourceReport(workspace, inventory, never, run(decided, empty))
	if len(got) != 1 || got[0].Status != scanreport.CRStatusNotEvaluated || got[0].Reason != scanreport.CRPairNotCovered || !strings.Contains(got[0].Next, "hop 2 B -> C") {
		t.Fatalf("one hop undecided: %+v", got)
	}
	got = customResourceReport(workspace, inventory, never, run(decided, &hopCover{label: "hop 2 B -> C", evaluated: true, decided: true, kinds: map[string]bool{kind: true}}))
	if len(got) != 1 || got[0].Status != scanreport.CRStatusEvaluated {
		t.Fatalf("all hops decided: %+v", got)
	}
}

// The same object in two input files is two documents: one entry each, with
// its file shown.
func TestScanListsOneCustomResourceEntryPerDocument(t *testing.T) {
	t.Parallel()
	_, paths := files(t, map[string]string{"a.yaml": kafkaV1Doc, "b.yaml": kafkaV1Doc})
	result := mustScan(t, newCRDKnowledge(t), append(append([]string{}, paths...), "--now", testNow, "--from", "strimzi=0.51.0", "--to", "strimzi=1.0.0")...)
	list := result.Report.CustomResources
	if len(list) != 2 || list[0].File == list[1].File || list[0].Name != "events" || list[1].Name != "events" {
		t.Fatalf("entries %+v", list)
	}
}

// A planned hop that is not evaluated (a whole major line has no engine
// version) is recorded, and an object is then NOT_EVALUATED although another
// hop of the plan decided its kind.
func TestCustomResourceUnevaluatedPlannedHopIsRecorded(t *testing.T) {
	t.Parallel()
	run := &customResourceRun{report: &scanreport.Report{}, rootGaps: map[scanreport.GapKey]scanreport.Gap{}, blocked: map[intake.Source]bool{}, ran: true}
	major, _, err := run.hop(upgradepath.Hop{Index: 1, From: upgradepath.Endpoint{Version: "0.50.0"}, To: upgradepath.Endpoint{Line: "1"}}, nil)
	if err != nil || major.Status != scanreport.HopNoData || len(run.hops) != 1 || run.hops[0].evaluated {
		t.Fatalf("hop %+v err %v recorded %+v", major, err, run.hops)
	}
	kind := "kafka.strimzi.io/Kafka"
	run.hops = append(run.hops, &hopCover{label: "hop 2 1.0.0 -> 1.1.0", evaluated: true, decided: true, kinds: map[string]bool{kind: true}})
	run.decided = true
	reason, hop := run.coverage(kind)
	if reason != scanreport.CRPairNotCovered || !strings.Contains(hop, "hop 1") {
		t.Fatalf("coverage %q %q", reason, hop)
	}
	workspace, err := intake.Decode("k.yaml", []byte(kafkaV1Doc))
	if err != nil {
		t.Fatal(err)
	}
	inventory := map[string]*scanreport.Component{"strimzi": {Name: "strimzi", Current: "0.50.0", Target: "1.1.0"}}
	got := customResourceReport(workspace, inventory, func(string) bool { return false }, map[string]*customResourceRun{"strimzi": run})
	if len(got) != 1 || got[0].Status != scanreport.CRStatusNotEvaluated || got[0].Reason != scanreport.CRPairNotCovered || !strings.Contains(got[0].Next, "hop 1") {
		t.Fatalf("report %+v", got)
	}
}
