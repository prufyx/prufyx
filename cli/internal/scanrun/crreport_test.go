// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
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
