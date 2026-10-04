// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package communityapp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/batchcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

// strimziKafkaRuleFacts are the four facts of the reviewed Strimzi Kafka
// rule, declared so that it passes.
const strimziKafkaRuleFacts = `{"id":"component.strimzi.distribution","state":"declared","enumValue":"official_upstream"},` +
	`{"id":"component.strimzi.execution_surface","state":"declared","enumValue":"kafka_custom_resource"},` +
	`{"id":"component.strimzi.kafka_v1beta2_api_present","state":"declared","boolValue":false},` +
	`{"id":"component.strimzi.target_kafka_crd_admission_required","state":"declared","boolValue":true}`

// strimziHandWrittenInput is an operator-declared input for Strimzi
// 0.51.0 -> 1.0.0 written by hand, without any manifest: the facts given.
func strimziHandWrittenInput(facts string) []byte {
	return []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED",` +
		`"current":{"components":[{"component":"pkg:github/strimzi/strimzi-kafka-operator","version":"0.51.0","facts":[]}]},` +
		`"proposed":{"components":[{"component":"pkg:github/strimzi/strimzi-kafka-operator","version":"1.0.0","facts":[` + facts + `]}]}}`)
}

// The complete set of served versions of every derived rule's kind.
const strimziServedSet = `{"id":"component.strimzi.custom_resource_versions_set","state":"declared","setValue":{"members":["kafka.strimzi.io/v1/Kafka","kafka.strimzi.io/v1/KafkaTopic"],"complete":true}}`

// TestGenericInputNeverPassesCustomResourceRules reproduces a reported case: with
// the ten derived Strimzi rules loaded, `check cncf --project strimzi
// --input FILE` over a hand-written input carrying the complete served set
// and the four facts of the reviewed Kafka rule passes all eleven rules. It
// must exit 11, not 0, on the current check, its replay and a batch item.
func TestGenericInputNeverPassesCustomResourceRules(t *testing.T) {
	const now = "2026-10-05T00:00:00Z" // inside the derived rules' validity
	kafkaOnly := writeCNCFFile(t, "kafka-only.json", strimziHandWrittenInput(strimziKafkaRuleFacts), 0o600)
	// Before the derived rules are loaded the reviewed Kafka rule alone
	// decides, and passing it exits 0: the cap applies to set rules only.
	if code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "strimzi", "--input", kafkaOnly, "--now", now); code != ExitOK || stderr != "" || strings.Contains(stdout, customResourceScopeLine) {
		t.Fatalf("Kafka rule alone: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	useStrimziCRDKnowledge(t)
	inputRaw := strimziHandWrittenInput(strimziServedSet + "," + strimziKafkaRuleFacts)
	input := writeCNCFFile(t, "input.json", inputRaw, 0o600)
	code, original, stderr := runCNCFCLI(t, "check", "cncf", "--project", "strimzi", "--input", input, "--now", now, "--format", "json")
	if code != ExitUnknown || stderr != "" {
		t.Fatalf("json: code=%d stdout=%q stderr=%q", code, original, stderr)
	}
	var report cncfcheck.Report
	if err := json.Unmarshal([]byte(original), &report); err != nil {
		t.Fatal(err)
	}
	reading := 0
	for _, claim := range report.Check.Claims {
		if claim.Status != "PASS" {
			t.Fatalf("claim %s %s %s", claim.RuleID, claim.Status, claim.ReasonCode)
		}
		if cncfcheck.ReadsCustomResourceVersions(claim) {
			reading++
		}
	}
	if len(report.Check.Claims) != 11 || reading != 10 {
		t.Fatalf("%d claims, %d read the set; want 11 PASS claims, 10 over the set", len(report.Check.Claims), reading)
	}

	code, human, stderr := runCNCFCLI(t, "check", "cncf", "--project", "strimzi", "--input", input, "--now", now, "--show-passes")
	if code != ExitUnknown || stderr != "" || !strings.Contains(human, customResourceScopeLine) || !strings.Contains(human, "strimzi.kafka-v1beta2-api-removed.1-0: PASS") {
		t.Fatalf("human: code=%d stdout=%q stderr=%q", code, human, stderr)
	}

	replay := writeCNCFFile(t, "report.json", []byte(original), 0o600)
	if code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "strimzi", "--input", input, "--now", now, "--format", "json", "--replay-report", replay); code != ExitUnknown || stderr != "" || stdout != original {
		t.Fatalf("replay: code=%d stderr=%q", code, stderr)
	}

	// The same input as a batch item: the item is UNKNOWN, never PASS.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "strimzi.json"), inputRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := json.Marshal(batchcheck.Plan{Schema: batchcheck.PlanSchema, Authority: batchcheck.PlanAuthority, Knowledge: batchcheck.KnowledgeSelection{Mode: "embedded_only"}, Items: []batchcheck.Item{{ID: "strimzi", Kind: "cncf", Project: "strimzi", From: "0.51.0", To: "1.0.0", InputPath: "strimzi.json"}}})
	if err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(root, "plan.json")
	if err := os.WriteFile(planPath, plan, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, errout bytes.Buffer
	code = Run(t.Context(), []string{"check", "batch", "--plan", planPath, "--root", root, "--now", now, "--format", "json"}, &stdout, &errout, "test")
	var batch batchcheck.Report
	if err := json.Unmarshal(stdout.Bytes(), &batch); err != nil {
		t.Fatalf("batch: code=%d stdout=%q stderr=%q", code, stdout.String(), errout.String())
	}
	if code != ExitUnknown || len(batch.Items) != 1 || batch.Items[0].Outcome != "UNKNOWN" || batch.Items[0].Category != "UNKNOWN_CLAIM" {
		t.Fatalf("batch: code=%d items=%+v", code, batch.Items)
	}
}
