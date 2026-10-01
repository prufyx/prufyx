// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failedBatchWriter struct{}

func (failedBatchWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func writeEmbeddedCLIBatch(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	input := map[string]any{
		"schema": "prufyx.io/operator-declared-constraint-input/v1alpha1", "authority": "OPERATOR_DECLARED_MINIMIZED",
		"current":  map[string]any{"components": []any{map[string]any{"component": "pkg:github/thanos-io/thanos", "version": "0.41.0", "facts": []any{}}}},
		"proposed": map[string]any{"components": []any{map[string]any{"component": "pkg:github/thanos-io/thanos", "version": "0.42.0", "facts": []any{map[string]any{"id": "component.thanos.removed_subcommand_flags_present", "state": "declared", "boolValue": false}}}}},
	}
	raw, _ := json.Marshal(input)
	if err := os.WriteFile(filepath.Join(root, "input.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	plan := map[string]any{"schema": "prufyx.io/batch-check-plan/v1alpha1", "authority": "OPERATOR_DECLARED_LOCAL_CANONICAL_INPUTS", "knowledge": map[string]any{"mode": "embedded_only"}, "items": []any{map[string]any{"id": "thanos-pass", "kind": "cncf", "project": "thanos", "from": "0.41.0", "to": "0.42.0", "inputPath": "input.json"}}}
	planRaw, _ := json.Marshal(plan)
	planPath := filepath.Join(root, "plan.json")
	if err := os.WriteFile(planPath, planRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	return root, planPath
}

func TestBatchCheckCLIEmitsMachineActionableOutcomesWithoutPrivatePaths(t *testing.T) {
	root := t.TempDir()
	input := map[string]any{
		"schema": "prufyx.io/operator-declared-constraint-input/v1alpha1", "authority": "OPERATOR_DECLARED_MINIMIZED",
		"current":  map[string]any{"components": []any{map[string]any{"component": "pkg:github/thanos-io/thanos", "version": "0.41.0", "facts": []any{}}}},
		"proposed": map[string]any{"components": []any{map[string]any{"component": "pkg:github/thanos-io/thanos", "version": "0.42.0", "facts": []any{map[string]any{"id": "component.thanos.removed_subcommand_flags_present", "state": "declared", "boolValue": false}}}}},
	}
	raw, _ := json.Marshal(input)
	inputPath := filepath.Join(root, "input.json")
	if err := os.WriteFile(inputPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	plan := map[string]any{"schema": "prufyx.io/batch-check-plan/v1alpha1", "authority": "OPERATOR_DECLARED_LOCAL_CANONICAL_INPUTS", "knowledge": map[string]any{"mode": "embedded_only"}, "items": []any{map[string]any{"id": "thanos-pass", "kind": "cncf", "project": "thanos", "from": "0.41.0", "to": "0.42.0", "inputPath": "input.json"}}}
	planRaw, _ := json.Marshal(plan)
	planPath := filepath.Join(root, "plan.json")
	if err := os.WriteFile(planPath, planRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	exit := Run(t.Context(), []string{"check", "batch", "--plan", planPath, "--root", root, "--now", "2026-09-12T22:00:00Z", "--format", "json"}, &stdout, &stderr, "test")
	if exit != ExitOK || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"aggregateCategory":"PASS"`) || !strings.Contains(stdout.String(), `"outcome":"PASS"`) || strings.Contains(stdout.String(), root) || strings.Contains(stdout.String(), "input.json") {
		t.Fatalf("exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func TestBatchCheckCLIEvaluatesOpenTelemetryInternalMetricsRule(t *testing.T) {
	root := t.TempDir()
	facts := []any{
		map[string]any{"id": "component.opentelemetry.config_complete", "state": "declared", "boolValue": true},
		map[string]any{"id": "component.opentelemetry.config_precedence_resolved", "state": "declared", "boolValue": true},
		map[string]any{"id": "component.opentelemetry.distribution", "state": "declared", "enumValue": "official"},
		map[string]any{"id": "component.opentelemetry.internal_metrics_localhost_remote_conflict", "state": "declared", "boolValue": false},
		map[string]any{"id": "component.opentelemetry.internal_metrics_override_absent", "state": "declared", "boolValue": true},
		map[string]any{"id": "component.opentelemetry.internal_metrics_remote_scrape_required", "state": "declared", "boolValue": true},
		map[string]any{"id": "component.opentelemetry.logging_exporter_present", "state": "declared", "boolValue": false},
		map[string]any{"id": "component.opentelemetry.telemetry_use_localhost_default_metrics_address_effective", "state": "declared", "boolValue": false},
	}
	input := map[string]any{
		"schema": "prufyx.io/operator-declared-constraint-input/v1alpha1", "authority": "OPERATOR_DECLARED_MINIMIZED",
		"current":  map[string]any{"components": []any{map[string]any{"component": "pkg:github/open-telemetry/opentelemetry-collector", "version": "0.110.0", "facts": facts}}},
		"proposed": map[string]any{"components": []any{map[string]any{"component": "pkg:github/open-telemetry/opentelemetry-collector", "version": "0.111.0", "facts": facts}}},
	}
	raw, _ := json.Marshal(input)
	inputPath := filepath.Join(root, "otel-input.json")
	if err := os.WriteFile(inputPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	plan := map[string]any{
		"schema": "prufyx.io/batch-check-plan/v1alpha1", "authority": "OPERATOR_DECLARED_LOCAL_CANONICAL_INPUTS",
		"knowledge": map[string]any{"mode": "embedded_only"},
		"items":     []any{map[string]any{"id": "otel-internal-metrics", "kind": "cncf", "project": "opentelemetry", "from": "0.110.0", "to": "0.111.0", "inputPath": "otel-input.json"}},
	}
	planRaw, _ := json.Marshal(plan)
	planPath := filepath.Join(root, "plan.json")
	if err := os.WriteFile(planPath, planRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	exit := Run(t.Context(), []string{"check", "batch", "--plan", planPath, "--root", root, "--now", "2026-09-13T10:00:00Z", "--format", "json"}, &stdout, &stderr, "test")
	if exit != ExitOK || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"aggregateCategory":"PASS"`) || !strings.Contains(stdout.String(), `"outcome":"PASS"`) || !strings.Contains(stdout.String(), `opentelemetry.internal-telemetry-default-bind`) || strings.Contains(stdout.String(), root) || strings.Contains(stdout.String(), "otel-input.json") {
		t.Fatalf("exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func TestBatchCheckCLIRejectsMalformedPlanWithoutReadingItem(t *testing.T) {
	root := t.TempDir()
	planPath := filepath.Join(root, "plan.json")
	if err := os.WriteFile(planPath, []byte(`{"schema":"prufyx.io/batch-check-plan/v1alpha1","authority":"OPERATOR_DECLARED_LOCAL_CANONICAL_INPUTS","knowledge":{"mode":"embedded_only"},"items":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	exit := Run(t.Context(), []string{"check", "batch", "--plan", planPath, "--root", root, "--now", "2026-09-12T22:00:00Z", "--format", "json"}, &stdout, &stderr, "test")
	if exit != ExitUsage || stdout.Len() != 0 || !strings.Contains(stderr.String(), "batch check input failed admission") || strings.Contains(stderr.String(), root) {
		t.Fatalf("exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func TestBatchCheckCLIRejectsEmptyOppositeModeFlagsAndNoncanonicalTime(t *testing.T) {
	root, planPath := writeEmbeddedCLIBatch(t)
	for _, args := range [][]string{
		{"check", "batch", "--plan", planPath, "--root", root, "--knowledge-db=/missing", "--now="},
		{"check", "batch", "--plan", planPath, "--root", root, "--now=2026-09-12T22:00:00Z", "--knowledge-db="},
		{"check", "batch", "--plan", planPath, "--root", root, "--now=2026-09-12T22:00:00+00:00"},
	} {
		var stdout, stderr bytes.Buffer
		if exit := Run(t.Context(), args, &stdout, &stderr, "test"); exit != ExitUsage || stdout.Len() != 0 {
			t.Fatalf("invalid flags accepted: args=%v exit=%d stdout=%s stderr=%s", args, exit, stdout.String(), stderr.String())
		}
	}
}

func TestBatchCheckCLIPropagatesOutputFailures(t *testing.T) {
	root, planPath := writeEmbeddedCLIBatch(t)
	for _, format := range []string{"json", "human"} {
		var stderr bytes.Buffer
		exit := Run(t.Context(), []string{"check", "batch", "--plan", planPath, "--root", root, "--now", "2026-09-12T22:00:00Z", "--format", format}, failedBatchWriter{}, &stderr, "test")
		if exit != ExitIntegrity {
			t.Fatalf("%s output failure exit=%d stderr=%s", format, exit, stderr.String())
		}
	}
}
