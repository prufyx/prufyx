// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"strings"
	"testing"
)

const otelSelectionClock = "2026-09-12T02:41:00Z"

func TestOpenTelemetryNativeSelectionSealsExistingRule(t *testing.T) {
	t.Parallel()
	raw := []byte("exporters:\n  debug: {}\n")
	path := writeCNCFFile(t, "collector.yaml", raw, 0o600)
	args := []string{
		"check", "cncf", "--project", "opentelemetry", "--otel-collector-config", path,
		"--otel-collector-config-digest", cncfDigest(raw), "--otel-distribution", "official",
		"--otel-config-complete", "--otel-config-precedence-resolved", "--from", "0.110.0", "--to", "0.111.0",
		"--now", otelSelectionClock, "--format", "json",
	}
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || strings.Contains(stdout, path) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var report struct {
		RequestedRuleID string `json:"requestedRuleId"`
		SelectedRuleID  string `json:"selectedRuleId"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil || report.RequestedRuleID != opentelemetryLoggingRuleID || report.SelectedRuleID != opentelemetryLoggingRuleID {
		t.Fatalf("selection err=%v report=%q", err, stdout)
	}
}

func TestOpenTelemetryExternalSelectionHasNoFallbackAndReplayPins(t *testing.T) {
	t.Parallel()
	fixture := makeExternalCLIFixture(t)
	raw := []byte("exporters:\n  debug: {}\n")
	path := writeCNCFFile(t, "collector.yaml", raw, 0o600)
	external := []string{
		"check", "cncf", "--project", "opentelemetry", "--otel-collector-config", path,
		"--otel-collector-config-digest", cncfDigest(raw), "--otel-distribution", "official",
		"--otel-config-complete", "--otel-config-precedence-resolved", "--from", "0.110.0", "--to", "0.111.0",
		"--knowledge-db", fixture.store, "--knowledge-revision", "1",
		"--knowledge-bundle-digest", fixture.manifest.Revisions[0].BundleDigest,
		"--knowledge-trust-receipt-digest", fixture.receipt1.TrustReceiptDigest, "--format", "json",
	}
	code, original, stderr := runCNCFCLI(t, external...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(original, `"knowledgeOrigin":"external_declared"`) || !strings.Contains(original, `"requestedRuleId":"`+opentelemetryLoggingRuleID+`"`) || strings.Contains(original, `"selectedRuleId"`) || strings.Contains(original, path) {
		t.Fatalf("external no-fallback code=%d stdout=%q stderr=%q", code, original, stderr)
	}
	report := writeCNCFFile(t, "opentelemetry-external-report.json", []byte(original), 0o600)
	importExternalCLIRevision2(t, &fixture)
	code, stdout, stderr := runCNCFCLI(t, append(append([]string(nil), external...), "--replay-report", report)...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"mode":"historical"`) || !strings.Contains(stdout, `"status":"MATCH"`) {
		t.Fatalf("pinned replay code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	withoutRawPin := omitCLIOption(external, "--otel-collector-config-digest")
	code, stdout, stderr = runCNCFCLI(t, append(withoutRawPin, "--replay-report", report)...)
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "external native CNCF replay requires every raw resource digest") {
		t.Fatalf("missing raw replay pin code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	badRawPin := append([]string(nil), external...)
	for i := range badRawPin {
		if badRawPin[i] == cncfDigest(raw) {
			badRawPin[i] = "sha256:" + strings.Repeat("0", 64)
			break
		}
	}
	code, stdout, stderr = runCNCFCLI(t, badRawPin...)
	if code != ExitIntegrity || stdout != "" || strings.Contains(stderr, path) {
		t.Fatalf("raw pin tamper code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	badSelection := append([]string(nil), external...)
	for i := range badSelection {
		if badSelection[i] == fixture.manifest.Revisions[0].BundleDigest {
			badSelection[i] = fixture.manifest.Revisions[1].BundleDigest
			break
		}
	}
	code, stdout, stderr = runCNCFCLI(t, badSelection...)
	if code != ExitIntegrity || stdout != "" || strings.Contains(stderr, fixture.store) {
		t.Fatalf("selection tamper code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
