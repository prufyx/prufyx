// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFluentBitProjectRouteAndPrivacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fluent-bit.conf")
	raw := "[OUTPUT]\n  Name opentelemetry\n  Host collector.private.invalid\n  http2 on\n"
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	base := []string{"check", "project", "--project", "fluent-bit", "--effective-config", path, "--from", "3.2.0", "--to", "4.0.0", "--effective-config-complete", "--current-default-was-used", "--preserve-http2-enabled", "--now", "2026-09-12T00:00:00Z", "--format", "json"}
	var stdout, stderr bytes.Buffer
	if exit := Run(t.Context(), base, &stdout, &stderr, "test"); exit != ExitOK || stderr.Len() != 0 {
		t.Fatalf("on exit=%d stderr=%q stdout=%q", exit, stderr.String(), stdout.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "collector.private.invalid") || strings.Contains(stdout.String()+stderr.String(), path) {
		t.Fatal("private config value leaked")
	}
	if !strings.Contains(stdout.String(), "fluent-bit.http2-setting.3-2-to-4-0") {
		t.Fatalf("missing reviewed rule: %q", stdout.String())
	}

	off := "[OUTPUT]\n  Name opentelemetry\n  http2 off\n"
	if err := os.WriteFile(path, []byte(off), 0600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if exit := Run(t.Context(), base, &stdout, &stderr, "test"); exit != ExitBlocked {
		t.Fatalf("off exit=%d want=%d stderr=%q stdout=%q", exit, ExitBlocked, stderr.String(), stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	missing := append([]string{}, base[:10]...)
	missing = append(missing, base[12:]...)
	if exit := Run(t.Context(), missing, &stdout, &stderr, "test"); exit != ExitUnknown {
		t.Fatalf("missing current declaration exit=%d want=%d stderr=%q", exit, ExitUnknown, stderr.String())
	}
}

func TestFluentBitLatestTargetRequirementRoute(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fluent-bit.conf")
	if err := os.WriteFile(path, []byte("[OUTPUT]\n  Name opentelemetry\n  http2 off\n"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"check", "project", "--project", "fluent-bit", "--effective-config", path, "--from", "4.2.8", "--to", "5.1.2", "--effective-config-complete", "--require-http2", "--now", "2026-09-12T10:00:00Z", "--format", "json"}
	var stdout, stderr bytes.Buffer
	if exit := Run(t.Context(), args, &stdout, &stderr, "test"); exit != ExitBlocked || stderr.Len() != 0 || !strings.Contains(stdout.String(), "fluent-bit.http2-target-required.4-2-to-5-1") {
		t.Fatalf("exit=%d stderr=%q stdout=%q", exit, stderr.String(), stdout.String())
	}
	unknown := append([]string(nil), args...)
	for index, value := range unknown {
		if value == "4.2.8" {
			unknown[index] = "4.2.7"
		}
	}
	stdout.Reset()
	stderr.Reset()
	if exit := Run(t.Context(), unknown, &stdout, &stderr, "test"); exit != ExitUnknown || stderr.Len() != 0 {
		t.Fatalf("wrong pair exit=%d stderr=%q stdout=%q", exit, stderr.String(), stdout.String())
	}
	legacyDeclarations := []string{"check", "project", "--project", "fluent-bit", "--effective-config", path, "--from", "4.2.8", "--to", "5.1.2", "--effective-config-complete", "--current-default-was-used", "--preserve-http2-enabled", "--now", "2026-09-12T08:50:00Z", "--format", "json"}
	stdout.Reset()
	stderr.Reset()
	if exit := Run(t.Context(), legacyDeclarations, &stdout, &stderr, "test"); exit != ExitUnknown || stderr.Len() != 0 {
		t.Fatalf("legacy declarations cannot satisfy target intent exit=%d stderr=%q stdout=%q", exit, stderr.String(), stdout.String())
	}
}
