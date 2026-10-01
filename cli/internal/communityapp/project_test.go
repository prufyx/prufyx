// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectCLIEndToEndAndPrivacy(t *testing.T) {
	now := "2026-09-12T00:00:00Z"
	for _, tc := range []struct {
		name, project, from, to, body string
		want                          int
	}{
		{"grafana-blocked", "grafana", "10.4.0", "11.0.0", "[server]\nroot_url=https://secret.invalid\n[alerting]\nenabled=true\n", ExitBlocked},
		{"grafana-pass", "grafana", "10.4.0", "11.0.0", "[unified_alerting]\nenabled=true\n", ExitOK},
		{"kibana-blocked", "kibana", "8.18.0", "9.0.0", "xpack.reporting.roles.allow: [private-role]\n", ExitBlocked},
		{"kibana-pass", "kibana", "8.18.0", "9.0.0", "server.host: private-host\n", ExitOK},
		{"wrong-pair", "kibana", "8.17.0", "9.0.0", "server.host: private-host\n", ExitUnknown},
		{"loki-blocked", "loki", "2.9.8", "3.0.0", "compactor:\n  shared_store: private-store\n", ExitBlocked},
		{"loki-pass", "loki", "2.9.8", "3.0.0", "compactor:\n  working_directory: /private/loki\n", ExitOK},
		{"loki-unknown", "loki", "2.9.8", "3.0.0", "compactor:\n  working_directory: ${PRIVATE_PATH}\n", ExitUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writePrivateProjectFixture(t, tc.body)
			var stdout, stderr bytes.Buffer
			exit := Run(t.Context(), []string{"check", "project", "--project", tc.project, "--effective-config", path, "--from", tc.from, "--to", tc.to, "--effective-config-complete", "--precedence-resolved", "--now", now, "--format", "json"}, &stdout, &stderr, "test")
			if exit != tc.want {
				t.Fatalf("exit=%d want=%d stderr=%q stdout=%q", exit, tc.want, stderr.String(), stdout.String())
			}
			for _, secret := range []string{path, "secret.invalid", "private-role", "private-host", "private-store", "/private/loki", "PRIVATE_PATH"} {
				if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
					t.Fatalf("private value leaked: %q", secret)
				}
			}
		})
	}
}

func TestProjectCLILokiPinnedSourcesAndScopedOutput(t *testing.T) {
	path := writePrivateProjectFixture(t, "compactor:\n  shared_store_key_prefix: private-index/\n")
	var stdout, stderr bytes.Buffer
	exit := Run(t.Context(), []string{"check", "project", "--project", "loki", "--effective-config", path, "--from", "2.9.8", "--to", "3.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-12T00:00:00Z"}, &stdout, &stderr, "test")
	if exit != ExitBlocked || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%q stdout=%q", exit, stderr.String(), stdout.String())
	}
	for _, source := range []string{"pkg/storage/stores/indexshipper/compactor/compactor.go", "docs/sources/setup/upgrade/_index.md"} {
		if !strings.Contains(stdout.String(), source) {
			t.Fatalf("missing source %q", source)
		}
	}
	for _, private := range []string{path, "private-index"} {
		if strings.Contains(stdout.String()+stderr.String(), private) {
			t.Fatalf("private input leaked: %q", private)
		}
	}
	if !strings.Contains(stdout.String(), "whole-upgrade assessment: UNKNOWN") {
		t.Fatalf("missing scope limit: %q", stdout.String())
	}
}

func TestProjectCLILokiExamples(t *testing.T) {
	for name, want := range map[string]int{"broken.yml": ExitBlocked, "fixed.yml": ExitOK, "unknown.yml": ExitUnknown} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "projects", "loki", name))
		if err != nil {
			t.Fatal(err)
		}
		path := writePrivateProjectFixture(t, string(raw))
		var stdout, stderr bytes.Buffer
		exit := Run(t.Context(), []string{"check", "project", "--project", "loki", "--effective-config", path, "--from", "2.9.8", "--to", "3.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-12T00:00:00Z", "--format", "json"}, &stdout, &stderr, "test")
		if exit != want || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"assessment":"UNKNOWN"`) || strings.Contains(stdout.String(), path) || strings.Contains(stdout.String(), "/var/loki") {
			t.Fatalf("%s exit=%d stdout=%q stderr=%q", name, exit, stdout.String(), stderr.String())
		}
	}
}

func TestProjectCLILokiStructuredMetadataRoute(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       int
		defaultUse bool
	}{
		{"blocked", "limits_config:\n  allow_structured_metadata: true\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: boltdb-shipper\n      schema: v12\n", ExitBlocked, false},
		{"pass", "limits_config:\n  allow_structured_metadata: false\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: boltdb-shipper\n      schema: v12\n", ExitOK, false},
		{"default-pass", "limits_config: {}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n", ExitOK, true},
		{"unknown-without-default", "limits_config: {}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n", ExitUnknown, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writePrivateProjectFixture(t, tc.body)
			args := []string{"check", "project", "--project", "loki", "--loki-schema-config", path, "--from", "2.9.8", "--to", "3.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-12T02:00:00Z", "--format", "json"}
			if tc.defaultUse {
				args = append(args, "--use-reviewed-target-default")
			}
			var stdout, stderr bytes.Buffer
			if exit := Run(t.Context(), args, &stdout, &stderr, "test"); exit != tc.want || stderr.Len() != 0 {
				t.Fatalf("exit=%d want=%d stderr=%q stdout=%q", exit, tc.want, stderr.String(), stdout.String())
			}
			for _, private := range []string{path, "2024-01-01", "boltdb-shipper"} {
				if strings.Contains(stdout.String()+stderr.String(), private) {
					t.Fatalf("private selected value leaked: %q", private)
				}
			}
			if !strings.Contains(stdout.String(), `"requestedRuleId":"loki.structured-metadata-tsdb-v13.2-9-8-to-3-0-0"`) || !strings.Contains(stdout.String(), `"selectedRuleId":"loki.structured-metadata-tsdb-v13.2-9-8-to-3-0-0"`) {
				t.Fatalf("sealed route identity missing: %q", stdout.String())
			}
		})
	}
	path := writePrivateProjectFixture(t, "limits_config: {}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n")
	var stdout, stderr bytes.Buffer
	if exit := Run(t.Context(), []string{"check", "project", "--project", "loki", "--loki-schema-config", path, "--effective-config", path, "--from", "2.9.8", "--to", "3.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-12T02:00:00Z"}, &stdout, &stderr, "test"); exit != ExitUsage {
		t.Fatalf("mixed Loki modes exit=%d output=%q", exit, stdout.String()+stderr.String())
	}
	digest := digestCommunityBytes([]byte("limits_config: {}\nschema_config:\n  configs:\n    - from: 2024-01-01\n      store: tsdb\n      schema: v13\n"))
	stdout.Reset()
	stderr.Reset()
	if exit := Run(t.Context(), []string{"check", "project", "--project", "loki", "--loki-schema-config", path, "--loki-schema-config-digest", digest, "--from", "2.9.8", "--to", "3.0.0", "--effective-config-complete", "--precedence-resolved", "--use-reviewed-target-default", "--now", "2026-09-12T02:00:00Z", "--format", "json"}, &stdout, &stderr, "test"); exit != ExitOK || stderr.Len() != 0 {
		t.Fatalf("matching schema digest rejected exit=%d stderr=%q", exit, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if exit := Run(t.Context(), []string{"check", "project", "--project", "loki", "--loki-schema-config", path, "--loki-schema-config-digest", "sha256:0000000000000000000000000000000000000000000000000000000000000000", "--from", "2.9.8", "--to", "3.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-12T02:00:00Z"}, &stdout, &stderr, "test"); exit != ExitIntegrity {
		t.Fatalf("mismatched schema digest exit=%d stderr=%q", exit, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if exit := Run(t.Context(), []string{"prepare", "project", "--project", "loki", "--loki-schema-config", path, "--loki-schema-config-digest", digest, "--from", "2.9.8", "--to", "3.0.0", "--effective-config-complete", "--precedence-resolved", "--use-reviewed-target-default", "--format", "json"}, &stdout, &stderr, "test"); exit != ExitOK || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"authority":"CALLER_SUPPLIED_NATIVE_LOKI_SCHEMA_CONFIG"`) {
		t.Fatalf("matching prepare schema digest rejected exit=%d stderr=%q stdout=%q", exit, stderr.String(), stdout.String())
	}
}

func TestProjectCLILokiStructuredMetadataExamples(t *testing.T) {
	for name, want := range map[string]int{"schema-structured-broken.yml": ExitBlocked, "schema-structured-fixed.yml": ExitOK, "schema-structured-unknown.yml": ExitUnknown} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "projects", "loki", name))
		if err != nil {
			t.Fatal(err)
		}
		path := writePrivateProjectFixture(t, string(raw))
		var stdout, stderr bytes.Buffer
		exit := Run(t.Context(), []string{"check", "project", "--project", "loki", "--loki-schema-config", path, "--from", "2.9.8", "--to", "3.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-12T02:00:00Z", "--format", "json"}, &stdout, &stderr, "test")
		if exit != want || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"requestedRuleId":"loki.structured-metadata-tsdb-v13.2-9-8-to-3-0-0"`) || strings.Contains(stdout.String(), path) {
			t.Fatalf("%s exit=%d want=%d stdout=%q stderr=%q", name, exit, want, stdout.String(), stderr.String())
		}
	}
}

func TestProjectCLILokiRejectsConflictingModeAndDigest(t *testing.T) {
	path := writePrivateProjectFixture(t, "compactor:\n  working_directory: /var/loki\n")
	for _, extra := range [][]string{{"--knowledge-db", "store"}, {"--profile", "cncf"}, {"--workload", path}, {"--effective-config-digest="}} {
		args := []string{"check", "project", "--project", "loki", "--effective-config", path, "--from", "2.9.8", "--to", "3.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-12T00:00:00Z"}
		args = append(args, extra...)
		var stdout, stderr bytes.Buffer
		if exit := Run(t.Context(), args, &stdout, &stderr, "test"); exit != ExitUsage || strings.Contains(stdout.String()+stderr.String(), path) {
			t.Fatalf("extra=%v exit=%d output=%q", extra, exit, stdout.String()+stderr.String())
		}
	}
	digest := digestCommunityBytes([]byte("compactor:\n  working_directory: /var/loki\n"))
	var stdout, stderr bytes.Buffer
	if exit := Run(t.Context(), []string{"check", "project", "--project", "loki", "--effective-config", path, "--effective-config-digest", digest, "--from", "2.9.8", "--to", "3.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-12T00:00:00Z", "--format", "json"}, &stdout, &stderr, "test"); exit != ExitOK {
		t.Fatalf("pinned exit=%d stderr=%q", exit, stderr.String())
	}
}

func TestProjectCLIRejectsExternalSelectorsAndUnsafeFiles(t *testing.T) {
	path := writePrivateProjectFixture(t, "[alerting]\nenabled=false\n")
	for _, extra := range [][]string{{"--knowledge-db", "store"}, {"--profile", "cncf"}, {"--replay-report", "receipt"}, {"--effective-config", path}} {
		args := []string{"check", "project", "--project", "grafana", "--effective-config", path, "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-11T20:00:00Z"}
		args = append(args, extra...)
		var stdout, stderr bytes.Buffer
		if exit := Run(t.Context(), args, &stdout, &stderr, "test"); exit != ExitUsage {
			t.Fatalf("extra=%v exit=%d", extra, exit)
		}
		if strings.Contains(stderr.String(), path) {
			t.Fatal("path leaked")
		}
	}
	unsafe := filepath.Join(t.TempDir(), "config.ini")
	if err := os.WriteFile(unsafe, []byte("[alerting]\nenabled=false\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(t.Context(), []string{"prepare", "project", "--project", "grafana", "--effective-config", unsafe, "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved"}, &stdout, &stderr, "test"); exit != ExitUsage {
		t.Fatalf("unsafe exit=%d", exit)
	}
	stdout.Reset()
	stderr.Reset()
	if exit := Run(t.Context(), []string{"check", "project", "--project", "grafana", "--effective-config", path, "--effective-config-digest", "sha256:0", "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-11T20:00:00Z"}, &stdout, &stderr, "test"); exit != ExitUsage {
		t.Fatalf("malformed digest exit=%d", exit)
	}
	for _, command := range [][]string{
		{"check", "project", "--project", "grafana", "--effective-config", path, "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-11T20:00:00Z"},
		{"prepare", "project", "--project", "grafana", "--effective-config", path, "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved"},
	} {
		for _, value := range []string{"", " "} {
			stdout.Reset()
			stderr.Reset()
			args := append(append([]string{}, command...), "--effective-config-digest="+value)
			if exit := Run(t.Context(), args, &stdout, &stderr, "test"); exit != ExitUsage || strings.Contains(stdout.String()+stderr.String(), path) {
				t.Fatalf("empty effective-config pin args=%v exit=%d output=%q", args, exit, stdout.String()+stderr.String())
			}
		}
	}
	wantDigest := digestCommunityBytes([]byte("[alerting]\nenabled=false\n"))
	stdout.Reset()
	stderr.Reset()
	if exit := Run(t.Context(), []string{"check", "project", "--project", "grafana", "--effective-config", path, "--effective-config-digest", wantDigest, "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-11T20:00:00Z"}, &stdout, &stderr, "test"); exit != ExitOK {
		t.Fatalf("pinned input exit=%d stderr=%q", exit, stderr.String())
	}
	badDigest := "sha256:" + strings.Repeat("0", 64)
	stdout.Reset()
	stderr.Reset()
	if exit := Run(t.Context(), []string{"check", "project", "--project", "grafana", "--effective-config", path, "--effective-config-digest", badDigest, "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-11T20:00:00Z"}, &stdout, &stderr, "test"); exit != ExitIntegrity || strings.Contains(stdout.String()+stderr.String(), path) {
		t.Fatalf("mismatched digest exit=%d output=%q", exit, stdout.String()+stderr.String())
	}
}

func TestProjectCLIHelpAndPreparation(t *testing.T) {
	path := writePrivateProjectFixture(t, "xpack.reporting.roles.allow: [reporting_user]\n")
	var stdout, stderr bytes.Buffer
	if exit := Run(t.Context(), []string{"prepare", "project", "--project", "kibana", "--effective-config", path, "--from", "8.18.0", "--to", "9.0.0", "--effective-config-complete", "--precedence-resolved", "--format", "input"}, &stdout, &stderr, "test"); exit != ExitOK {
		t.Fatalf("exit=%d stderr=%q", exit, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"component":"pkg:github/elastic/kibana"`) || strings.Contains(stdout.String(), "reporting_user") {
		t.Fatalf("unexpected canonical input %q", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if exit := Run(t.Context(), []string{"check", "project", "--help"}, &stdout, &stderr, "test"); exit != ExitOK || !strings.Contains(stdout.String(), "embedded-only") {
		t.Fatalf("help exit/output %d %q", exit, stdout.String())
	}
}

func TestProjectCLIHumanShowsPinnedSourcesWithoutPrivateInput(t *testing.T) {
	path := writePrivateProjectFixture(t, "xpack.reporting.roles.allow: [private-role]\n")
	var stdout, stderr bytes.Buffer
	exit := Run(t.Context(), []string{"check", "project", "--project", "kibana", "--effective-config", path, "--from", "8.18.0", "--to", "9.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-11T20:00:00Z"}, &stdout, &stderr, "test")
	if exit != ExitBlocked || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%q", exit, stderr.String())
	}
	for _, source := range []string{"docs/settings/reporting-settings.asciidoc", "docs/release-notes/breaking-changes.md"} {
		if !strings.Contains(stdout.String(), source) {
			t.Fatalf("missing source %q from %q", source, stdout.String())
		}
	}
	for _, private := range []string{path, "private-role"} {
		if strings.Contains(stdout.String(), private) {
			t.Fatalf("private input leaked: %q", private)
		}
	}
}

func TestProjectCLIUnreviewedTransitionIsExplicitUnknown(t *testing.T) {
	path := writePrivateProjectFixture(t, "server.host: private-host\n")
	var stdout, stderr bytes.Buffer
	exit := Run(t.Context(), []string{"check", "project", "--project", "kibana", "--effective-config", path, "--from", "8.17.0", "--to", "9.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-11T20:00:00Z"}, &stdout, &stderr, "test")
	if exit != ExitUnknown || stderr.Len() != 0 || !strings.Contains(stdout.String(), "no reviewed rule matches this exact project transition") || strings.Contains(stdout.String(), path) || strings.Contains(stdout.String(), "private-host") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
}

func writePrivateProjectFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "effective-config")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProjectCLILatestGrafanaAndKibanaScopes(t *testing.T) {
	grafanaBlocked := writePrivateProjectFixture(t, "[alerting]\nenabled = true\n")
	grafanaFixed := writePrivateProjectFixture(t, "[unified_alerting]\nenabled = true\n")
	for _, from := range []string{"12.2.10", "12.3.11", "12.4.10", "13.0.8", "13.1.5"} {
		for _, tc := range []struct {
			path string
			want int
		}{{grafanaBlocked, ExitBlocked}, {grafanaFixed, ExitOK}} {
			var stdout, stderr bytes.Buffer
			exit := Run(t.Context(), []string{"check", "project", "--project", "grafana", "--effective-config", tc.path, "--from", from, "--to", "13.2.1", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-12T09:24:22Z", "--format", "json"}, &stdout, &stderr, "test")
			if exit != tc.want || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"assessment":"UNKNOWN"`) || strings.Contains(stdout.String(), tc.path) {
				t.Fatalf("grafana from=%s exit=%d stdout=%q stderr=%q", from, exit, stdout.String(), stderr.String())
			}
		}
	}
	kibanaBlocked := writePrivateProjectFixture(t, "server.host: localhost\n")
	kibanaPass := writePrivateProjectFixture(t, "status.statusPageBypassMonitorPrivilege: true\n")
	kibanaAnonymous := writePrivateProjectFixture(t, "status.allowAnonymous: true\n")
	kibanaAmbiguous := writePrivateProjectFixture(t, "status:\n  statusPageBypassMonitorPrivilege: true\n")
	for _, from := range []string{"9.0.8", "9.1.10", "9.2.8", "9.3.8", "9.4.6"} {
		for _, tc := range []struct {
			path   string
			intent bool
			want   int
		}{{kibanaBlocked, true, ExitBlocked}, {kibanaPass, true, ExitOK}, {kibanaAnonymous, true, ExitUnknown}, {kibanaAmbiguous, true, ExitUnknown}, {kibanaPass, false, ExitUnknown}} {
			args := []string{"check", "project", "--project", "kibana", "--effective-config", tc.path, "--from", from, "--to", "9.5.3", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-12T09:24:22Z", "--format", "json"}
			if tc.intent {
				args = append(args, "--full-status-without-monitor-required")
			}
			var stdout, stderr bytes.Buffer
			exit := Run(t.Context(), args, &stdout, &stderr, "test")
			if exit != tc.want || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"assessment":"UNKNOWN"`) || strings.Contains(stdout.String(), tc.path) || strings.Contains(stdout.String(), "localhost") {
				t.Fatalf("kibana from=%s exit=%d stdout=%q stderr=%q", from, exit, stdout.String(), stderr.String())
			}
		}
	}
	for _, from := range []string{"9.0.8", "9.1.10", "9.2.8", "9.3.8", "9.4.6"} {
		var stdout, stderr bytes.Buffer
		exit := Run(t.Context(), []string{"check", "project", "--project", "kibana", "--effective-config", kibanaPass, "--from", from, "--to", "9.5.3", "--effective-config-complete", "--precedence-resolved", "--full-status-without-monitor-required=false", "--now", "2026-09-12T09:24:22Z", "--format", "json"}, &stdout, &stderr, "test")
		if exit != ExitUnknown || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"assessment":"UNKNOWN"`) {
			t.Fatalf("kibana from=%s false intent exit=%d stdout=%q stderr=%q", from, exit, stdout.String(), stderr.String())
		}
	}
	wrong := writePrivateProjectFixture(t, "status.statusPageBypassMonitorPrivilege: true\n")
	var stdout, stderr bytes.Buffer
	if exit := Run(t.Context(), []string{"check", "project", "--project", "kibana", "--effective-config", wrong, "--from", "9.4.5", "--to", "9.5.3", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-12T09:24:22Z", "--format", "json"}, &stdout, &stderr, "test"); exit != ExitUnknown || stderr.Len() != 0 {
		t.Fatalf("wrong pair exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if exit := Run(t.Context(), []string{"check", "project", "--project", "kibana", "--effective-config", kibanaPass, "--from", "8.18.0", "--to", "9.0.0", "--effective-config-complete", "--precedence-resolved", "--full-status-without-monitor-required", "--now", "2026-09-12T09:24:22Z"}, &stdout, &stderr, "test"); exit != ExitUsage || stdout.Len() != 0 {
		t.Fatalf("legacy intent flag exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
}
