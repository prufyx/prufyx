// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

const otelRouteConfig = `exporters:
  logging/example: {}
service:
  pipelines:
    traces:
      exporters: [logging/example]
`

func TestCNCFOpenTelemetryNativeRouteUsesSelectedConfig(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "collector.yaml", []byte(otelRouteConfig), 0o600)
	args := []string{"check", "cncf", "--project", "opentelemetry", "--otel-collector-config", path, "--otel-collector-config-digest", cncfDigest([]byte(otelRouteConfig)), "--otel-distribution", "official", "--otel-config-complete", "--otel-config-precedence-resolved", "--from", "0.110.0", "--to", "0.111.0", "--now", "2026-09-12T02:35:00Z", "--format", "json"}
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, `"status":"BLOCKED"`) || !strings.Contains(stdout, "opentelemetry.logging-exporter-removed") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if strings.Contains(stdout, path) || strings.Contains(stdout, "logging/example") {
		t.Fatalf("private native input escaped: %q", stdout)
	}
}

func TestCNCFOpenTelemetryNativeRouteBoundaries(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "collector.yaml", []byte("exporters:\n  debug: {}\n"), 0o600)
	base := []string{"check", "cncf", "--project", "opentelemetry", "--otel-collector-config", path, "--otel-distribution", "official", "--otel-config-complete", "--otel-config-precedence-resolved", "--from", "0.110.0", "--to", "0.111.0", "--now", "2026-09-12T02:35:00Z", "--format", "json"}
	code, stdout, stderr := runCNCFCLI(t, base...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || strings.Contains(stdout, path) {
		t.Fatalf("absence code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	wrongPair := append([]string{}, base...)
	wrongPair[11] = "0.109.0"
	customDistribution := append([]string{}, base...)
	customDistribution[7] = "custom"
	for _, test := range []struct {
		name string
		args []string
		want int
	}{
		{"wrong pair", wrongPair, ExitUnknown},
		{"custom distribution", customDistribution, ExitUnknown},
		{"orphan flag", []string{"check", "cncf", "--project", "grafana", "--otel-collector-config", path, "--otel-distribution", "official", "--from", "0.110.0", "--to", "0.111.0", "--now", "2026-09-12T02:35:00Z"}, ExitUsage},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runCNCFCLI(t, test.args...)
			if code != test.want || (test.want == ExitUsage && stdout != "") || (test.want != ExitUsage && stdout == "") || strings.Contains(stderr, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestCNCFOpenTelemetryNativeRouteRejectsBadPinAndMode(t *testing.T) {
	t.Parallel()
	raw := []byte("exporters:\n  debug: {}\n")
	private := writeCNCFFile(t, "collector.yaml", raw, 0o600)
	base := []string{"check", "cncf", "--project", "opentelemetry", "--otel-collector-config", private, "--otel-distribution", "official", "--otel-config-complete", "--otel-config-precedence-resolved", "--from", "0.110.0", "--to", "0.111.0", "--now", "2026-09-12T02:35:00Z"}
	badPin := append(append([]string{}, base...), "--otel-collector-config-digest", "sha256:"+strings.Repeat("0", 64))
	if code, stdout, stderr := runCNCFCLI(t, badPin...); code != ExitIntegrity || stdout != "" || strings.Contains(stderr, private) {
		t.Fatalf("bad pin code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	permissive := writeCNCFFile(t, "collector-permissive.yaml", raw, 0o644)
	modeArgs := append(append([]string{}, base[:5]...), permissive)
	modeArgs = append(modeArgs, base[6:]...)
	if code, stdout, stderr := runCNCFCLI(t, modeArgs...); code != ExitUsage || stdout != "" || strings.Contains(stderr, permissive) {
		t.Fatalf("permissive mode code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCNCFOpenTelemetryInternalMetricsSelectorTruthTable(t *testing.T) {
	t.Parallel()
	raw := []byte("exporters:\n  debug: {}\n")
	path := writeCNCFFile(t, "collector-metrics.yaml", raw, 0o600)
	base := []string{"check", "cncf", "--project", "opentelemetry", "--otel-collector-config", path, "--otel-collector-config-digest", cncfDigest(raw), "--otel-distribution", "official", "--otel-config-complete", "--otel-config-precedence-resolved", "--otel-rule", "internal-telemetry-default-bind", "--from", "0.110.0", "--to", "0.111.0", "--now", "2026-09-13T10:00:00Z", "--format", "json"}
	withAuthorities := func(gate, remote string) []string {
		args := append([]string(nil), base...)
		return append(args, "--otel-metrics-localhost-default", gate, "--otel-metrics-remote-scrape-required", remote)
	}
	for _, test := range []struct {
		name, gate, remote, status string
		wantCode                   int
	}{
		{"localhost default blocks remote scrape", "true", "true", "BLOCKED", ExitBlocked},
		{"wildcard default passes remote scrape", "false", "true", "PASS", ExitOK},
		{"remote scrape not required passes", "true", "false", "PASS", ExitOK},
		{"wildcard default without remote scrape passes", "false", "false", "PASS", ExitOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runCNCFCLI(t, withAuthorities(test.gate, test.remote)...)
			if code != test.wantCode || stderr != "" || !strings.Contains(stdout, `"status":"`+test.status+`"`) || !strings.Contains(stdout, `"selectedRuleId":"opentelemetry.internal-telemetry-default-bind.0-110-to-0-111"`) || strings.Contains(stdout, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
	for _, test := range []struct {
		name string
		args []string
	}{
		{"missing authority", base},
		{"invalid gate authority", append(append([]string(nil), base...), "--otel-metrics-localhost-default", "yes", "--otel-metrics-remote-scrape-required", "true")},
		{"metrics override", append(append([]string(nil), base[:0]...), base...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := test.args
			if test.name == "metrics override" {
				override := []byte("exporters:\n  debug: {}\nservice:\n  telemetry:\n    metrics:\n      address: 0.0.0.0:8888\n")
				overridePath := writeCNCFFile(t, "collector-metrics-override.yaml", override, 0o600)
				args = append([]string(nil), base...)
				for i := range args {
					if args[i] == path {
						args[i] = overridePath
					}
					if args[i] == cncfDigest(raw) {
						args[i] = cncfDigest(override)
					}
				}
				args = append(args, "--otel-metrics-localhost-default", "false", "--otel-metrics-remote-scrape-required", "true")
			}
			code, stdout, stderr := runCNCFCLI(t, args...)
			if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"status":"UNKNOWN"`) || strings.Contains(stdout, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}
