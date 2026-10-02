// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

func TestPrometheusSelectedAlertmanagerExamples(t *testing.T) {
	root := filepath.Join("..", "..", "examples", "cncf", "native-resources", "prometheus")
	for name, want := range map[string]int{
		"alertmanager-broken.yml":     ExitBlocked,
		"alertmanager-fixed.yml":      ExitOK,
		"alertmanager-default-v2.yml": ExitOK,
		"alertmanager-unknown.yml":    ExitUnknown,
	} {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		path := writeCNCFFile(t, name, raw, 0o600)
		code, stdout, stderr := runCNCFCLI(t,
			"check", "cncf", "--project", "prometheus", "--alertmanager-config", path,
			"--from", "2.55.1", "--to", "3.1.0", "--alertmanager-config-complete",
			"--alertmanager-config-precedence-resolved", "--now", "2026-09-12T00:30:00Z", "--format", "json")
		if code != want || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || !strings.Contains(stdout, `"selectedRuleId":"`+prometheusAlertmanagerRuleID+`"`) || strings.Contains(stdout, "127.0.0.1") || strings.Contains(stdout, path) {
			t.Fatalf("%s code=%d stdout=%q stderr=%q", name, code, stdout, stderr)
		}
	}
}

func TestPrometheusSelectedAlertmanagerDirectChecks(t *testing.T) {
	for _, test := range []struct {
		name, raw, from, to  string
		complete, precedence bool
		want                 int
		wantReason           string
	}{
		{"v1 blocked", "api_version: v1\nscheme: http\nstatic_configs:\n  - targets: [private.example:9093]\n", "2.55.1", "3.1.0", true, true, ExitBlocked, "REVIEWED_SOURCE_CONSTRAINT"},
		{"v2 passes selection", "api_version: v2\nscheme: http\nstatic_configs:\n  - targets: [private.example:9093]\n", "2.55.1", "3.1.0", true, true, ExitOK, "REVIEWED_SOURCE_CONSTRAINT"},
		{"omitted uses source default", "scheme: http\nstatic_configs:\n  - targets: [private.example:9093]\n", "2.55.1", "3.1.0", true, true, ExitOK, "REVIEWED_SOURCE_CONSTRAINT"},
		{"whitespace api version key unknown", "'api_version ': v1\nscheme: http\n", "2.55.1", "3.1.0", true, true, ExitUnknown, "RULE_FACT_UNAVAILABLE"},
		{"full config unknown", "alerting:\n  alertmanagers:\n    - api_version: v1\n", "2.55.1", "3.1.0", true, true, ExitUnknown, "RULE_FACT_UNAVAILABLE"},
		{"unresolved precedence unknown", "api_version: v2\nscheme: http\n", "2.55.1", "3.1.0", true, false, ExitUnknown, "RULE_FACT_UNAVAILABLE"},
		{"unreviewed pair unknown", "api_version: v1\nscheme: http\n", "3.1.0", "3.2.0", true, true, ExitUnknown, "RULE_TRANSITION_NOT_REVIEWED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeCNCFFile(t, "private-alertmanager.yml", []byte(test.raw), 0o600)
			args := []string{"check", "cncf", "--project", "prometheus", "--alertmanager-config", path, "--from", test.from, "--to", test.to, "--now", "2026-09-12T09:03:00Z", "--format", "json"}
			if test.complete {
				args = append(args, "--alertmanager-config-complete")
			}
			if test.precedence {
				args = append(args, "--alertmanager-config-precedence-resolved")
			}
			code, stdout, stderr := runCNCFCLI(t, args...)
			selectedLegacy := test.from == cncfprepare.PrometheusFrom && test.to == cncfprepare.PrometheusTo
			if code != test.want || stderr != "" || !strings.Contains(stdout, test.wantReason) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || (selectedLegacy && !strings.Contains(stdout, `"selectedRuleId":"`+prometheusAlertmanagerRuleID+`"`)) || (!selectedLegacy && strings.Contains(stdout, `"selectedRuleId"`)) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			for _, private := range []string{"private-alertmanager", "private.example", path} {
				if strings.Contains(stdout, private) || strings.Contains(stderr, private) {
					t.Fatalf("private input escaped: %q", private)
				}
			}
		})
	}
}

func TestPrometheusSelectedAlertmanagerHumanScope(t *testing.T) {
	path := writeCNCFFile(t, "private-alertmanager.yml", []byte("scheme: http\nstatic_configs:\n  - targets: [private.example:9093]\n"), 0o600)
	code, stdout, stderr := runCNCFCLI(t,
		"check", "cncf", "--project", "prometheus", "--alertmanager-config", path,
		"--from", "2.55.1", "--to", "3.1.0", "--alertmanager-config-complete",
		"--alertmanager-config-precedence-resolved", "--now", "2026-09-12T00:30:00Z", "--show-passes")
	for _, text := range []string{"api_version omitted; exact target source-derived default v2", "caller-selected mapping; not observed running configuration", "v2 support, reachability and alert delivery remain unverified", "verify that the actual Alertmanager supports v2"} {
		if !strings.Contains(stdout, text) {
			t.Fatalf("missing %q from %q", text, stdout)
		}
	}
	if code != ExitOK || stderr != "" || strings.Contains(stdout, "private.example") || strings.Contains(stdout, path) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestPrometheusSelectedAlertmanagerRejectsMixedModesAndBadPins(t *testing.T) {
	raw := []byte("api_version: v2\nscheme: http\n")
	path := writeCNCFFile(t, "private-alertmanager.yml", raw, 0o600)
	base := []string{"check", "cncf", "--project", "prometheus", "--alertmanager-config", path, "--from", "2.55.1", "--to", "3.1.0", "--alertmanager-config-complete", "--alertmanager-config-precedence-resolved", "--now", "2026-09-12T00:30:00Z"}
	for _, args := range [][]string{
		append(append([]string{}, base...), "--scrape-config", path),
		append(append([]string{}, base...), "--native-resource", path),
		append(append([]string{}, base...), "--alertmanager-config-digest="),
		append(append([]string{}, base...), "--alertmanager-config-digest", "sha256:"+strings.Repeat("0", 64)),
		{"check", "cncf", "--project", "nats", "--alertmanager-config", path, "--from", "2.10.0", "--to", "2.11.0", "--now", "2026-09-12T00:30:00Z"},
		{"check", "cncf", "--project", "prometheus", "--alertmanager-config", filepath.Join(t.TempDir(), "missing.yml"), "--from", "2.55.1", "--to", "3.1.0", "--now", "2026-09-12T00:30:00Z"},
	} {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage && code != ExitIntegrity || stdout != "" || strings.Contains(stderr, path) || strings.Contains(stderr, "private-alertmanager") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	}
}

func TestPrometheusSelectedAlertmanagerExternalStoreNoFallbackAndReplayPinsRaw(t *testing.T) {
	fixture := makeExternalCLIFixture(t)
	raw := []byte("api_version: v2\nscheme: http\n")
	path := writeCNCFFile(t, "private-alertmanager.yml", raw, 0o600)
	external := []string{
		"check", "cncf", "--project", "prometheus", "--alertmanager-config", path,
		"--alertmanager-config-digest", cncfDigest(raw), "--alertmanager-config-complete",
		"--alertmanager-config-precedence-resolved", "--from", "2.55.1", "--to", "3.1.0",
		"--knowledge-db", fixture.store, "--knowledge-revision", "1",
		"--knowledge-bundle-digest", fixture.manifest.Revisions[0].BundleDigest,
		"--knowledge-trust-receipt-digest", fixture.receipt1.TrustReceiptDigest, "--format", "json",
	}
	code, original, stderr := runCNCFCLI(t, external...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(original, `"knowledgeOrigin":"external_declared"`) || !strings.Contains(original, `"requestedRuleId":"`+prometheusAlertmanagerRuleID+`"`) || strings.Contains(original, `"selectedRuleId"`) || strings.Contains(original, path) {
		t.Fatalf("external code=%d stdout=%q stderr=%q", code, original, stderr)
	}
	report := writeCNCFFile(t, "prometheus-alertmanager-report.json", []byte(original), 0o600)
	importExternalCLIRevision2(t, &fixture)
	code, stdout, stderr := runCNCFCLI(t, append(append([]string{}, external...), "--replay-report", report)...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"mode":"historical"`) || !strings.Contains(stdout, `"status":"MATCH"`) {
		t.Fatalf("replay code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	withoutRawPin := make([]string, 0, len(external))
	for index := 0; index < len(external); index++ {
		if external[index] == "--alertmanager-config-digest" {
			index++
			continue
		}
		withoutRawPin = append(withoutRawPin, external[index])
	}
	code, stdout, stderr = runCNCFCLI(t, append(withoutRawPin, "--replay-report", report)...)
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "external native CNCF replay requires every raw resource digest") {
		t.Fatalf("missing raw replay pin code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestPrometheusLatestAlertmanagerTargetPairsEndToEnd(t *testing.T) {
	for _, from := range []string{"3.9.1", "3.10.0", "3.11.3", "3.12.0", "3.13.3"} {
		t.Run(from, func(t *testing.T) {
			for _, scenario := range []struct {
				name, version string
				want          int
			}{
				{"blocker", "v1", ExitBlocked},
				{"scoped-pass", "v2", ExitOK},
			} {
				path := writeCNCFFile(t, scenario.name+".yml", []byte("api_version: "+scenario.version+"\nscheme: http\n"), 0o600)
				code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "prometheus", "--alertmanager-config", path, "--alertmanager-config-complete", "--alertmanager-config-precedence-resolved", "--from", from, "--to", "3.14.0", "--now", "2026-09-12T09:03:00Z", "--format", "json")
				if code != scenario.want || stderr != "" || !strings.Contains(stdout, `"selectedRuleId":"`+prometheusNativeRuleID(from, "3.14.0", true)+`"`) {
					t.Fatalf("%s code=%d stdout=%q stderr=%q", scenario.name, code, stdout, stderr)
				}
			}
		})
	}
}

func TestPrometheusLatestAlertmanagerExamples(t *testing.T) {
	root := filepath.Join("..", "..", "examples", "cncf", "native-resources", "prometheus")
	for name, want := range map[string]int{
		"latest-v3.14.0-alertmanager-blocked.yml": ExitBlocked,
		"latest-v3.14.0-alertmanager-fixed.yml":   ExitOK,
	} {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		path := writeCNCFFile(t, name, raw, 0o600)
		code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "prometheus", "--alertmanager-config", path, "--alertmanager-config-complete", "--alertmanager-config-precedence-resolved", "--from", "3.13.3", "--to", "3.14.0", "--now", "2026-09-12T09:03:00Z", "--format", "json")
		if code != want || stderr != "" || !strings.Contains(stdout, `"selectedRuleId":"`+prometheusNativeRuleID("3.13.3", "3.14.0", true)+`"`) {
			t.Fatalf("%s code=%d stdout=%q stderr=%q", name, code, stdout, stderr)
		}
	}
}
