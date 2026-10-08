// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrometheusSelectedScrapeConfigExamples(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "examples", "cncf", "native-resources", "prometheus")
	for name, want := range map[string]int{"broken.yml": ExitBlocked, "fixed.yml": ExitOK, "unknown.yml": ExitUnknown} {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		path := writeCNCFFile(t, name, raw, 0o600)
		code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "prometheus", "--scrape-config", path, "--scrape-job", "selected-api", "--from", "2.55.1", "--to", "3.1.0", "--scrape-config-complete", "--scrape-config-precedence-resolved", "--now", "2026-09-11T23:00:00Z", "--format", "json")
		if code != want || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || !strings.Contains(stdout, `"selectedRuleId":"`+prometheusScrapeRuleID+`"`) || strings.Contains(stdout, "selected-api") || strings.Contains(stdout, "127.0.0.1") {
			t.Fatalf("%s code=%d stdout=%q stderr=%q", name, code, stdout, stderr)
		}
	}
}

func TestPrometheusSelectedScrapeConfigDirectChecks(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, raw, from, to  string
		complete, precedence bool
		want                 int
		wantReason           string
	}{
		{"old key blocks", "job_name: private-job\nscrape_classic_histograms: false\nstatic_configs:\n  - targets: [private.example:9090]\n", "2.55.1", "3.1.0", true, true, ExitBlocked, "REVIEWED_SOURCE_CONSTRAINT"},
		{"new key passes selected rename", "job_name: private-job\nalways_scrape_classic_histograms: true\nstatic_configs:\n  - targets: [private.example:9090]\n", "2.55.1", "3.1.0", true, true, ExitOK, "REVIEWED_SOURCE_CONSTRAINT"},
		{"neither key unknown", "job_name: private-job\nscrape_interval: 30s\n", "2.55.1", "3.1.0", true, true, ExitUnknown, "RULE_FACT_UNAVAILABLE"},
		{"unresolved precedence unknown", "job_name: private-job\nalways_scrape_classic_histograms: true\n", "2.55.1", "3.1.0", true, false, ExitUnknown, "RULE_FACT_UNAVAILABLE"},
		{"unreviewed pair unknown", "job_name: private-job\nscrape_classic_histograms: true\n", "3.1.0", "3.2.0", true, true, ExitUnknown, "RULE_TRANSITION_NOT_REVIEWED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeCNCFFile(t, "selected-private.yml", []byte(test.raw), 0o600)
			args := []string{"check", "cncf", "--project", "prometheus", "--scrape-config", path, "--scrape-job", "private-job", "--from", test.from, "--to", test.to, "--now", "2026-09-11T23:00:00Z", "--format", "json"}
			if test.complete {
				args = append(args, "--scrape-config-complete")
			}
			if test.precedence {
				args = append(args, "--scrape-config-precedence-resolved")
			}
			code, stdout, stderr := runCNCFCLI(t, args...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, test.wantReason) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			for _, private := range []string{"private-job", "private.example", path} {
				if strings.Contains(stdout, private) || strings.Contains(stderr, private) {
					t.Fatalf("private input escaped: %q", private)
				}
			}
		})
	}
}

func TestPrometheusSelectedScrapeConfigRejectsMixedModesAndBadPins(t *testing.T) {
	t.Parallel()
	raw := []byte("job_name: private-job\nalways_scrape_classic_histograms: true\n")
	path := writeCNCFFile(t, "selected-private.yml", raw, 0o600)
	base := []string{"check", "cncf", "--project", "prometheus", "--scrape-config", path, "--scrape-job", "private-job", "--from", "2.55.1", "--to", "3.1.0", "--scrape-config-complete", "--scrape-config-precedence-resolved", "--now", "2026-09-11T23:00:00Z"}
	for _, args := range [][]string{
		append(append([]string{}, base...), "--native-resource", path),
		append(append([]string{}, base...), "--scrape-config-digest="),
		append(append([]string{}, base...), "--scrape-config-digest", "sha256:"+strings.Repeat("0", 64)),
		{"check", "cncf", "--project", "nats", "--scrape-config", path, "--from", "2.10.0", "--to", "2.11.0", "--now", "2026-09-11T23:00:00Z"},
		{"check", "cncf", "--project", "prometheus", "--scrape-config", filepath.Join(t.TempDir(), "missing.yml"), "--scrape-job", "private-job", "--from", "2.55.1", "--to", "3.1.0", "--now", "2026-09-11T23:00:00Z"},
	} {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage && code != ExitIntegrity || stdout != "" || strings.Contains(stderr, path) || strings.Contains(stderr, "private-job") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	}
}

func TestPrometheusSelectedScrapeConfigAmbiguousYAMLNeverPasses(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"job_name: private-job\nalways_scrape_classic_histograms: true#suffix\n",
		"job_name: private-job\n\"\\x73crape_classic_histograms\": true\nalways_scrape_classic_histograms: true\n",
		"job_name: private-job\nscrape_interval: 15s\nscrape_interval: 30s\nalways_scrape_classic_histograms: true\n",
	} {
		path := writeCNCFFile(t, "private-ambiguous.yml", []byte(raw), 0o600)
		code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "prometheus", "--scrape-config", path, "--scrape-job", "private-job", "--scrape-config-complete", "--scrape-config-precedence-resolved", "--from", "2.55.1", "--to", "3.1.0", "--now", "2026-09-11T23:00:00Z", "--format", "json")
		if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"reasonCode":"RULE_FACT_UNAVAILABLE"`) || strings.Contains(stdout, path) || strings.Contains(stdout, "private-job") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	}
}

func TestPrometheusSelectedScrapeConfigExternalStoreNoFallbackAndReplayPinsRaw(t *testing.T) {
	t.Parallel()
	fixture := makeExternalCLIFixture(t)
	raw := []byte("job_name: private-job\nalways_scrape_classic_histograms: true\n")
	path := writeCNCFFile(t, "selected-private.yml", raw, 0o600)
	external := []string{
		"check", "cncf", "--project", "prometheus", "--scrape-config", path, "--scrape-config-digest", cncfDigest(raw), "--scrape-job", "private-job",
		"--scrape-config-complete", "--scrape-config-precedence-resolved", "--from", "2.55.1", "--to", "3.1.0", "--knowledge-db", fixture.store,
		"--knowledge-revision", "1", "--knowledge-bundle-digest", fixture.manifest.Revisions[0].BundleDigest,
		"--knowledge-trust-receipt-digest", fixture.receipt1.TrustReceiptDigest, "--format", "json",
	}
	code, original, stderr := runCNCFCLI(t, external...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(original, `"knowledgeOrigin":"external_declared"`) || strings.Contains(original, "private-job") {
		t.Fatalf("external code=%d stdout=%q stderr=%q", code, original, stderr)
	}
	report := writeCNCFFile(t, "prometheus-report.json", []byte(original), 0o600)
	importExternalCLIRevision2(t, &fixture)
	code, stdout, stderr := runCNCFCLI(t, append(append([]string{}, external...), "--replay-report", report)...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"mode":"historical"`) || !strings.Contains(stdout, `"status":"MATCH"`) {
		t.Fatalf("replay code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	withoutRawPin := make([]string, 0, len(external))
	for index := 0; index < len(external); index++ {
		if external[index] == "--scrape-config-digest" {
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

func TestPrometheusLatestScrapeTargetPairsEndToEnd(t *testing.T) {
	t.Parallel()
	for _, from := range []string{"3.9.1", "3.10.0", "3.11.3", "3.12.0", "3.13.3"} {
		t.Run(from, func(t *testing.T) {
			for _, scenario := range []struct {
				name, key string
				want      int
			}{
				{"blocker", "scrape_classic_histograms", ExitBlocked},
				{"scoped-pass", "always_scrape_classic_histograms", ExitOK},
			} {
				path := writeCNCFFile(t, scenario.name+".yml", []byte("job_name: private-job\n"+scenario.key+": true\n"), 0o600)
				code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "prometheus", "--scrape-config", path, "--scrape-job", "private-job", "--scrape-config-complete", "--scrape-config-precedence-resolved", "--from", from, "--to", "3.14.0", "--now", "2026-09-12T09:03:00Z", "--format", "json")
				if code != scenario.want || stderr != "" || !strings.Contains(stdout, `"selectedRuleId":"`+prometheusNativeRuleID(from, "3.14.0", false)+`"`) || strings.Contains(stdout, "private-job") {
					t.Fatalf("%s code=%d stdout=%q stderr=%q", scenario.name, code, stdout, stderr)
				}
			}
		})
	}
	path := writeCNCFFile(t, "unlisted.yml", []byte("job_name: private-job\nscrape_classic_histograms: true\n"), 0o600)
	code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "prometheus", "--scrape-config", path, "--scrape-job", "private-job", "--scrape-config-complete", "--scrape-config-precedence-resolved", "--from", "3.8.0", "--to", "3.14.0", "--now", "2026-09-12T09:03:00Z", "--format", "json")
	if code != ExitUnknown || stderr != "" || strings.Contains(stdout, `"selectedRuleId"`) || !strings.Contains(stdout, "RULE_TRANSITION_NOT_REVIEWED") {
		t.Fatalf("unlisted code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestPrometheusLatestScrapeExamples(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "examples", "cncf", "native-resources", "prometheus")
	for name, want := range map[string]int{
		"latest-v3.14.0-scrape-blocked.yml": ExitBlocked,
		"latest-v3.14.0-scrape-fixed.yml":   ExitOK,
		"latest-v3.14.0-scrape-unknown.yml": ExitUnknown,
	} {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		path := writeCNCFFile(t, name, raw, 0o600)
		code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "prometheus", "--scrape-config", path, "--scrape-job", "selected-api", "--scrape-config-complete", "--scrape-config-precedence-resolved", "--from", "3.13.3", "--to", "3.14.0", "--now", "2026-09-12T09:03:00Z", "--format", "json")
		if code != want || stderr != "" || !strings.Contains(stdout, `"selectedRuleId":"`+prometheusNativeRuleID("3.13.3", "3.14.0", false)+`"`) {
			t.Fatalf("%s code=%d stdout=%q stderr=%q", name, code, stdout, stderr)
		}
	}
}
