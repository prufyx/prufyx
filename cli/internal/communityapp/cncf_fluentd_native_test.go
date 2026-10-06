// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

func fluentdRubyTargetInput(distribution, rubyVersion string, includeRuby bool) []byte {
	if !includeRuby {
		return []byte(`{"distribution":"` + distribution + `"}`)
	}
	return []byte(`{"distribution":"` + distribution + `","rubyVersion":"` + rubyVersion + `"}`)
}

func fluentdNativeArgs(path, from, to string) []string {
	return []string{
		"check", "cncf", "--project", "fluentd", "--native-resource", path,
		"--from", from, "--to", to, "--now", "2026-09-19T00:00:00Z", "--format", "json",
	}
}

// The native one-step route reuses the already-reviewed PrepareFluentDLiteral
// adapter for the literal-treatment rule and the new PrepareFluentDRubyTarget
// adapter (shape-dispatched by PrepareFluentD) for the Ruby-minimum rules;
// this exercises both shapes end to end without a separate prepare step.
func TestFluentDNativeCheck_RubyTargetBoundedOutcomes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, status, reason string
		distribution         string
		rubyVersion          string
		includeRuby          bool
		want                 int
	}{
		{"official with old ruby blocks", "BLOCKED", "REVIEWED_SOURCE_CONSTRAINT", "official_upstream", "3.1.0", true, ExitBlocked},
		{"official with new ruby passes", "PASS", "REVIEWED_SOURCE_CONSTRAINT", "official_upstream", "3.2.0", true, ExitOK},
		{"missing ruby stays unknown, never a negative-presence pass", "UNKNOWN", "RULE_DEPENDENCY_COMPONENT_MISSING", "official_upstream", "", false, ExitUnknown},
		{"custom build stays unknown", "UNKNOWN", "RULE_APPLICABILITY_NOT_MATCHED", "custom_build", "3.2.0", true, ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := fluentdRubyTargetInput(test.distribution, test.rubyVersion, test.includeRuby)
			path := writeCNCFFile(t, "fluentd-ruby.json", raw, 0o600)
			code, stdout, stderr := runCNCFCLI(t, fluentdNativeArgs(path, "1.18.0", "1.19.3")...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, test.reason) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			if test.status != "BLOCKED" && strings.Contains(stdout, `"status":"BLOCKED"`) {
				t.Fatalf("unexpected BLOCKED: %q", stdout)
			}
		})
	}
}

// The aggregate gate is unchanged by this route: even a scoped PASS keeps the
// whole-upgrade assessment UNKNOWN.
func TestFluentDNativeCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	t.Parallel()
	raw := fluentdRubyTargetInput("official_upstream", "3.2.0", true)
	path := writeCNCFFile(t, "fluentd-ruby.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, fluentdNativeArgs(path, "1.18.0", "1.19.3")...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

// All five reviewed 1.19.3 target-only origins, plus the separate direct
// 1.16.0 to 1.17.0 rule, are routed through the same native path.
func TestFluentDNativeCheck_AllReviewedPairsAreRouted(t *testing.T) {
	t.Parallel()
	for _, pair := range []struct{ from, to string }{
		{"1.14.6", "1.19.3"},
		{"1.15.3", "1.19.3"},
		{"1.16.11", "1.19.3"},
		{"1.17.1", "1.19.3"},
		{"1.18.0", "1.19.3"},
		{"1.16.0", "1.17.0"},
	} {
		t.Run(pair.from+"-to-"+pair.to, func(t *testing.T) {
			blocked := writeCNCFFile(t, "fluentd-ruby-blocked.json", fluentdRubyTargetInput("official_upstream", "0.0.1", true), 0o600)
			code, stdout, stderr := runCNCFCLI(t, fluentdNativeArgs(blocked, pair.from, pair.to)...)
			if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, `"status":"BLOCKED"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
				t.Fatalf("from=%s to=%s blocked code=%d stdout=%q stderr=%q", pair.from, pair.to, code, stdout, stderr)
			}
			clean := writeCNCFFile(t, "fluentd-ruby-clean.json", fluentdRubyTargetInput("official_upstream", "9.9.9", true), 0o600)
			code, stdout, stderr = runCNCFCLI(t, fluentdNativeArgs(clean, pair.from, pair.to)...)
			if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
				t.Fatalf("from=%s to=%s clean code=%d stdout=%q stderr=%q", pair.from, pair.to, code, stdout, stderr)
			}
		})
	}
}

// The native route also still serves the pre-existing literal-treatment
// shape (current/proposed selected values), unchanged by the new
// distribution/rubyVersion shape added to the same PrepareFluentD dispatcher.
func TestFluentDNativeCheck_LiteralTreatmentShapeStillRoutes(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"current":"{\"path\":\"plain\"}","proposed":"{\"path\":\"plain\"}","selectedValueComplete":true,"currentDefaultUsed":true,"preserveLiteralTreatment":true}`)
	path := writeCNCFFile(t, "fluentd-literal.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, fluentdNativeArgs(path, "1.17.1", "1.18.0")...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestFluentDNativeCheck_RejectsMalformedWrongPairAndWrongRoute(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "fluentd-ruby.json", fluentdRubyTargetInput("official_upstream", "3.1.0", true), 0o600)
	code, stdout, stderr := runCNCFCLI(t, fluentdNativeArgs(path, "1.18.0", "1.19.4")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "falco", "--native-resource", "PRIVATE-NOT-READ.json", "--from", "0.40.0", "--to", "0.41.0", "--now", "2026-09-19T00:00:00Z", "--format", "json")
	if code != ExitUsage || strings.Contains(stderr, "PRIVATE-NOT-READ") || strings.Contains(stdout, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestFluentDNativeCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "fluentd-ruby.json", fluentdRubyTargetInput("official_upstream", "3.1.0", true), 0o600)
	args := append(fluentdNativeArgs(path, "1.18.0", "1.19.3"), "--native-resource-digest", cncfDigest(fluentdRubyTargetInput("official_upstream", "3.2.0", true)))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "BLOCKED") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestFluentDPrepareFeedsNativeCheckEquivalently(t *testing.T) {
	t.Parallel()
	raw := fluentdRubyTargetInput("official_upstream", "3.1.0", true)
	path := writeCNCFFile(t, "fluentd-ruby.json", raw, 0o600)
	code, canonical, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "fluentd", "--input", path, "--from", "1.18.0", "--to", "1.19.3", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.fluentd.distribution") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "fluentd-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "fluentd", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-19T00:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, report, stderr)
	}
	nativeCode, nativeReport, nativeErr := runCNCFCLI(t, fluentdNativeArgs(path, "1.18.0", "1.19.3")...)
	if nativeCode != code || nativeErr != "" || !strings.Contains(nativeReport, `"status":"BLOCKED"`) {
		t.Fatalf("native code=%d stdout=%q stderr=%q", nativeCode, nativeReport, nativeErr)
	}
}
