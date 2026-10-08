// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/checkroutemetadata"
)

// TestRenderCatalogCheckRangeMatchShowsModeNotAnchorCommand proves fix 1's
// human-output half: a range match must print its match mode and must never
// print the native route's exact-pair command, since that command is always
// pinned to the anchor pair and would misdescribe the queried, off-anchor
// pair as if it were the reviewed anchor's own transition.
func TestRenderCatalogCheckRangeMatchShowsModeNotAnchorCommand(t *testing.T) {
	t.Parallel()
	item := checkroutemetadata.Check{
		Project: "kubernetes", RuleID: "kubernetes.example", From: "1.24.0", To: "1.25.0",
		MatchMode: "range",
		NativeDescriptor: checkroutemetadata.Route{
			State:   checkroutemetadata.DescriptorExact,
			Command: []checkroutemetadata.Argument{{Kind: "literal", Literal: "check"}, {Kind: "literal", Literal: "cncf"}},
		},
		GenericDeclarationRoute: checkroutemetadata.Route{State: checkroutemetadata.RouteExposed},
	}
	var buf bytes.Buffer
	renderCatalogCheck(&buf, item)
	out := buf.String()
	if !strings.Contains(out, "match mode: range") {
		t.Fatalf("range match output missing match mode: %q", out)
	}
	if strings.Contains(out, "prufyx check cncf") {
		t.Fatalf("range match output printed the anchor-pinned native command: %q", out)
	}

	anchorItem := item
	anchorItem.MatchMode = ""
	buf.Reset()
	renderCatalogCheck(&buf, anchorItem)
	anchorOut := buf.String()
	if !strings.Contains(anchorOut, "prufyx check cncf") {
		t.Fatalf("anchor match output missing the native command: %q", anchorOut)
	}
	if strings.Contains(anchorOut, "match mode:") {
		t.Fatalf("anchor match output unexpectedly printed a match mode: %q", anchorOut)
	}
}

func TestCatalogChecksPublicRouteReportsExactNativeBindings(t *testing.T) {
	t.Parallel()
	tests := []struct{ project, from, to, ruleID string }{
		{"prometheus", "2.55.1", "3.1.0", "prometheus.alertmanager-api-v1-removed.3-1"},
		{"prometheus", "3.9.1", "3.14.0", "prometheus.alertmanager-api-v1.target-config.3-9-1-to-3-14-0"},
		{"prometheus", "3.10.0", "3.14.0", "prometheus.alertmanager-api-v1.target-config.3-10-0-to-3-14-0"},
		{"prometheus", "3.11.3", "3.14.0", "prometheus.alertmanager-api-v1.target-config.3-11-3-to-3-14-0"},
		{"prometheus", "3.12.0", "3.14.0", "prometheus.alertmanager-api-v1.target-config.3-12-0-to-3-14-0"},
		{"prometheus", "3.13.3", "3.14.0", "prometheus.alertmanager-api-v1.target-config.3-13-3-to-3-14-0"},
		{"prometheus", "2.55.1", "3.1.0", "prometheus.scrape-classic-histograms-key-renamed.3-1"},
		{"prometheus", "3.9.1", "3.14.0", "prometheus.scrape-classic-histograms.target-config.3-9-1-to-3-14-0"},
		{"prometheus", "3.10.0", "3.14.0", "prometheus.scrape-classic-histograms.target-config.3-10-0-to-3-14-0"},
		{"prometheus", "3.11.3", "3.14.0", "prometheus.scrape-classic-histograms.target-config.3-11-3-to-3-14-0"},
		{"prometheus", "3.12.0", "3.14.0", "prometheus.scrape-classic-histograms.target-config.3-12-0-to-3-14-0"},
		{"prometheus", "3.13.3", "3.14.0", "prometheus.scrape-classic-histograms.target-config.3-13-3-to-3-14-0"},
		{"prometheus", "2.55.1", "3.14.0", "prometheus.remote-write-http2-default.2-55-1-to-3-14-0"},
		{"envoy", "1.34.14", "1.39.1", "envoy.xds-v2-unsupported-at-1-39-1-from-1-34-14"},
		{"envoy", "1.35.13", "1.39.1", "envoy.xds-v2-unsupported-at-1-39-1-from-1-35-13"},
		{"envoy", "1.36.10", "1.39.1", "envoy.xds-v2-unsupported-at-1-39-1-from-1-36-10"},
		{"envoy", "1.37.6", "1.39.1", "envoy.xds-v2-unsupported-at-1-39-1-from-1-37-6"},
		{"envoy", "1.38.4", "1.39.1", "envoy.xds-v2-unsupported-at-1-39-1-from-1-38-4"},
		{"mariadb-operator", "26.3.0", "26.6.0", "mariadb-operator.upgrade-26-6.requires-dataplane-prerequisite"},
	}
	for _, tc := range tests {
		t.Run(tc.ruleID, func(t *testing.T) {
			code, stdout, stderr := runCNCFCLI(t, "catalog", "checks", "--project", tc.project, "--from", tc.from, "--to", tc.to, "--format", "json")
			if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"ruleId":"`+tc.ruleID+`"`) || !strings.Contains(stdout, `"state":"EXACT_PAIR_NATIVE_ROUTE"`) {
				t.Fatalf("catalog=(%d,%q,%q)", code, stdout, stderr)
			}
			var document struct {
				Schema string `json:"schema"`
				Checks []struct {
					RuleID string `json:"ruleId"`
					Native struct {
						State string `json:"state"`
					} `json:"nativeDescriptor"`
				} `json:"checks"`
			}
			if err := json.Unmarshal([]byte(stdout), &document); err != nil || document.Schema != "prufyx.io/check-route-catalog/v1alpha1" {
				t.Fatalf("catalog JSON=%q err=%v", stdout, err)
			}
			found := false
			for _, item := range document.Checks {
				if item.RuleID == tc.ruleID && item.Native.State == "EXACT_PAIR_NATIVE_ROUTE" {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected exact descriptor missing: %q", stdout)
			}
		})
	}
}

func TestCatalogChecksKnownWrongPairAndGenericCommunityBoundary(t *testing.T) {
	t.Parallel()
	code, stdout, stderr := runCNCFCLI(t, "catalog", "checks", "--project", "envoy", "--from", "1.17.2", "--to", "1.18.0", "--format", "json")
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"state":"NO_NATIVE_DESCRIPTOR"`) {
		t.Fatalf("historical Envoy=(%d,%q,%q)", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "catalog", "checks", "--project", "mariadb-operator", "--from", "26.3.0", "--to", "26.6.0", "--format", "json")
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"state":"NOT_EXPOSED_BY_PUBLIC_CLI"`) || strings.Contains(stdout, `"--input"`) {
		t.Fatalf("community boundary=(%d,%q,%q)", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "catalog", "checks", "--project", "envoy", "--from", "1.34.14", "--to", "1.38.4")
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, "known embedded project, but no matching source-rule transition") {
		t.Fatalf("wrong pair=(%d,%q,%q)", code, stdout, stderr)
	}
}

func TestCatalogChecksRejectsIncompleteOrUnsafeQueryWithoutEchoingIt(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"catalog", "checks", "--format", "json"},
		{"catalog", "checks", "--project", "envoy", "--from", "1.38.4"},
		{"catalog", "checks", "--project", "envoy", "--from="},
		{"catalog", "checks", "--project", "envoy", "--to="},
		{"catalog", "checks", "--project", "envoy", "--from=", "--to=1.39.1"},
		{"catalog", "checks", "--project", "envoy", "--from=", "--to="},
		{"catalog", "checks", "--project", "Envoy"},
		{"catalog", "checks", "--project", "envoy;private"},
		{"catalog", "checks", "--project", "envoy", "--from", "01.38.4", "--to", "1.39.1"},
		{"catalog", "checks", "--project", "envoy", "--project", "coredns"},
	} {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "invalid check catalogue arguments") {
			t.Fatalf("args=%q got=(%d,%q,%q)", args, code, stdout, stderr)
		}
	}
}

func TestCatalogChecksAllowsAbsentPairAsAnUnfilteredProjectQuery(t *testing.T) {
	t.Parallel()
	code, stdout, stderr := runCNCFCLI(t, "catalog", "checks", "--project", "envoy", "--format", "json")
	var result checkroutemetadata.Result
	if code != ExitOK || stderr != "" || json.Unmarshal([]byte(stdout), &result) != nil || result.Query.Project != "envoy" || result.Query.From != "" || result.Query.To != "" || len(result.Checks) < 2 {
		t.Fatalf("unfiltered project query=(%d,%q,%q)", code, stdout, stderr)
	}
}

func TestCatalogNativeBindingsPopulatePublicRun(t *testing.T) {
	t.Parallel()
	tests := []catalogRouteCase{
		{"prometheus", "2.55.1", "3.1.0", "prometheus.alertmanager-api-v1-removed.3-1", "alert", ExitBlocked},
		{"prometheus", "3.9.1", "3.14.0", "prometheus.alertmanager-api-v1.target-config.3-9-1-to-3-14-0", "alert", ExitBlocked},
		{"prometheus", "3.10.0", "3.14.0", "prometheus.alertmanager-api-v1.target-config.3-10-0-to-3-14-0", "alert", ExitBlocked},
		{"prometheus", "3.11.3", "3.14.0", "prometheus.alertmanager-api-v1.target-config.3-11-3-to-3-14-0", "alert", ExitBlocked},
		{"prometheus", "3.12.0", "3.14.0", "prometheus.alertmanager-api-v1.target-config.3-12-0-to-3-14-0", "alert", ExitBlocked},
		{"prometheus", "3.13.3", "3.14.0", "prometheus.alertmanager-api-v1.target-config.3-13-3-to-3-14-0", "alert", ExitBlocked},
		{"prometheus", "2.55.1", "3.1.0", "prometheus.scrape-classic-histograms-key-renamed.3-1", "scrape", ExitBlocked},
		{"prometheus", "3.9.1", "3.14.0", "prometheus.scrape-classic-histograms.target-config.3-9-1-to-3-14-0", "scrape", ExitBlocked},
		{"prometheus", "3.10.0", "3.14.0", "prometheus.scrape-classic-histograms.target-config.3-10-0-to-3-14-0", "scrape", ExitBlocked},
		{"prometheus", "3.11.3", "3.14.0", "prometheus.scrape-classic-histograms.target-config.3-11-3-to-3-14-0", "scrape", ExitBlocked},
		{"prometheus", "3.12.0", "3.14.0", "prometheus.scrape-classic-histograms.target-config.3-12-0-to-3-14-0", "scrape", ExitBlocked},
		{"prometheus", "3.13.3", "3.14.0", "prometheus.scrape-classic-histograms.target-config.3-13-3-to-3-14-0", "scrape", ExitBlocked},
		{"prometheus", "2.55.1", "3.14.0", "prometheus.remote-write-http2-default.2-55-1-to-3-14-0", "remote", ExitBlocked},
		{"envoy", "1.34.14", "1.39.1", "envoy.xds-v2-unsupported-at-1-39-1-from-1-34-14", "envoy", ExitBlocked},
		{"envoy", "1.35.13", "1.39.1", "envoy.xds-v2-unsupported-at-1-39-1-from-1-35-13", "envoy", ExitBlocked},
		{"envoy", "1.36.10", "1.39.1", "envoy.xds-v2-unsupported-at-1-39-1-from-1-36-10", "envoy", ExitBlocked},
		{"envoy", "1.37.6", "1.39.1", "envoy.xds-v2-unsupported-at-1-39-1-from-1-37-6", "envoy", ExitBlocked},
		{"envoy", "1.38.4", "1.39.1", "envoy.xds-v2-unsupported-at-1-39-1-from-1-38-4", "envoy", ExitBlocked},
		{"mariadb-operator", "26.3.0", "26.6.0", "mariadb-operator.upgrade-26-6.requires-dataplane-prerequisite", "mariadb", ExitOK},
	}
	for _, tc := range tests {
		t.Run(tc.ruleID, func(t *testing.T) {
			command := emittedCatalogNativeCommand(t, tc, nativeFixture(t, tc.fixture))
			code, stdout, stderr := runCNCFCLI(t, append(command, "--format", "json")...)
			if code != tc.exit || stderr != "" {
				t.Fatalf("run=(%d,%q,%q)", code, stdout, stderr)
			}
			assertCatalogOutcome(t, stdout, tc.ruleID)
		})
	}
}

type catalogRouteCase struct {
	project, from, to, ruleID, fixture string
	exit                               int
}

func catalogCheck(t *testing.T, tc catalogRouteCase) checkroutemetadata.Check {
	t.Helper()
	code, stdout, stderr := runCNCFCLI(t, "catalog", "checks", "--project", tc.project, "--from", tc.from, "--to", tc.to, "--format", "json")
	var result checkroutemetadata.Result
	if code != ExitOK || stderr != "" || json.Unmarshal([]byte(stdout), &result) != nil {
		t.Fatalf("catalog route=(%d,%q,%q)", code, stdout, stderr)
	}
	var found []checkroutemetadata.Check
	for _, item := range result.Checks {
		if item.Project == tc.project && item.From == tc.from && item.To == tc.to && item.RuleID == tc.ruleID {
			found = append(found, item)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected exact catalog identity %s %s -> %s %s, got %#v", tc.project, tc.from, tc.to, tc.ruleID, result.Checks)
	}
	return found[0]
}

func emittedCatalogNativeCommand(t *testing.T, tc catalogRouteCase, path string) []string {
	t.Helper()
	item := catalogCheck(t, tc)
	if item.NativeDescriptor.State != checkroutemetadata.DescriptorExact {
		t.Fatalf("native descriptor=%#v", item.NativeDescriptor)
	}
	return substituteCatalogRoute(t, item.NativeDescriptor.Command, path)
}

func substituteCatalogRoute(t *testing.T, route []checkroutemetadata.Argument, path string) []string {
	t.Helper()
	args := make([]string, 0, len(route)*2)
	for _, item := range route {
		switch item.Kind {
		case "literal":
			args = append(args, item.Literal)
		case "file_placeholder":
			args = append(args, item.Name, path)
		case "name_placeholder":
			args = append(args, item.Name, "selected")
		case "boolean_operator_declaration":
			args = append(args, item.Name, "true")
		case "timestamp_placeholder":
			args = append(args, item.Name, "2026-09-13T12:00:00Z")
		default:
			t.Fatalf("unsupported emitted argument %#v", item)
		}
	}
	return args
}

func nativeFixture(t *testing.T, kind string) string {
	t.Helper()
	switch kind {
	case "alert":
		return writeCNCFFile(t, "alert.yml", []byte("api_version: v1\nscheme: http\n"), 0o600)
	case "scrape":
		return writeCNCFFile(t, "scrape.yml", []byte("job_name: selected\nscrape_classic_histograms: true\n"), 0o600)
	case "remote":
		return writeCNCFFile(t, "remote.yml", []byte("remote_write:\n  - name: selected\n    enable_http2: false\n"), 0o600)
	case "envoy":
		return writeCNCFFile(t, "envoy.json", []byte(`{"dynamic_resources":{"ads_config":{"api_type":"GRPC","transport_api_version":"V2"}}}`), 0o600)
	case "mariadb":
		return writeCNCFFile(t, "mariadb.json", []byte(mariadbOperatorTestResource), 0o600)
	default:
		t.Fatalf("unknown fixture kind %q", kind)
		return ""
	}
}

func assertCatalogOutcome(t *testing.T, stdout, ruleID string) {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatal(err)
	}
	if document["assessment"] != "UNKNOWN" || document["networkUsed"] != false || !hasEmittedRuleID(document, ruleID) {
		t.Fatalf("unexpected emitted outcome %#v", document)
	}
}

func hasEmittedRuleID(value any, ruleID string) bool {
	switch typed := value.(type) {
	case map[string]any:
		for _, key := range []string{"ruleId", "selectedRuleId"} {
			if typed[key] == ruleID {
				return true
			}
		}
		for _, item := range typed {
			if hasEmittedRuleID(item, ruleID) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if hasEmittedRuleID(item, ruleID) {
				return true
			}
		}
	}
	return false
}

func TestCatalogNativeBindingsRejectWrongPairAndCrossMode(t *testing.T) {
	t.Parallel()
	alert := writeCNCFFile(t, "alert-wrong-pair.yml", []byte("api_version: v1\nscheme: http\n"), 0o600)
	code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "prometheus", "--alertmanager-config", alert, "--alertmanager-config-complete", "--alertmanager-config-precedence-resolved", "--from", "2.55.1", "--to", "3.14.0", "--now", "2026-09-12T09:03:00Z", "--format", "json")
	if code != ExitUnknown || stderr != "" || strings.Contains(stdout, `"selectedRuleId":"prometheus.alertmanager-api-v1-removed.3-1"`) {
		t.Fatalf("wrong alert pair=(%d,%q,%q)", code, stdout, stderr)
	}
	bootstrap := writeCNCFFile(t, "envoy-cross-mode.json", []byte(`{"dynamic_resources":{"ads_config":{"api_type":"GRPC","transport_api_version":"V2"}}}`), 0o600)
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "envoy", "--envoy-bootstrap", bootstrap, "--input", bootstrap, "--envoy-bootstrap-selected", "--from", "1.38.4", "--to", "1.39.1", "--now", "2026-09-13T12:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "invalid native CNCF resource check arguments") {
		t.Fatalf("cross mode=(%d,%q,%q)", code, stdout, stderr)
	}
}

func TestCatalogGenericCommandUsesCanonicalInputPair(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/envoyproxy/envoy","version":"1.38.4","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/envoyproxy/envoy","version":"1.39.1","facts":[{"id":"component.envoy.xds_api_major","state":"declared","enumValue":"v2"}]}]}}`)
	path := writeCNCFFile(t, "generic-envoy.json", raw, 0o600)
	tc := catalogRouteCase{"envoy", "1.38.4", "1.39.1", "envoy.xds-v2-unsupported-at-1-39-1-from-1-38-4", "", ExitBlocked}
	item := catalogCheck(t, tc)
	command := substituteCatalogRoute(t, item.GenericDeclarationRoute.Command, path)
	code, stdout, stderr := runCNCFCLI(t, append(command, "--format", "json")...)
	if code != ExitBlocked || stderr != "" {
		t.Fatalf("generic=(%d,%q,%q)", code, stdout, stderr)
	}
	assertCatalogOutcome(t, stdout, tc.ruleID)
	extraPair := append(append([]string(nil), command...), "--from", tc.from, "--to", tc.to, "--format", "json")
	code, stdout, stderr = runCNCFCLI(t, extraPair...)
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "invalid CNCF check arguments") {
		t.Fatalf("extra generic pair=(%d,%q,%q)", code, stdout, stderr)
	}
	for _, arg := range item.GenericDeclarationRoute.Command {
		if arg.Literal == "--from" || arg.Literal == "--to" || arg.Name == "--from" || arg.Name == "--to" {
			t.Fatalf("generic command carries forbidden pair flag: %#v", item.GenericDeclarationRoute.Command)
		}
	}
}
