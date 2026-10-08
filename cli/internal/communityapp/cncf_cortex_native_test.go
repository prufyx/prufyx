// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCortexNativeWorkloadCheckEvaluatesLiteralTargetArgs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, raw, from, to string
		want                int
		wantReason          string
	}{
		{
			name: "removed target option is blocked", from: "1.17.2", to: "1.21.1", want: ExitBlocked, wantReason: "REVIEWED_SOURCE_CONSTRAINT",
			raw: cortexNativeWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["/bin/cortex"],"args":["--querier.at-modifier-enabled=true"]}`),
		},
		{
			name: "literal target absence is scoped pass", from: "1.17.2", to: "1.21.1", want: ExitOK, wantReason: "REVIEWED_SOURCE_CONSTRAINT",
			raw: cortexNativeWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["/bin/cortex"],"args":["--querier.max-samples=1000"]},{"name":"sidecar","image":"example.invalid/sidecar:v1"}`),
		},
		{
			name: "source-derived default entrypoint absence is scoped pass", from: "1.17.2", to: "1.21.1", want: ExitOK, wantReason: "REVIEWED_SOURCE_CONSTRAINT",
			raw: cortexNativeWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","args":[]}`),
		},
		{
			name: "null command remains unknown", from: "1.17.2", to: "1.21.1", want: ExitUnknown, wantReason: "RULE_APPLICABILITY_FACT_UNAVAILABLE",
			raw: cortexNativeWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":null,"args":[]}`),
		},
		{
			name: "empty command remains unknown", from: "1.17.2", to: "1.21.1", want: ExitUnknown, wantReason: "RULE_APPLICABILITY_FACT_UNAVAILABLE",
			raw: cortexNativeWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":[],"args":[]}`),
		},
		{
			name: "unreviewed transition is unknown", from: "1.21.1", to: "1.22.0", want: ExitUnknown, wantReason: "RULE_TRANSITION_NOT_REVIEWED",
			raw: cortexNativeWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.22.0","command":["/bin/cortex"],"args":[]}`),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeCNCFFile(t, "cortex-workload.json", []byte(tc.raw), 0o600)
			code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "cortex", "--native-resource", path, "--from", tc.from, "--to", tc.to, "--now", "2026-09-11T23:00:00Z", "--format", "json")
			if code != tc.want || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || !strings.Contains(stdout, tc.wantReason) || strings.Contains(stdout, "example.invalid") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestCortexNativeWorkloadRejectsUnlistedLatestExpansionPair(t *testing.T) {
	t.Parallel()
	raw := cortexNativeWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["/bin/cortex"],"args":["--target=all"]}`)
	path := writeCNCFFile(t, "cortex-workload.json", []byte(raw), 0o600)
	code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "cortex", "--native-resource", path, "--from", "1.20.2", "--to", "1.21.1", "--now", "2026-09-12T07:38:00Z", "--format", "json")
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_TRANSITION_NOT_REVIEWED") || strings.Contains(stdout, "private-cortex") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCortexLatestTargetPairsEndToEnd(t *testing.T) {
	t.Parallel()
	for _, from := range []string{"1.16.1", "1.17.2", "1.18.1", "1.19.1", "1.20.1"} {
		for _, tc := range []struct {
			name, container, reason string
			want                    int
		}{
			{"blocker", `{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","args":["--querier.at-modifier-enabled=true"]}`, "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
			{"scoped pass", `{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["/bin/cortex"],"args":["--target=all"]}`, "REVIEWED_SOURCE_CONSTRAINT", ExitOK},
			{"unsupported image", `{"name":"cortex","image":"registry.example/cortex:v1.21.1","command":["/bin/cortex"],"args":["--target=all"]}`, "RULE_APPLICABILITY_FACT_UNAVAILABLE", ExitUnknown},
		} {
			t.Run(from+"/"+tc.name, func(t *testing.T) {
				path := writeCNCFFile(t, "cortex-latest.json", []byte(cortexNativeWorkload(tc.container)), 0o600)
				code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "cortex", "--native-resource", path, "--from", from, "--to", "1.21.1", "--now", "2026-09-12T07:38:00Z", "--format", "json")
				if code != tc.want || stderr != "" || !strings.Contains(stdout, tc.reason) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, "private-cortex") {
					t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
				}
			})
		}
	}
}

func TestCortexNativeWorkloadRejectsMixedOrMissingInput(t *testing.T) {
	t.Parallel()
	raw := []byte(cortexNativeWorkload(`{"name":"cortex","image":"quay.io/cortexproject/cortex:v1.21.1","command":["/bin/cortex"],"args":[]}`))
	path := writeCNCFFile(t, "cortex-workload.json", raw, 0o600)
	for _, args := range [][]string{
		{"check", "cncf", "--project", "cortex", "--native-resource", path, "--from", "1.17.2", "--to", "1.21.1", "--now", "2026-09-11T23:00:00Z", "--image-manifest", path},
		{"check", "cncf", "--project", "cortex", "--native-resource", filepath.Join(t.TempDir(), "missing.json"), "--from", "1.17.2", "--to", "1.21.1", "--now", "2026-09-11T23:00:00Z"},
	} {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage || stdout != "" || strings.Contains(stderr, path) {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	}
}

func cortexNativeWorkload(containers string) string {
	return `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"private-cortex","namespace":"private-observability"},"spec":{"template":{"spec":{"containers":[` + containers + `]}}}}`
}
