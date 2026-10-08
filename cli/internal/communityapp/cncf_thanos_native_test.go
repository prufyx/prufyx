// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestThanosNativeWorkloadCheckEvaluatesLiteralTargetArgs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, raw, from, to string
		want                int
		wantReason          string
	}{
		{
			name: "removed receive flag is blocked", from: "0.41.0", to: "0.42.0", want: ExitBlocked, wantReason: "REVIEWED_SOURCE_CONSTRAINT",
			raw: thanosNativeWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","command":["thanos"],"args":["receive","--shipper.ignore-unequal-block-size"]}`),
		},
		{
			name: "literal target absence is scoped pass", from: "0.41.0", to: "0.42.0", want: ExitOK, wantReason: "REVIEWED_SOURCE_CONSTRAINT",
			raw: thanosNativeWorkload(`{"name":"thanos","image":"thanosio/thanos:v0.42.0","command":["thanos"],"args":["store","--log.level=info"]},{"name":"sidecar","image":"example.invalid/sidecar:v1"}`),
		},
		{
			name: "custom image is unknown", from: "0.41.0", to: "0.42.0", want: ExitUnknown, wantReason: "RULE_FACT_UNAVAILABLE",
			raw: thanosNativeWorkload(`{"name":"thanos","image":"example.invalid/custom/thanos:v0.42.0","command":["thanos"],"args":["receive"]}`),
		},
		{
			name: "unreviewed transition is unknown", from: "0.42.0", to: "0.43.0", want: ExitUnknown, wantReason: "RULE_TRANSITION_NOT_REVIEWED",
			raw: thanosNativeWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.43.0","command":["thanos"],"args":["receive"]}`),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeCNCFFile(t, "thanos-workload.json", []byte(tc.raw), 0o600)
			code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "thanos", "--native-resource", path, "--from", tc.from, "--to", tc.to, "--now", "2026-09-11T19:16:43Z", "--format", "json")
			if code != tc.want || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || !strings.Contains(stdout, tc.wantReason) || strings.Contains(stdout, "example.invalid") || strings.Contains(stdout, "shipper.ignore") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestThanosNativeWorkloadRejectsUnlistedLatestExpansionPair(t *testing.T) {
	t.Parallel()
	raw := thanosNativeWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.4","command":["/bin/thanos"],"args":["receive","--log.level=info"]}`)
	path := writeCNCFFile(t, "thanos-workload.json", []byte(raw), 0o600)
	code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "thanos", "--native-resource", path, "--from", "0.41.1", "--to", "0.42.4", "--now", "2026-09-12T07:38:00Z", "--format", "json")
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_TRANSITION_NOT_REVIEWED") || strings.Contains(stdout, "private-receive") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestThanosLatestTargetPairsEndToEnd(t *testing.T) {
	t.Parallel()
	origins := []string{"0.37.2", "0.38.0", "0.39.2", "0.40.1", "0.41.0"}
	for i, from := range origins {
		blockerArgs := `["receive","--shipper.ignore-unequal-block-size"]`
		if i%2 == 1 {
			blockerArgs = `["store","--debug.advertise-compatibility-label=true"]`
		}
		for _, tc := range []struct {
			name, container, reason string
			want                    int
		}{
			{"blocker", `{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.4","command":["/bin/thanos"],"args":` + blockerArgs + `}`, "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
			{"scoped pass", `{"name":"thanos","image":"thanosio/thanos:v0.42.4","args":["receive","--log.level=info"]}`, "REVIEWED_SOURCE_CONSTRAINT", ExitOK},
			{"legacy command is unsupported", `{"name":"thanos","image":"docker.io/thanosio/thanos:v0.42.4","command":["thanos"],"args":["store","--log.level=info"]}`, "RULE_FACT_UNAVAILABLE", ExitUnknown},
		} {
			t.Run(from+"/"+tc.name, func(t *testing.T) {
				path := writeCNCFFile(t, "thanos-latest.json", []byte(thanosNativeWorkload(tc.container)), 0o600)
				code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "thanos", "--native-resource", path, "--from", from, "--to", "0.42.4", "--now", "2026-09-12T07:38:00Z", "--format", "json")
				if code != tc.want || stderr != "" || !strings.Contains(stdout, tc.reason) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, "private-receive") {
					t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
				}
			})
		}
	}
}

func TestThanosNativeWorkloadCheckRejectsMissingAndMixedInputModes(t *testing.T) {
	t.Parallel()
	raw := []byte(thanosNativeWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","command":["thanos"],"args":["receive"]}`))
	path := writeCNCFFile(t, "thanos-workload.json", raw, 0o600)
	for _, args := range [][]string{
		{"check", "cncf", "--project", "thanos", "--native-resource", path, "--from", "0.41.0", "--to", "0.42.0", "--now", "2026-09-11T19:16:43Z", "--image-manifest", path},
		{"check", "cncf", "--project", "thanos", "--native-resource", path, "--from", "0.41.0", "--to", "0.42.0", "--now", "2026-09-11T19:16:43Z", "--knowledge-db", ""},
		{"check", "cncf", "--project", "thanos", "--native-resource", filepath.Join(t.TempDir(), "missing.json"), "--from", "0.41.0", "--to", "0.42.0", "--now", "2026-09-11T19:16:43Z"},
	} {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage || stdout != "" || strings.Contains(stderr, path) {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	}
}

func thanosNativeWorkload(containers string) string {
	return `{"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"private-receive","namespace":"private-observability"},"spec":{"template":{"spec":{"containers":[` + containers + `]}}}}`
}

func TestThanosNativeWorkloadExternalStoreHasNoFallbackAndReplayPinsRawBytes(t *testing.T) {
	t.Parallel()
	fixture := makeExternalCLIFixture(t)
	raw := []byte(thanosNativeWorkload(`{"name":"thanos","image":"quay.io/thanos/thanos:v0.42.0","command":["thanos"],"args":["receive","--log.level=info"]}`))
	resource := writeCNCFFile(t, "thanos-workload.json", raw, 0o600)
	external := []string{
		"check", "cncf", "--project", "thanos", "--native-resource", resource, "--native-resource-digest", cncfDigest(raw),
		"--from", "0.41.0", "--to", "0.42.0", "--knowledge-db", fixture.store, "--knowledge-revision", "1",
		"--knowledge-bundle-digest", fixture.manifest.Revisions[0].BundleDigest,
		"--knowledge-trust-receipt-digest", fixture.receipt1.TrustReceiptDigest, "--format", "json",
	}
	code, original, stderr := runCNCFCLI(t, external...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(original, `"knowledgeOrigin":"external_declared"`) || strings.Contains(original, "private-receive") {
		t.Fatalf("external no-fallback code=%d stdout=%q stderr=%q", code, original, stderr)
	}
	report := writeCNCFFile(t, "thanos-report.json", []byte(original), 0o600)
	importExternalCLIRevision2(t, &fixture)
	code, stdout, stderr := runCNCFCLI(t, append(append([]string(nil), external...), "--replay-report", report)...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"mode":"historical"`) || !strings.Contains(stdout, `"status":"MATCH"`) {
		t.Fatalf("replay code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	withoutRawPin := []string{
		"check", "cncf", "--project", "thanos", "--native-resource", resource,
		"--from", "0.41.0", "--to", "0.42.0", "--knowledge-db", fixture.store, "--knowledge-revision", "1",
		"--knowledge-bundle-digest", fixture.manifest.Revisions[0].BundleDigest,
		"--knowledge-trust-receipt-digest", fixture.receipt1.TrustReceiptDigest, "--format", "json", "--replay-report", report,
	}
	code, stdout, stderr = runCNCFCLI(t, withoutRawPin...)
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "external native CNCF replay requires every raw resource digest") {
		t.Fatalf("missing raw replay pin code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
