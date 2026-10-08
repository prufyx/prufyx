// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestNATSNativeConfigChecksSelectedLiteralNames(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, raw, from, to string
		want                int
		wantReason          string
	}{
		{"selected cluster name with space blocks", `{"cluster":{"name":"edge cluster"}}`, "2.10.0", "2.11.0", ExitBlocked, "REVIEWED_SOURCE_CONSTRAINT"},
		{"all selected names without spaces pass", `{"server_name":"edge","gateway":{"name":"edge-gateway"}}`, "2.10.0", "2.11.0", ExitOK, "REVIEWED_SOURCE_CONSTRAINT"},
		{"include stays unknown", `{"include":"private.conf","server_name":"edge"}`, "2.10.0", "2.11.0", ExitUnknown, "RULE_FACT_UNAVAILABLE"},
		{"wrong pair stays unknown", `{"server_name":"edge node"}`, "2.11.0", "2.12.0", ExitUnknown, "RULE_TRANSITION_NOT_REVIEWED"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeCNCFFile(t, "nats.json", []byte(tc.raw), 0o600)
			code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "nats", "--nats-config", path, "--from", tc.from, "--to", tc.to, "--now", "2026-09-11T21:00:00Z", "--format", "json")
			if code != tc.want || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || !strings.Contains(stdout, tc.wantReason) || strings.Contains(stdout, "edge cluster") || strings.Contains(stdout, "private.conf") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestNATSLatestNativeConfigAllExactOrigins(t *testing.T) {
	t.Parallel()
	for _, from := range []string{"2.12.15", "2.11.17", "2.10.29", "2.9.25", "2.8.4"} {
		for _, tc := range []struct {
			name, raw, status string
			want              int
		}{
			{"ascii-space-blocked", `{"cluster":{"name":"edge cluster"}}`, "BLOCKED", ExitBlocked},
			{"literal-name-pass", `{"server_name":"edge-west","gateway":{"name":"edge-gateway"}}`, "PASS", ExitOK},
			{"include-unknown", `{"include":"private.conf","server_name":"edge-west"}`, "UNKNOWN", ExitUnknown},
			{"unicode-escape-unknown", `{"server_name":"edge\u0020west"}`, "UNKNOWN", ExitUnknown},
			{"dotted-key-unknown", `{"cluster.name":"edge-west"}`, "UNKNOWN", ExitUnknown},
			{"variable-unknown", `{"server_name":"$NAME"}`, "UNKNOWN", ExitUnknown},
		} {
			t.Run(from+"/"+tc.name, func(t *testing.T) {
				path := writeCNCFFile(t, "nats-latest.json", []byte(tc.raw), 0o600)
				code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "nats", "--nats-config", path, "--from", from, "--to", "2.14.6", "--now", "2026-09-12T08:47:00Z", "--format", "json")
				if code != tc.want || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, "edge cluster") || strings.Contains(stdout, "private.conf") {
					t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
				}
				if tc.status != "UNKNOWN" && !strings.Contains(stdout, `"status":"`+tc.status+`"`) {
					t.Fatalf("missing status %s: %s", tc.status, stdout)
				}
			})
		}
	}
	for _, tc := range []struct{ from, to string }{{"2.12.14", "2.14.6"}, {"2.12.15", "2.14.5"}} {
		path := writeCNCFFile(t, "nats-latest-wrong-pair.json", []byte(`{"server_name":"edge node"}`), 0o600)
		code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "nats", "--nats-config", path, "--from", tc.from, "--to", tc.to, "--now", "2026-09-12T08:47:00Z", "--format", "json")
		if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_TRANSITION_NOT_REVIEWED") || strings.Contains(stdout, "edge node") {
			t.Fatalf("pair=%s/%s code=%d stdout=%q stderr=%q", tc.from, tc.to, code, stdout, stderr)
		}
	}
}

func TestNATSNativeConfigRejectsInvalidAndMixedModes(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"server_name":"edge"}`)
	path := writeCNCFFile(t, "nats.json", raw, 0o600)
	for _, args := range [][]string{
		{"check", "cncf", "--project", "nats", "--nats-config", path, "--from", "2.10.0", "--to", "2.11.0", "--now", "2026-09-11T21:00:00Z", "--native-resource", path},
		{"check", "cncf", "--project", "nats", "--nats-config", path, "--from", "2.10.0", "--to", "2.11.0", "--now", "2026-09-11T21:00:00Z", "--nats-config-digest", "sha256:" + strings.Repeat("0", 64)},
		{"check", "cncf", "--project", "nats", "--nats-config", filepath.Join(t.TempDir(), "missing.json"), "--from", "2.10.0", "--to", "2.11.0", "--now", "2026-09-11T21:00:00Z"},
		{"check", "cncf", "--project", "thanos", "--nats-config", path, "--from", "0.41.0", "--to", "0.42.0", "--now", "2026-09-11T21:00:00Z"},
	} {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if (code != ExitUsage && code != ExitIntegrity) || stdout != "" || strings.Contains(stderr, path) {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	}
}

func TestNATSNativeConfigExternalStoreHasNoFallbackAndReplayPinsRawInput(t *testing.T) {
	t.Parallel()
	fixture := makeExternalCLIFixture(t)
	raw := []byte(`{"server_name":"edge"}`)
	path := writeCNCFFile(t, "nats.json", raw, 0o600)
	external := []string{
		"check", "cncf", "--project", "nats", "--nats-config", path, "--nats-config-digest", cncfDigest(raw),
		"--from", "2.10.0", "--to", "2.11.0", "--knowledge-db", fixture.store, "--knowledge-revision", "1",
		"--knowledge-bundle-digest", fixture.manifest.Revisions[0].BundleDigest,
		"--knowledge-trust-receipt-digest", fixture.receipt1.TrustReceiptDigest, "--format", "json",
	}
	code, original, stderr := runCNCFCLI(t, external...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(original, `"knowledgeOrigin":"external_declared"`) || strings.Contains(original, `"server_name"`) {
		t.Fatalf("external no-fallback code=%d stdout=%q stderr=%q", code, original, stderr)
	}
	report := writeCNCFFile(t, "nats-report.json", []byte(original), 0o600)
	importExternalCLIRevision2(t, &fixture)
	code, stdout, stderr := runCNCFCLI(t, append(append([]string(nil), external...), "--replay-report", report)...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"mode":"historical"`) || !strings.Contains(stdout, `"status":"MATCH"`) {
		t.Fatalf("replay code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	withoutRawPin := append([]string{}, external[:6]...)
	withoutRawPin = append(withoutRawPin, external[8:]...)
	withoutRawPin = append(withoutRawPin, "--replay-report", report)
	code, stdout, stderr = runCNCFCLI(t, withoutRawPin...)
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "external native CNCF replay requires every raw resource digest") {
		t.Fatalf("missing raw replay pin code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
