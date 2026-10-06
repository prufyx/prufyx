// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestFluxNativeResourceCheckSelectedSet(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, raw string
		complete  bool
		want      int
		reason    string
	}{
		{"removed beta API blocks without completeness", `{"apiVersion":"source.toolkit.fluxcd.io/v1beta1","kind":"GitRepository","metadata":{"name":"app"}}`, false, ExitBlocked, "REVIEWED_SOURCE_CONSTRAINT"},
		{"clear selected list passes with completeness", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"GitRepository","metadata":{"name":"app"}}]}`, true, ExitOK, "REVIEWED_SOURCE_CONSTRAINT"},
		{"clear selected list without completeness unknown", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"GitRepository","metadata":{"name":"app"}}]}`, false, ExitUnknown, "RULE_FACT_UNAVAILABLE"},
		{"pagination keeps clear set unknown", `{"apiVersion":"v1","kind":"List","metadata":{"remainingItemCount":1},"items":[{"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"GitRepository","metadata":{"name":"app"}}]}`, true, ExitUnknown, "RULE_FACT_UNAVAILABLE"},
		{"pagination does not hide removed witness", `{"apiVersion":"v1","kind":"List","metadata":{"continue":"next"},"items":[{"apiVersion":"helm.toolkit.fluxcd.io/v2beta1","kind":"HelmRelease","metadata":{"name":"chart"}}]}`, true, ExitBlocked, "REVIEWED_SOURCE_CONSTRAINT"},
		{"api only remains unknown", `{"apiVersion":"source.toolkit.fluxcd.io/v1beta1","metadata":{"name":"app"}}`, true, ExitUnknown, "RULE_FACT_UNAVAILABLE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeCNCFFile(t, "flux.json", []byte(tc.raw), 0o600)
			args := []string{"check", "cncf", "--project", "flux", "--native-resource", path, "--from", "2.6.4", "--to", "2.7.0", "--now", "2026-09-11T21:00:00Z", "--format", "json"}
			if tc.complete {
				args = append(args, "--resource-scope-complete")
			}
			code, stdout, stderr := runCNCFCLI(t, args...)
			if code != tc.want || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || !strings.Contains(stdout, tc.reason) || strings.Contains(stdout, "GitRepository") || strings.Contains(stdout, "HelmRelease") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestFluxNativeResourceCheckRejectsInvalidMixedAndWrongPair(t *testing.T) {
	t.Parallel()
	valid := []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"GitRepository","metadata":{"name":"app"}}]}`)
	path := writeCNCFFile(t, "flux.json", valid, 0o600)
	for _, args := range [][]string{
		{"check", "cncf", "--project", "flux", "--native-resource", path, "--from", "2.6.4", "--to", "2.7.0", "--now", "2026-09-11T21:00:00Z", "--resource-scope-complete", "--nats-config", path},
		{"check", "cncf", "--project", "thanos", "--native-resource", path, "--from", "0.41.0", "--to", "0.42.0", "--now", "2026-09-11T21:00:00Z", "--resource-scope-complete"},
		{"check", "cncf", "--project", "flux", "--native-resource", path, "--native-resource-digest=", "--from", "2.6.4", "--to", "2.7.0", "--now", "2026-09-11T21:00:00Z"},
		{"check", "cncf", "--project", "flux", "--native-resource", filepath.Join(t.TempDir(), "missing.json"), "--from", "2.6.4", "--to", "2.7.0", "--now", "2026-09-11T21:00:00Z"},
	} {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage || stdout != "" || strings.Contains(stderr, path) {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	}
	code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "flux", "--native-resource", path, "--from", "2.7.0", "--to", "2.8.0", "--now", "2026-09-11T21:00:00Z", "--resource-scope-complete", "--format", "json")
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_TRANSITION_NOT_REVIEWED") {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "flux", "--native-resource", path, "--from", "2.6.4", "--to", "2.7.0", "--now", "2026-09-11T21:00:00Z", "--resource-scope-complete=false", "--format", "json")
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_FACT_UNAVAILABLE") {
		t.Fatalf("explicit incomplete scope code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestFluxNativeResourceExternalStoreHasNoFallbackAndReplayPinsRawInput(t *testing.T) {
	t.Parallel()
	fixture := makeExternalCLIFixture(t)
	raw := []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"GitRepository","metadata":{"name":"private-app"}}]}`)
	path := writeCNCFFile(t, "flux.json", raw, 0o600)
	external := []string{
		"check", "cncf", "--project", "flux", "--native-resource", path, "--native-resource-digest", cncfDigest(raw), "--resource-scope-complete",
		"--from", "2.6.4", "--to", "2.7.0", "--knowledge-db", fixture.store, "--knowledge-revision", "1",
		"--knowledge-bundle-digest", fixture.manifest.Revisions[0].BundleDigest,
		"--knowledge-trust-receipt-digest", fixture.receipt1.TrustReceiptDigest, "--format", "json",
	}
	code, original, stderr := runCNCFCLI(t, external...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(original, `"knowledgeOrigin":"external_declared"`) || strings.Contains(original, "private-app") {
		t.Fatalf("external code=%d stdout=%q stderr=%q", code, original, stderr)
	}
	report := writeCNCFFile(t, "flux-report.json", []byte(original), 0o600)
	importExternalCLIRevision2(t, &fixture)
	code, stdout, stderr := runCNCFCLI(t, append(append([]string(nil), external...), "--replay-report", report)...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"mode":"historical"`) || !strings.Contains(stdout, `"status":"MATCH"`) {
		t.Fatalf("replay code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	withoutRawPin := []string{
		"check", "cncf", "--project", "flux", "--native-resource", path, "--resource-scope-complete",
		"--from", "2.6.4", "--to", "2.7.0", "--knowledge-db", fixture.store, "--knowledge-revision", "1",
		"--knowledge-bundle-digest", fixture.manifest.Revisions[0].BundleDigest,
		"--knowledge-trust-receipt-digest", fixture.receipt1.TrustReceiptDigest, "--format", "json", "--replay-report", report,
	}
	code, stdout, stderr = runCNCFCLI(t, withoutRawPin...)
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "external native CNCF replay requires every raw resource digest") {
		t.Fatalf("missing pin code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestFluxNativeResourceLatestCoversFiveOrigins(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"apiVersion":"source.toolkit.fluxcd.io/v1beta2","kind":"GitRepository","metadata":{"name":"app"}}`)
	path := writeCNCFFile(t, "flux-latest.json", raw, 0o600)
	for _, from := range []string{"2.4.0", "2.5.1", "2.6.4", "2.7.5", "2.8.8"} {
		code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "flux", "--native-resource", path, "--from", from, "--to", "2.9.5", "--now", "2026-09-12T10:00:00Z", "--format", "json")
		if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, `"status":"BLOCKED"`) || !strings.Contains(stdout, "component.flux.latest_removed_beta_api_present") {
			t.Fatalf("from=%s code=%d stdout=%q stderr=%q", from, code, stdout, stderr)
		}
	}
	clear := writeCNCFFile(t, "flux-latest-clear.json", []byte(`{"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"GitRepository","metadata":{"name":"app"}}`), 0o600)
	for _, from := range []string{"2.4.0", "2.5.1", "2.6.4", "2.7.5", "2.8.8"} {
		code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "flux", "--native-resource", clear, "--from", from, "--to", "2.9.5", "--resource-scope-complete", "--now", "2026-09-12T10:00:00Z", "--format", "json")
		if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) {
			t.Fatalf("clear from=%s code=%d stdout=%q stderr=%q", from, code, stdout, stderr)
		}
	}
	code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "flux", "--native-resource", clear, "--from", "2.3.0", "--to", "2.9.5", "--resource-scope-complete", "--now", "2026-09-12T10:00:00Z", "--format", "json")
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_TRANSITION_NOT_REVIEWED") {
		t.Fatalf("unsupported origin code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	unknownVersion := writeCNCFFile(t, "flux-latest-unknown-version.json", []byte(`{"apiVersion":"source.toolkit.fluxcd.io/v99","kind":"GitRepository","metadata":{"name":"app"}}`), 0o600)
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "flux", "--native-resource", unknownVersion, "--from", "2.8.8", "--to", "2.9.5", "--resource-scope-complete", "--now", "2026-09-12T10:00:00Z", "--format", "json")
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"status":"UNKNOWN"`) || !strings.Contains(stdout, "RULE_FACT_UNAVAILABLE") || strings.Contains(stdout, `"boolValue":false`) {
		t.Fatalf("unknown API version code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
