// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"strings"
	"testing"
)

func linkerdNativeResource(t *testing.T, spec map[string]any, canary string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "policy.linkerd.io/v1alpha1",
		"kind":       "MeshTLSAuthentication",
		"metadata":   map[string]any{"name": canary, "namespace": canary},
		"spec":       spec,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func linkerdNativeArgs(path, from, to string) []string {
	return []string{
		"check", "cncf", "--project", "linkerd", "--linkerd-resource", path,
		"--from", from, "--to", to,
		"--linkerd-distribution", "official_upstream", "--schema-validation", "required",
		"--now", "2026-09-19T00:00:00Z", "--format", "json",
	}
}

// The native one-step route reuses the already-reviewed PrepareLinkerd
// adapter; this exercises it end to end without a separate prepare step. It
// authors no new compatibility claim: the preparer already existed and
// evaluated the reviewed 2.13.7 -> 2.14.0 pair before this route was wired.
func TestLinkerdNativeCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	for _, test := range []struct {
		name   string
		spec   map[string]any
		status string
		want   int
	}{
		{"empty identities blocks", map[string]any{"identities": []any{}}, "BLOCKED", ExitBlocked},
		{"nonempty identities pass", map[string]any{"identities": []any{"spiffe://synthetic.example/id"}}, "PASS", ExitOK},
		{"neither selector unknown", map[string]any{}, "UNKNOWN", ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := linkerdNativeResource(t, test.spec, "private-linkerd-canary")
			path := writeCNCFFile(t, "linkerd.json", raw, 0o600)
			code, stdout, stderr := runCNCFCLI(t, linkerdNativeArgs(path, "2.13.7", "2.14.0")...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, `"status":"`+test.status+`"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, path) || strings.Contains(stdout, "private-linkerd-canary") || strings.Contains(stdout, "spiffe://") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// The aggregate gate is unchanged by this route: even a scoped PASS keeps the
// whole-upgrade assessment UNKNOWN.
func TestLinkerdNativeCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	raw := linkerdNativeResource(t, map[string]any{"identities": []any{"spiffe://synthetic.example/id"}}, "private-linkerd-canary")
	path := writeCNCFFile(t, "linkerd-pass.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, linkerdNativeArgs(path, "2.13.7", "2.14.0")...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

func TestLinkerdNativeCheck_RejectsMalformedWrongPairAndWrongRoute(t *testing.T) {
	raw := linkerdNativeResource(t, map[string]any{"identities": []any{}}, "private-linkerd-canary")
	path := writeCNCFFile(t, "linkerd.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, linkerdNativeArgs(path, "2.13.7", "2.14.1")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "falco", "--native-resource", "PRIVATE-NOT-READ.json", "--from", "0.40.0", "--to", "0.41.0", "--now", "2026-09-19T00:00:00Z", "--format", "json")
	if code != ExitUsage || strings.Contains(stderr, "PRIVATE-NOT-READ") || strings.Contains(stdout, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestLinkerdNativeCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	raw := linkerdNativeResource(t, map[string]any{"identities": []any{}}, "private-linkerd-canary")
	path := writeCNCFFile(t, "linkerd.json", raw, 0o600)
	other := linkerdNativeResource(t, map[string]any{"identities": []any{"spiffe://synthetic.example/id"}}, "other")
	args := append(linkerdNativeArgs(path, "2.13.7", "2.14.0"), "--linkerd-resource-digest", cncfDigest(other))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "BLOCKED") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestLinkerdPrepareFeedsNativeCheckEquivalently(t *testing.T) {
	raw := linkerdNativeResource(t, map[string]any{"identities": []any{}}, "private-linkerd-canary")
	path := writeCNCFFile(t, "linkerd.json", raw, 0o600)
	code, canonical, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "linkerd", "--input", path, "--from", "2.13.7", "--to", "2.14.0", "--distribution", "official_upstream", "--schema-validation", "required", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.linkerd.mtls_identity_selector_empty") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "linkerd-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "linkerd", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-19T00:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, report, stderr)
	}
	nativeCode, nativeReport, nativeErr := runCNCFCLI(t, linkerdNativeArgs(path, "2.13.7", "2.14.0")...)
	if nativeCode != code || nativeErr != "" || !strings.Contains(nativeReport, `"status":"BLOCKED"`) {
		t.Fatalf("native code=%d stdout=%q stderr=%q", nativeCode, nativeReport, nativeErr)
	}
}
