// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"strings"
	"testing"
)

func ciliumPolicyNativeResource(t *testing.T, requires []any) []byte {
	t.Helper()
	value := map[string]any{
		"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
		"metadata": map[string]any{"name": "private-cilium-policy"},
		"spec":     map[string]any{"ingress": []any{map[string]any{"fromRequires": requires}}},
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func ciliumPolicyNativeArgs(path, from, to string, completeSet bool) []string {
	args := []string{
		"check", "cncf", "--project", "cilium", "--cilium-policy", path,
		"--from", from, "--to", to,
	}
	if completeSet {
		args = append(args, "--complete-cnp-ccnp-set", "true")
	}
	return append(args, "--now", "2026-09-19T00:00:00Z", "--format", "json")
}

// The native one-step route reuses the already-reviewed PrepareCilium
// adapter; this exercises it end to end without a separate prepare step for
// both reviewed pairs. It authors no new compatibility claim: the preparer
// already existed and evaluated both pairs before this route was wired.
func TestCiliumPolicyNativeCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		from, to    string
		requires    []any
		completeSet bool
		status      string
		want        int
	}{
		{"legacy witness blocks", "1.18.6", "1.19.0", []any{map[string]any{}}, false, "BLOCKED", ExitBlocked},
		{"target CRD witness blocks", "1.18.13", "1.19.7", []any{map[string]any{}}, false, "BLOCKED", ExitBlocked},
		{"target complete clean set passes", "1.18.13", "1.19.7", []any{}, true, "PASS", ExitOK},
		{"target incomplete clean set unknown", "1.18.13", "1.19.7", []any{}, false, "UNKNOWN", ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := ciliumPolicyNativeResource(t, test.requires)
			path := writeCNCFFile(t, "cilium-policy.json", raw, 0o600)
			code, stdout, stderr := runCNCFCLI(t, ciliumPolicyNativeArgs(path, test.from, test.to, test.completeSet)...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, `"status":"`+test.status+`"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, path) || strings.Contains(stdout, "private-cilium-policy") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// The aggregate gate is unchanged by this route: even a scoped PASS keeps the
// whole-upgrade assessment UNKNOWN.
func TestCiliumPolicyNativeCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	t.Parallel()
	raw := ciliumPolicyNativeResource(t, []any{})
	path := writeCNCFFile(t, "cilium-policy-clean.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, ciliumPolicyNativeArgs(path, "1.18.13", "1.19.7", true)...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

func TestCiliumPolicyNativeCheck_RejectsMalformedWrongPairAndWrongRoute(t *testing.T) {
	t.Parallel()
	raw := ciliumPolicyNativeResource(t, []any{})
	path := writeCNCFFile(t, "cilium-policy.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, ciliumPolicyNativeArgs(path, "1.18.6", "1.19.1", false)...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "falco", "--native-resource", "PRIVATE-NOT-READ.json", "--from", "0.40.0", "--to", "0.41.0", "--now", "2026-09-19T00:00:00Z", "--format", "json")
	if code != ExitUsage || strings.Contains(stderr, "PRIVATE-NOT-READ") || strings.Contains(stdout, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCiliumPolicyNativeCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	t.Parallel()
	raw := ciliumPolicyNativeResource(t, []any{map[string]any{}})
	path := writeCNCFFile(t, "cilium-policy.json", raw, 0o600)
	other := ciliumPolicyNativeResource(t, []any{})
	args := append(ciliumPolicyNativeArgs(path, "1.18.6", "1.19.0", false), "--cilium-policy-digest", cncfDigest(other))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "BLOCKED") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCiliumPolicyPrepareFeedsNativeCheckEquivalently(t *testing.T) {
	t.Parallel()
	raw := ciliumPolicyNativeResource(t, []any{map[string]any{}})
	path := writeCNCFFile(t, "cilium-policy.json", raw, 0o600)
	code, canonical, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "cilium", "--input", path, "--from", "1.18.6", "--to", "1.19.0", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.cilium.nonempty_requires_fields") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "cilium-policy-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "cilium", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-19T00:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, report, stderr)
	}
	nativeCode, nativeReport, nativeErr := runCNCFCLI(t, ciliumPolicyNativeArgs(path, "1.18.6", "1.19.0", false)...)
	if nativeCode != code || nativeErr != "" || !strings.Contains(nativeReport, `"status":"BLOCKED"`) {
		t.Fatalf("native code=%d stdout=%q stderr=%q", nativeCode, nativeReport, nativeErr)
	}
}
