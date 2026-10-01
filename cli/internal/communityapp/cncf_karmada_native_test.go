// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"strings"
	"testing"
)

func karmadaNativeResource(t *testing.T, kind, mode, canary string) []byte {
	t.Helper()
	spec := map[string]any{"failover": map[string]any{"application": map[string]any{}}}
	if mode != "" {
		spec["failover"].(map[string]any)["application"].(map[string]any)["purgeMode"] = mode
	}
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "policy.karmada.io/v1alpha1", "kind": kind,
		"metadata": map[string]any{"name": canary, "labels": map[string]any{"private": canary}},
		"spec":     spec,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func karmadaNativeArgs(path, from, to string) []string {
	return []string{
		"check", "cncf", "--project", "karmada", "--karmada-resource", path,
		"--from", from, "--to", to,
		"--karmada-distribution", "official_upstream", "--target-policy-crd-admission", "required",
		"--now", "2026-09-19T00:00:00Z", "--format", "json",
	}
}

// The native one-step route reuses the already-reviewed PrepareKarmada
// adapter; this exercises it end to end without a separate prepare step. It
// authors no new compatibility claim: the preparer already existed and
// evaluated the reviewed 1.18.3 -> 1.19.0 pair before this route was wired.
// Karmada can witness a legacy purgeMode blocker but never proves aggregate
// absence, so it never emits a PASS.
func TestKarmadaNativeCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	for _, test := range []struct {
		name, kind, mode, status string
		want                     int
	}{
		{"policy immediately blocks", "PropagationPolicy", "Immediately", "BLOCKED", ExitBlocked},
		{"cluster graciously blocks", "ClusterPropagationPolicy", "Graciously", "BLOCKED", ExitBlocked},
		{"unrecognized value unknown", "PropagationPolicy", "Directly", "UNKNOWN", ExitUnknown},
		{"missing purge mode unknown", "PropagationPolicy", "", "UNKNOWN", ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := karmadaNativeResource(t, test.kind, test.mode, "private-karmada-canary")
			path := writeCNCFFile(t, "karmada.json", raw, 0o600)
			code, stdout, stderr := runCNCFCLI(t, karmadaNativeArgs(path, "1.18.3", "1.19.0")...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, `"status":"`+test.status+`"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, path) || strings.Contains(stdout, "private-karmada-canary") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// The aggregate gate is unchanged by this route: a scoped BLOCKED keeps the
// whole-upgrade assessment UNKNOWN.
func TestKarmadaNativeCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	raw := karmadaNativeResource(t, "PropagationPolicy", "Immediately", "private-karmada-canary")
	path := writeCNCFFile(t, "karmada-blocked.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, karmadaNativeArgs(path, "1.18.3", "1.19.0")...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, `"status":"BLOCKED"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

func TestKarmadaNativeCheck_RejectsMalformedWrongPairAndWrongRoute(t *testing.T) {
	raw := karmadaNativeResource(t, "PropagationPolicy", "", "private-karmada-canary")
	path := writeCNCFFile(t, "karmada.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, karmadaNativeArgs(path, "1.18.3", "1.19.1")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "falco", "--native-resource", "PRIVATE-NOT-READ.json", "--from", "0.40.0", "--to", "0.41.0", "--now", "2026-09-19T00:00:00Z", "--format", "json")
	if code != ExitUsage || strings.Contains(stderr, "PRIVATE-NOT-READ") || strings.Contains(stdout, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestKarmadaNativeCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	raw := karmadaNativeResource(t, "PropagationPolicy", "Immediately", "private-karmada-canary")
	path := writeCNCFFile(t, "karmada.json", raw, 0o600)
	other := karmadaNativeResource(t, "PropagationPolicy", "", "other")
	args := append(karmadaNativeArgs(path, "1.18.3", "1.19.0"), "--karmada-resource-digest", cncfDigest(other))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "BLOCKED") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestKarmadaPrepareFeedsNativeCheckEquivalently(t *testing.T) {
	raw := karmadaNativeResource(t, "PropagationPolicy", "Immediately", "private-karmada-canary")
	path := writeCNCFFile(t, "karmada.json", raw, 0o600)
	code, canonical, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "karmada", "--input", path, "--from", "1.18.3", "--to", "1.19.0", "--distribution", "official_upstream", "--target-policy-crd-admission", "required", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.karmada.removed_application_purge_mode_present") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "karmada-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "karmada", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-19T00:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, report, stderr)
	}
	nativeCode, nativeReport, nativeErr := runCNCFCLI(t, karmadaNativeArgs(path, "1.18.3", "1.19.0")...)
	if nativeCode != code || nativeErr != "" || !strings.Contains(nativeReport, `"status":"BLOCKED"`) {
		t.Fatalf("native code=%d stdout=%q stderr=%q", nativeCode, nativeReport, nativeErr)
	}
}
