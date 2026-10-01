// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"strings"
	"testing"
)

func harborNativeInput(declared bool, argv ...string) []byte {
	encoded, _ := json.Marshal(argv)
	return []byte(`{"apiVersion":"prufyx.io/harbor-installer-argv/v1alpha1","kind":"HarborInstallerArguments","effectiveArgvDeclared":` + map[bool]string{true: "true", false: "false"}[declared] + `,"argv":` + string(encoded) + `}`)
}

func harborNativeArgs(path, from, to string) []string {
	return []string{
		"check", "cncf", "--project", "harbor", "--native-resource", path,
		"--from", from, "--to", to, "--now", "2026-09-18T10:00:00Z", "--format", "json",
	}
}

// The native one-step route reuses the already-reviewed PrepareHarbor
// adapter; this exercises it end to end for the 2.7.0 -> 2.8.0 pair without a
// separate prepare step. A false witness is only ever emitted for a fully
// modeled literal argv covering the complete closed option set, never for an
// unreviewed absence.
func TestHarborNativeCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	for _, test := range []struct {
		name, status, reason string
		declared             bool
		argv                 []string
		want                 int
	}{
		{"removed option blocks", "BLOCKED", "REVIEWED_SOURCE_CONSTRAINT", true, []string{"--with-chartmuseum"}, ExitBlocked},
		{"complete absence passes", "PASS", "REVIEWED_SOURCE_CONSTRAINT", true, []string{"--with-trivy"}, ExitOK},
		{"unmodeled option stays unknown, never a negative-presence pass", "UNKNOWN", "RULE_FACT_UNAVAILABLE", true, []string{"--help"}, ExitUnknown},
		{"declaration not asserted stays unknown", "UNKNOWN", "RULE_FACT_UNAVAILABLE", false, []string{"--with-chartmuseum"}, ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := harborNativeInput(test.declared, test.argv...)
			path := writeCNCFFile(t, "harbor.json", raw, 0o600)
			code, stdout, stderr := runCNCFCLI(t, harborNativeArgs(path, "2.7.0", "2.8.0")...)
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
func TestHarborNativeCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	raw := harborNativeInput(true, "--with-trivy")
	path := writeCNCFFile(t, "harbor.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, harborNativeArgs(path, "2.7.0", "2.8.0")...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

// All five reviewed 2.15.2 target-only origins are routed through the same
// native path.
func TestHarborNativeCheck_AllLatestOriginsAreRouted(t *testing.T) {
	for _, from := range []string{"2.10.3", "2.11.2", "2.12.4", "2.13.5", "2.14.4"} {
		t.Run(from, func(t *testing.T) {
			blocked := writeCNCFFile(t, "harbor-latest-blocked.json", harborNativeInput(true, "--with-chartmuseum"), 0o600)
			code, stdout, stderr := runCNCFCLI(t, harborNativeArgs(blocked, from, "2.15.2")...)
			if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, `"status":"BLOCKED"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
				t.Fatalf("from=%s blocked code=%d stdout=%q stderr=%q", from, code, stdout, stderr)
			}
			clean := writeCNCFFile(t, "harbor-latest-clean.json", harborNativeInput(true, "--with-trivy"), 0o600)
			code, stdout, stderr = runCNCFCLI(t, harborNativeArgs(clean, from, "2.15.2")...)
			if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
				t.Fatalf("from=%s clean code=%d stdout=%q stderr=%q", from, code, stdout, stderr)
			}
		})
	}
}

func TestHarborNativeCheck_RejectsMalformedWrongPairAndWrongRoute(t *testing.T) {
	path := writeCNCFFile(t, "harbor.json", harborNativeInput(true, "--with-chartmuseum"), 0o600)
	code, stdout, stderr := runCNCFCLI(t, harborNativeArgs(path, "2.7.0", "2.8.1")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "falco", "--native-resource", "PRIVATE-NOT-READ.json", "--from", "0.40.0", "--to", "0.41.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || strings.Contains(stderr, "PRIVATE-NOT-READ") || strings.Contains(stdout, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestHarborNativeCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	path := writeCNCFFile(t, "harbor.json", harborNativeInput(true, "--with-chartmuseum"), 0o600)
	args := append(harborNativeArgs(path, "2.7.0", "2.8.0"), "--native-resource-digest", cncfDigest(harborNativeInput(true, "--with-trivy")))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "BLOCKED") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestHarborPrepareFeedsNativeCheckEquivalently(t *testing.T) {
	raw := harborNativeInput(true, "--with-chartmuseum")
	path := writeCNCFFile(t, "harbor.json", raw, 0o600)
	code, canonical, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "harbor", "--input", path, "--from", "2.7.0", "--to", "2.8.0", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.harbor.installer_with_chartmuseum_present") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "harbor-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "harbor", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, report, stderr)
	}
	nativeCode, nativeReport, nativeErr := runCNCFCLI(t, harborNativeArgs(path, "2.7.0", "2.8.0")...)
	if nativeCode != code || nativeErr != "" || !strings.Contains(nativeReport, `"status":"BLOCKED"`) {
		t.Fatalf("native code=%d stdout=%q stderr=%q", nativeCode, nativeReport, nativeErr)
	}
}
