// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

func opencostNativeInput(proposedSource, proposedConfig string) []byte {
	return []byte(`{"schema":"prufyx.io/opencost-cloud-cost-source-selection/v1alpha1","current":{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"provider_derived"},"proposed":{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"` + proposedSource + `","cloudIntegrationConfigSource":"` + proposedConfig + `"}}`)
}

func opencostNativeArgs(path, from, to string) []string {
	return []string{
		"check", "cncf", "--project", "opencost", "--native-resource", path,
		"--from", from, "--to", to, "--now", "2026-09-19T00:00:00Z", "--format", "json",
	}
}

// The native one-step route reuses the already-reviewed
// PrepareOpenCostCloudSource adapter; this exercises it end to end for the
// 1.119.0 -> 1.120.0 pair without a separate prepare step. It authors no new
// compatibility claim: the preparer already existed and evaluated all six
// reviewed rule pairs before this route was wired.
func TestOpenCostNativeCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, source, config, status string
		want                         int
	}{
		{"provider-only target blocks", "provider_derived", "absent", "BLOCKED", ExitBlocked},
		{"declared cloud-integration file passes", "cloud_integration", "present", "PASS", ExitOK},
		{"unresolved target source stays unknown", "api_managed", "unknown", "UNKNOWN", ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := opencostNativeInput(test.source, test.config)
			path := writeCNCFFile(t, "opencost.json", raw, 0o600)
			code, stdout, stderr := runCNCFCLI(t, opencostNativeArgs(path, "1.119.0", "1.120.0")...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, `"status":"`+test.status+`"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// The aggregate gate is unchanged by this route: even a scoped PASS keeps the
// whole-upgrade assessment UNKNOWN.
func TestOpenCostNativeCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	t.Parallel()
	raw := opencostNativeInput("cloud_integration", "present")
	path := writeCNCFFile(t, "opencost.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, opencostNativeArgs(path, "1.119.0", "1.120.0")...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

// All five reviewed 1.121.2 latest-target origins are routed through the
// same native path.
func TestOpenCostNativeCheck_AllLatestOriginsAreRouted(t *testing.T) {
	t.Parallel()
	for _, from := range []string{"1.116.0", "1.117.6", "1.118.0", "1.119.2", "1.120.4"} {
		t.Run(from, func(t *testing.T) {
			blocked := writeCNCFFile(t, "opencost-latest-blocked.json", opencostNativeInput("provider_derived", "absent"), 0o600)
			code, stdout, stderr := runCNCFCLI(t, opencostNativeArgs(blocked, from, "1.121.2")...)
			if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, `"status":"BLOCKED"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
				t.Fatalf("from=%s blocked code=%d stdout=%q stderr=%q", from, code, stdout, stderr)
			}
			clean := writeCNCFFile(t, "opencost-latest-clean.json", opencostNativeInput("cloud_integration", "present"), 0o600)
			code, stdout, stderr = runCNCFCLI(t, opencostNativeArgs(clean, from, "1.121.2")...)
			if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
				t.Fatalf("from=%s clean code=%d stdout=%q stderr=%q", from, code, stdout, stderr)
			}
		})
	}
}

func TestOpenCostNativeCheck_RejectsMalformedWrongPairAndWrongRoute(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "opencost.json", opencostNativeInput("cloud_integration", "present"), 0o600)
	code, stdout, stderr := runCNCFCLI(t, opencostNativeArgs(path, "1.119.0", "1.120.1")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "falco", "--native-resource", "PRIVATE-NOT-READ.json", "--from", "0.40.0", "--to", "0.41.0", "--now", "2026-09-19T00:00:00Z", "--format", "json")
	if code != ExitUsage || strings.Contains(stderr, "PRIVATE-NOT-READ") || strings.Contains(stdout, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestOpenCostNativeCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "opencost.json", opencostNativeInput("provider_derived", "absent"), 0o600)
	args := append(opencostNativeArgs(path, "1.119.0", "1.120.0"), "--native-resource-digest", cncfDigest(opencostNativeInput("cloud_integration", "present")))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "BLOCKED") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestOpenCostPrepareFeedsNativeCheckEquivalently(t *testing.T) {
	t.Parallel()
	raw := opencostNativeInput("provider_derived", "absent")
	path := writeCNCFFile(t, "opencost.json", raw, 0o600)
	code, canonical, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "opencost", "--input", path, "--from", "1.119.0", "--to", "1.120.0", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.opencost.target_cloud_integration_source_selected_and_declared_present") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "opencost-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "opencost", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-19T00:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, report, stderr)
	}
	nativeCode, nativeReport, nativeErr := runCNCFCLI(t, opencostNativeArgs(path, "1.119.0", "1.120.0")...)
	if nativeCode != code || nativeErr != "" || !strings.Contains(nativeReport, `"status":"BLOCKED"`) {
		t.Fatalf("native code=%d stdout=%q stderr=%q", nativeCode, nativeReport, nativeErr)
	}
}
