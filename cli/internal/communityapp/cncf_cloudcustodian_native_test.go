// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

func cloudCustodianNativeArgs(path, from, to string) []string {
	return []string{
		"check", "cncf", "--project", "cloud-custodian", "--native-resource", path,
		"--from", from, "--to", to, "--now", "2026-09-19T00:00:00Z", "--format", "json",
	}
}

// The native one-step route reuses the already-reviewed PrepareCloudCustodian
// adapter; this exercises it end to end without a separate prepare step. It
// authors no new compatibility claim: the preparer already existed and
// evaluated all six reviewed rule pairs before this route was wired.
func TestCloudCustodianNativeCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	for _, test := range []struct {
		name, raw, status string
		want              int
	}{
		{"json-diff filter blocks", `{"policies":[{"name":"private-policy","resource":"iam-access-key","filters":[{"type":"json-diff","selector":"previous"}]}]}`, "BLOCKED", ExitBlocked},
		{"empty filters pass", `{"policies":[{"name":"private-policy","resource":"iam-access-key","filters":[]}]}`, "PASS", ExitOK},
		{"other filter stays unknown", `{"policies":[{"name":"private-policy","resource":"iam-access-key","filters":[{"type":"value","key":"tag:team","value":"private"}]}]}`, "UNKNOWN", ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeCNCFFile(t, "cloud-custodian.json", []byte(test.raw), 0o600)
			code, stdout, stderr := runCNCFCLI(t, cloudCustodianNativeArgs(path, "0.9.50", "0.9.51")...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, `"status":"`+test.status+`"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, path) || strings.Contains(stdout, "private-policy") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// The aggregate gate is unchanged by this route: even a scoped PASS keeps the
// whole-upgrade assessment UNKNOWN.
func TestCloudCustodianNativeCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	raw := `{"policies":[{"name":"private-policy","resource":"iam-access-key","filters":[]}]}`
	path := writeCNCFFile(t, "cloud-custodian-clear.json", []byte(raw), 0o600)
	code, stdout, stderr := runCNCFCLI(t, cloudCustodianNativeArgs(path, "0.9.50", "0.9.51")...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

// All five reviewed 0.9.52 latest-target origins are routed through the same
// native path.
func TestCloudCustodianNativeCheck_AllLatestOriginsAreRouted(t *testing.T) {
	for _, from := range []string{"0.9.47", "0.9.48", "0.9.49", "0.9.50", "0.9.51"} {
		t.Run(from, func(t *testing.T) {
			blocked := writeCNCFFile(t, "cloud-custodian-latest-blocked.json", []byte(`{"policies":[{"name":"private-policy","resource":"iam-access-key","filters":[{"type":"json-diff","selector":"previous"}]}]}`), 0o600)
			code, stdout, stderr := runCNCFCLI(t, cloudCustodianNativeArgs(blocked, from, "0.9.52")...)
			if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, `"status":"BLOCKED"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
				t.Fatalf("from=%s blocked code=%d stdout=%q stderr=%q", from, code, stdout, stderr)
			}
			clean := writeCNCFFile(t, "cloud-custodian-latest-clean.json", []byte(`{"policies":[{"name":"private-policy","resource":"iam-access-key","filters":[]}]}`), 0o600)
			code, stdout, stderr = runCNCFCLI(t, cloudCustodianNativeArgs(clean, from, "0.9.52")...)
			if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
				t.Fatalf("from=%s clean code=%d stdout=%q stderr=%q", from, code, stdout, stderr)
			}
		})
	}
}

func TestCloudCustodianNativeCheck_RejectsMalformedWrongPairAndWrongRoute(t *testing.T) {
	path := writeCNCFFile(t, "cloud-custodian.json", []byte(`{"policies":[{"name":"private-policy","resource":"iam-access-key","filters":[]}]}`), 0o600)
	code, stdout, stderr := runCNCFCLI(t, cloudCustodianNativeArgs(path, "0.9.50", "0.9.53")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "falco", "--native-resource", "PRIVATE-NOT-READ.json", "--from", "0.40.0", "--to", "0.41.0", "--now", "2026-09-19T00:00:00Z", "--format", "json")
	if code != ExitUsage || strings.Contains(stderr, "PRIVATE-NOT-READ") || strings.Contains(stdout, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCloudCustodianNativeCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	path := writeCNCFFile(t, "cloud-custodian.json", []byte(`{"policies":[{"name":"private-policy","resource":"iam-access-key","filters":[{"type":"json-diff","selector":"previous"}]}]}`), 0o600)
	args := append(cloudCustodianNativeArgs(path, "0.9.50", "0.9.51"), "--native-resource-digest", cncfDigest([]byte(`{"policies":[{"name":"private-policy","resource":"iam-access-key","filters":[]}]}`)))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "BLOCKED") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCloudCustodianPrepareFeedsNativeCheckEquivalently(t *testing.T) {
	raw := `{"policies":[{"name":"private-policy","resource":"iam-access-key","filters":[{"type":"json-diff","selector":"previous"}]}]}`
	path := writeCNCFFile(t, "cloud-custodian.json", []byte(raw), 0o600)
	code, canonical, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "cloud-custodian", "--input", path, "--from", "0.9.50", "--to", "0.9.51", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.cloud_custodian.iam_access_key_json_diff_present") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "cloud-custodian-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "cloud-custodian", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-19T00:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, report, stderr)
	}
	nativeCode, nativeReport, nativeErr := runCNCFCLI(t, cloudCustodianNativeArgs(path, "0.9.50", "0.9.51")...)
	if nativeCode != code || nativeErr != "" || !strings.Contains(nativeReport, `"status":"BLOCKED"`) {
		t.Fatalf("native code=%d stdout=%q stderr=%q", nativeCode, nativeReport, nativeErr)
	}
}
