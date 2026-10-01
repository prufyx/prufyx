// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

const falcoCleanArgvInput = `["falco","-c","/etc/private-falco.yaml","--unbuffered"]`
const falcoRemovedArgvInput = `["falco","-c","/etc/private-falco.yaml","--snaplen","256"]`

func falcoNativeArgs(path, to string) []string {
	return []string{
		"check", "cncf", "--project", "falco", "--falco-argv", path,
		"--falco-distribution", "official_upstream",
		"--from", "0.40.0", "--to", to, "--now", "2026-09-18T10:00:00Z", "--format", "json",
	}
}

func TestFalcoNativeArgvCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	for _, test := range []struct {
		name, raw, reason string
		want              int
	}{
		{"removed long spelling blocks", falcoRemovedArgvInput, "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
		{"removed short spelling blocks", `["falco","-A"]`, "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
		{"clean argv passes", falcoCleanArgvInput, "REVIEWED_SOURCE_CONSTRAINT", ExitOK},
		{"other surface stays unknown", `["falcoctl","install","-A"]`, "RULE_APPLICABILITY_NOT_MATCHED", ExitUnknown},
		{"clustered short token stays unknown", `["falco","-Ab"]`, "RULE_FACT_UNAVAILABLE", ExitUnknown},
		{"option delimiter stays unknown", `["falco","--","-A"]`, "RULE_FACT_UNAVAILABLE", ExitUnknown},
		{"unresolved rendering stays unknown", `["falco","{{ .Values.extraArgs }}"]`, "RULE_APPLICABILITY_FACT_UNAVAILABLE", ExitUnknown},
		{"unparseable shape stays unknown", `{"command":["falco"]}`, "RULE_APPLICABILITY_FACT_UNAVAILABLE", ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeCNCFFile(t, "falco.json", []byte(test.raw), 0o600)
			code, stdout, stderr := runCNCFCLI(t, falcoNativeArgs(path, "0.41.0")...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, test.reason) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, "private-") || strings.Contains(stdout, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// The aggregate gate is unchanged by this route: even a scoped PASS keeps the
// whole-upgrade assessment UNKNOWN.
func TestFalcoNativeArgvCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	path := writeCNCFFile(t, "falco.json", []byte(falcoCleanArgvInput), 0o600)
	code, stdout, stderr := runCNCFCLI(t, falcoNativeArgs(path, "0.41.0")...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

func TestFalcoNativeArgvCheck_BothReviewedTargetsAreRouted(t *testing.T) {
	blocked := writeCNCFFile(t, "falco-blocked.json", []byte(falcoRemovedArgvInput), 0o600)
	clean := writeCNCFFile(t, "falco-clean.json", []byte(falcoCleanArgvInput), 0o600)
	for _, to := range []string{"0.41.0", "0.42.0"} {
		code, stdout, stderr := runCNCFCLI(t, falcoNativeArgs(blocked, to)...)
		if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, "falco.deprecated-cli-flags-removed.0-40-to-0-4") || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
			t.Fatalf("to=%s code=%d stdout=%q stderr=%q", to, code, stdout, stderr)
		}
		code, stdout, stderr = runCNCFCLI(t, falcoNativeArgs(clean, to)...)
		if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
			t.Fatalf("to=%s code=%d stdout=%q stderr=%q", to, code, stdout, stderr)
		}
	}
}

func TestFalcoNativeArgvCheck_CustomBuildAndMissingDistributionStayUnknown(t *testing.T) {
	path := writeCNCFFile(t, "falco.json", []byte(falcoRemovedArgvInput), 0o600)
	for _, test := range []struct {
		name string
		args []string
	}{
		{"custom build", []string{
			"check", "cncf", "--project", "falco", "--falco-argv", path,
			"--falco-distribution", "custom_build",
			"--from", "0.40.0", "--to", "0.41.0", "--now", "2026-09-18T10:00:00Z", "--format", "json",
		}},
		{"distribution not declared", []string{
			"check", "cncf", "--project", "falco", "--falco-argv", path,
			"--from", "0.40.0", "--to", "0.41.0", "--now", "2026-09-18T10:00:00Z", "--format", "json",
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runCNCFCLI(t, test.args...)
			if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_APPLICABILITY") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			if strings.Contains(stdout, `"status":"PASS"`) {
				t.Fatalf("unreviewed build produced a PASS: %q", stdout)
			}
		})
	}
}

func TestFalcoNativeArgvCheck_RejectsMalformedWrongPairAndWrongRoute(t *testing.T) {
	path := writeCNCFFile(t, "falco.json", []byte(falcoRemovedArgvInput), 0o600)
	args := falcoNativeArgs(path, "0.43.0")
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_TRANSITION_NOT_REVIEWED") {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "falco", "--falco-argv", path, "--falco-distribution", "vendor_build", "--from", "0.40.0", "--to", "0.41.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, path) {
		t.Fatalf("bad distribution code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "kubernetes", "--falco-argv", "PRIVATE-NOT-READ.json", "--from", "1.31.0", "--to", "1.32.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "falco", "--falco-argv", path, "--native-resource", path, "--falco-distribution", "official_upstream", "--from", "0.40.0", "--to", "0.41.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" {
		t.Fatalf("cross-mode selector code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestFalcoNativeArgvCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	path := writeCNCFFile(t, "falco.json", []byte(falcoRemovedArgvInput), 0o600)
	args := append(falcoNativeArgs(path, "0.41.0"), "--falco-argv-digest", cncfDigest([]byte(falcoCleanArgvInput)))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "BLOCKED") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestFalcoPrepareArgvFeedsCheck(t *testing.T) {
	raw := []byte(falcoRemovedArgvInput)
	path := writeCNCFFile(t, "falco.json", raw, 0o600)
	code, canonical, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "falco", "--falco-argv", path, "--falco-argv-digest", cncfDigest(raw), "--from", "0.40.0", "--to", "0.41.0", "--falco-distribution", "official_upstream", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.falco.removed_040_cli_flags_present") || strings.Contains(canonical, "private-") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "falco-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "falco", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, report, stderr)
	}
}
