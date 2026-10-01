// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

const spireCleanArgvInput = `["spire-server","entry","create","-spiffeID","spiffe://private-trust/workload","-selector","unix:uid:1000"]`
const spireRemovedArgvInput = `["spire-server","entry","create","-spiffeID","spiffe://private-trust/workload","-ttl","3600"]`

func spireNativeArgs(path string) []string {
	return []string{
		"check", "cncf", "--project", "spire", "--spire-entry-argv", path,
		"--spire-distribution", "official_upstream",
		"--from", "1.10.4", "--to", "1.11.0", "--now", "2026-09-18T10:00:00Z", "--format", "json",
	}
}

func TestSpireNativeArgvCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	for _, test := range []struct {
		name, raw, reason string
		want              int
	}{
		{"removed single dash spelling blocks", spireRemovedArgvInput, "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
		{"removed double dash spelling blocks", `["spire-server","entry","create","--ttl","3600"]`, "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
		{"removed attached value blocks", `["spire-server","entry","create","-ttl=3600"]`, "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
		{"clean argv passes", spireCleanArgvInput, "REVIEWED_SOURCE_CONSTRAINT", ExitOK},
		{"replacement ttl options pass", `["spire-server","entry","create","-x509SVIDTTL","3600"]`, "REVIEWED_SOURCE_CONSTRAINT", ExitOK},
		{"other subcommand stays unknown", `["spire-server","entry","update","-ttl","3600"]`, "RULE_APPLICABILITY_NOT_MATCHED", ExitUnknown},
		{"wrapper surface stays unknown", `["sh","-c","spire-server entry create -ttl 3600"]`, "RULE_APPLICABILITY_NOT_MATCHED", ExitUnknown},
		{"option delimiter stays unknown", `["spire-server","entry","create","--","-ttl"]`, "RULE_FACT_UNAVAILABLE", ExitUnknown},
		{"unresolved rendering stays unknown", `["spire-server","entry","create","-ttl","{{ .Values.ttl }}"]`, "RULE_APPLICABILITY_FACT_UNAVAILABLE", ExitUnknown},
		{"unparseable shape stays unknown", `{"command":["spire-server","entry","create"]}`, "RULE_APPLICABILITY_FACT_UNAVAILABLE", ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeCNCFFile(t, "spire.json", []byte(test.raw), 0o600)
			code, stdout, stderr := runCNCFCLI(t, spireNativeArgs(path)...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, test.reason) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, "private-") || strings.Contains(stdout, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// The aggregate gate is unchanged by this route: even a scoped PASS keeps the
// whole-upgrade assessment UNKNOWN.
func TestSpireNativeArgvCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	path := writeCNCFFile(t, "spire.json", []byte(spireCleanArgvInput), 0o600)
	code, stdout, stderr := runCNCFCLI(t, spireNativeArgs(path)...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

func TestSpireNativeArgvCheck_CustomBuildAndMissingDistributionStayUnknown(t *testing.T) {
	path := writeCNCFFile(t, "spire.json", []byte(spireRemovedArgvInput), 0o600)
	for _, test := range []struct {
		name string
		args []string
	}{
		{"custom build", []string{
			"check", "cncf", "--project", "spire", "--spire-entry-argv", path,
			"--spire-distribution", "custom_build",
			"--from", "1.10.4", "--to", "1.11.0", "--now", "2026-09-18T10:00:00Z", "--format", "json",
		}},
		{"distribution not declared", []string{
			"check", "cncf", "--project", "spire", "--spire-entry-argv", path,
			"--from", "1.10.4", "--to", "1.11.0", "--now", "2026-09-18T10:00:00Z", "--format", "json",
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

func TestSpireNativeArgvCheck_RejectsMalformedWrongPairAndWrongRoute(t *testing.T) {
	path := writeCNCFFile(t, "spire.json", []byte(spireRemovedArgvInput), 0o600)
	code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "spire", "--spire-entry-argv", path, "--spire-distribution", "official_upstream", "--from", "1.10.4", "--to", "1.12.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_TRANSITION_NOT_REVIEWED") {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "spire", "--spire-entry-argv", path, "--spire-distribution", "vendor_build", "--from", "1.10.4", "--to", "1.11.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, path) {
		t.Fatalf("bad distribution code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "kubernetes", "--spire-entry-argv", "PRIVATE-NOT-READ.json", "--from", "1.31.0", "--to", "1.32.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "spire", "--spire-entry-argv", path, "--native-resource", path, "--spire-distribution", "official_upstream", "--from", "1.10.4", "--to", "1.11.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" {
		t.Fatalf("cross-mode selector code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestSpireNativeArgvCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	path := writeCNCFFile(t, "spire.json", []byte(spireRemovedArgvInput), 0o600)
	args := append(spireNativeArgs(path), "--spire-entry-argv-digest", cncfDigest([]byte(spireCleanArgvInput)))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "BLOCKED") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestSpirePrepareArgvFeedsCheck(t *testing.T) {
	raw := []byte(spireRemovedArgvInput)
	path := writeCNCFFile(t, "spire.json", raw, 0o600)
	code, canonical, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "spire", "--spire-entry-argv", path, "--spire-entry-argv-digest", cncfDigest(raw), "--from", "1.10.4", "--to", "1.11.0", "--spire-distribution", "official_upstream", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.spire.removed_entry_ttl_flag_present") || strings.Contains(canonical, "private-") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "spire-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "spire", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, report, stderr)
	}
}
