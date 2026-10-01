// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

const kumaCleanArgvInput = `["kumactl","install","transparent-proxy","--kuma-cp-ip","private-cp.internal","--exclude-outbound-ports-for-uids","tcp:3000:1000"]`
const kumaRemovedArgvInput = `["kumactl","install","transparent-proxy","--kuma-cp-ip","private-cp.internal","--exclude-outbound-tcp-ports-for-uids","3000:1000"]`

func kumaNativeArgs(path string) []string {
	return []string{
		"check", "cncf", "--project", "kuma", "--kumactl-argv", path,
		"--kuma-distribution", "official_upstream",
		"--from", "2.8.0", "--to", "2.9.0", "--now", "2026-09-18T10:00:00Z", "--format", "json",
	}
}

func TestKumaNativeArgvCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	for _, test := range []struct {
		name, raw, reason string
		want              int
	}{
		{"removed tcp spelling blocks", kumaRemovedArgvInput, "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
		{"removed udp spelling blocks", `["kumactl","install","transparent-proxy","--exclude-outbound-udp-ports-for-uids","53:1000"]`, "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
		{"consolidated flag passes", kumaCleanArgvInput, "REVIEWED_SOURCE_CONSTRAINT", ExitOK},
		{"other subcommand stays unknown", `["kumactl","install","control-plane"]`, "RULE_APPLICABILITY_NOT_MATCHED", ExitUnknown},
		{"global option before subcommand stays unknown", `["kumactl","--config-file","/etc/kumactl.yaml","install","transparent-proxy"]`, "RULE_APPLICABILITY_NOT_MATCHED", ExitUnknown},
		{"ambiguous short token stays unknown", `["kumactl","install","transparent-proxy","-vv"]`, "RULE_FACT_UNAVAILABLE", ExitUnknown},
		{"option delimiter stays unknown", `["kumactl","install","transparent-proxy","--","--exclude-outbound-tcp-ports-for-uids"]`, "RULE_FACT_UNAVAILABLE", ExitUnknown},
		{"unresolved rendering stays unknown", `["kumactl","install","transparent-proxy","{{ .Values.extraArgs }}"]`, "RULE_APPLICABILITY_FACT_UNAVAILABLE", ExitUnknown},
		{"unparseable shape stays unknown", `{"command":["kumactl","install","transparent-proxy"]}`, "RULE_APPLICABILITY_FACT_UNAVAILABLE", ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeCNCFFile(t, "kuma.json", []byte(test.raw), 0o600)
			code, stdout, stderr := runCNCFCLI(t, kumaNativeArgs(path)...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, test.reason) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, "private-cp") || strings.Contains(stdout, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// The aggregate gate is unchanged by this route: even a scoped PASS keeps the
// whole-upgrade assessment UNKNOWN.
func TestKumaNativeArgvCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	path := writeCNCFFile(t, "kuma.json", []byte(kumaCleanArgvInput), 0o600)
	code, stdout, stderr := runCNCFCLI(t, kumaNativeArgs(path)...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

func TestKumaNativeArgvCheck_CustomBuildAndMissingDistributionStayUnknown(t *testing.T) {
	path := writeCNCFFile(t, "kuma.json", []byte(kumaRemovedArgvInput), 0o600)
	for _, test := range []struct {
		name string
		args []string
	}{
		{"custom build", []string{
			"check", "cncf", "--project", "kuma", "--kumactl-argv", path,
			"--kuma-distribution", "custom_build",
			"--from", "2.8.0", "--to", "2.9.0", "--now", "2026-09-18T10:00:00Z", "--format", "json",
		}},
		{"distribution not declared", []string{
			"check", "cncf", "--project", "kuma", "--kumactl-argv", path,
			"--from", "2.8.0", "--to", "2.9.0", "--now", "2026-09-18T10:00:00Z", "--format", "json",
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

func TestKumaNativeArgvCheck_RejectsMalformedWrongPairAndWrongRoute(t *testing.T) {
	path := writeCNCFFile(t, "kuma.json", []byte(kumaRemovedArgvInput), 0o600)
	args := kumaNativeArgs(path)
	for index := range args {
		if args[index] == "2.9.0" {
			args[index] = "2.10.0"
		}
	}
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_TRANSITION_NOT_REVIEWED") {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "kuma", "--kumactl-argv", path, "--kuma-distribution", "vendor_build", "--from", "2.8.0", "--to", "2.9.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, path) {
		t.Fatalf("bad distribution code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "falco", "--kumactl-argv", "PRIVATE-NOT-READ.json", "--from", "0.40.0", "--to", "0.41.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "kuma", "--kumactl-argv", path, "--native-resource", path, "--kuma-distribution", "official_upstream", "--from", "2.8.0", "--to", "2.9.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" {
		t.Fatalf("cross-mode selector code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "kuma", "--kumactl-argv", path, "--falco-argv", path, "--kuma-distribution", "official_upstream", "--from", "2.8.0", "--to", "2.9.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" {
		t.Fatalf("cross-adapter selector code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestKumaNativeArgvCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	path := writeCNCFFile(t, "kuma.json", []byte(kumaRemovedArgvInput), 0o600)
	args := append(kumaNativeArgs(path), "--kumactl-argv-digest", cncfDigest([]byte(kumaCleanArgvInput)))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "BLOCKED") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestKumaPrepareArgvFeedsCheck(t *testing.T) {
	raw := []byte(kumaRemovedArgvInput)
	path := writeCNCFFile(t, "kuma.json", raw, 0o600)
	code, canonical, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "kuma", "--kumactl-argv", path, "--kumactl-argv-digest", cncfDigest(raw), "--from", "2.8.0", "--to", "2.9.0", "--kuma-distribution", "official_upstream", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.kuma.removed_exclude_uid_flags_present") || strings.Contains(canonical, "private-cp") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "kuma-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "kuma", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, report, stderr)
	}
}
