// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

func kyvernoNativeArgs(path, from, to, distribution string) []string {
	args := []string{
		"check", "cncf", "--project", "kyverno", "--kyverno-resource", path,
		"--container", "selected", "--from", from, "--to", to,
		"--now", "2026-09-18T10:00:00Z", "--format", "json",
	}
	if distribution != "" {
		args = append(args, "--kyverno-distribution", distribution)
	}
	return args
}

// The native one-step route reuses the already-reviewed PrepareKyvernoScoped
// adapter; this exercises it end to end for the 1.12.5 -> 1.13.0 pair without
// a separate prepare step.
func TestKyvernoNativeCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name                 string
		command, args        []string
		distribution, canary string
		reason               string
		want                 int
	}{
		{"removed flag blocks", []string{"reports-controller"}, []string{"--reportsChunkSize=16"}, "official_upstream", "private-canary-blocked", "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
		{"clean command passes", []string{"reports-controller"}, nil, "official_upstream", "private-canary-clean", "REVIEWED_SOURCE_CONSTRAINT", ExitOK},
		{"other command stays unknown", []string{"reports-cleaner"}, nil, "official_upstream", "private-canary-other", "RULE_APPLICABILITY", ExitUnknown},
		{"custom distribution stays unknown", []string{"reports-controller"}, []string{"--reportsChunkSize=16"}, "custom_build", "private-canary-custom", "RULE_APPLICABILITY", ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := kyvernoProposal(t, test.command, test.args, test.canary)
			path := writeCNCFFile(t, "kyverno.json", raw, 0o600)
			code, stdout, stderr := runCNCFCLI(t, kyvernoNativeArgs(path, "1.12.5", "1.13.0", test.distribution)...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, test.reason) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, test.canary) || strings.Contains(stdout, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// The aggregate gate is unchanged by this route: even a scoped PASS keeps the
// whole-upgrade assessment UNKNOWN.
func TestKyvernoNativeCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	t.Parallel()
	raw := kyvernoProposal(t, []string{"reports-controller"}, nil, "private-canary-agg")
	path := writeCNCFFile(t, "kyverno.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, kyvernoNativeArgs(path, "1.12.5", "1.13.0", "official_upstream")...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

// All five reviewed 1.19.1 origins are routed through the same native path.
func TestKyvernoNativeCheck_AllLatestOriginsAreRouted(t *testing.T) {
	t.Parallel()
	for _, from := range []string{"1.14.5", "1.15.3", "1.16.4", "1.17.2", "1.18.2"} {
		t.Run(from, func(t *testing.T) {
			blockedRaw := kyvernoProposal(t, []string{"reports-controller"}, []string{"--reportsChunkSize=16"}, "private-canary-lb-"+from)
			blocked := writeCNCFFile(t, "kyverno-latest-blocked.json", blockedRaw, 0o600)
			code, stdout, stderr := runCNCFCLI(t, kyvernoNativeArgs(blocked, from, "1.19.1", "official_upstream")...)
			if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, "kyverno.reports-chunk-size-unsupported-at-1-19-1-from-"+strings.ReplaceAll(from, ".", "-")) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
				t.Fatalf("from=%s code=%d stdout=%q stderr=%q", from, code, stdout, stderr)
			}
			cleanRaw := kyvernoProposal(t, []string{"reports-controller"}, nil, "private-canary-lc-"+from)
			clean := writeCNCFFile(t, "kyverno-latest-clean.json", cleanRaw, 0o600)
			code, stdout, stderr = runCNCFCLI(t, kyvernoNativeArgs(clean, from, "1.19.1", "official_upstream")...)
			if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
				t.Fatalf("from=%s code=%d stdout=%q stderr=%q", from, code, stdout, stderr)
			}
		})
	}
}

func TestKyvernoNativeCheck_RejectsMalformedWrongPairAndWrongRoute(t *testing.T) {
	t.Parallel()
	raw := kyvernoProposal(t, []string{"reports-controller"}, []string{"--reportsChunkSize=16"}, "private-canary-wr")
	path := writeCNCFFile(t, "kyverno.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, kyvernoNativeArgs(path, "1.12.5", "1.13.1", "official_upstream")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "kyverno", "--kyverno-resource", path, "--container", "selected", "--from", "1.12.5", "--to", "1.13.0", "--kyverno-distribution", "vendor_build", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, path) {
		t.Fatalf("bad distribution code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "kyverno", "--kyverno-resource", path, "--from", "1.12.5", "--to", "1.13.0", "--kyverno-distribution", "official_upstream", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, path) {
		t.Fatalf("missing container code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "falco", "--kyverno-resource", "PRIVATE-NOT-READ.json", "--container", "selected", "--from", "0.40.0", "--to", "0.41.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "kyverno", "--kyverno-resource", path, "--container", "selected", "--native-resource", path, "--kyverno-distribution", "official_upstream", "--from", "1.12.5", "--to", "1.13.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" {
		t.Fatalf("cross-mode selector code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestKyvernoNativeCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	t.Parallel()
	raw := kyvernoProposal(t, []string{"reports-controller"}, []string{"--reportsChunkSize=16"}, "private-canary-pin")
	path := writeCNCFFile(t, "kyverno.json", raw, 0o600)
	otherRaw := kyvernoProposal(t, []string{"reports-controller"}, nil, "private-canary-pin-other")
	args := append(kyvernoNativeArgs(path, "1.12.5", "1.13.0", "official_upstream"), "--kyverno-resource-digest", cncfDigest(otherRaw))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "BLOCKED") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestKyvernoPrepareResourceFeedsNativeCheckEquivalently(t *testing.T) {
	t.Parallel()
	raw := kyvernoProposal(t, []string{"reports-controller"}, []string{"--reportsChunkSize=16"}, "private-canary-equiv")
	path := writeCNCFFile(t, "kyverno.json", raw, 0o600)
	code, canonical, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "kyverno", "--input", path, "--container", "selected", "--from", "1.12.5", "--to", "1.13.0", "--distribution", "official_upstream", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.kyverno.reports_chunk_size_flag_present") || strings.Contains(canonical, "private-canary-equiv") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "kyverno-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "kyverno", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, report, stderr)
	}
	nativeCode, nativeReport, nativeErr := runCNCFCLI(t, kyvernoNativeArgs(path, "1.12.5", "1.13.0", "official_upstream")...)
	if nativeCode != code || nativeErr != "" || !strings.Contains(nativeReport, `"status":"BLOCKED"`) {
		t.Fatalf("native code=%d stdout=%q stderr=%q", nativeCode, nativeReport, nativeErr)
	}
}
