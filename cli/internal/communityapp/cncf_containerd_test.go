// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

func containerdNativeTOML(version, plugin, handler, runtimeType, extra string) []byte {
	return []byte("version = " + version + "\n" + extra + "\n[plugins.\"" + plugin + "\".containerd.runtimes.\"" + handler + "\"]\nruntime_type = \"" + runtimeType + "\"\n")
}

func containerdCheckArgs(path, handler, now string) []string {
	return []string{
		"check", "cncf", "--project", "containerd", "--containerd-config", path,
		"--runtime-handler", handler, "--from", "1.7.28", "--to", "2.0.0",
		"--containerd-config-complete", "--containerd-config-precedence-resolved",
		"--containerd-official-upstream", "--containerd-official-bundled-runtimes-only",
		"--now", now, "--format", "json",
	}
}

func TestContainerdNativeCheckBlockedPassUnknownAndPrivacy(t *testing.T) {
	t.Parallel()
	const (
		v2Plugin = "io.containerd.grpc.v1.cri"
		v3Plugin = "io.containerd.cri.v1.runtime"
		handler  = "PRIVATE-HANDLER-NAME"
	)
	for _, tc := range []struct {
		name, version, plugin, runtimeType, extra string
		omitScope                                 bool
		wantCode                                  int
		wantStatus                                string
	}{
		{"v2 old official shim blocked", "2", v2Plugin, "io.containerd.runc.v1", "", false, ExitBlocked, `"status":"BLOCKED"`},
		{"v3 old official shim blocked", "3", v3Plugin, "io.containerd.runtime.v1.linux", "", false, ExitBlocked, `"status":"BLOCKED"`},
		{"v2 migrates and runc v2 passes", "2", v2Plugin, "io.containerd.runc.v2", "", false, ExitOK, `"status":"PASS"`},
		{"custom runtime unknown", "3", v3Plugin, "PRIVATE-CUSTOM-RUNTIME", "", false, ExitUnknown, `"status":"UNKNOWN"`},
		{"imports unknown", "2", v2Plugin, "io.containerd.runc.v1", `imports = ["/PRIVATE/INCLUDED.toml"]`, false, ExitUnknown, `"status":"UNKNOWN"`},
		{"runtime path override unknown", "2", v2Plugin, "io.containerd.runc.v1", "", false, ExitUnknown, `"status":"UNKNOWN"`},
		{"custom shim scope unknown", "2", v2Plugin, "io.containerd.runc.v1", "", true, ExitUnknown, `"status":"UNKNOWN"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := containerdNativeTOML(tc.version, tc.plugin, handler, tc.runtimeType, tc.extra)
			if tc.name == "runtime path override unknown" {
				raw = append(raw, []byte("runtime_path = \"/PRIVATE/containerd-shim-runc-v1\"\n")...)
			}
			path := writeCNCFFile(t, "PRIVATE-containerd.toml", raw, 0o600)
			args := containerdCheckArgs(path, handler, "2026-09-12T12:30:00Z")
			if tc.omitScope {
				for i := 0; i < len(args); i++ {
					if args[i] == "--containerd-official-bundled-runtimes-only" {
						args = append(args[:i], args[i+1:]...)
						break
					}
				}
			}
			code, stdout, stderr := runCNCFCLI(t, args...)
			if code != tc.wantCode || stderr != "" || !strings.Contains(stdout, tc.wantStatus) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || !strings.Contains(stdout, `"networkUsed":false`) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			for _, private := range []string{handler, "PRIVATE-CUSTOM-RUNTIME", "/PRIVATE/INCLUDED.toml", "/PRIVATE/containerd-shim-runc-v1", path} {
				if private != "" && strings.Contains(stdout, private) {
					t.Fatalf("private containerd input escaped: %q in %q", private, stdout)
				}
			}
		})
	}
}

func TestContainerdNativeCheckFreshnessAndPinnedEvidence(t *testing.T) {
	t.Parallel()
	raw := containerdNativeTOML("2", "io.containerd.grpc.v1.cri", "selected", "io.containerd.runc.v1", "")
	path := writeCNCFFile(t, "config.toml", raw, 0o600)
	activeArgs := append(containerdCheckArgs(path, "selected", "2026-09-12T12:30:00Z"), "--containerd-config-digest", cncfDigest(raw))
	code, stdout, stderr := runCNCFCLI(t, activeArgs...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, "containerd-v2-0-0-removed-official-runtimes") || !strings.Contains(stdout, "containerd-v2-0-0-cri-runtime-migration-preserves-runtime-type") {
		t.Fatalf("active code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	staleArgs := containerdCheckArgs(path, "selected", "2026-12-11T12:00:00Z")
	code, stdout, stderr = runCNCFCLI(t, staleArgs...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_EVIDENCE_STALE") {
		t.Fatalf("stale code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestContainerdNativeCheckHumanUnsupportedVersionDoesNotClaimAdmission(t *testing.T) {
	t.Parallel()
	raw := containerdNativeTOML("1", "io.containerd.grpc.v1.cri", "selected", "io.containerd.runc.v1", "")
	path := writeCNCFFile(t, "unsupported.toml", raw, 0o600)
	args := containerdCheckArgs(path, "selected", "2026-09-12T12:30:00Z")
	args[len(args)-1] = "human"
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "supported configuration formats: v2 and v3") || strings.Contains(stdout, "configuration version: admitted") || !strings.Contains(stdout, "RULE_FACT_UNAVAILABLE") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestContainerdNativeCheckRejectsExternalNowBeforePrivateRead(t *testing.T) {
	t.Parallel()
	args := []string{"check", "cncf", "--project", "containerd", "--containerd-config", "PRIVATE-NOT-READ.toml", "--runtime-handler", "selected", "--from", "1.7.28", "--to", "2.0.0", "--containerd-config-complete", "--containerd-config-precedence-resolved", "--containerd-official-upstream", "--containerd-official-bundled-runtimes-only", "--knowledge-db", "PRIVATE-NOT-OPENED-STORE", "--now=", "--format", "json"}
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, "PRIVATE-NOT-READ.toml") || strings.Contains(stderr, "PRIVATE-NOT-OPENED-STORE") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestContainerdPrepareProducesBatchInputAndUnknown(t *testing.T) {
	t.Parallel()
	raw := containerdNativeTOML("2", "io.containerd.grpc.v1.cri", "PRIVATE-HANDLER", "io.containerd.runc.v1", "")
	path := writeCNCFFile(t, "config.toml", raw, 0o600)
	base := []string{"prepare", "cncf", "--project", "containerd", "--input", path, "--runtime-handler", "PRIVATE-HANDLER", "--from", "1.7.28", "--to", "2.0.0", "--containerd-config-complete", "--containerd-config-precedence-resolved", "--containerd-official-upstream", "--containerd-official-bundled-runtimes-only", "--input-digest", cncfDigest(raw)}
	code, input, stderr := runCNCFCLI(t, append(base, "--format", "input")...)
	if code != ExitOK || stderr != "" || !strings.Contains(input, `"component.containerd.selected_runtime_uses_removed_official_shim"`) || !strings.Contains(input, `"boolValue":true`) || strings.Contains(input, "PRIVATE-HANDLER") || strings.Contains(input, "io.containerd.runc.v1") {
		t.Fatalf("prepared code=%d input=%q stderr=%q", code, input, stderr)
	}
	canonical := writeCNCFFile(t, "prepared.json", []byte(input), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "containerd", "--input", canonical, "--now", "2026-09-12T12:30:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("batch code=%d report=%q stderr=%q", code, report, stderr)
	}

	unknown := append([]string{}, base...)
	for i := 0; i < len(unknown); i++ {
		if unknown[i] == "--containerd-config-precedence-resolved" {
			unknown = append(unknown[:i], unknown[i+1:]...)
			break
		}
	}
	code, output, stderr := runCNCFCLI(t, append(unknown, "--format", "json")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(output, `"state":"UNKNOWN"`) || !strings.Contains(output, "CONTAINERD_CONFIG_DECLARATIONS_INCOMPLETE") {
		t.Fatalf("unknown code=%d output=%q stderr=%q", code, output, stderr)
	}
}

func TestContainerdModesRejectCrossProjectAndExplicitFalseFlags(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "config.toml", containerdNativeTOML("2", "io.containerd.grpc.v1.cri", "selected", "io.containerd.runc.v2", ""), 0o600)
	for _, args := range [][]string{
		{"check", "cncf", "--project", "helm", "--input", path, "--runtime-handler", "selected", "--containerd-config-complete=false", "--now", "2026-09-12T12:30:00Z"},
		{"check", "cncf", "--project", "containerd", "--containerd-config", path, "--runtime-handler", "selected", "--input", path, "--from", "1.7.28", "--to", "2.0.0", "--now", "2026-09-12T12:30:00Z"},
		{"prepare", "cncf", "--project", "metallb", "--input", path, "--runtime-handler", "selected", "--containerd-official-bundled-runtimes-only=false", "--from", "0.12.1", "--to", "0.13.2"},
	} {
		code, _, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage || stderr == "" {
			t.Fatalf("args=%v code=%d stderr=%q", args, code, stderr)
		}
	}
}

func TestContainerdNativeCheckUsesSelectedExternalPackWithoutFallback(t *testing.T) {
	t.Parallel()
	fixture := makeExternalCLIFixture(t)
	raw := containerdNativeTOML("2", "io.containerd.grpc.v1.cri", "PRIVATE-HANDLER", "io.containerd.runc.v1", "")
	path := writeCNCFFile(t, "PRIVATE-containerd.toml", raw, 0o600)
	args := []string{
		"check", "cncf", "--project", "containerd", "--containerd-config", path,
		"--containerd-config-digest", cncfDigest(raw), "--runtime-handler", "PRIVATE-HANDLER",
		"--from", "1.7.28", "--to", "2.0.0", "--containerd-config-complete",
		"--containerd-config-precedence-resolved", "--containerd-official-upstream",
		"--containerd-official-bundled-runtimes-only", "--knowledge-db", fixture.store,
		"--knowledge-revision", "1", "--knowledge-bundle-digest", fixture.manifest.Revisions[0].BundleDigest,
		"--knowledge-trust-receipt-digest", fixture.receipt1.TrustReceiptDigest, "--format", "json",
	}
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"knowledgeOrigin":"external_declared"`) || !strings.Contains(stdout, `"requestedRuleId":"`+containerdRemovedOfficialShimRuleID+`"`) || strings.Contains(stdout, `"status":"BLOCKED"`) || strings.Contains(stdout, "containerd-v2-0-0-removed-official-runtimes") || strings.Contains(stdout, "PRIVATE-HANDLER") || strings.Contains(stdout, path) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
