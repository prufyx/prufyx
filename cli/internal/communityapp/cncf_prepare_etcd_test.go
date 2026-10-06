// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestEtcdPreparationCLIUsesPrivateMinimizedInput(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--name=private-node","--enable-v2=false"]}`)
	path := writeCNCFFile(t, "etcd-argv.json", raw, 0o600)
	code, input, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "etcd", "--input", path, "--from", "3.5.17", "--to", "3.6.0", "--format", "input")
	if code != ExitOK || stderr != "" {
		t.Fatalf("prepare code=%d stderr=%q", code, stderr)
	}
	if strings.Contains(input, "private-node") || strings.Contains(input, "enable-v2") || !json.Valid([]byte(input)) {
		t.Fatalf("canonical output leaked argv or was invalid: %s", input)
	}
	preparedPath := writeCNCFFile(t, "etcd-prepared.json", []byte(input), 0o600)
	code, output, stderr := runCNCFCLI(t, "check", "cncf", "--project", "etcd", "--input", preparedPath, "--input-digest", cncfDigest([]byte(input)), "--now", "2026-09-10T00:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(output, `"status":"BLOCKED"`) || !strings.Contains(output, `"assessment":"UNKNOWN"`) {
		t.Fatalf("check code=%d stderr=%q output=%s", code, stderr, output)
	}
}

func TestEtcdPreparationCLIUnknownDoesNotEmitFalse(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--initial-cluster","--enable-v2=true"]}`)
	path := writeCNCFFile(t, "etcd-unknown.json", raw, 0o600)
	code, input, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "etcd", "--input", path, "--from", "3.5.17", "--to", "3.6.0", "--format", "input")
	if code != ExitUnknown || stderr != "" || strings.Contains(input, `"boolValue"`) || strings.Contains(input, "enable-v2") {
		t.Fatalf("unknown output code=%d stderr=%q input=%s", code, stderr, input)
	}
}

func TestEtcdLatestPreparationCLIAllExactOrigins(t *testing.T) {
	t.Parallel()
	for _, from := range []string{"3.6.14", "3.5.33", "3.4.45", "3.3.27", "3.2.32"} {
		for _, tc := range []struct {
			name       string
			flag       string
			checkCode  int
			wantStatus string
		}{
			{"removed", "--experimental-compact-hash-check-enabled=true", ExitBlocked, `"status":"BLOCKED"`},
			{"replacement", "--feature-gates=CompactHashCheck=true", map[bool]int{true: ExitOK, false: ExitBlocked}[from == "3.6.14"], map[bool]string{true: `"status":"PASS"`, false: `"status":"BLOCKED"`}[from == "3.6.14"]},
		} {
			t.Run(from+"/"+tc.name, func(t *testing.T) {
				raw := []byte(fmt.Sprintf(`{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--name=private-node",%q]}`, tc.flag))
				path := writeCNCFFile(t, "etcd-latest.json", raw, 0o600)
				code, input, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "etcd", "--input", path, "--from", from, "--to", "3.7.1", "--input-digest", cncfDigest(raw), "--format", "input")
				if code != ExitOK || stderr != "" || strings.Contains(input, "private-node") || strings.Contains(input, tc.flag) || !json.Valid([]byte(input)) {
					t.Fatalf("prepare code=%d stderr=%q input=%s", code, stderr, input)
				}
				prepared := writeCNCFFile(t, "etcd-latest-prepared.json", []byte(input), 0o600)
				code, output, stderr := runCNCFCLI(t, "check", "cncf", "--project", "etcd", "--input", prepared, "--input-digest", cncfDigest([]byte(input)), "--now", "2026-09-12T07:38:00Z", "--format", "json")
				if code != tc.checkCode || stderr != "" || !strings.Contains(output, tc.wantStatus) || !strings.Contains(output, `"assessment":"UNKNOWN"`) {
					t.Fatalf("check code=%d stderr=%q output=%s", code, stderr, output)
				}
				if tc.name == "replacement" && from != "3.6.14" && !strings.Contains(output, `"status":"PASS"`) {
					t.Fatalf("replacement predicate should pass while hop blocks: %s", output)
				}
			})
		}
	}
}

func TestEtcdLatestPreparationCLIUnknownBoundaries(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		declared bool
		argv     string
		from     string
		to       string
	}{
		{"missing", false, `"--experimental-memory-mlock=true"`, "3.6.14", "3.7.1"},
		{"ambiguous", true, `"--feature-gates","CompactHashCheck=true"`, "3.6.14", "3.7.1"},
		{"unsupported-inference", true, `"--compact-hash-check-enabled=true"`, "3.6.14", "3.7.1"},
		{"wrong-origin", true, `"--feature-gates=CompactHashCheck=true"`, "3.6.13", "3.7.1"},
		{"wrong-target", true, `"--feature-gates=CompactHashCheck=true"`, "3.6.14", "3.7.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":%t,"argv":[%s]}`, tc.declared, tc.argv))
			path := writeCNCFFile(t, "etcd-latest-unknown.json", raw, 0o600)
			code, input, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "etcd", "--input", path, "--from", tc.from, "--to", tc.to, "--input-digest", cncfDigest(raw), "--format", "input")
			if code != ExitUnknown || stderr != "" || strings.Contains(input, `"boolValue"`) || !json.Valid([]byte(input)) {
				t.Fatalf("prepare code=%d stderr=%q input=%s", code, stderr, input)
			}
			prepared := writeCNCFFile(t, "etcd-latest-unknown-prepared.json", []byte(input), 0o600)
			code, output, stderr := runCNCFCLI(t, "check", "cncf", "--project", "etcd", "--input", prepared, "--input-digest", cncfDigest([]byte(input)), "--now", "2026-09-12T07:38:00Z", "--format", "json")
			if code != ExitUnknown || stderr != "" || !strings.Contains(output, `"assessment":"UNKNOWN"`) {
				t.Fatalf("check code=%d stderr=%q output=%s", code, stderr, output)
			}
		})
	}
}
