// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const jaegerAuthority = "OPERATOR_DECLARED_DIRECT_OFFICIAL_JAEGER_V2_ARGUMENTS_ONLY"

func jaegerPreparationArgs(path string) []string {
	return []string{"prepare", "cncf", "--project", "jaeger", "--input", path, "--from", "1.76.0", "--to", "2.20.0"}
}

func jaegerPreparationDeclaration(t *testing.T, argv any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"authority": jaegerAuthority, "argv": argv})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func jaegerExampleFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "cncf", "jaeger-explicit-config", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestJaegerPreparationFeedsExistingScopedRuleWithoutLeakingArguments(t *testing.T) {
	t.Parallel()
	const canary = "private-jaeger-cli-canary-4ed2"
	raw := jaegerPreparationDeclaration(t, []any{"--config=/etc/jaeger/" + canary + ".yaml"})
	path := writeCNCFFile(t, "jaeger.json", raw, 0o600)
	args := append(jaegerPreparationArgs(path), "--non-memory-storage-required", "true", "--official-jaeger-distribution", "true", "--input-digest", cncfDigest(raw), "--format", "input")
	code, input, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || !json.Valid([]byte(input)) || strings.Contains(input, canary) || strings.Contains(input, path) {
		t.Fatalf("prepare code=%d stderr=%q input=%s", code, stderr, input)
	}
	prepared := writeCNCFFile(t, "prepared.json", []byte(input), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "jaeger", "--input", prepared, "--input-digest", cncfDigest([]byte(input)), "--now", "2026-09-10T01:00:00Z", "--format", "json")
	if code != ExitOK || stderr != "" || !strings.Contains(report, `"status":"PASS"`) || !strings.Contains(report, `"assessment":"UNKNOWN"`) || strings.Contains(report, canary) || strings.Contains(report, path) {
		t.Fatalf("check code=%d stderr=%q report=%s", code, stderr, report)
	}
}

func TestJaegerPreparationAmbiguitiesRemainUnknownAndRedacted(t *testing.T) {
	t.Parallel()
	const canary = "private-jaeger-ambiguous-canary-761c"
	for _, tc := range []struct {
		name string
		argv any
	}{
		{"zero", []any{}},
		{"multiple", []any{"--config=/one", "--config=/two"}},
		{"split", []any{"--config", "/" + canary}},
		{"empty", []any{"--config="}},
		{"delimiter", []any{"--"}},
		{"executable", []any{"jaeger"}},
		{"wrapper", []any{"/bin/sh -c --config=/" + canary}},
		{"expansion", []any{"--config=$PRIVATE"}},
		{"provider", []any{"--config=env:PRIVATE"}},
		{"remote", []any{"--config=https://example.invalid/" + canary}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := jaegerPreparationDeclaration(t, tc.argv)
			path := writeCNCFFile(t, tc.name+".json", raw, 0o600)
			args := append(jaegerPreparationArgs(path), "--non-memory-storage-required", "true", "--official-jaeger-distribution", "true", "--format", "input")
			code, input, stderr := runCNCFCLI(t, args...)
			if code != ExitUnknown || stderr != "" || !json.Valid([]byte(input)) || strings.Contains(input, canary) || strings.Contains(input, path) {
				t.Fatalf("prepare code=%d stderr=%q input=%s", code, stderr, input)
			}
			prepared := writeCNCFFile(t, tc.name+"-prepared.json", []byte(input), 0o600)
			code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "jaeger", "--input", prepared, "--input-digest", cncfDigest([]byte(input)), "--now", "2026-09-10T01:00:00Z", "--format", "json")
			if code != ExitUnknown || stderr != "" || !strings.Contains(report, `"status":"UNKNOWN"`) || !strings.Contains(report, `"assessment":"UNKNOWN"`) || strings.Contains(report, canary) || strings.Contains(report, path) {
				t.Fatalf("check code=%d stderr=%q report=%s", code, stderr, report)
			}
		})
	}
}

func TestJaegerPreparationAdmissionAndCrossProjectFlagsStaySanitized(t *testing.T) {
	t.Parallel()
	const canary = "private-jaeger-admission-canary-82d5"
	raw := jaegerPreparationDeclaration(t, []any{"--config=/" + canary})
	private := writeCNCFFile(t, "private.json", raw, 0o600)
	permissive := writeCNCFFile(t, "permissive.json", raw, 0o644)
	for _, args := range [][]string{
		append(jaegerPreparationArgs(permissive), "--format", "json"),
		append(jaegerPreparationArgs(private), "--distribution", "official_upstream"),
		append(jaegerPreparationArgs(private), "--non-memory-storage-required", "maybe"),
		append(jaegerPreparationArgs(private), "--input-digest", "sha256:"+strings.Repeat("0", 64)),
	} {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage && code != ExitIntegrity || stdout != "" || strings.Contains(stderr, canary) || strings.Contains(stderr, private) || strings.Contains(stderr, permissive) {
			t.Fatalf("args=%q code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
}

func TestJaegerLatestTargetPairRoute(t *testing.T) {
	t.Parallel()
	raw := jaegerPreparationDeclaration(t, []any{"--config=/etc/jaeger/config.yaml"})
	path := writeCNCFFile(t, "jaeger-latest.json", raw, 0o600)
	args := []string{"prepare", "cncf", "--project", "jaeger", "--input", path, "--from", "2.19.0", "--to", "2.20.0", "--non-memory-storage-required", "true", "--official-jaeger-distribution", "true", "--format", "input"}
	code, input, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || !json.Valid([]byte(input)) {
		t.Fatalf("prepare code=%d stderr=%q input=%q", code, stderr, input)
	}
	prepared := writeCNCFFile(t, "jaeger-latest-prepared.json", []byte(input), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "jaeger", "--input", prepared, "--now", "2026-09-12T08:39:00Z", "--format", "json")
	if code != ExitOK || stderr != "" || !strings.Contains(report, "jaeger.explicit-config-required-for-non-memory.target.2-19-to-2-20") || !strings.Contains(report, `"status":"PASS"`) {
		t.Fatalf("check code=%d stderr=%q report=%s", code, stderr, report)
	}
}

func TestJaegerExampleFixturesKeepNativeAndOperatorDeclaredScopesSeparate(t *testing.T) {
	t.Parallel()
	nativeRaw := jaegerExampleFixture(t, "unknown-empty.json")
	native := writeCNCFFile(t, "unknown-empty.json", nativeRaw, 0o600)
	prepareArgs := []string{"prepare", "cncf", "--project", "jaeger", "--input", native, "--from", "2.19.0", "--to", "2.20.0", "--non-memory-storage-required", "true", "--official-jaeger-distribution", "true", "--format", "input"}
	code, prepared, stderr := runCNCFCLI(t, prepareArgs...)
	if code != ExitUnknown || stderr != "" || !json.Valid([]byte(prepared)) {
		t.Fatalf("native empty prepare code=%d stderr=%q input=%q", code, stderr, prepared)
	}
	preparedPath := writeCNCFFile(t, "unknown-empty-prepared.json", []byte(prepared), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "jaeger", "--input", preparedPath, "--now", "2026-09-12T08:39:00Z", "--format", "json")
	if code != ExitUnknown || stderr != "" || !strings.Contains(report, `"status":"UNKNOWN"`) {
		t.Fatalf("native empty check code=%d stderr=%q report=%s", code, stderr, report)
	}

	declaredRaw := jaegerExampleFixture(t, "blocked-operator-declared.json")
	declared := writeCNCFFile(t, "blocked-operator-declared.json", declaredRaw, 0o600)
	code, report, stderr = runCNCFCLI(t, "check", "cncf", "--project", "jaeger", "--input", declared, "--now", "2026-09-12T08:39:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) || !strings.Contains(report, "jaeger.explicit-config-required-for-non-memory.target.2-19-to-2-20") {
		t.Fatalf("operator-declared check code=%d stderr=%q report=%s", code, stderr, report)
	}
}
