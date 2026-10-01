// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func linkerdPreparationResource(t *testing.T, spec map[string]any, canary string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "policy.linkerd.io/v1alpha1",
		"kind":       "MeshTLSAuthentication",
		"metadata":   map[string]any{"name": canary, "namespace": canary},
		"spec":       spec,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func linkerdPreparationArgs(path string) []string {
	return []string{
		"prepare", "cncf", "--project", "linkerd", "--input", path,
		"--from", "2.13.7", "--to", "2.14.0",
		"--distribution", "official_upstream", "--schema-validation", "required",
	}
}

func linkerdPreparationBaseArgs(path, from, to string) []string {
	return []string{"prepare", "cncf", "--project", "linkerd", "--input", path, "--from", from, "--to", to}
}

func TestLinkerdPreparationFeedsScopedCheckAndRetainsUnknowns(t *testing.T) {
	tests := []struct {
		name    string
		spec    map[string]any
		prepare int
		check   int
		status  string
	}{
		{"empty identities", map[string]any{"identities": []any{}}, ExitOK, ExitBlocked, "BLOCKED"},
		{"nonempty identities", map[string]any{"identities": []any{"spiffe://synthetic.example/id"}}, ExitOK, ExitOK, "PASS"},
		{"both selectors", map[string]any{"identities": []any{}, "identityRefs": []any{}}, ExitUnknown, ExitUnknown, "UNKNOWN"},
		{"neither selector", map[string]any{}, ExitUnknown, ExitUnknown, "UNKNOWN"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := linkerdPreparationResource(t, tc.spec, "private-linkerd-canary")
			path := writeCNCFFile(t, "linkerd.json", raw, 0o600)
			args := append(linkerdPreparationArgs(path), "--format", "input")
			prepareCode, input, stderr := runCNCFCLI(t, args...)
			if prepareCode != tc.prepare || stderr != "" || !strings.HasSuffix(input, "\n") || strings.Contains(input, "private-linkerd-canary") || strings.Contains(input, "spiffe://") {
				t.Fatalf("prepare code=%d stderr=%q input=%s", prepareCode, stderr, input)
			}
			preparedPath := writeCNCFFile(t, "prepared.json", []byte(input), 0o600)
			checkCode, report, checkErr := runCNCFCLI(t, "check", "cncf", "--project", "linkerd", "--input", preparedPath, "--input-digest", cncfDigest([]byte(input)), "--now", "2026-09-08T23:00:00Z", "--format", "json")
			if checkCode != tc.check || checkErr != "" || !strings.Contains(report, `"status":"`+tc.status+`"`) || !strings.Contains(report, `"assessment":"UNKNOWN"`) {
				t.Fatalf("check code=%d stderr=%q report=%s", checkCode, checkErr, report)
			}
		})
	}
}

func TestLinkerdPreparationGuardAndEndpointStates(t *testing.T) {
	raw := linkerdPreparationResource(t, map[string]any{"identities": []any{"synthetic"}}, "private")
	for _, tc := range []struct {
		name, from, to, distribution, schema string
		wantCode                             int
		wantReason                           string
	}{
		{"missing distribution", "2.13.7", "2.14.0", "", "required", ExitUnknown, "GUARD_DECLARATION_MISSING"},
		{"missing schema intent", "2.13.7", "2.14.0", "official_upstream", "", ExitUnknown, "GUARD_DECLARATION_MISSING"},
		{"custom distribution", "2.13.7", "2.14.0", "custom_build", "required", ExitOK, "LINKERD_SELECTOR_DERIVED"},
		{"disabled schema", "2.13.7", "2.14.0", "official_upstream", "disabled", ExitOK, "LINKERD_SELECTOR_DERIVED"},
		{"unsupported pair", "2.14.0", "2.15.0", "official_upstream", "required", ExitUnknown, "UNSUPPORTED_VERSION_PAIR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeCNCFFile(t, "linkerd.json", raw, 0o600)
			args := linkerdPreparationBaseArgs(path, tc.from, tc.to)
			if tc.distribution != "" {
				args = append(args, "--distribution", tc.distribution)
			}
			if tc.schema != "" {
				args = append(args, "--schema-validation", tc.schema)
			}
			args = append(args, "--format", "json")
			code, output, stderr := runCNCFCLI(t, args...)
			if code != tc.wantCode || stderr != "" || !strings.Contains(output, tc.wantReason) {
				t.Fatalf("code=%d stderr=%q output=%s", code, stderr, output)
			}
			if strings.Contains(output, "private") {
				t.Fatalf("private value escaped: %s", output)
			}
			if tc.name == "unsupported pair" && (!strings.Contains(output, `"version":"2.14.0"`) || !strings.Contains(output, `"version":"2.15.0"`)) {
				t.Fatalf("declared endpoints were not retained: %s", output)
			}
		})
	}
}

func TestLinkerdPreparationRejectsCrossProjectFlagsBeforeOpeningInput(t *testing.T) {
	// The input path is deliberately absent: project-specific argument errors
	// must be reported before any private file admission is attempted.
	path := "/private/canary/linkerd.json"
	for _, tc := range []struct {
		args       []string
		wantStderr string
	}{
		{append(linkerdPreparationArgs(path), "--container", "selected"), "prufyx: LINKERD_PREPARATION_INPUT_INVALID\n"},
		{append(linkerdPreparationBaseArgs(path, "2.13.7", "2.14.0"), "--distribution="), "prufyx: LINKERD_PREPARATION_INPUT_INVALID\n"},
		{append(linkerdPreparationBaseArgs(path, "2.13.7", "2.14.0"), "--distribution", ""), "prufyx: LINKERD_PREPARATION_INPUT_INVALID\n"},
		{append(linkerdPreparationBaseArgs(path, "2.13.7", "2.14.0"), "--schema-validation="), "prufyx: LINKERD_PREPARATION_INPUT_INVALID\n"},
		{append(linkerdPreparationBaseArgs(path, "2.13.7", "2.14.0"), "--schema-validation", ""), "prufyx: LINKERD_PREPARATION_INPUT_INVALID\n"},
		{[]string{"prepare", "cncf", "--project", "kyverno", "--input", path, "--container", "selected", "--from", "1.12.5", "--to", "1.13.0", "--distribution", "invalid"}, "prufyx: invalid Kyverno preparation arguments; use --help\n"},
		{[]string{"prepare", "cncf", "--project", "unknown", "--input", path, "--from", "1.0.0", "--to", "1.1.0"}, "prufyx: invalid CNCF preparation project; use --help\n"},
	} {
		code, stdout, stderr := runCNCFCLI(t, tc.args...)
		if code != ExitUsage || stdout != "" || stderr != tc.wantStderr || strings.Contains(stderr, path) {
			t.Fatalf("unsafe argument rejection: code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	}
}

func TestLinkerdPreparationRejectsMalformedInputWithoutCanary(t *testing.T) {
	raw := linkerdPreparationResource(t, map[string]any{"identities": []any{}, "identityRefs": []any{"wrong"}}, "private-malformed-linkerd")
	path := writeCNCFFile(t, "linkerd-invalid.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, append(linkerdPreparationArgs(path), "--format", "json")...)
	if code != ExitUsage || stdout != "" || stderr != "prufyx: LINKERD_PREPARATION_INPUT_INVALID\n" || strings.Contains(stderr, "private-malformed-linkerd") || strings.Contains(stderr, path) {
		t.Fatalf("malformed input escaped or was accepted: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestLinkerdPreparationHumanOmissionAndIntegrityCode(t *testing.T) {
	raw := linkerdPreparationResource(t, map[string]any{"identities": []any{"synthetic"}}, "private-human-linkerd")
	path := writeCNCFFile(t, "linkerd-human.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, append(linkerdPreparationArgs(path), "--format", "human")...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, "omissions: CRD_SCHEMA_VALIDATION_NOT_PERFORMED, LIVE_OBSERVATION_NOT_PERFORMED, WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") || strings.Contains(stdout, "private-human-linkerd") {
		t.Fatalf("human Linkerd output=%q stderr=%q code=%d", stdout, stderr, code)
	}
	code, stdout, stderr = runCNCFCLI(t, append(linkerdPreparationArgs(path), "--format", "json", "--input-digest", "sha256:"+strings.Repeat("0", 64))...)
	if code != ExitIntegrity || stdout != "" || stderr != "prufyx: CNCF_PREPARATION_INTEGRITY_FAILURE\n" {
		t.Fatalf("integrity code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, format := range []string{"human", "json", "input"} {
		var errOut strings.Builder
		code := Run(context.TODO(), append(linkerdPreparationArgs(path), "--format", format), failedPreparationWriter{}, &errOut, "test")
		if code != ExitIntegrity || errOut.String() != "prufyx: CNCF_PREPARATION_INTEGRITY_FAILURE\n" {
			t.Fatalf("%s output failure code=%d stderr=%q", format, code, errOut.String())
		}
	}
}
