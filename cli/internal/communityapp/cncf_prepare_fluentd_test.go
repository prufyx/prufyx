// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestFluentDLiteralPreparationAndCheckStayPrivateAndFailClosed(t *testing.T) {
	canary := "${FLUENTD_PRIVATE_PLACEHOLDER}"
	raw := []byte(`{"current":"{\"path\":\"` + canary + `\"}","proposed":"{\"path\":\"` + canary + `\"}","selectedValueComplete":true,"currentDefaultUsed":true,"preserveLiteralTreatment":true}`)
	path := writeCNCFFile(t, "fluentd-expansion.json", raw, 0o600)
	args := []string{"prepare", "cncf", "--project", "fluentd", "--input", path, "--from", "1.17.1", "--to", "1.18.0", "--format", "input"}
	code, prepared, stderr := runCNCFCLI(t, args...)
	if code != ExitUnknown || stderr != "" || strings.Contains(prepared, canary) || strings.Contains(prepared, path) {
		t.Fatalf("expansion preparation code=%d stderr=%q output=%q", code, stderr, prepared)
	}
	preparedPath := writeCNCFFile(t, "fluentd-expansion-prepared.json", []byte(prepared), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "fluentd", "--input", preparedPath, "--now", "2026-09-12T00:20:00Z", "--format", "json")
	if code != ExitUnknown || stderr != "" || !strings.Contains(report, `"status":"UNKNOWN"`) || strings.Contains(report, canary) || strings.Contains(report, path) {
		t.Fatalf("expansion check code=%d stderr=%q report=%q", code, stderr, report)
	}
}

func TestFluentDLiteralCLIReportsPassAndBlockedForSupportedLiterals(t *testing.T) {
	for _, tc := range []struct {
		name, current  string
		prepare, check int
	}{
		{"safe", `{"path":"plain"}`, ExitOK, ExitOK},
		{"marker", `{"path":"#{record_tag}"}`, ExitOK, ExitBlocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := json.Marshal(tc.current)
			if err != nil {
				t.Fatal(err)
			}
			raw := []byte(`{"current":` + string(encoded) + `,"proposed":` + string(encoded) + `,"selectedValueComplete":true,"currentDefaultUsed":true,"preserveLiteralTreatment":true}`)
			path := writeCNCFFile(t, "fluentd-supported.json", raw, 0o600)
			prepareArgs := []string{"prepare", "cncf", "--project", "fluentd", "--input", path, "--from", "1.17.1", "--to", "1.18.0", "--format", "input"}
			code, prepared, stderr := runCNCFCLI(t, prepareArgs...)
			if code != tc.prepare || stderr != "" {
				t.Fatalf("prepare code=%d want=%d stderr=%q", code, tc.prepare, stderr)
			}
			preparedPath := writeCNCFFile(t, "fluentd-supported-prepared.json", []byte(prepared), 0o600)
			code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "fluentd", "--input", preparedPath, "--now", "2026-09-12T00:20:00Z", "--format", "json")
			if code != tc.check || stderr != "" {
				t.Fatalf("check code=%d want=%d stderr=%q report=%q", code, tc.check, stderr, report)
			}
		})
	}
}

func TestFluentDLiteralPreparationRejectsInvalidUTF8AndDigest(t *testing.T) {
	raw := []byte(`{"current":"{\"path\":\"plain\"}","proposed":"{\"path\":\"plain\"}","selectedValueComplete":true,"currentDefaultUsed":true,"preserveLiteralTreatment":true}`)
	path := writeCNCFFile(t, "fluentd-valid.json", raw, 0o600)
	base := []string{"prepare", "cncf", "--project", "fluentd", "--input", path, "--from", "1.17.1", "--to", "1.18.0", "--format", "input"}
	code, stdout, stderr := runCNCFCLI(t, append(base, "--input-digest", "sha256:"+strings.Repeat("0", 64))...)
	if code != ExitIntegrity || stdout != "" || stderr != "prufyx: CNCF_PREPARATION_INTEGRITY_FAILURE\n" {
		t.Fatalf("wrong digest code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	invalid := append([]byte(nil), raw...)
	if index := bytes.Index(invalid, []byte("plain")); index >= 0 {
		invalid[index] = 0xff
	} else {
		t.Fatal("test envelope did not contain selected value")
	}
	invalidPath := writeCNCFFile(t, "fluentd-invalid-utf8.json", invalid, 0o600)
	invalidArgs := []string{"prepare", "cncf", "--project", "fluentd", "--input", invalidPath, "--from", "1.17.1", "--to", "1.18.0", "--format", "json"}
	code, stdout, stderr = runCNCFCLI(t, invalidArgs...)
	if code != ExitUsage || stdout != "" || stderr != "prufyx: CNCF preparation input is invalid\n" {
		t.Fatalf("invalid UTF-8 code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	permissivePath := writeCNCFFile(t, "fluentd-permissive.json", raw, 0o644)
	permissiveArgs := []string{"prepare", "cncf", "--project", "fluentd", "--input", permissivePath, "--from", "1.17.1", "--to", "1.18.0", "--format", "json"}
	code, stdout, stderr = runCNCFCLI(t, permissiveArgs...)
	if code != ExitUsage || stdout != "" || !strings.HasPrefix(stderr, "prufyx: CNCF preparation input failed local admission: ") || !strings.Contains(stderr, "chmod 600") {
		t.Fatalf("permissive mode code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
