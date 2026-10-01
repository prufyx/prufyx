// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

func TestEnvoyBootstrapNativeCheckAndPrepare(t *testing.T) {
	raw := []byte(`{"dynamic_resources":{"ads_config":{"api_type":"GRPC","transport_api_version":"V2"}}}`)
	path := writeCNCFFile(t, "bootstrap.json", raw, 0o600)
	base := []string{"--project", "envoy", "--envoy-bootstrap", path, "--envoy-bootstrap-digest", cncfDigest(raw), "--envoy-bootstrap-selected", "--from", "1.38.4", "--to", "1.39.1"}
	prepareArgs := append(append([]string{"prepare", "cncf"}, base...), "--format", "input")
	prepareCode, prepared, prepareErr := runCNCFCLI(t, prepareArgs...)
	if prepareCode != ExitOK || prepareErr != "" || !strings.Contains(prepared, `"enumValue":"v2"`) || strings.Contains(prepared, path) || strings.Contains(prepared, "GRPC") {
		t.Fatalf("prepare=(%d,%q,%q)", prepareCode, prepared, prepareErr)
	}
	checkArgs := append(append([]string{"check", "cncf"}, base...), "--now", "2026-09-13T12:00:00Z", "--format", "json")
	checkCode, checked, checkErr := runCNCFCLI(t, checkArgs...)
	if checkCode != ExitBlocked || checkErr != "" || !strings.Contains(checked, `"status":"BLOCKED"`) || strings.Contains(checked, path) || strings.Contains(checked, "GRPC") || !strings.Contains(checked, `"networkUsed":false`) {
		t.Fatalf("check=(%d,%q,%q)", checkCode, checked, checkErr)
	}
}

func TestEnvoyBootstrapNativeUnknownAndGuards(t *testing.T) {
	raw := []byte(`{"dynamic_resources":{"ads_config":{"api_type":"GRPC","transport_api_version":"V3"}}}`)
	path := writeCNCFFile(t, "bootstrap.json", raw, 0o600)
	base := []string{"--project", "envoy", "--envoy-bootstrap", path, "--from", "1.38.4"}
	for _, tc := range []struct {
		name  string
		extra []string
		to    string
		want  int
	}{
		{"unselected", nil, "", ExitUnknown},
		{"false selected", []string{"--envoy-bootstrap-selected=false"}, "", ExitUnknown},
		{"v3", []string{"--envoy-bootstrap-selected"}, "", ExitUnknown},
		{"wrong pair", []string{"--envoy-bootstrap-selected"}, "1.39.0", ExitUnknown},
		{"bad digest", []string{"--envoy-bootstrap-selected", "--envoy-bootstrap-digest", "sha256:" + strings.Repeat("0", 64)}, "", ExitIntegrity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			to := tc.to
			if to == "" {
				to = "1.39.1"
			}
			prepareArgs := append(append([]string{"prepare", "cncf"}, base...), tc.extra...)
			prepareArgs = append(prepareArgs, "--to", to, "--format", "json")
			prepareCode, prepared, prepareErr := runCNCFCLI(t, prepareArgs...)
			checkArgs := append(append([]string{"check", "cncf"}, base...), tc.extra...)
			checkArgs = append(checkArgs, "--to", to, "--now", "2026-09-13T12:00:00Z", "--format", "json")
			checkCode, checked, checkErr := runCNCFCLI(t, checkArgs...)
			if prepareCode != tc.want || checkCode != tc.want || strings.Contains(prepared+prepareErr+checked+checkErr, path) {
				t.Fatalf("prepare=(%d,%q,%q) check=(%d,%q,%q)", prepareCode, prepared, prepareErr, checkCode, checked, checkErr)
			}
			if tc.want == ExitUnknown && (!strings.Contains(prepared, `"state":"UNKNOWN"`) || !strings.Contains(checked, `"status":"UNKNOWN"`)) {
				t.Fatalf("prepare=%q check=%q", prepared, checked)
			}
			if tc.want == ExitIntegrity && (prepared != "" || checked != "") {
				t.Fatalf("prepare=%q check=%q", prepared, checked)
			}
		})
	}
	for _, aliasRaw := range [][]byte{
		[]byte(`{"dynamic_resources":{"lds_config":{"api_config_source":{"api_type":"GRPC","transport_api_version":"V2"},"pathConfigSource":{}}}}`),
		[]byte(`{"dynamic_resources":{"lds_config":{"api_config_source":{"api_type":"GRPC","transport_api_version":"V2"},"apiConfigSource":{}}}}`),
	} {
		aliasPath := writeCNCFFile(t, "bootstrap-alias.json", aliasRaw, 0o600)
		for _, command := range []string{"prepare", "check"} {
			args := []string{command, "cncf", "--project", "envoy", "--envoy-bootstrap", aliasPath, "--envoy-bootstrap-selected", "--from", "1.38.4", "--to", "1.39.1", "--format", "json"}
			if command == "check" {
				args = append(args, "--now", "2026-09-13T12:00:00Z")
			}
			code, stdout, stderr := runCNCFCLI(t, args...)
			if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"UNKNOWN"`) || strings.Contains(stdout, aliasPath) || strings.Contains(stdout, `"enumValue":"v2"`) {
				t.Fatalf("command=%s code=%d stdout=%q stderr=%q", command, code, stdout, stderr)
			}
		}
	}
	for _, args := range [][]string{
		{"check", "cncf", "--project", "coredns", "--envoy-bootstrap", path, "--now", "2026-09-13T12:00:00Z"},
		{"check", "cncf", "--project", "envoy", "--envoy-bootstrap", path, "--input", path, "--now", "2026-09-13T12:00:00Z"},
		{"check", "cncf", "--project", "envoy", "--envoy-bootstrap", path, "--envoy-bootstrap", path, "--now", "2026-09-13T12:00:00Z"},
	} {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage || stdout != "" || strings.Contains(stdout+stderr, path) {
			t.Fatalf("args=%q code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
}
