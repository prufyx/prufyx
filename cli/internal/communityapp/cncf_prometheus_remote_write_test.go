// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrometheusRemoteWriteHTTP2CheckedInExamples(t *testing.T) {
	for name, want := range map[string]struct {
		code   int
		status string
	}{
		"remote-write-http2-blocked.yml": {ExitBlocked, "BLOCKED"},
		"remote-write-http2-fixed.yml":   {ExitOK, "PASS"},
		"remote-write-http2-unknown.yml": {ExitUnknown, "UNKNOWN"},
	} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "cncf", "native-resources", "prometheus", name))
		if err != nil {
			t.Fatal(err)
		}
		path := writeCNCFFile(t, name, raw, 0o600)
		args := replaceCNCFArg(prometheusRemoteWriteArgs(path), "primary-private-canary", "primary")
		args = append([]string{"check", "cncf"}, args...)
		args = append(args, "--now", "2026-09-13T09:00:00Z", "--format", "json")
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != want.code || stderr != "" || !strings.Contains(stdout, `"status":"`+want.status+`"`) {
			t.Fatalf("%s code=%d stdout=%q stderr=%q", name, code, stdout, stderr)
		}
	}
}

func prometheusRemoteWriteArgs(path string) []string {
	return []string{"--project", "prometheus", "--prometheus-config", path, "--prometheus-config-complete", "--prometheus-config-precedence-resolved", "--prometheus-rule", "remote-write-http2-default", "--prometheus-remote-write-name", "primary-private-canary", "--prometheus-remote-write-http2-required", "true", "--from", "2.55.1", "--to", "3.14.0"}
}

func TestPrometheusRemoteWriteHTTP2PublicCheckAndPrepareParity(t *testing.T) {
	raw := []byte("global:\n  scrape_interval: 30s\nremote_write:\n  - name: primary-private-canary\n    url: https://PRIVATE-ENDPOINT-CANARY.invalid/write\n")
	path := writeCNCFFile(t, "PRIVATE-PATH-CANARY.yml", raw, 0o600)
	common := prometheusRemoteWriteArgs(path)
	checkArgs := append([]string{"check", "cncf"}, common...)
	checkArgs = append(checkArgs, "--now", "2026-09-13T09:00:00Z", "--format", "json")
	code, output, stderr := runCNCFCLI(t, checkArgs...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(output, `"selectedRuleId":"prometheus.remote-write-http2-default.2-55-1-to-3-14-0"`) || !strings.Contains(output, `"status":"BLOCKED"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, output, stderr)
	}

	prepareArgs := append([]string{"prepare", "cncf"}, common...)
	prepareArgs = append(prepareArgs, "--format", "json")
	code, preparedOutput, stderr := runCNCFCLI(t, prepareArgs...)
	if code != ExitOK || stderr != "" {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, preparedOutput, stderr)
	}
	var prepared struct {
		Input       json.RawMessage `json:"input"`
		InputDigest string          `json:"inputDigest"`
	}
	var checked struct {
		InputFileDigest string `json:"inputFileDigest"`
	}
	if json.Unmarshal([]byte(preparedOutput), &prepared) != nil || json.Unmarshal([]byte(output), &checked) != nil || prepared.InputDigest != checked.InputFileDigest || prepared.InputDigest != cncfDigest(append(append([]byte(nil), prepared.Input...), '\n')) {
		t.Fatalf("prepare/check canonical mismatch prepared=%q checked=%q", prepared.InputDigest, checked.InputFileDigest)
	}
	for _, secret := range []string{"PRIVATE-ENDPOINT-CANARY", "PRIVATE-PATH-CANARY", path, "primary-private-canary"} {
		if strings.Contains(output+preparedOutput+stderr, secret) {
			t.Fatalf("private input escaped: %q", secret)
		}
	}
}

func TestPrometheusRemoteWriteHTTP2PublicVerdicts(t *testing.T) {
	tests := []struct {
		name, raw string
		mutate    func([]string) []string
		want      int
		status    string
	}{
		{"required explicit true", "remote_write:\n  - name: primary-private-canary\n    enable_http2: true\n", nil, ExitOK, "PASS"},
		{"required explicit false", "remote_write:\n  - name: primary-private-canary\n    enable_http2: false\n", nil, ExitBlocked, "BLOCKED"},
		{"not required omitted", "remote_write:\n  - name: primary-private-canary\n", func(args []string) []string { return replaceCNCFArg(args, "true", "false") }, ExitOK, "PASS"},
		{"nested lookalike", "remote_write:\n  - name: primary-private-canary\n    http_config:\n      enable_http2: true\n", nil, ExitUnknown, "UNKNOWN"},
		{"wrong pair", "remote_write:\n  - name: primary-private-canary\n    enable_http2: true\n", func(args []string) []string { return replaceCNCFArg(args, "3.14.0", "3.14.1") }, ExitUnknown, "UNKNOWN"},
		{"missing selector", "remote_write:\n  - name: primary-private-canary\n    enable_http2: true\n", func(args []string) []string { return dropCNCFOption(args, "--prometheus-rule") }, ExitUnknown, "UNKNOWN"},
		{"wrong selector", "remote_write:\n  - name: primary-private-canary\n    enable_http2: true\n", func(args []string) []string {
			return replaceCNCFArg(args, "remote-write-http2-default", "another-rule")
		}, ExitUnknown, "UNKNOWN"},
		{"missing entry name", "remote_write:\n  - name: primary-private-canary\n    enable_http2: true\n", func(args []string) []string { return dropCNCFOption(args, "--prometheus-remote-write-name") }, ExitUnknown, "UNKNOWN"},
		{"missing policy authority", "remote_write:\n  - name: primary-private-canary\n    enable_http2: true\n", func(args []string) []string { return dropCNCFOption(args, "--prometheus-remote-write-http2-required") }, ExitUnknown, "UNKNOWN"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeCNCFFile(t, "PRIVATE-PATH-CANARY.yml", []byte(test.raw), 0o600)
			args := prometheusRemoteWriteArgs(path)
			if test.mutate != nil {
				args = test.mutate(args)
			}
			args = append([]string{"check", "cncf"}, args...)
			args = append(args, "--now", "2026-09-13T09:00:00Z", "--format", "json")
			code, output, stderr := runCNCFCLI(t, args...)
			if code != test.want || stderr != "" || !strings.Contains(output, `"status":"`+test.status+`"`) || strings.Contains(output, "PRIVATE-PATH-CANARY") || strings.Contains(output, "primary-private-canary") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, output, stderr)
			}
		})
	}
}

func TestPrometheusRemoteWriteHTTP2HelpAndSafeFailures(t *testing.T) {
	code, stdout, stderr := runCNCFCLI(t, "--help")
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, "--prometheus-config") || !strings.Contains(stdout, "remote-write-http2-default") {
		t.Fatalf("root help code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, command := range []string{"check", "prepare"} {
		code, stdout, stderr := runCNCFCLI(t, command, "cncf", "--help")
		if code != ExitOK || stderr != "" || !strings.Contains(stdout, "--prometheus-config") || !strings.Contains(stdout, "--prometheus-remote-write-http2-required") || !strings.Contains(stdout, "enable_http2") {
			t.Fatalf("%s help code=%d stdout=%q stderr=%q", command, code, stdout, stderr)
		}
	}
	path := writeCNCFFile(t, "PRIVATE-PATH-CANARY.yml", []byte("remote_write: []\n"), 0o600)
	for _, args := range [][]string{
		{"check", "cncf", "--project", "prometheus", "--prometheus-config", path, "--prometheus-config-digest", "sha256:" + strings.Repeat("0", 64), "--from", "2.55.1", "--to", "3.14.0", "--now", "2026-09-13T09:00:00Z"},
		{"check", "cncf", "--project", "coredns", "--prometheus-config", path, "--from", "1.13.1", "--to", "1.14.7", "--now", "2026-09-13T09:00:00Z"},
	} {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitIntegrity && code != ExitUsage || stdout != "" || strings.Contains(stderr, path) || strings.Contains(stderr, "PRIVATE-PATH-CANARY") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	}
}

func replaceCNCFArg(args []string, old, replacement string) []string {
	result := append([]string(nil), args...)
	for i := range result {
		if result[i] == old {
			result[i] = replacement
			return result
		}
	}
	return result
}

func dropCNCFOption(args []string, option string) []string {
	result := make([]string, 0, len(args)-2)
	for i := 0; i < len(args); i++ {
		if args[i] == option && i+1 < len(args) {
			i++
			continue
		}
		result = append(result, args[i])
	}
	return result
}
