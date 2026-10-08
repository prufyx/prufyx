// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func kyvernoProposal(t *testing.T, command, args []string, canary string) []byte {
	t.Helper()
	container := map[string]any{
		"name": "selected", "image": "private.example/" + canary,
		"env": []any{map[string]any{"name": "PRIVATE_VALUE", "value": canary}},
	}
	if command != nil {
		container["command"] = command
	}
	if args != nil {
		container["args"] = args
	}
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": canary, "namespace": canary},
		"spec":     map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{container}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func prepareArgs(input string) []string {
	return []string{"prepare", "cncf", "--project", "kyverno", "--input", input, "--container", "selected", "--from", "1.12.5", "--to", "1.13.0"}
}

func TestKyvernoPreparationScopedOutputIsMinimizedAndBindsExactBytes(t *testing.T) {
	t.Parallel()
	var previousInput, previousSource string
	for _, canary := range []string{"private-canary-a-881df1", "private-canary-b-2765ca"} {
		raw := kyvernoProposal(t, []string{"reports-controller"}, nil, canary)
		path := writeCNCFFile(t, canary+".json", raw, 0o600)
		args := append(prepareArgs(path), "--distribution", "official_upstream", "--format", "json", "--input-digest", cncfDigest(raw))
		code, output, stderr := runCNCFCLI(t, args...)
		if code != ExitOK || stderr != "" {
			t.Fatalf("prepare code=%d stderr=%q", code, stderr)
		}
		var report struct {
			Schema, Project, Authority, State, Reason, SourceDigest, InputDigest string
			NetworkUsed, CheckPerformed                                          bool
			Omissions                                                            []string
			Input                                                                json.RawMessage
		}
		if err := json.Unmarshal([]byte(output), &report); err != nil {
			t.Fatal(err)
		}
		inputCode, input, inputErr := runCNCFCLI(t, append(append(prepareArgs(path), "--distribution", "official_upstream"), "--format", "input")...)
		if inputCode != ExitOK || inputErr != "" || !strings.HasSuffix(input, "\n") || strings.HasSuffix(input, "\n\n") || input != string(report.Input)+"\n" {
			t.Fatalf("canonical output mismatch: code=%d stderr=%q", inputCode, inputErr)
		}
		if report.Schema != "prufyx.io/local-cncf-preparation/v1alpha1" || report.Project != "kyverno" || report.Authority != "LOCAL_PREPARATION_OF_OPERATOR_DECLARATION" || report.State != "PREPARED" || report.Reason != "DIRECT_REPORTS_CONTROLLER_COMMAND_PARSED" || report.NetworkUsed || report.CheckPerformed || len(report.Omissions) != 2 {
			t.Fatalf("unexpected preparation authority: %s", output)
		}
		if report.SourceDigest != cncfDigest(raw) || report.InputDigest != cncfDigest([]byte(input)) {
			t.Fatal("digest did not bind exact source and canonical input bytes")
		}
		for _, forbidden := range []string{canary, path, "selected", "private.example"} {
			if strings.Contains(output+input, forbidden) {
				t.Fatalf("private source data escaped into preparation output: %q", forbidden)
			}
		}
		if previousInput != "" && (previousInput != input || previousSource == report.SourceDigest) {
			t.Fatal("irrelevant private values changed minimized input or failed to change raw source identity")
		}
		previousInput, previousSource = input, report.SourceDigest
	}
}

func TestKyvernoPreparationFeedsOnlyScopedCheck(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                   string
		command, args          []string
		distribution           string
		prepareCode, checkCode int
		status                 string
	}{
		{"zero args pass", []string{"reports-controller"}, nil, "official_upstream", ExitOK, ExitOK, "PASS"},
		{"one dash attached blocks", []string{"reports-controller", "-reportsChunkSize=1"}, nil, "official_upstream", ExitOK, ExitBlocked, "BLOCKED"},
		{"two dash following negative blocks", []string{"reports-controller"}, []string{"--reportsChunkSize", "-1"}, "official_upstream", ExitOK, ExitBlocked, "BLOCKED"},
		{"omitted distribution", []string{"reports-controller"}, nil, "", ExitUnknown, ExitUnknown, "UNKNOWN"},
		{"custom distribution", []string{"reports-controller"}, nil, "custom_build", ExitUnknown, ExitUnknown, "UNKNOWN"},
		{"kyverno surface", []string{"/kyverno"}, nil, "official_upstream", ExitUnknown, ExitUnknown, "UNKNOWN"},
		{"absolute reports surface", []string{"/reports-controller"}, nil, "official_upstream", ExitUnknown, ExitUnknown, "UNKNOWN"},
		{"wrapper", []string{"/bin/sh", "-c", "reports-controller --reportsChunkSize=1"}, nil, "official_upstream", ExitUnknown, ExitUnknown, "UNKNOWN"},
		{"unknown option", []string{"reports-controller"}, []string{"--other=1"}, "official_upstream", ExitUnknown, ExitUnknown, "UNKNOWN"},
		{"overflow", []string{"reports-controller"}, []string{"--reportsChunkSize=2147483648"}, "official_upstream", ExitUnknown, ExitUnknown, "UNKNOWN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := kyvernoProposal(t, tc.command, tc.args, "canary-8a2ded")
			path := writeCNCFFile(t, "proposal.json", raw, 0o600)
			args := prepareArgs(path)
			if tc.distribution != "" {
				args = append(args, "--distribution", tc.distribution)
			}
			code, input, stderr := runCNCFCLI(t, append(args, "--format", "input")...)
			if code != tc.prepareCode || stderr != "" || !json.Valid([]byte(input)) {
				t.Fatalf("prepare code=%d stderr=%q", code, stderr)
			}
			preparedPath := writeCNCFFile(t, "prepared.json", []byte(input), 0o600)
			code, output, stderr := runCNCFCLI(t, "check", "cncf", "--project", "kyverno", "--input", preparedPath, "--input-digest", cncfDigest([]byte(input)), "--now", "2026-09-09T01:00:00Z", "--format", "json")
			if code != tc.checkCode || stderr != "" || !strings.Contains(output, `"status":"`+tc.status+`"`) || !strings.Contains(output, `"assessment":"UNKNOWN"`) || !strings.Contains(output, `"networkUsed":false`) || strings.Contains(output, "canary-8a2ded") {
				t.Fatalf("check code=%d stderr=%q report=%s", code, stderr, output)
			}
		})
	}
}

func TestKyvernoPreparationPreflightAndPrivateAdmissionStaySanitized(t *testing.T) {
	t.Parallel()
	const canary = "private-malformed-canary-f82f8d"
	raw := kyvernoProposal(t, []string{"reports-controller"}, nil, canary)
	private := writeCNCFFile(t, canary+".json", raw, 0o600)
	symlink := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(private, symlink); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"symlink":               symlink,
		"permissive":            writeCNCFFile(t, "permissive.json", raw, 0o644),
		"private unknown field": writeCNCFFile(t, "invalid.json", []byte(`{"`+canary+`":true}`), 0o600),
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runCNCFCLI(t, append(append(prepareArgs(path), "--distribution", "official_upstream"), "--format", "json")...)
			if code != ExitUsage || stdout != "" || strings.Contains(stderr, path) || strings.Contains(stderr, canary) {
				t.Fatalf("unsafe rejection: code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
	for _, extra := range [][]string{{"--distribution"}, {"--distribution", ""}, {"--distribution", canary}, {"--distribution", "official_upstream", "--distribution", "custom_build"}, {"--schema-validation", "required"}} {
		code, stdout, stderr := runCNCFCLI(t, append(prepareArgs(symlink), extra...)...)
		if code != ExitUsage || stdout != "" || strings.Contains(stderr, canary) || strings.Contains(stderr, symlink) {
			t.Fatalf("invalid preflight admitted private path/value: args=%q code=%d stdout=%q stderr=%q", extra, code, stdout, stderr)
		}
	}
	code, stdout, stderr := runCNCFCLI(t, append(append(prepareArgs(private), "--distribution", "official_upstream"), "--input-digest", "sha256:"+strings.Repeat("0", 64))...)
	if code != ExitIntegrity || stdout != "" || strings.Contains(stderr, canary) || strings.Contains(stderr, private) {
		t.Fatalf("bad pin rejection: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCNCFPreparationRejectsKubernetesAndCiliumFlagsBeforeInputRead(t *testing.T) {
	t.Parallel()
	privateInput := filepath.Join(t.TempDir(), "private-not-read.json")
	base := []string{"prepare", "cncf", "--project", "kyverno", "--input", privateInput, "--container", "selected", "--from", "1.12.5", "--to", "1.13.0"}
	for _, extra := range [][]string{
		{"--cilium-config-map", privateInput},
		{"--cilium-config-map-digest", "sha256:" + strings.Repeat("0", 64)},
		{"--cilium-config-complete=false"},
		{"--cilium-config-precedence-resolved=false"},
		{"--cilium-distribution", "custom_build"},
		{"--target-api-apply-required=false"},
		{"--resource-scope-complete=false"},
	} {
		code, stdout, stderr := runCNCFCLI(t, append(append([]string{}, base...), extra...)...)
		if code != ExitUsage || stdout != "" || strings.Contains(stderr, privateInput) {
			t.Fatalf("cross-project flags admitted input: args=%q code=%d stdout=%q stderr=%q", extra, code, stdout, stderr)
		}
	}
}

type failedPreparationWriter struct{}

func (failedPreparationWriter) Write([]byte) (int, error) {
	return 0, errors.New("synthetic output failure")
}

func TestKyvernoPreparationDoesNotSucceedWhenOutputFails(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "proposal.json", kyvernoProposal(t, []string{"reports-controller"}, nil, "private"), 0o600)
	for _, format := range []string{"human", "json", "input"} {
		var stderr bytes.Buffer
		code := Run(context.Background(), append(append(prepareArgs(path), "--distribution", "official_upstream"), "--format", format), failedPreparationWriter{}, &stderr, "test")
		if code != ExitIntegrity {
			t.Fatalf("%s output failure exit=%d", format, code)
		}
	}
}
