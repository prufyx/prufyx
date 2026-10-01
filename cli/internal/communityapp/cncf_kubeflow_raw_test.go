// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func kubeflowRawArgs(t *testing.T, path, from, to, format string) []string {
	t.Helper()
	return []string{"check", "cncf", "--project", "kubeflow", "--python-source", path, "--from", from, "--to", to, "--now", "2026-09-10T22:00:00Z", "--format", format}
}

func TestKubeflowKFPRawSourceEditAndRepeatWithoutSourceExecution(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "component.py")
	canary := filepath.Join(dir, "MUST_NOT_EXIST")
	beforeRaw := []byte(fmt.Sprintf("# %s\nfrom kfp.components import create_component_from_func\n@create_component_from_func\ndef PRIVATE_COMPONENT(value):\n    return value\n", canary))
	writeCNCFFileAt(t, path, beforeRaw)
	args := kubeflowRawArgs(t, path, "1.8.22", "2.0.0", "human")
	code, before, stderr := runCNCFCLI(t, args...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(before, "create_component_from_func") || !strings.Contains(before, "scoped result: BLOCKED") || !strings.Contains(before, "aggregate: UNKNOWN") || !strings.Contains(before, "does not modify or execute") || !strings.Contains(before, "Go lexical subset") {
		t.Fatalf("code=%d stderr=%q output=%s", code, stderr, before)
	}
	assertKubeflowKFPRedacted(t, before, path, canary)
	if _, err := os.Stat(canary); !os.IsNotExist(err) {
		t.Fatal("supplied source was executed")
	}
	afterRaw := []byte(fmt.Sprintf("# %s\nfrom kfp import dsl\n@dsl.component\ndef PRIVATE_COMPONENT(value):\n    return value\n", canary))
	writeCNCFFileAt(t, path, afterRaw)
	code, after, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || !strings.Contains(after, "dsl.component") || !strings.Contains(after, "scoped result: PASS") || !strings.Contains(after, "aggregate: UNKNOWN") || !strings.Contains(after, "separately validate component inputs") {
		t.Fatalf("code=%d stderr=%q output=%s", code, stderr, after)
	}
	assertKubeflowKFPRedacted(t, after, path, canary)
	code, repeated, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || repeated != after {
		t.Fatalf("repeat code=%d stderr=%q equal=%t", code, stderr, repeated == after)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("persisted intermediates: %v", entries)
	}
}

func TestKubeflowKFPRawUnknownPrivacyAndModeGuards(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "component.py")
	tests := []struct{ name, source, from, to, category string }{
		{"alias", "from kfp.components import create_component_from_func as PrivateAlias\n@PrivateAlias\ndef private_component():\n    pass\n", "1.8.22", "2.0.0", "binding_missing"},
		{"except handler rebound", "from kfp import dsl\ntry:\n    pass\nexcept Exception as dsl:\n    pass\n@dsl.component\ndef private_component():\n    pass\n", "1.8.22", "2.0.0", "unsupported_lexical_form"},
		{"decorator call", "from kfp import dsl\n@dsl.component()\ndef private_component():\n    pass\n", "1.8.22", "2.0.0", "unsupported_lexical_form"},
		{"multiple", "from kfp import dsl\n@dsl.component\ndef one():\n    pass\n@dsl.component\ndef two():\n    pass\n", "1.8.22", "2.0.0", "unsupported_lexical_form"},
		{"wrong pair", "from kfp.components import create_component_from_func\n@create_component_from_func\ndef private_component():\n    pass\n", "1.8.21", "2.0.0", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			writeCNCFFileAt(t, path, []byte(tc.source))
			code, out, errout := runCNCFCLI(t, kubeflowRawArgs(t, path, tc.from, tc.to, "human")...)
			if code != ExitUnknown || errout != "" || !strings.Contains(out, "UNKNOWN") || (tc.category != "" && !strings.Contains(out, tc.category)) {
				t.Fatalf("code=%d stderr=%q output=%s", code, errout, out)
			}
			assertKubeflowKFPRedacted(t, out, path)
		})
	}
	writeCNCFFileAt(t, path, []byte("def broken(:\n"))
	code, out, errout := runCNCFCLI(t, kubeflowRawArgs(t, path, "1.8.22", "2.0.0", "human")...)
	if code != ExitUsage || out != "" || errout != "prufyx: KUBEFLOW_KFP_SOURCE_OUTSIDE_ADMITTED_GO_LEXICAL_SYNTAX\n" {
		t.Fatalf("syntax code=%d stdout=%q stderr=%q", code, out, errout)
	}
	raw := []byte("from kfp import dsl\n@dsl.component\ndef private_component():\n    pass\n")
	writeCNCFFileAt(t, path, raw)
	base := kubeflowRawArgs(t, path, "1.8.22", "2.0.0", "json")
	matching := append(append([]string{}, base...), "--python-source-digest", digestCommunityBytes(raw))
	code, out, errout = runCNCFCLI(t, matching...)
	if code != ExitOK || errout != "" || !json.Valid([]byte(out)) || strings.Contains(out, "private.invalid") {
		t.Fatalf("matching code=%d stderr=%q output=%s", code, errout, out)
	}
	badDigest := "sha256:" + strings.Repeat("0", 64)
	code, out, errout = runCNCFCLI(t, append(base, "--python-source-digest", badDigest)...)
	if code != ExitIntegrity || out != "" || errout != "prufyx: CNCF_PREPARATION_INTEGRITY_FAILURE\n" {
		t.Fatalf("digest code=%d stdout=%q stderr=%q", code, out, errout)
	}
	for _, extra := range [][]string{{"--input", path}, {"--service", path}, {"--in-toto-run-argv", path}, {"--metanode-config", path}, {"--knowledge-db", dir}, {"--replay-report", path}} {
		args := append(append([]string{}, base...), extra...)
		code, out, errout = runCNCFCLI(t, args...)
		if code != ExitUsage || out != "" || errout == "" || strings.Contains(errout, path) {
			t.Fatalf("extra=%v code=%d out=%q err=%q", extra, code, out, errout)
		}
	}
	code, out, errout = runCNCFCLI(t, append(base, "--python-ast-interpreter", "/usr/bin/false")...)
	if code != ExitUsage || out != "" || errout == "" || strings.Contains(errout, path) {
		t.Fatalf("interpreter flag code=%d stdout=%q stderr=%q", code, out, errout)
	}
}

func assertKubeflowKFPRedacted(t *testing.T, output string, forbidden ...string) {
	t.Helper()
	for _, value := range append(forbidden, "PRIVATE_COMPONENT", "private.invalid") {
		if strings.Contains(output, value) {
			t.Fatalf("private Python source crossed output: %q in %s", value, output)
		}
	}
}
