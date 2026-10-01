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

func tufRawArgs(t *testing.T, path, from, to, format string) []string {
	t.Helper()
	return []string{"check", "cncf", "--project", "the-update-framework-tuf", "--python-source", path, "--from", from, "--to", to, "--now", "2026-09-10T22:00:00Z", "--format", format}
}

func TestTUFUpdaterRawSourceEditAndRepeatWithoutSourceExecution(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "updater.py")
	canary := filepath.Join(dir, "MUST_NOT_EXIST")
	beforeRaw := []byte(fmt.Sprintf("# %s\nfrom tuf.ngclient import Updater\nclient = Updater(metadata_dir, metadata_base_url)\n", canary))
	writeCNCFFileAt(t, path, beforeRaw)
	args := tufRawArgs(t, path, "6.0.0", "7.0.0", "human")
	code, before, stderr := runCNCFCLI(t, args...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(before, "bootstrap keyword: absent") || !strings.Contains(before, "scoped result: BLOCKED") || !strings.Contains(before, "aggregate: UNKNOWN") || !strings.Contains(before, "does not modify or execute") || !strings.Contains(before, "Go lexical subset") {
		t.Fatalf("code=%d stderr=%q output=%s", code, stderr, before)
	}
	assertTUFRedacted(t, before, path, canary)
	if _, err := os.Stat(canary); !os.IsNotExist(err) {
		t.Fatal("supplied source was executed")
	}
	afterRaw := []byte(fmt.Sprintf("# %s\nfrom tuf.ngclient import Updater\nclient = Updater(metadata_dir, metadata_base_url, bootstrap=trusted_root_bytes)\n", canary))
	writeCNCFFileAt(t, path, afterRaw)
	code, after, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || !strings.Contains(after, "bootstrap keyword: present") || !strings.Contains(after, "scoped result: PASS") || !strings.Contains(after, "aggregate: UNKNOWN") || !strings.Contains(after, "separately validate its value") {
		t.Fatalf("code=%d stderr=%q output=%s", code, stderr, after)
	}
	assertTUFRedacted(t, after, path, canary)
	code, repeated, stderr := runCNCFCLI(t, args...)
	if code != ExitOK || stderr != "" || repeated != after {
		t.Fatalf("repeat code=%d stderr=%q equal=%t", code, stderr, repeated == after)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("persisted intermediates: %v", entries)
	}
}

func TestTUFUpdaterRawUnknownPrivacyAndModeGuards(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "updater.py")
	tests := []struct{ name, source, from, to, category string }{
		{"alias", "from tuf.ngclient import Updater as PrivateAlias\nPrivateAlias('/m','https://private.invalid/')\n", "6.0.0", "7.0.0", "binding_missing"},
		{"except handler rebound", "from tuf.ngclient import Updater\ntry:\n    pass\nexcept Exception as Updater:\n    Updater('/m','https://private.invalid/', bootstrap=None)\n", "6.0.0", "7.0.0", "candidate_call_count"},
		{"star args", "from tuf.ngclient import Updater\nUpdater(*PRIVATE_VALUES)\n", "6.0.0", "7.0.0", "star_arguments"},
		{"positional bootstrap", "from tuf.ngclient import Updater\nUpdater(a,b,c,d,e,f,PRIVATE_ROOT)\n", "6.0.0", "7.0.0", "positional_bootstrap"},
		{"wrong pair", "from tuf.ngclient import Updater\nUpdater('/m','https://private.invalid/')\n", "6.0.1", "7.0.0", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			writeCNCFFileAt(t, path, []byte(tc.source))
			code, out, errout := runCNCFCLI(t, tufRawArgs(t, path, tc.from, tc.to, "human")...)
			if code != ExitUnknown || errout != "" || !strings.Contains(out, "UNKNOWN") || (tc.category != "" && !strings.Contains(out, tc.category)) {
				t.Fatalf("code=%d stderr=%q output=%s", code, errout, out)
			}
			assertTUFRedacted(t, out, path)
		})
	}
	writeCNCFFileAt(t, path, []byte("def broken(:\n"))
	code, out, errout := runCNCFCLI(t, tufRawArgs(t, path, "6.0.0", "7.0.0", "human")...)
	if code != ExitUsage || out != "" || errout != "prufyx: TUF_SOURCE_OUTSIDE_ADMITTED_GO_LEXICAL_SYNTAX\n" {
		t.Fatalf("syntax code=%d stdout=%q stderr=%q", code, out, errout)
	}
	raw := []byte("from tuf.ngclient import Updater\nUpdater('/m','https://private.invalid/', bootstrap=None)\n")
	writeCNCFFileAt(t, path, raw)
	base := tufRawArgs(t, path, "6.0.0", "7.0.0", "json")
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
	if code != ExitUsage || out != "" || errout == "" || strings.Contains(errout, "/usr/bin/false") {
		t.Fatalf("removed interpreter flag code=%d stdout=%q stderr=%q", code, out, errout)
	}
}

func assertTUFRedacted(t *testing.T, output string, forbidden ...string) {
	t.Helper()
	for _, value := range append(forbidden, "PRIVATE_TUF", "private.invalid", "/private/metadata", "trusted_root_bytes", "PRIVATE_VALUES", "PRIVATE_ROOT") {
		if strings.Contains(output, value) {
			t.Fatalf("private Python source crossed output: %q in %s", value, output)
		}
	}
}
